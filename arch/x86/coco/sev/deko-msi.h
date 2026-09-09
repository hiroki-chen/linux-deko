/* SPDX-License-Identifier: GPL-2.0-only */
/* Private implementation included after struct deko_ring_poller in deko.c.
 * Experimental fixed guest PCI layout; no device payload contains app data.
 * All service execution stays in the context-bound create_io_thread task.
 */
#define DEKO_MSI_SLOTS 32
#define DEKO_MSI_BAR0 0x80001000ULL
#define DEKO_RING_MSI_MAGIC 0x444d5349U
#define DEKO_RING_MSI_OFFSET 0xa20

struct deko_ring_msi_control {
	u32 magic;
	u16 version;
	u16 enabled;
	u32 vector;
	u32 parked;
	u64 incarnation;
	u64 sleeps;
	u64 progress_batches;
	u64 irq_count;
	u64 last_irq_tsc;
	u32 last_irq_cpu;
	u32 reserved;
};
static_assert(sizeof(struct deko_ring_msi_control) == 0x40);
static_assert(DEKO_RING_MSI_OFFSET + sizeof(struct deko_ring_msi_control) < PAGE_SIZE);
static_assert(offsetof(struct deko_ring_msi_control, parked) == 0xc);
static_assert(offsetof(struct deko_ring_msi_control, incarnation) == 0x10);

struct deko_msi_slot {
	spinlock_t lock;
	struct deko_ring_poller *poller;
	int irq;
	bool registered;
};
/* Static slot storage outlives every IRQ. The mutex serializes PCI and task
 * lifetime changes; the IRQ lock protects its one referenced poller pointer. */
static struct deko_msi_slot deko_msi_slots[DEKO_MSI_SLOTS];
static DEFINE_MUTEX(deko_msi_mutex);
static struct pci_dev *deko_msi_pci;
static void __iomem *deko_msi_regs;
static u64 deko_msi_incarnation;

static struct deko_ring_msi_control *deko_msi_control(struct deko_ring_poller *poller)
{
	return poller->buf->buf + DEKO_RING_MSI_OFFSET;
}

static irqreturn_t deko_msi_irq(int irq, void *opaque)
{
	struct deko_msi_slot *slot = opaque;
	struct deko_ring_poller *poller;
	unsigned long flags;

	spin_lock_irqsave(&slot->lock, flags);
	poller = slot->poller;
	if (poller) {
		struct deko_ring_msi_control *control = deko_msi_control(poller);

		WRITE_ONCE(control->irq_count, control->irq_count + 1);
		WRITE_ONCE(control->last_irq_tsc, rdtsc_ordered());
		WRITE_ONCE(control->last_irq_cpu, raw_smp_processor_id());
		atomic_inc(&poller->work_seq);
		wake_up_all(&poller->work_wait);
	}
	spin_unlock_irqrestore(&slot->lock, flags);
	return IRQ_HANDLED;
}

static struct deko_ring_msi_control *deko_msi_attach(struct deko_ring_poller *poller)
{
	struct deko_ring_msi_control *control = NULL;
	struct deko_msi_slot *slot;
	unsigned long flags;
	unsigned int cpu;
	int i, ret;

	if (!READ_ONCE(deko_ring_msi) ||
	    READ_ONCE(deko_ring_poller_affinity) != DEKO_RING_POLLER_AFFINITY_NEXT ||
	    cpumask_weight(current->cpus_ptr) != 1)
		return NULL;
	cpu = cpumask_first(current->cpus_ptr);
	if (cpu >= nr_cpu_ids || !cpu_online(cpu))
		return NULL;
	mutex_lock(&deko_msi_mutex);
	if (!deko_msi_pci || deko_msi_incarnation == U64_MAX)
		goto out;
	for (i = 0; i < DEKO_MSI_SLOTS; i++)
		if (!deko_msi_slots[i].poller)
			break;
	if (i == DEKO_MSI_SLOTS)
		goto out;
	slot = &deko_msi_slots[i];
	control = deko_msi_control(poller);
	memset(control, 0, sizeof(*control));
	WRITE_ONCE(control->magic, DEKO_RING_MSI_MAGIC);
	WRITE_ONCE(control->version, 1);
	WRITE_ONCE(control->vector, i);
	WRITE_ONCE(control->incarnation, ++deko_msi_incarnation);
	slot->irq = pci_irq_vector(deko_msi_pci, i);
	/* Set the destination before IRQ startup to avoid deferred migration. */
	ret = irq_set_affinity(slot->irq, cpumask_of(cpu));
	if (ret)
		goto failed;
	spin_lock_irqsave(&slot->lock, flags);
	slot->poller = poller;
	spin_unlock_irqrestore(&slot->lock, flags);
	ret = request_irq(slot->irq, deko_msi_irq, 0, "deko-service-msi", slot);
	if (ret) {
		spin_lock_irqsave(&slot->lock, flags);
		slot->poller = NULL;
		spin_unlock_irqrestore(&slot->lock, flags);
		goto failed;
	}
	slot->registered = true;
	poller->msi_slot = i;
	smp_store_release(&control->enabled, 1);
	pr_info("Deko ring MSI endpoint owner=%d poller=%d cpu=%u vector=%d irq=%d incarnation=%llu spin_us=%u\n",
		poller->owner->pid, current->pid, cpu, i, slot->irq,
		control->incarnation, READ_ONCE(deko_ring_msi_spin_us));
	goto out;
failed:
	pr_warn("Deko ring MSI attach failed ret=%d; retaining ordinary service\n", ret);
	control = NULL;
out:
	mutex_unlock(&deko_msi_mutex);
	return control;
}

static void deko_msi_detach_locked(struct deko_ring_poller *poller)
{
	struct deko_ring_msi_control *control;
	struct deko_msi_slot *slot;
	unsigned long flags;
	int i = poller->msi_slot;

	lockdep_assert_held(&deko_msi_mutex);
	if (i < 0 || i >= DEKO_MSI_SLOTS)
		return;
	slot = &deko_msi_slots[i];
	control = deko_msi_control(poller);
	smp_store_release(&control->enabled, 0);
	smp_mb();
	/* IRQ callbacks finish before the task pointer or ring can be released.
	 * A delayed MSI after slot reuse is only an empty wake; it grants nothing. */
	if (slot->registered) {
		free_irq(slot->irq, slot);
		slot->registered = false;
	}
	spin_lock_irqsave(&slot->lock, flags);
	slot->poller = NULL;
	spin_unlock_irqrestore(&slot->lock, flags);
	poller->msi_slot = -1;
	pr_info("Deko ring MSI retired owner=%d poller=%d vector=%d incarnation=%llu sleeps=%llu progress_batches=%llu irq_count=%llu last_irq_tsc=%llu last_irq_cpu=%u\n",
		poller->owner->pid, poller->task->pid, i, control->incarnation,
		control->sleeps, control->progress_batches, control->irq_count,
		control->last_irq_tsc, control->last_irq_cpu);
}

static void deko_msi_detach(struct deko_ring_poller *poller)
{
	mutex_lock(&deko_msi_mutex);
	deko_msi_detach_locked(poller);
	mutex_unlock(&deko_msi_mutex);
}

/* Failure-only guest diagnostics. The lifetime mutex prevents detach/free
 * while pointers are inspected. Values may change between READ_ONCE loads;
 * this is a scheduling snapshot, never a coherent request or authorization.
 * Only already-public ring metadata is exposed, with no arguments or payload.
 * The PCI core removes the attribute before invoking the driver's remove().
 */
static ssize_t service_state_show(struct device *dev,
				 struct device_attribute *attr, char *buffer)
{
	ssize_t used = 0;
	int i;

	mutex_lock(&deko_msi_mutex);
	used += sysfs_emit_at(buffer, used, "version=2 tsc=%llu device=%u\n",
			     rdtsc_ordered(),
			     deko_msi_pci && &deko_msi_pci->dev == dev);
	for (i = 0; i < DEKO_MSI_SLOTS; i++) {
		struct deko_ring_poller *poller = deko_msi_slots[i].poller;
		struct deko_ring_msi_control *control;
		struct deko_syscall_ring *ring;
		struct mm_struct *owner_mm;
		u32 head, tail, state = U32_MAX, flags = 0;
		u64 nr = U64_MAX;
		int turn_owner = 0, turn_seq = 0;

		if (!poller)
			continue;
		/* Reserve enough space for one worst-case line and a truncation
		 * marker. sysfs_emit_at() additionally bounds every individual write. */
		if (used > PAGE_SIZE - 768) {
			used += sysfs_emit_at(buffer, used, "truncated=1\n");
			break;
		}
		ring = poller->ring;
		control = deko_msi_control(poller);
		owner_mm = get_task_mm(poller->owner);
		if (owner_mm) {
			turn_owner =
				atomic_read(&owner_mm->deko_service_turn_owner);
			turn_seq = atomic_read(&owner_mm->deko_service_turn_seq);
			mmput(owner_mm);
		}
		head = READ_ONCE(ring->head);
		tail = READ_ONCE(ring->tail);
		if (head < DEKO_RING_CAPACITY && head != tail) {
			state = READ_ONCE(ring->entries[head].state);
			nr = READ_ONCE(ring->entries[head].ax);
			flags = READ_ONCE(ring->entries[head]._reserved);
		}
		used += sysfs_emit_at(buffer, used,
			"slot=%d owner=%d worker=%d owner_state=%u worker_state=%u turn_owner=%d turn_seq=%d head=%u tail=%u producer=%u poller=%u parked=%u enabled=%u seq=%d sleeps=%llu progress=%llu irq=%llu heartbeat=%llu entry_state=%u nr=%llu flags=%u\n",
			i, poller->owner->pid, poller->task->pid,
			READ_ONCE(poller->owner->__state),
			READ_ONCE(poller->task->__state), turn_owner,
			turn_seq, head, tail,
			READ_ONCE(ring->producer_state), READ_ONCE(ring->poller_state),
			READ_ONCE(control->parked), READ_ONCE(control->enabled),
			atomic_read(&poller->work_seq), READ_ONCE(control->sleeps),
			READ_ONCE(control->progress_batches), READ_ONCE(control->irq_count),
			READ_ONCE(ring->poller_heartbeat), state, nr, flags);
	}
	mutex_unlock(&deko_msi_mutex);
	return used;
}
static DEVICE_ATTR(service_state, 0400, service_state_show, NULL);
static struct attribute *deko_msi_attrs[] = {
	&dev_attr_service_state.attr,
	NULL,
};
ATTRIBUTE_GROUPS(deko_msi);

static int deko_msi_probe(struct pci_dev *pci, const struct pci_device_id *id)
{
	void __iomem *regs;
	int ret;

	mutex_lock(&deko_msi_mutex);
	if (deko_msi_pci || pci_resource_start(pci, 0) != DEKO_MSI_BAR0 ||
	    pci_resource_len(pci, 0) < 256 ||
	    !(pci_resource_flags(pci, 0) & IORESOURCE_MEM)) {
		ret = -ENODEV;
		goto out;
	}
	ret = pci_enable_device_mem(pci);
	if (ret)
		goto out;
	ret = pci_request_regions(pci, "deko-service-msi");
	if (ret)
		goto disable;
	regs = pci_iomap(pci, 0, 0);
	if (!regs) {
		ret = -ENOMEM;
		goto regions;
	}
	/* Peer zero is fixed in the monitor; a different server fails closed. */
	if (ioread32(regs + 8) != 0) {
		ret = -ENODEV;
		goto unmap;
	}
	ret = pci_alloc_irq_vectors(pci, DEKO_MSI_SLOTS, DEKO_MSI_SLOTS, PCI_IRQ_MSIX);
	if (ret < 0)
		goto unmap;
	pci_set_master(pci);
	deko_msi_regs = regs;
	deko_msi_pci = pci;
	dev_info(&pci->dev, "Deko service MSI device ready bar0=%llx peer=0 vectors=%u\n",
		 DEKO_MSI_BAR0, DEKO_MSI_SLOTS);
	ret = 0;
	goto out;
unmap:
	pci_iounmap(pci, regs);
regions:
	pci_release_regions(pci);
disable:
	pci_disable_device(pci);
out:
	mutex_unlock(&deko_msi_mutex);
	return ret;
}

static void deko_msi_remove(struct pci_dev *pci)
{
	int i;

	mutex_lock(&deko_msi_mutex);
	deko_msi_pci = NULL;
	for (i = 0; i < DEKO_MSI_SLOTS; i++) {
		struct deko_ring_poller *poller = deko_msi_slots[i].poller;

		if (poller) {
			deko_msi_detach_locked(poller);
			atomic_inc(&poller->work_seq);
			wake_up_all(&poller->work_wait);
		}
	}
	pci_free_irq_vectors(pci);
	pci_iounmap(pci, deko_msi_regs);
	deko_msi_regs = NULL;
	pci_clear_master(pci);
	pci_release_regions(pci);
	pci_disable_device(pci);
	dev_info(&pci->dev, "Deko service MSI device removed\n");
	mutex_unlock(&deko_msi_mutex);
}

static const struct pci_device_id deko_msi_ids[] = {
	{ PCI_DEVICE(0x1af4, 0x1110) },
	{ }
};
static struct pci_driver deko_msi_driver = {
	.name = "deko-service-msi",
	.id_table = deko_msi_ids,
	.probe = deko_msi_probe,
	.remove = deko_msi_remove,
	.dev_groups = deko_msi_groups,
};

static int __init deko_msi_init(void)
{
	int i;

	if (!deko_syscall_ring_enabled)
		return 0;
	for (i = 0; i < DEKO_MSI_SLOTS; i++)
		spin_lock_init(&deko_msi_slots[i].lock);
	/* deko.c's KBUILD_MODNAME is also the external control module's name.
	 * Give this built-in driver a distinct sysfs module namespace. */
	return __pci_register_driver(&deko_msi_driver, NULL, "deko_service_msi");
}
device_initcall(deko_msi_init);
