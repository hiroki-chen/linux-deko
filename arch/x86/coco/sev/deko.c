// SPDX-License-Identifier: GPL-2.0-only
/*
 * Deko extension for AMD SEV-SNP support
 *
 * Copyright (C) 2026 Hiroki Chen
 *
 * Author: Hiroki Chen <haobchen@iu.edu>
 */

#define pr_fmt(fmt) "Deko: CPU%u: " fmt, raw_smp_processor_id()

#define CREATE_TRACE_POINTS

#include <trace/events/deko.h>

#undef CREATE_TRACE_POINTS

#include <linux/completion.h>
#include <linux/hashtable.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/mnt_namespace.h>
#include <linux/mmap_lock.h>
#include <linux/ns_common.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kstrtox.h>
#include <linux/local_lock.h>
#include <linux/mutex.h>
#include <linux/irqflags.h>
#include <linux/sizes.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/prio.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/task_work.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <asm-generic/mman-common.h>
#include <asm/mem_encrypt.h>
#include <asm/processor.h>
#include <asm/sev.h>
#include <asm/syscall.h>
#include <asm/trap_pf.h>
#include <asm/tsc.h>
#include <asm/current.h>
#include <uapi/linux/sched.h>

extern char __per_cpu_start[];

#define DEKO_DEFAULT_SHARED_BUF_SIZE SZ_2M
#define DEKO_RING_CAPACITY 32
#define DEKO_SYSCALL_RING_MAGIC 0x44535953U
#define DEKO_SYSCALL_RING_VERSION 2
#define DEKO_SYSCALL_RING_ENTRY_EMPTY 0
#define DEKO_SYSCALL_RING_ENTRY_READY 1
#define DEKO_SYSCALL_RING_ENTRY_DONE 2
#define DEKO_SYSCALL_RING_ENTRY_CLAIMED 3
#define DEKO_SYSCALL_RING_ENTRY_FLAG_EPOLL_PEEK 1U
#define DEKO_POLLER_ASLEEP 0
#define DEKO_POLLER_AWAKE 1
#define DEKO_RING_POLLER_IDLE_CYCLES_DEFAULT 30000000ULL
#define DEKO_RING_POLLER_SLEEP_MS_DEFAULT 1
#define DEKO_RING_POLLER_AFFINITY_NONE 0
#define DEKO_RING_POLLER_AFFINITY_SAME 1
#define DEKO_RING_POLLER_AFFINITY_NEXT 2
#define DEKO_RING_WAIT_RESCHED_INTERVAL 1024
#define DEKO_DOMAIN_BITS 8
#define DEKO_PIN_PREFAULT_MAX_RETRIES 3
#define DEKO_EXEC_RANGE_MAX_PAGES 16384UL
#define DEKO_EXEC_RANGE_MAX_BYTES (DEKO_EXEC_RANGE_MAX_PAGES << PAGE_SHIFT)

struct deko_domain_entry {
	u64 mnt_ns_id;
	u32 domain_id;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(deko_domain_table, DEKO_DOMAIN_BITS);
static DEFINE_MUTEX(deko_domain_lock);
static DEFINE_PER_CPU(local_lock_t,
		      deko_svsm_caa_lock) = INIT_LOCAL_LOCK(deko_svsm_caa_lock);
static bool deko_no_eager_fault = true;
static bool deko_pin_proxy_task = true;
static bool deko_syscall_ring_enabled;
static bool deko_ring_poll;
static u64 deko_ring_poller_idle_cycles = DEKO_RING_POLLER_IDLE_CYCLES_DEFAULT;
static unsigned int deko_ring_poller_sleep_ms =
	DEKO_RING_POLLER_SLEEP_MS_DEFAULT;
static int deko_ring_poller_nice;
static unsigned int deko_ring_poller_affinity =
	DEKO_RING_POLLER_AFFINITY_NONE;

static int __init deko_pin_proxy_task_setup(char *str)
{
	return kstrtobool(str, &deko_pin_proxy_task) == 0;
}
__setup("deko_pin_proxy_task=", deko_pin_proxy_task_setup);

static int __init deko_syscall_ring_setup(char *str)
{
	return kstrtobool(str, &deko_syscall_ring_enabled) == 0;
}
__setup("deko_syscall_ring=", deko_syscall_ring_setup);

static int __init deko_ring_poll_setup(char *str)
{
	return kstrtobool(str, &deko_ring_poll) == 0;
}
__setup("deko_ring_poll=", deko_ring_poll_setup);

static int __init deko_ring_poller_idle_cycles_setup(char *str)
{
	return kstrtoull(str, 0, &deko_ring_poller_idle_cycles) == 0;
}
__setup("deko_ring_poller_idle_cycles=", deko_ring_poller_idle_cycles_setup);

static int __init deko_ring_poller_sleep_ms_setup(char *str)
{
	return kstrtouint(str, 0, &deko_ring_poller_sleep_ms) == 0;
}
__setup("deko_ring_poller_sleep_ms=", deko_ring_poller_sleep_ms_setup);

static int __init deko_ring_poller_nice_setup(char *str)
{
	int nice;

	if (kstrtoint(str, 0, &nice) != 0)
		return 0;
	if (nice < MIN_NICE)
		nice = MIN_NICE;
	if (nice > MAX_NICE)
		nice = MAX_NICE;
	deko_ring_poller_nice = nice;
	return 1;
}
__setup("deko_ring_poller_nice=", deko_ring_poller_nice_setup);

static int __init deko_ring_poller_affinity_setup(char *str)
{
	if (!str)
		return 0;
	if (!strcmp(str, "none")) {
		deko_ring_poller_affinity = DEKO_RING_POLLER_AFFINITY_NONE;
		return 1;
	}
	if (!strcmp(str, "same")) {
		deko_ring_poller_affinity = DEKO_RING_POLLER_AFFINITY_SAME;
		return 1;
	}
	if (!strcmp(str, "next")) {
		deko_ring_poller_affinity = DEKO_RING_POLLER_AFFINITY_NEXT;
		return 1;
	}

	return 0;
}
__setup("deko_ring_poller_affinity=", deko_ring_poller_affinity_setup);

struct deko_launch_app_call_args {
	const struct pt_regs *regs;
	u32 launch_type;
	u64 migration_version;
};

struct deko_migration_call_args {
	unsigned int old_cpu;
	unsigned int current_cpu;
	const struct deko_handoff_checkpoint *checkpoint;
};

struct deko_exec_range_ready_call_args {
	unsigned long start;
	unsigned long end;
};

struct deko_exec_range_unlift_call_args {
	unsigned long start;
	unsigned long end;
	unsigned int page_count;
	u64 page_gpas[DEKO_EXEC_RANGE_UNLIFT_MAX_PAGES];
};

struct deko_exec_pin_entry {
	struct list_head node;
	struct mm_struct *mm;
	unsigned long addr;
	struct page *page;
};

static LIST_HEAD(deko_exec_pin_list);
static DEFINE_MUTEX(deko_exec_pin_lock);

static int deko_prepare_monitor_migration_call(struct svsm_call *call,
					       struct svsm_ca *caa, void *arg);
static int deko_prepare_exec_range_ready_call(struct svsm_call *call,
					     struct svsm_ca *caa, void *arg);
static int deko_prepare_exec_range_unlift_call(struct svsm_call *call,
					       struct svsm_ca *caa, void *arg);
static bool deko_lookup_user_page_state(struct mm_struct *mm,
					unsigned long address,
					u64 *page_gpa,
					bool *anon_exclusive);
static int deko_prefault_lift_exec_user_range(struct mm_struct *mm,
					      unsigned long start_addr,
					      unsigned long length,
					      const char *reason);

static int deko_refresh_launch_app_context(struct svsm_call *call,
					   struct svsm_ca *caa)
{
	if (unlikely(!caa))
		return -ENODEV;

	call->caa = caa;
	call->r9 = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);

	return 0;
}

static int deko_svsm_call_locked(struct svsm_call *call,
				 int (*prepare)(struct svsm_call *,
						struct svsm_ca *, void *),
				 void *arg)
{
	struct svsm_ca *caa;
	unsigned long flags;
	int ret;

	migrate_disable();

	if (current->mm) {
		ret = svsm_prepare_vmpl1_current_mm(current->mm);
		if (ret < 0)
			goto out_migrate;
	}

	local_lock_irqsave(&deko_svsm_caa_lock, flags);

	caa = svsm_get_caa();
	ret = deko_refresh_launch_app_context(call, caa);
	if (ret < 0)
		goto out;

	if (prepare) {
		ret = prepare(call, caa, arg);
		if (ret < 0)
			goto out;
	}

	ret = svsm_perform_call_protocol(call);

out:
	local_unlock_irqrestore(&deko_svsm_caa_lock, flags);
out_migrate:
	migrate_enable();

	return ret;
}

static int deko_prepare_exec_range_ready_call(struct svsm_call *call,
					     struct svsm_ca *caa, void *arg)
{
	struct deko_exec_range_ready_call_args *range = arg;
	struct deko_exec_range_ready_req *req;

	req = (struct deko_exec_range_ready_req *)caa->svsm_buffer;
	memset(req, 0, sizeof(*req));
	req->version = DEKO_EXEC_RANGE_READY_REQ_VERSION_V1;
	req->req_size = sizeof(*req);
	req->flags = DEKO_EXEC_RANGE_F_PRIVATE_CANDIDATE;
	req->pid = current->pid;
	req->tgid = current->tgid;
	req->start_va = range->start;
	req->end_va = range->end;

	call->rax = SVSM_EXTEND_CALL(SVSM_EXTEND_EXEC_RANGE_READY);

	return 0;
}

static int deko_prepare_exec_range_unlift_call(struct svsm_call *call,
					       struct svsm_ca *caa, void *arg)
{
	struct deko_exec_range_unlift_call_args *range = arg;
	struct deko_exec_range_unlift_req *req;

	if (!range->page_count ||
	    range->page_count > DEKO_EXEC_RANGE_UNLIFT_MAX_PAGES)
		return -EINVAL;

	req = (struct deko_exec_range_unlift_req *)caa->svsm_buffer;
	memset(req, 0, sizeof(*req));
	req->version = DEKO_EXEC_RANGE_UNLIFT_REQ_VERSION_V1;
	req->req_size = sizeof(*req);
	req->pid = current->pid;
	req->tgid = current->tgid;
	req->start_va = range->start;
	req->end_va = range->end;
	req->page_count = range->page_count;
	memcpy(req->page_gpas, range->page_gpas,
	       range->page_count * sizeof(req->page_gpas[0]));

	call->rax = SVSM_EXTEND_CALL(SVSM_EXTEND_EXEC_RANGE_UNLIFT);

	return 0;
}

static int deko_notify_monitor_exec_range_ready(unsigned long start,
						unsigned long end,
						const char *reason)
{
	struct deko_exec_range_ready_call_args args = {
		.start = start,
		.end = end,
	};
	struct svsm_call call = { 0 };
	int ret;

	if (!current->is_monitored)
		return 0;
	if (!start || start >= end)
		return -EINVAL;

	ret = deko_svsm_call_locked(&call, deko_prepare_exec_range_ready_call,
				    &args);
	if (ret < 0) {
		pr_err("Deko %s exec range lift failed pid=%d tgid=%d range=[0x%lx-0x%lx) ret=%d\n",
		       reason, current->pid, current->tgid, start, end, ret);
		return ret;
	}

	pr_debug("Deko %s exec range lifted pid=%d tgid=%d range=[0x%lx-0x%lx)\n",
		 reason, current->pid, current->tgid, start, end);
	return 0;
}

static int deko_notify_monitor_exec_range_unlift(unsigned long start,
						 unsigned long end,
						 const u64 *page_gpas,
						 unsigned int page_count,
						 const char *reason)
{
	struct deko_exec_range_unlift_call_args args = {
		.start = start,
		.end = end,
		.page_count = page_count,
	};
	struct svsm_call call = { 0 };
	int ret;

	if (!current->is_monitored)
		return 0;
	if (!start || start >= end || !page_count ||
	    page_count > DEKO_EXEC_RANGE_UNLIFT_MAX_PAGES)
		return -EINVAL;
	memcpy(args.page_gpas, page_gpas, page_count * sizeof(args.page_gpas[0]));

	ret = deko_svsm_call_locked(&call, deko_prepare_exec_range_unlift_call,
				    &args);
	if (ret < 0) {
		pr_err("Deko %s exec range unlift failed pid=%d tgid=%d range=[0x%lx-0x%lx) ret=%d\n",
		       reason, current->pid, current->tgid, start, end, ret);
		return ret;
	}

	pr_debug("Deko %s exec range unlifted pid=%d tgid=%d range=[0x%lx-0x%lx)\n",
		 reason, current->pid, current->tgid, start, end);
	return 0;
}

static struct deko_exec_pin_entry *
deko_exec_pin_find_locked(struct mm_struct *mm, unsigned long addr)
{
	struct deko_exec_pin_entry *entry;

	list_for_each_entry(entry, &deko_exec_pin_list, node) {
		if (entry->mm == mm && entry->addr == (addr & PAGE_MASK))
			return entry;
	}

	return NULL;
}

static int deko_pin_private_exec_page(struct mm_struct *mm, unsigned long addr,
				      const char *reason)
{
	struct deko_exec_pin_entry *entry;
	struct deko_exec_pin_entry *existing;
	struct page *page = NULL;
	unsigned long page_addr = addr & PAGE_MASK;
	u64 page_gpa = 0;
	bool anon_exclusive = false;
	long pinned;
	int locked = 1;
	int ret = 0;

	if (!mm)
		return -EINVAL;

	mmap_read_lock(mm);
	pinned = pin_user_pages_remote(mm, page_addr, 1, FOLL_FORCE, &page,
				       &locked);
	if (locked)
		mmap_read_unlock(mm);
	if (pinned != 1) {
		pr_err("Deko %s exec pin failed pid=%d addr=0x%lx pinned=%ld\n",
		       reason, current->pid, page_addr, pinned);
		return pinned < 0 ? (int)pinned : -EFAULT;
	}

	if (!PageAnon(page) || !PageAnonExclusive(page)) {
		pr_err("Deko %s exec pin rejected non-private page pid=%d addr=0x%lx anon=%d anon_exclusive=%d\n",
		       reason, current->pid, page_addr, PageAnon(page) ? 1 : 0,
		       PageAnonExclusive(page) ? 1 : 0);
		ret = -EFAULT;
		goto out_unpin;
	}

	if (!deko_lookup_user_page_state(mm, page_addr, &page_gpa,
					 &anon_exclusive) ||
	    !anon_exclusive ||
	    (page_gpa & PAGE_MASK) != ((u64)page_to_pfn(page) << PAGE_SHIFT)) {
		pr_err("Deko %s exec pin/PTE mismatch pid=%d addr=0x%lx gpa=0x%llx page_pfn=0x%lx anon_exclusive=%d\n",
		       reason, current->pid, page_addr,
		       (unsigned long long)page_gpa, page_to_pfn(page),
		       anon_exclusive ? 1 : 0);
		ret = -EFAULT;
		goto out_unpin;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		ret = -ENOMEM;
		goto out_unpin;
	}

	mutex_lock(&deko_exec_pin_lock);
	existing = deko_exec_pin_find_locked(mm, page_addr);
	if (existing) {
		ret = existing->page == page ? 0 : -EEXIST;
		mutex_unlock(&deko_exec_pin_lock);
		kfree(entry);
		goto out_unpin;
	}

	entry->mm = mm;
	entry->addr = page_addr;
	entry->page = page;
	list_add(&entry->node, &deko_exec_pin_list);
	mutex_unlock(&deko_exec_pin_lock);

	return 0;

out_unpin:
	unpin_user_page(page);
	return ret;
}

static unsigned long deko_unpin_exec_user_range_locked(struct mm_struct *mm,
						       unsigned long start,
						       unsigned long end)
{
	struct deko_exec_pin_entry *entry;
	struct deko_exec_pin_entry *tmp;
	unsigned long restored = 0;

	list_for_each_entry_safe(entry, tmp, &deko_exec_pin_list, node) {
		if (entry->mm != mm)
			continue;
		if (entry->addr < start || entry->addr >= end)
			continue;
		list_del(&entry->node);
		unpin_user_page(entry->page);
		kfree(entry);
		restored++;
	}

	return restored;
}

static unsigned long deko_unpin_all_exec_user_ranges_locked(struct mm_struct *mm)
{
	struct deko_exec_pin_entry *entry;
	struct deko_exec_pin_entry *tmp;
	unsigned long restored = 0;

	list_for_each_entry_safe(entry, tmp, &deko_exec_pin_list, node) {
		if (entry->mm != mm)
			continue;
		list_del(&entry->node);
		unpin_user_page(entry->page);
		kfree(entry);
		restored++;
	}

	return restored;
}

static bool deko_exec_pin_next_range_locked(struct mm_struct *mm,
					    unsigned long start,
					    unsigned long end,
					    unsigned long *range_start,
					    unsigned long *range_end)
{
	struct deko_exec_pin_entry *entry;
	unsigned long first = ULONG_MAX;
	bool extended;

	list_for_each_entry(entry, &deko_exec_pin_list, node) {
		if (entry->mm != mm)
			continue;
		if (entry->addr < start || entry->addr >= end)
			continue;
		if (entry->addr < first)
			first = entry->addr;
	}

	if (first == ULONG_MAX)
		return false;

	*range_start = first;
	*range_end = first + PAGE_SIZE;

	do {
		extended = false;
		list_for_each_entry(entry, &deko_exec_pin_list, node) {
			if (entry->mm != mm)
				continue;
			if (entry->addr == *range_end && *range_end < end) {
				*range_end += PAGE_SIZE;
				extended = true;
				break;
			}
		}
	} while (extended);

	return true;
}

static unsigned int deko_exec_pin_collect_gpas_locked(struct mm_struct *mm,
						      unsigned long start,
						      unsigned long end,
						      u64 *page_gpas,
						      unsigned int max_pages)
{
	unsigned long addr = start;
	unsigned int count = 0;

	while (addr < end && count < max_pages) {
		struct deko_exec_pin_entry *entry;

		entry = deko_exec_pin_find_locked(mm, addr);
		if (!entry)
			break;

		page_gpas[count++] = (u64)page_to_pfn(entry->page) << PAGE_SHIFT;
		addr += PAGE_SIZE;
	}

	return count;
}

int deko_unlift_exec_user_range(struct mm_struct *mm, unsigned long start_addr,
				unsigned long length, const char *reason)
{
	unsigned long end_addr;
	unsigned long cur;
	unsigned long unpinned;
	int ret;

	if (!mm || !length)
		return 0;
	if (check_add_overflow(start_addr, length, &end_addr))
		return -EINVAL;

	start_addr = PAGE_ALIGN_DOWN(start_addr);
	end_addr = PAGE_ALIGN(end_addr);
	if (start_addr >= end_addr)
		return 0;

	if (!current->is_monitored) {
		mutex_lock(&deko_exec_pin_lock);
		deko_unpin_exec_user_range_locked(mm, start_addr, end_addr);
		mutex_unlock(&deko_exec_pin_lock);
		return 0;
	}

	cur = start_addr;
	for (;;) {
		unsigned long sub_start;
		unsigned long sub_end;
		unsigned long notify_start;
		bool found;

		mutex_lock(&deko_exec_pin_lock);
		found = deko_exec_pin_next_range_locked(mm, cur, end_addr,
							&sub_start, &sub_end);
		mutex_unlock(&deko_exec_pin_lock);
		if (!found)
			break;

		notify_start = sub_start;
		while (notify_start < sub_end) {
			u64 page_gpas[DEKO_EXEC_RANGE_UNLIFT_MAX_PAGES];
			unsigned int page_count;
			unsigned long notify_end;

			mutex_lock(&deko_exec_pin_lock);
			page_count = deko_exec_pin_collect_gpas_locked(
				mm, notify_start, sub_end, page_gpas,
				DEKO_EXEC_RANGE_UNLIFT_MAX_PAGES);
			mutex_unlock(&deko_exec_pin_lock);
			if (!page_count)
				return -EFAULT;
			notify_end = notify_start + page_count * PAGE_SIZE;
			ret = deko_notify_monitor_exec_range_unlift(notify_start,
								   notify_end,
								   page_gpas,
								   page_count,
								   reason);
			if (ret < 0)
				return ret;
			notify_start = notify_end;
		}

		if (sub_end <= cur)
			return -EFAULT;
		cur = sub_end;
	}

	mutex_lock(&deko_exec_pin_lock);
	unpinned = deko_unpin_exec_user_range_locked(mm, start_addr, end_addr);
	mutex_unlock(&deko_exec_pin_lock);

	if (unpinned)
		pr_debug("Deko %s exec range unpinned pid=%d range=[0x%lx-0x%lx) pages=%lu\n",
			 reason, current->pid, start_addr, end_addr, unpinned);

	return 0;
}
EXPORT_SYMBOL_GPL(deko_unlift_exec_user_range);

int deko_unlift_all_exec_user_ranges(struct mm_struct *mm, const char *reason)
{
	unsigned long start = 0;
	int ret;

	if (!mm)
		return 0;
	if (!current->is_monitored) {
		mutex_lock(&deko_exec_pin_lock);
		deko_unpin_all_exec_user_ranges_locked(mm);
		mutex_unlock(&deko_exec_pin_lock);
		return 0;
	}

	for (;;) {
		unsigned long sub_start;
		unsigned long sub_end;
		bool found;

		mutex_lock(&deko_exec_pin_lock);
		found = deko_exec_pin_next_range_locked(mm, start, TASK_SIZE_MAX,
							&sub_start, &sub_end);
		mutex_unlock(&deko_exec_pin_lock);
		if (!found)
			break;

		ret = deko_unlift_exec_user_range(mm, sub_start,
						  sub_end - sub_start, reason);
		if (ret < 0)
			return ret;

		if (sub_end <= start)
			return -EFAULT;
		start = sub_end;
	}

	mutex_lock(&deko_exec_pin_lock);
	deko_unpin_all_exec_user_ranges_locked(mm);
	mutex_unlock(&deko_exec_pin_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(deko_unlift_all_exec_user_ranges);

static int deko_prepare_exit_call(struct svsm_call *call, struct svsm_ca *caa,
				  void *arg)
{
	struct deko_new_app_req *req;

	(void)arg;

	req = (struct deko_new_app_req *)caa->svsm_buffer;
	memset(req, 0, sizeof(*req));
	req->version = DEKO_NEW_APP_REQ_VERSION_V3;
	req->req_size = sizeof(*req);
	req->tgid = current->tgid;
	req->pid = current->pid;
	req->ppid = current->real_parent->pid;
	req->app_type = DEKO_DOCKER_APPS;

	call->rax = SVSM_EXTEND_CALL(SVSM_EXTEND_REPORT_APP);
	call->r8 = 0; /* Not a creation event */

	return 0;
}

static struct deko_domain_entry *deko_domain_find_locked(u64 mnt_ns_id)
{
	struct deko_domain_entry *entry;

	hash_for_each_possible(deko_domain_table, entry, node, mnt_ns_id) {
		if (entry->mnt_ns_id == mnt_ns_id)
			return entry;
	}

	return NULL;
}

int deko_domain_bind(u64 mnt_ns_id, u32 domain_id)
{
	struct deko_domain_entry *entry;

	if (!mnt_ns_id || !domain_id)
		return -EINVAL;

	mutex_lock(&deko_domain_lock);

	entry = deko_domain_find_locked(mnt_ns_id);
	if (entry) {
		int ret = (entry->domain_id == domain_id) ? 0 : -EEXIST;

		mutex_unlock(&deko_domain_lock);
		return ret;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		mutex_unlock(&deko_domain_lock);
		return -ENOMEM;
	}

	entry->mnt_ns_id = mnt_ns_id;
	entry->domain_id = domain_id;
	hash_add(deko_domain_table, &entry->node, entry->mnt_ns_id);

	mutex_unlock(&deko_domain_lock);

	pr_debug("bind mnt_ns_id=%llu domain_id=%u\n", mnt_ns_id, domain_id);
	return 0;
}
EXPORT_SYMBOL_GPL(deko_domain_bind);

int deko_domain_lookup(u64 mnt_ns_id, u32 *domain_id)
{
	struct deko_domain_entry *entry;
	int ret = -ENOENT;

	if (!mnt_ns_id || !domain_id)
		return -EINVAL;

	mutex_lock(&deko_domain_lock);
	entry = deko_domain_find_locked(mnt_ns_id);
	if (entry) {
		*domain_id = entry->domain_id;
		ret = 0;
	}
	mutex_unlock(&deko_domain_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(deko_domain_lookup);

int deko_domain_unbind(u64 mnt_ns_id, u32 domain_id)
{
	struct deko_domain_entry *entry;

	if (!mnt_ns_id)
		return -EINVAL;

	mutex_lock(&deko_domain_lock);
	entry = deko_domain_find_locked(mnt_ns_id);
	if (!entry) {
		mutex_unlock(&deko_domain_lock);
		return -ENOENT;
	}
	if (domain_id && entry->domain_id != domain_id) {
		mutex_unlock(&deko_domain_lock);
		return -EEXIST;
	}
	hash_del(&entry->node);
	mutex_unlock(&deko_domain_lock);
	pr_debug("unbind mnt_ns_id=%llu domain_id=%u\n", entry->mnt_ns_id,
		 entry->domain_id);
	kfree(entry);
	return 0;
}
EXPORT_SYMBOL_GPL(deko_domain_unbind);

extern const sys_call_ptr_t sys_call_table[];

struct deko_syscall_entry {
	u64 req_id;
	u64 ax;
	u64 di, si, dx, r10, r8, r9;
	u64 ret;
	u32 state;
	u32 _reserved;
};

struct deko_syscall_ring {
	u32 magic;
	u16 version;
	u16 capacity;
	u32 head;
	u32 tail;
	u32 poller_state;
	u32 _pad;
	u64 poller_heartbeat;
	struct deko_syscall_entry entries[DEKO_RING_CAPACITY];
};

struct deko_shared_ring_buf {
	struct deko_syscall_ring tx;
	struct deko_syscall_ring rx;
};

struct deko_syscall_body {
	u64 ax;
	u64 di;
	u64 si;
	u64 dx;
	u64 r10;
	u64 r8;
	u64 r9;
	u64 rcx;
	u64 r11;
	u64 __reserved;
};

struct deko_migration_req {
	u32 old_cpu;
	u32 new_cpu;
	u32 pid;
	u32 _reserved;
	u64 kernel_gs_base; /*  Linux Per-CPU  */
	u64 user_gs_base; /*  TLS  */
};

struct deko_shared_buf {
	struct deko_syscall_body syscall_body;
	void *buf;
	void *alias_buf;
	u64 alias_len;
	struct deko_page_fault_frame page_fault;
};

struct deko_ring_poller {
	struct deko_shared_buf *buf;
	struct deko_syscall_ring *ring;
	struct task_struct *owner;
	struct task_struct *task;
	struct completion exited;
	bool stop;
	bool started;
};

struct deko_page_fault_progress {
	u64 fault_va;
	u64 rip;
	u64 error_code;
	u32 access;
	u32 reason;
	unsigned int repeats;
};

struct deko_handoff_checkpoint {
	u64 seq;
	u32 pid;
	u32 owner_cpu;
	u64 generation;
	u64 user_rsp;
	u64 user_gs_base;
	u64 kernel_gs_base;
	bool valid;
};

struct deko_migration_state {
	u32 committed_owner_cpu;
	u64 committed_generation;
	u32 staged_target_cpu;
	u32 expected_owner_cpu;
	u64 expected_source_generation;
	u64 staged_generation;
	bool pending;
};

/* Allocate a hidden reserced user VMA not visible to the application
 * provided as a communication channel between VMPL1 and VMPL2.
 */
static int deko_alloc_hidden_user_alias(struct mm_struct *mm,
					unsigned long *alias_addr,
					unsigned long len)
{
	unsigned long addr;

	if (!mm || !alias_addr || !len)
		return -EINVAL;

	addr = vm_mmap(NULL, 0, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE(addr))
		return (int)addr;

	mm_populate(addr, len);
	*alias_addr = addr;

	return 0;
}

static void deko_free_hidden_user_alias(unsigned long alias_addr,
					unsigned long len)
{
	if (!alias_addr || !len)
		return;

	vm_munmap(alias_addr, len);
}

static inline bool is_exit_syscall(u64 syscall_num)
{
	return syscall_num == __NR_exit || syscall_num == __NR_exit_group;
}

static inline bool deko_ring_poller_syscall_eligible(u64 syscall_num)
{
	switch (syscall_num) {
	case __NR_read:
	case __NR_write:
	case __NR_pread64:
	case __NR_pwrite64:
	case __NR_readv:
	case __NR_writev:
	case __NR_recvfrom:
	case __NR_sendto:
	case __NR_sendfile:
		return true;
	default:
		return false;
	}
}

static inline bool
deko_syscall_ring_entry_has_flag(const struct deko_syscall_entry *entry,
				 u32 flag)
{
	return (READ_ONCE(entry->_reserved) & flag) != 0;
}

static inline bool
deko_ring_poller_entry_eligible(const struct deko_syscall_entry *entry)
{
	u64 syscall_num = READ_ONCE(entry->ax);

	if (deko_ring_poller_syscall_eligible(syscall_num))
		return true;

	switch (syscall_num) {
	case __NR_epoll_wait_old:
	case __NR_epoll_wait:
	case __NR_epoll_pwait:
		return deko_syscall_ring_entry_has_flag(
			entry, DEKO_SYSCALL_RING_ENTRY_FLAG_EPOLL_PEEK);
	default:
		return false;
	}
}

static inline bool deko_ring_poller_syscall_dangerous(u64 syscall_num)
{
	switch (syscall_num) {
	case __NR_exit:
	case __NR_exit_group:
	case __NR_clone:
	case __NR_clone3:
	case __NR_fork:
	case __NR_vfork:
	case __NR_execve:
	case __NR_execveat:
		return true;
	default:
		return false;
	}
}

static void deko_log_vma_attrs_for_range(struct mm_struct *mm,
					 unsigned long start_addr,
					 unsigned long end_addr,
					 unsigned long prot, const char *reason)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, start_addr);
	bool saw_overlap = false;

	if (!mm)
		return;

	for_each_vma_range(vmi, vma, end_addr) {
		unsigned long overlap_start;
		unsigned long overlap_end;

		overlap_start = max(start_addr, vma->vm_start);
		overlap_end = min(end_addr, vma->vm_end);
		if (overlap_start >= overlap_end)
			continue;

		saw_overlap = true;
		if (vma->vm_file) {
			pr_err("Populate failure attrs for %s: req=[0x%lx-0x%lx) prot=0x%lx overlap=[0x%lx-0x%lx) vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=%pD\n",
				reason, start_addr, end_addr, prot,
				overlap_start, overlap_end, vma->vm_start,
				vma->vm_end, vma->vm_flags, vma->vm_pgoff,
				vma->vm_file);
		} else {
			pr_err("Populate failure attrs for %s: req=[0x%lx-0x%lx) prot=0x%lx overlap=[0x%lx-0x%lx) vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=<anon>\n",
				reason, start_addr, end_addr, prot,
				overlap_start, overlap_end, vma->vm_start,
				vma->vm_end, vma->vm_flags, vma->vm_pgoff);
		}
	}

	if (!saw_overlap) {
		vma = find_vma(mm, start_addr);
		if (!vma) {
			pr_err("Populate failure attrs for %s: req=[0x%lx-0x%lx) prot=0x%lx no following vma\n",
			       reason, start_addr, end_addr, prot);
		} else if (vma->vm_file) {
			pr_err("Populate failure attrs for %s: req=[0x%lx-0x%lx) prot=0x%lx no overlap next_vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=%pD\n",
			       reason, start_addr, end_addr, prot,
			       vma->vm_start, vma->vm_end, vma->vm_flags,
			       vma->vm_pgoff, vma->vm_file);
		} else {
			pr_err("Populate failure attrs for %s: req=[0x%lx-0x%lx) prot=0x%lx no overlap next_vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=<anon>\n",
			       reason, start_addr, end_addr, prot,
			       vma->vm_start, vma->vm_end, vma->vm_flags,
			       vma->vm_pgoff);
		}
	}
}

static void deko_log_pin_failure_vma(struct mm_struct *mm, unsigned long addr,
				     unsigned long end_addr,
				     unsigned long prot, const char *reason)
{
	struct vm_area_struct *vma;

	if (!mm)
		return;

	vma = find_vma(mm, addr);
	if (!vma) {
		pr_err("Pin failure VMA for %s: addr=0x%lx end=0x%lx prot=0x%lx no following vma\n",
		       reason, addr, end_addr, prot);
		return;
	}

	if (vma->vm_file) {
		pr_err("Pin failure VMA for %s: addr=0x%lx end=0x%lx prot=0x%lx covered=%d vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=%pD\n",
		       reason, addr, end_addr, prot, addr >= vma->vm_start,
		       vma->vm_start, vma->vm_end, vma->vm_flags, vma->vm_pgoff,
		       vma->vm_file);
	} else {
		pr_err("Pin failure VMA for %s: addr=0x%lx end=0x%lx prot=0x%lx covered=%d vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=<anon>\n",
		       reason, addr, end_addr, prot, addr >= vma->vm_start,
		       vma->vm_start, vma->vm_end, vma->vm_flags, vma->vm_pgoff);
	}
}

static void deko_clamp_file_tail_populate_range(struct mm_struct *mm,
						unsigned long start_addr,
						unsigned long *end_addr,
						unsigned long prot,
						const char *reason)
{
	struct vm_area_struct *vma;
	unsigned long orig_end = *end_addr;

	if (!mm || !end_addr || start_addr >= *end_addr)
		return;

	mmap_read_lock(mm);

	vma = find_vma(mm, start_addr);
	if (!vma || start_addr < vma->vm_start || orig_end > vma->vm_end ||
	    !vma->vm_file)
		goto out;

	{
		loff_t file_size = i_size_read(file_inode(vma->vm_file));
		u64 file_off = (u64)vma->vm_pgoff << PAGE_SHIFT;
		u64 backed_len = 0;
		unsigned long file_backed_end;

		if (file_size > file_off)
			backed_len = PAGE_ALIGN((u64)file_size - file_off);

		backed_len = min_t(u64, backed_len,
				   (u64)(vma->vm_end - vma->vm_start));
		file_backed_end = vma->vm_start + (unsigned long)backed_len;

		if (file_backed_end < *end_addr) {
			pr_debug("Clamping populate range for %s: req=[0x%lx-0x%lx) prot=0x%lx file=%pD size=0x%llx pgoff=0x%lx clamped=[0x%lx-0x%lx)\n",
				reason, start_addr, orig_end, prot,
				vma->vm_file, (unsigned long long)file_size,
				vma->vm_pgoff, start_addr,
				max(start_addr, file_backed_end));
			*end_addr = max(start_addr, file_backed_end);
		}
	}

out:
	mmap_read_unlock(mm);
}

static int deko_pin_prefault_user_range(struct mm_struct *mm,
					unsigned long start_addr,
					unsigned long end_addr,
					unsigned long prot,
					const char *reason)
{
	struct page *pages[64];
	unsigned long cur = start_addr;
	unsigned int gup_flags = FOLL_FORCE;

	if (!mm || start_addr >= end_addr)
		return 0;

	if (prot & PROT_WRITE)
		gup_flags |= FOLL_WRITE;

	while (cur < end_addr) {
		unsigned long remaining = (end_addr - cur) >> PAGE_SHIFT;
		unsigned long chunk_pages = min_t(unsigned long, remaining,
						  ARRAY_SIZE(pages));
		long pinned;
		unsigned int attempt;

		for (attempt = 0; attempt <= DEKO_PIN_PREFAULT_MAX_RETRIES;
		     attempt++) {
			int locked = 1;

			mmap_read_lock(mm);
			pinned = pin_user_pages_remote(mm, cur, chunk_pages,
						       gup_flags, pages,
						       &locked);
			if (locked)
				mmap_read_unlock(mm);
			if (pinned != -EINTR && pinned != -EAGAIN)
				break;
			if (fatal_signal_pending(current)) {
				pr_debug("Interrupted pin-prefault range for %s at 0x%lx due to pending fatal signal\n",
					reason, cur);
				return -EINTR;
			}
			cond_resched();
		}
		if (pinned < 0) {
			pr_err("Failed to pin-prefault range for %s at 0x%lx pages 0x%lx, err: %ld\n",
				reason, cur, chunk_pages, pinned);
			mmap_read_lock(mm);
			deko_log_pin_failure_vma(mm, cur, end_addr, prot, reason);
			mmap_read_unlock(mm);
			return (int)pinned;
		}
		if (!pinned) {
			pr_err("Failed to pin-prefault range for %s at 0x%lx: zero pages pinned\n",
				reason, cur);
			mmap_read_lock(mm);
			deko_log_pin_failure_vma(mm, cur, end_addr, prot, reason);
			mmap_read_unlock(mm);
			break;
		}

		unpin_user_pages(pages, pinned);
		cur += (unsigned long)pinned << PAGE_SHIFT;
		cond_resched();
	}

	if (cur < end_addr) {
		pr_err("Incomplete pin-prefault range for %s: requested [0x%lx-0x%lx), stopped at 0x%lx\n",
			reason, start_addr, end_addr, cur);
		return -EFAULT;
	}

	return 0;
}

static int eager_fault_user_range(struct mm_struct *mm,
				  unsigned long start_addr,
				  unsigned long length, unsigned long prot,
				  const char *reason)
{
	unsigned long end_addr;
	int ret;

	if (READ_ONCE(deko_no_eager_fault))
		return 0;

	if (!mm || !length || !prot)
		return 0;

	if (check_add_overflow(start_addr, length, &end_addr))
		return -EINVAL;

	end_addr = PAGE_ALIGN(end_addr);
	start_addr = PAGE_ALIGN_DOWN(start_addr);

	if (start_addr >= end_addr)
		return 0;

	deko_clamp_file_tail_populate_range(mm, start_addr, &end_addr, prot,
					    reason);
	if (start_addr >= end_addr)
		return 0;

	trace_deko_eager_paging(reason, start_addr, length, prot);

	ret = __mm_populate(start_addr, end_addr - start_addr, 0);
	if (ret < 0) {
		pr_err("Failed to populate range for %s at 0x%lx len 0x%lx, err: %d\n",
			reason, start_addr, end_addr - start_addr, ret);
		mmap_read_lock(mm);
		deko_log_vma_attrs_for_range(mm, start_addr, end_addr, prot,
					     reason);
		mmap_read_unlock(mm);
		return ret;
	}

	ret = deko_pin_prefault_user_range(mm, start_addr, end_addr, prot, reason);
	if (ret < 0) {
		pr_err("Prefault range failed for %s: start=0x%lx end=0x%lx length=0x%lx prot=0x%lx ret=%d\n",
			reason, start_addr, end_addr, length, prot, ret);
		return ret;
	}

	return 0;
}

static inline int mmap_post_handler(struct mm_struct *mm,
				    unsigned long start_addr,
				    unsigned long length, unsigned long prot,
				    unsigned long ax)
{
	if (IS_ERR_VALUE(ax))
		return 0;

	if (prot & PROT_EXEC)
		return deko_prefault_lift_exec_user_range(mm, start_addr, length,
							  "mmap");

	return eager_fault_user_range(mm, start_addr, length, prot, "mmap");
}

static inline int brk_post_handler(struct mm_struct *mm, unsigned long old_brk,
				   unsigned long new_brk)
{
	if (!mm || new_brk <= old_brk)
		return 0;

	return eager_fault_user_range(mm, old_brk, new_brk - old_brk,
				      PROT_READ | PROT_WRITE, "brk");
}

static inline int mremap_post_handler(struct mm_struct *mm,
				      unsigned long ret_addr,
				      unsigned long old_length,
				      unsigned long new_length)
{
	unsigned long start_addr;

	if (!mm || IS_ERR_VALUE(ret_addr) || new_length <= old_length)
		return 0;

	start_addr = ret_addr + old_length;

	return eager_fault_user_range(mm, start_addr, new_length - old_length,
				      PROT_READ | PROT_WRITE, "mremap");
}

static inline int mprotect_post_handler(struct mm_struct *mm,
					unsigned long start_addr,
					unsigned long length,
					unsigned long prot,
					unsigned long ax)
{
	if (IS_ERR_VALUE(ax))
		return 0;

	if (!mm || !length)
		return 0;

	if (prot & PROT_EXEC)
		return deko_prefault_lift_exec_user_range(mm, start_addr, length,
							  "mprotect");

	if (current->is_monitored) {
		int ret = deko_unlift_exec_user_range(mm, start_addr, length,
						      "mprotect");

		if (ret < 0)
			return ret;
	}

	if (!(prot & (PROT_READ | PROT_WRITE)))
		return 0;

	return eager_fault_user_range(mm, start_addr, length, prot, "mprotect");
}

static inline int madvise_post_handler(struct mm_struct *mm,
				       unsigned long start_addr,
				       unsigned long length,
				       unsigned long advice,
				       unsigned long ax)
{
	if (!mm || IS_ERR_VALUE(ax) || advice != MADV_DONTNEED)
		return 0;

	return eager_fault_user_range(mm, start_addr, length,
				      PROT_READ | PROT_WRITE, "madvise");
}

static bool deko_vma_is_populatable(struct vm_area_struct *vma,
				    unsigned long prot)
{
	if (!vma_is_accessible(vma))
		return false;
	if ((vma->vm_flags & (VM_IO | VM_PFNMAP)))
		return false;
	if ((prot & PROT_WRITE) && !(vma->vm_flags & VM_WRITE))
		return false;

	return true;
}

static bool deko_vma_needs_write_prefault(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_WRITE)
		return true;

	return (vma->vm_flags & VM_MAYWRITE) &&
	       !(vma->vm_flags & (VM_EXEC | VM_SHARED));
}

static int eager_fault_populatable_user_range(struct mm_struct *mm,
					      unsigned long start_addr,
					      unsigned long length,
					      unsigned long prot,
					      const char *reason)
{
	struct vm_area_struct *vma;
	unsigned long end_addr;
	unsigned long cur;
	bool populated = false;
	int ret;

	if (READ_ONCE(deko_no_eager_fault))
		return 0;

	if (!mm || !length)
		return 0;

	if (check_add_overflow(start_addr, length, &end_addr))
		return -EINVAL;

	end_addr = PAGE_ALIGN(end_addr);
	start_addr = PAGE_ALIGN_DOWN(start_addr);
	if (start_addr >= end_addr)
		return 0;

	cur = start_addr;
	while (cur < end_addr) {
		unsigned long sub_start;
		unsigned long sub_end;

		mmap_read_lock(mm);
		vma = find_vma(mm, cur);
		if (!vma) {
			mmap_read_unlock(mm);
			break;
		}

		if (cur < vma->vm_start)
			cur = vma->vm_start;
		if (cur >= end_addr) {
			mmap_read_unlock(mm);
			break;
		}

		sub_start = max(cur, vma->vm_start);
		sub_end = min(end_addr, vma->vm_end);
		if (!deko_vma_is_populatable(vma, prot)) {
			mmap_read_unlock(mm);
			cur = sub_end;
			continue;
		}
		mmap_read_unlock(mm);

		ret = eager_fault_user_range(mm, sub_start, sub_end - sub_start,
					     prot, reason);
		if (ret < 0)
			return ret;

		populated = true;
		cur = sub_end;
	}

	return populated ? 0 : -EFAULT;
}

static int eager_fault_vma_containing_addr(struct mm_struct *mm,
					   unsigned long addr,
					   unsigned long prot,
					   const char *reason)
{
	struct vm_area_struct *vma;
	unsigned long start;
	unsigned long length;

	if (READ_ONCE(deko_no_eager_fault))
		return 0;

	if (!mm || !addr)
		return 0;

	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start) {
		mmap_read_unlock(mm);
		return -EFAULT;
	}
	if (!deko_vma_is_populatable(vma, prot)) {
		mmap_read_unlock(mm);
		return -EFAULT;
	}

	start = vma->vm_start;
	length = vma->vm_end - vma->vm_start;
	mmap_read_unlock(mm);

	return eager_fault_user_range(mm, start, length, prot, reason);
}

static int clone_stack_pre_handler(struct mm_struct *mm,
				   const struct deko_syscall_body *syscall_body,
				   unsigned long syscall_nr)
{
	if (!mm || !syscall_body)
		return 0;

	if (syscall_nr == __NR_clone3) {
		struct clone_args args = {};
		size_t size = min_t(size_t, syscall_body->si, sizeof(args));

		if (!syscall_body->di ||
		    size < offsetofend(struct clone_args, stack_size))
			return 0;

		if (copy_from_user(&args, (void __user *)syscall_body->di,
				   size)) {
			pr_warn("failed to copy clone3 args for deko pre-clone stack prefault: pid=%d\n",
				current->pid);
			return 0;
		}

		if (!(args.flags & CLONE_THREAD) || !args.stack ||
		    !args.stack_size)
			return 0;

		return eager_fault_populatable_user_range(mm,
							  (unsigned long)args.stack,
							  (unsigned long)args.stack_size,
							  PROT_READ | PROT_WRITE,
							  "clone_stack_pre");
	}

	if (syscall_nr == __NR_clone) {
		unsigned long clone_flags = syscall_body->di;
		unsigned long sp = syscall_body->si;

		if (!(clone_flags & CLONE_THREAD) || sp <= PAGE_SIZE)
			return 0;

		return eager_fault_vma_containing_addr(mm, sp - 1,
						       PROT_READ | PROT_WRITE,
						       "clone_stack_pre");
	}

	return 0;
}

static int deko_queue_proxy_loop_for_task(struct task_struct *task,
					  const char *reason,
					  u32 launch_type)
{
	struct deko_task_work *dw;
	int ret;

	if (!task || !task->mm)
		return -EINVAL;

	dw = kzalloc(sizeof(*dw), GFP_KERNEL);
	if (!dw)
		return -ENOMEM;

	init_task_work(&dw->work, deko_proxy_loop);
	dw->launch_type = launch_type;
	ret = task_work_add(task, &dw->work, TWA_RESUME);
	if (ret) {
		kfree(dw);
		return ret;
	}

	pr_debug("queued proxy loop for %s child pid=%d tgid=%d comm=%s task=%px current_cpu=%u kernel_vmpl1_rsp=0x%lx launch_type=%u\n",
		reason, task->pid, task->tgid, task->comm, task,
		raw_smp_processor_id(), task->thread.kernel_vmpl1_rsp,
		launch_type);

	return 0;
}

static int deko_pin_current_proxy_task(void)
{
	unsigned int cpu;
	int ret;

	if (!READ_ONCE(deko_pin_proxy_task))
		return 0;

	cpu = raw_smp_processor_id();
	ret = set_cpus_allowed_ptr(current, cpumask_of(cpu));
	if (ret) {
		pr_warn("failed to pin Deko proxy task pid=%d tgid=%d comm=%s to cpu=%u ret=%d\n",
			current->pid, current->tgid, current->comm, cpu, ret);
		return ret;
	}

	pr_debug("pinned Deko proxy task pid=%d tgid=%d comm=%s to cpu=%u\n",
		current->pid, current->tgid, current->comm, cpu);
	return 0;
}

static int deko_register_current_clone_child(void)
{
	unsigned long token_low = 0;
	unsigned long token_high = 0;
	u64 mnt_ns_id = 0;
	enum es_result res;

	if (current->nsproxy && current->nsproxy->mnt_ns)
		mnt_ns_id = from_mnt_ns(current->nsproxy->mnt_ns)->inum;

	pr_debug("Deko registering current clone child pid=%d tgid=%d ppid=%d comm=%s mnt_ns_id=%llu mm=%px launch_type=%u\n",
		current->pid, current->tgid, current->real_parent->pid,
		current->comm, (unsigned long long)mnt_ns_id, current->mm,
		DEKO_LAUNCH_TYPE_PROCESS_FORK);

	res = svsm_deko_new_app_req(current, mnt_ns_id, current->comm,
				    DEKO_REPORT_APP_FORK_CREATE,
				    &token_low, &token_high, DEKO_DOCKER_APPS);
	if (res != ES_OK) {
		pr_warn("failed to register current deko clone child pid=%d tgid=%d res=%d\n",
			current->pid, current->tgid, res);
		return -EIO;
	}

	current->thread.user_rsp = 0;
	current->thread.kernel_vmpl1_rsp = token_low;
	current->thread.deko_checkpoint_generation = 0;
	this_cpu_write(deko_user_rsp, current->thread.user_rsp);
	this_cpu_write(deko_kernel_vmpl1_rsp,
		       current->thread.kernel_vmpl1_rsp);

	pr_debug("Deko registered current clone child pid=%d tgid=%d token_low=0x%lx token_high=0x%lx kernel_vmpl1_rsp=0x%lx\n",
		current->pid, current->tgid, token_low, token_high,
		current->thread.kernel_vmpl1_rsp);

	return 0;
}

int deko_prepare_clone_child_before_wake(struct task_struct *child)
{
	unsigned long token_low = 0;
	unsigned long token_high = 0;
	u64 mnt_ns_id = 0;
	enum es_result res;
	int ret;

	if (!current->is_monitored || !child)
		return 0;

	if (child->flags & (PF_IO_WORKER | PF_USER_WORKER)) {
		child->is_monitored = false;
		child->thread.user_rsp = 0;
		child->thread.kernel_vmpl1_rsp = 0;
		child->thread.deko_checkpoint_generation = 0;
		pr_debug("skip deko proxy loop for internal worker child_pid=%d child_tgid=%d parent_pid=%d flags=0x%x\n",
			 child->pid, child->tgid, current->pid, child->flags);
		return 0;
	}

	pr_debug("Deko prepare clone child before wake parent_pid=%d parent_tgid=%d child_pid=%d child_tgid=%d parent_mm=%px child_mm=%px child_comm=%s\n",
		current->pid, current->tgid, child->pid, child->tgid,
		current->mm, child->mm, child->comm);

	if (!child->mm) {
		pr_warn("skip deko proxy loop for clone child without mm pid=%d tgid=%d parent pid=%d tgid=%d\n",
			child->pid, child->tgid, current->pid, current->tgid);
		return 0;
	}

	child->is_monitored = true;

	if (child->tgid != current->tgid || child->mm != current->mm) {
		child->thread.user_rsp = 0;
		child->thread.kernel_vmpl1_rsp = 0;
		child->thread.deko_checkpoint_generation = 0;

		ret = deko_queue_proxy_loop_for_task(
			child, "fork", DEKO_LAUNCH_TYPE_PROCESS_FORK);
		pr_debug("Deko queued process-fork proxy loop child_pid=%d child_tgid=%d parent_pid=%d ret=%d\n",
			child->pid, child->tgid, current->pid, ret);
		if (ret < 0)
			child->is_monitored = false;
		return ret;
	}

	if (child->nsproxy && child->nsproxy->mnt_ns)
		mnt_ns_id = from_mnt_ns(child->nsproxy->mnt_ns)->inum;

	pr_debug("Deko reporting same-mm clone child pid=%d tgid=%d parent_pid=%d parent_tgid=%d mnt_ns_id=%llu\n",
		child->pid, child->tgid, current->pid, current->tgid,
		(unsigned long long)mnt_ns_id);

	res = svsm_deko_new_app_req(child, mnt_ns_id, child->comm,
				    DEKO_REPORT_APP_FORK_CREATE,
				    &token_low, &token_high, DEKO_DOCKER_APPS);
	if (res != ES_OK) {
		pr_warn("failed to register deko clone child pid=%d tgid=%d parent pid=%d tgid=%d res=%d\n",
			child->pid, child->tgid, current->pid, current->tgid,
			res);
		child->is_monitored = false;
		return -EIO;
	}

	child->thread.user_rsp = 0;
	child->thread.kernel_vmpl1_rsp = token_low;
	child->thread.deko_checkpoint_generation = 0;

	ret = deko_queue_proxy_loop_for_task(
		child, "clone", DEKO_LAUNCH_TYPE_THREAD);
	pr_debug("Deko queued same-mm clone proxy loop child_pid=%d child_tgid=%d token_low=0x%lx token_high=0x%lx kernel_vmpl1_rsp=0x%lx ret=%d\n",
		child->pid, child->tgid, token_low, token_high,
		child->thread.kernel_vmpl1_rsp, ret);
	if (ret < 0)
		child->is_monitored = false;

	return ret;
}

static int exit_lifecycle_handler(struct mm_struct *mm, unsigned long ax)
{
	struct svsm_call call = { 0 };
	int ret;

	(void)ax;

	if (mm && current->is_monitored) {
		ret = deko_unlift_all_exec_user_ranges(mm, "exit");
		if (ret < 0)
			return ret;
	}

	ret = deko_svsm_call_locked(&call, deko_prepare_exit_call, NULL);
	if (ret < 0) {
		pr_err("Failed to report app exit to SVSM for process %s (pid: %d), err: %d\n",
		       current->comm, current->pid, ret);
		return ret;
	}

	return 0;
}

static int deko_app_handle_system_calls_pre(
	struct mm_struct *mm, const struct deko_syscall_body *syscall_body,
	unsigned long syscall_nr)
{
	int ret;

	switch (syscall_nr) {
	case __NR_clone:
	case __NR_clone3:
		ret = clone_stack_pre_handler(mm, syscall_body, syscall_nr);
		if (ret < 0)
			return ret;
		break;
	case __NR_exit:
	case __NR_exit_group:
		/*
		 * exit()/exit_group() do not return to the post-syscall path, so
		 * lifecycle cleanup has to be reported before entering Linux's
		 * exit handler.
		 */
		ret = exit_lifecycle_handler(mm, 0);
		if (ret < 0)
			return ret;
		break;
	default:
		break;
	}

	return 0;
}

static int deko_app_handle_system_calls_post(
	struct mm_struct *mm, struct deko_syscall_body *syscall_body,
	unsigned long syscall_nr, unsigned long ax, unsigned long old_brk)
{
	int ret;

	switch (syscall_nr) {
	case __NR_mmap:
		ret = mmap_post_handler(mm, ax, syscall_body->si,
					syscall_body->dx, ax);
		if (ret < 0)
			return ret;
		break;
	case __NR_brk:
		ret = brk_post_handler(mm, old_brk, ax);
		if (ret < 0)
			return ret;
		break;
	case __NR_mremap:
		ret = mremap_post_handler(mm, ax, syscall_body->si,
					  syscall_body->dx);
		if (ret < 0)
			return ret;
		break;
	case __NR_mprotect:
	case __NR_pkey_mprotect:
		ret = mprotect_post_handler(mm, syscall_body->di,
					    syscall_body->si, syscall_body->dx,
					    ax);
		if (ret < 0)
			return ret;
		break;
	case __NR_madvise:
		ret = madvise_post_handler(mm, syscall_body->di,
					   syscall_body->si, syscall_body->dx,
					   ax);
		if (ret < 0)
			return ret;
		break;
	case __NR_exit:
	case __NR_exit_group:
		/* Notify us that this thread has exited. */
		ret = exit_lifecycle_handler(mm, ax);
		if (ret < 0)
			return ret;
		break;
	default:
		break;
	}

	syscall_body->ax = ax;

	return 0;
}

static int deko_app_handle_system_calls(struct deko_syscall_body *syscall_body)
{
	struct pt_regs tmp_regs = { 0 };
	sys_call_ptr_t syscall_fn;
	unsigned long syscall_nr;
	unsigned long sys_retval;
	unsigned long old_brk = 0;
	int ret;

	syscall_nr = syscall_body->ax;

	if (unlikely(syscall_nr >= NR_syscalls)) {
		pr_warn("Invalid syscall number %lu from VMPL1\n", syscall_nr);
		syscall_body->ax = -ENOSYS;
		return -EINVAL;
	}

	trace_deko_syscall_entry(syscall_nr, syscall_body->di, syscall_body->si,
				 syscall_body->dx);

	tmp_regs.di = syscall_body->di;
	tmp_regs.si = syscall_body->si;
	tmp_regs.dx = syscall_body->dx;
	tmp_regs.r10 = syscall_body->r10;
	tmp_regs.r8 = syscall_body->r8;
	tmp_regs.r9 = syscall_body->r9;
	tmp_regs.orig_ax = syscall_nr;

	if (current->mm)
		old_brk = current->mm->brk;

	ret = deko_app_handle_system_calls_pre(current->mm, syscall_body,
					       syscall_nr);
	if (ret < 0)
		return ret;

	syscall_fn = sys_call_table[syscall_nr];
	if (unlikely(!syscall_fn)) {
		pr_warn("Missing syscall handler for syscall number %lu\n",
			syscall_nr);
		syscall_body->ax = -ENOSYS;
		return -EINVAL;
	}

	sys_retval = syscall_fn(&tmp_regs);

	trace_deko_syscall_exit(tmp_regs.orig_ax, sys_retval);

	return deko_app_handle_system_calls_post(
		current->mm, syscall_body, syscall_nr, sys_retval, old_brk);
}

static void deko_syscall_ring_init(struct deko_syscall_ring *ring)
{
	BUILD_BUG_ON(sizeof(*ring) > DEKO_DEFAULT_SHARED_BUF_SIZE);

	memset(ring, 0, sizeof(*ring));
	if (!READ_ONCE(deko_syscall_ring_enabled)) {
		pr_debug("Deko syscall ring disabled; using legacy syscall buffer\n");
		return;
	}

	pr_info_once("Deko syscall ring enabled\n");
	WRITE_ONCE(ring->magic, DEKO_SYSCALL_RING_MAGIC);
	WRITE_ONCE(ring->version, DEKO_SYSCALL_RING_VERSION);
	WRITE_ONCE(ring->capacity, DEKO_RING_CAPACITY);
	WRITE_ONCE(ring->poller_state, DEKO_POLLER_ASLEEP);
	WRITE_ONCE(ring->poller_heartbeat, 0);
}

static bool deko_syscall_ring_available(const struct deko_syscall_ring *ring)
{
	return READ_ONCE(ring->magic) == DEKO_SYSCALL_RING_MAGIC &&
	       READ_ONCE(ring->version) == DEKO_SYSCALL_RING_VERSION &&
	       READ_ONCE(ring->capacity) == DEKO_RING_CAPACITY;
}

static inline u32 deko_syscall_ring_next(u32 index)
{
	index++;
	if (index == DEKO_RING_CAPACITY)
		index = 0;
	return index;
}

static u32 deko_syscall_ring_advance_head(struct deko_syscall_ring *ring,
					  u32 old_head)
{
	u32 next = deko_syscall_ring_next(old_head);
	u32 observed = cmpxchg(&ring->head, old_head, next);

	if (observed == old_head)
		return next;

	if (observed >= DEKO_RING_CAPACITY) {
		pr_err("Deko syscall ring head became corrupt pid=%d observed=%u\n",
		       current->pid, observed);
		return observed;
	}

	return observed;
}

static void deko_syscall_ring_entry_to_body(
	const struct deko_syscall_entry *entry,
	struct deko_syscall_body *syscall_body)
{
	syscall_body->ax = READ_ONCE(entry->ax);
	syscall_body->di = READ_ONCE(entry->di);
	syscall_body->si = READ_ONCE(entry->si);
	syscall_body->dx = READ_ONCE(entry->dx);
	syscall_body->r10 = READ_ONCE(entry->r10);
	syscall_body->r8 = READ_ONCE(entry->r8);
	syscall_body->r9 = READ_ONCE(entry->r9);
}

static int deko_syscall_ring_complete_claimed(
	struct deko_shared_buf *buf, struct deko_syscall_entry *entry, u32 index,
	bool *normal_exit, bool from_poller)
{
	struct deko_syscall_body syscall_body = { 0 };
	u64 syscall_nr;
	int ret;

	deko_syscall_ring_entry_to_body(entry, &syscall_body);
	syscall_nr = syscall_body.ax;

	if (from_poller && !deko_ring_poller_entry_eligible(entry) &&
	    deko_ring_poller_syscall_dangerous(syscall_nr)) {
		pr_warn_once("Deko syscall ring poller refused lifecycle syscall pid=%d index=%u syscall=%llu\n",
			     current->pid, index, (unsigned long long)syscall_nr);
		syscall_body.ax = (u64)-EAGAIN;
		WRITE_ONCE(entry->ret, syscall_body.ax);
		WRITE_ONCE(buf->syscall_body.ax, syscall_body.ax);
		smp_store_release(&entry->state, DEKO_SYSCALL_RING_ENTRY_DONE);
		return 0;
	}

	ret = deko_app_handle_system_calls(&syscall_body);
	if (ret != 0) {
		pr_err("Error handling syscall ring entry pid=%d index=%u syscall=%llu ret=%d\n",
		       current->pid, index, (unsigned long long)syscall_nr, ret);
		syscall_body.ax = (u64)ret;
	}

	WRITE_ONCE(entry->ret, syscall_body.ax);
	WRITE_ONCE(buf->syscall_body.ax, syscall_body.ax);
	smp_store_release(&entry->state, DEKO_SYSCALL_RING_ENTRY_DONE);

	if (!from_poller && is_exit_syscall(syscall_nr))
		*normal_exit = true;

	return ret;
}

static int deko_syscall_ring_wait_done(struct deko_syscall_entry *entry,
				       u32 index)
{
	unsigned int spins = 0;

	for (;;) {
		u32 state = smp_load_acquire(&entry->state);

		if (state == DEKO_SYSCALL_RING_ENTRY_DONE)
			return 0;

		if (state != DEKO_SYSCALL_RING_ENTRY_CLAIMED) {
			pr_err("Deko syscall ring wait saw invalid state pid=%d index=%u state=%u\n",
			       current->pid, index, state);
			return -EIO;
		}

		cpu_relax();
		spins++;
		if ((spins & (DEKO_RING_WAIT_RESCHED_INTERVAL - 1)) == 0)
			cond_resched();
	}
}

static bool deko_syscall_ring_has_poller_ready(
	const struct deko_syscall_ring *ring)
{
	u32 head = READ_ONCE(ring->head);
	u32 tail = READ_ONCE(ring->tail);

	if (head >= DEKO_RING_CAPACITY || tail >= DEKO_RING_CAPACITY)
		return false;

	while (head != tail) {
		const struct deko_syscall_entry *entry = &ring->entries[head];
		u32 state = smp_load_acquire(&entry->state);

		if (state == DEKO_SYSCALL_RING_ENTRY_READY)
			return deko_ring_poller_entry_eligible(entry);
		if (state == DEKO_SYSCALL_RING_ENTRY_CLAIMED)
			return false;

		head = deko_syscall_ring_next(head);
	}

	return false;
}

static int deko_syscall_ring_drain_common(struct deko_shared_buf *buf,
					  bool *normal_exit, bool *handled,
					  bool *ring_present,
					  bool from_poller)
{
	struct deko_syscall_ring *ring;
	u32 head, tail;
	unsigned int drained = 0;

	*handled = false;
	*ring_present = false;
	if (!buf || !buf->buf)
		return 0;

	ring = (struct deko_syscall_ring *)buf->buf;
	if (!deko_syscall_ring_available(ring))
		return 0;
	*ring_present = true;

	head = READ_ONCE(ring->head);
	tail = READ_ONCE(ring->tail);
	if (head >= DEKO_RING_CAPACITY || tail >= DEKO_RING_CAPACITY) {
		pr_err("Deko syscall ring corrupt head/tail pid=%d head=%u tail=%u\n",
		       current->pid, head, tail);
		return -EINVAL;
	}

	while (head != tail) {
		struct deko_syscall_entry *entry = &ring->entries[head];
		u32 state;
		int ret;

		state = smp_load_acquire(&entry->state);
		if (state == DEKO_SYSCALL_RING_ENTRY_READY) {
			if (from_poller &&
			    !deko_ring_poller_entry_eligible(entry))
				break;
			if (cmpxchg(&entry->state, DEKO_SYSCALL_RING_ENTRY_READY,
				    DEKO_SYSCALL_RING_ENTRY_CLAIMED) !=
			    DEKO_SYSCALL_RING_ENTRY_READY)
				continue;

			ret = deko_syscall_ring_complete_claimed(
				buf, entry, head, normal_exit, from_poller);
		} else if (state == DEKO_SYSCALL_RING_ENTRY_CLAIMED) {
			if (from_poller)
				break;
			ret = deko_syscall_ring_wait_done(entry, head);
			if (ret != 0)
				return ret;
		} else if (state == DEKO_SYSCALL_RING_ENTRY_DONE) {
			ret = 0;
		} else if (state == DEKO_SYSCALL_RING_ENTRY_EMPTY) {
			break;
		} else {
			pr_err("Deko syscall ring entry invalid pid=%d index=%u state=%u head=%u tail=%u\n",
			       current->pid, head, state, READ_ONCE(ring->head),
			       READ_ONCE(ring->tail));
			return -EIO;
		}

		*handled = true;
		drained++;
		head = deko_syscall_ring_advance_head(ring, head);
		if (head >= DEKO_RING_CAPACITY)
			return -EINVAL;

		if (ret != 0)
			return ret;
		if (*normal_exit)
			return 0;
	}

	if (drained > 1)
		pr_debug("Deko syscall ring drained %u entries pid=%d\n",
			 drained, current->pid);

	return 0;
}

static int deko_syscall_ring_drain(struct deko_shared_buf *buf,
				   bool *normal_exit, bool *handled,
				   bool *ring_present)
{
	return deko_syscall_ring_drain_common(buf, normal_exit, handled,
					      ring_present, false);
}

static int deko_syscall_ring_poller_main(void *data)
{
	struct deko_ring_poller *poller = data;
	struct deko_syscall_ring *ring = poller->ring;
	u64 idle_since = rdtsc_ordered();
	char comm[TASK_COMM_LEN] = {};

	snprintf(comm, sizeof(comm), "deko-ring-%d", current->pid);
	set_task_comm(current, comm);

	for (;;) {
		bool handled = false;
		bool normal_exit = false;
		bool ring_present = false;
		u64 now;
		int ret;

		if (READ_ONCE(poller->stop) ||
		    READ_ONCE(poller->owner->exit_state) ||
		    (READ_ONCE(poller->owner->flags) & PF_EXITING))
			break;

		WRITE_ONCE(ring->poller_state, DEKO_POLLER_AWAKE);
		WRITE_ONCE(ring->poller_heartbeat, rdtsc_ordered());

		ret = deko_syscall_ring_drain_common(poller->buf, &normal_exit,
						     &handled, &ring_present,
						     true);
		if (ret != 0)
			pr_warn("Deko syscall ring poller drain failed pid=%d ret=%d\n",
				current->pid, ret);

		now = rdtsc_ordered();
		WRITE_ONCE(ring->poller_heartbeat, now);

		if (handled) {
			idle_since = now;
			cond_resched();
			continue;
		}

		if (READ_ONCE(deko_ring_poller_idle_cycles) &&
		    now >= idle_since &&
		    now - idle_since > READ_ONCE(deko_ring_poller_idle_cycles)) {
			unsigned int sleep_ms =
				READ_ONCE(deko_ring_poller_sleep_ms);

			if (!sleep_ms) {
				cpu_relax();
				cond_resched();
				continue;
			}

			WRITE_ONCE(ring->poller_state, DEKO_POLLER_ASLEEP);
			smp_mb();
			if (deko_syscall_ring_has_poller_ready(ring)) {
				WRITE_ONCE(ring->poller_state, DEKO_POLLER_AWAKE);
				idle_since = rdtsc_ordered();
				continue;
			}
			schedule_timeout_interruptible(msecs_to_jiffies(sleep_ms));
			idle_since = rdtsc_ordered();
			continue;
		}

		cpu_relax();
		cond_resched();
	}

	WRITE_ONCE(ring->poller_state, DEKO_POLLER_ASLEEP);
	WRITE_ONCE(ring->poller_heartbeat, 0);
	complete(&poller->exited);
	do_exit(0);
	return 0;
}

static unsigned int deko_ring_poller_next_cpu(unsigned int owner_cpu)
{
	unsigned int cpu;

	cpu = cpumask_next(owner_cpu, cpu_online_mask);
	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(cpu_online_mask);
	if (cpu >= nr_cpu_ids)
		return owner_cpu;

	return cpu;
}

static void deko_ring_poller_configure_task(struct task_struct *task,
					    unsigned int owner_cpu)
{
	unsigned int affinity = READ_ONCE(deko_ring_poller_affinity);
	unsigned int target_cpu = owner_cpu;
	int nice = READ_ONCE(deko_ring_poller_nice);
	int ret;

	if (nice)
		set_user_nice(task, nice);

	if (affinity == DEKO_RING_POLLER_AFFINITY_NONE)
		return;
	if (affinity == DEKO_RING_POLLER_AFFINITY_NEXT)
		target_cpu = deko_ring_poller_next_cpu(owner_cpu);
	else if (affinity != DEKO_RING_POLLER_AFFINITY_SAME)
		return;

	ret = set_cpus_allowed_ptr(task, cpumask_of(target_cpu));
	if (ret)
		pr_warn("failed to pin Deko syscall ring poller pid=%d owner_cpu=%u target_cpu=%u ret=%d\n",
			task->pid, owner_cpu, target_cpu, ret);
	else
		pr_debug("configured Deko syscall ring poller pid=%d owner_cpu=%u target_cpu=%u nice=%d idle_cycles=%llu sleep_ms=%u affinity=%u\n",
			task->pid, owner_cpu, target_cpu, nice,
			(unsigned long long)READ_ONCE(deko_ring_poller_idle_cycles),
			READ_ONCE(deko_ring_poller_sleep_ms), affinity);
}

static int deko_syscall_ring_poller_start(struct deko_ring_poller **poller_out,
					  struct deko_shared_buf *buf)
{
	struct deko_ring_poller *poller;
	struct task_struct *task;
	unsigned int owner_cpu;

	if (!poller_out)
		return -EINVAL;
	*poller_out = NULL;

	if (!READ_ONCE(deko_ring_poll))
		return 0;
	if (!READ_ONCE(deko_syscall_ring_enabled)) {
		pr_warn_once("Deko ring poll requested without deko_syscall_ring=1\n");
		return 0;
	}
	if (!buf || !buf->buf)
		return -EINVAL;

	poller = kzalloc(sizeof(*poller), GFP_KERNEL);
	if (!poller)
		return -ENOMEM;
	init_completion(&poller->exited);

	poller->buf = buf;
	poller->ring = (struct deko_syscall_ring *)buf->buf;
	poller->owner = get_task_struct(current);
	owner_cpu = raw_smp_processor_id();
	task = create_io_thread(deko_syscall_ring_poller_main, poller,
				NUMA_NO_NODE);
	if (IS_ERR(task)) {
		put_task_struct(poller->owner);
		kfree(poller);
		return PTR_ERR(task);
	}

	poller->task = get_task_struct(task);
	poller->started = true;
	*poller_out = poller;
	deko_ring_poller_configure_task(task, owner_cpu);
	wake_up_new_task(task);
	pr_debug("Deko syscall ring poller started proxy_pid=%d poller_pid=%d\n",
		current->pid, task->pid);

	return 0;
}

static void deko_syscall_ring_poller_stop(struct deko_ring_poller *poller)
{
	if (!poller || !poller->started || !poller->task)
		return;

	WRITE_ONCE(poller->stop, true);
	wake_up_process(poller->task);
	wait_for_completion(&poller->exited);
	put_task_struct(poller->task);
	put_task_struct(poller->owner);
	poller->task = NULL;
	poller->owner = NULL;
	poller->started = false;
	kfree(poller);
}

static int __maybe_unused deko_pin_pages(struct mm_struct *mm,
					 struct page ***pages)
{
	struct vm_area_struct *vma;
	unsigned long expected_pages;
	unsigned long total_pinned = 0;
	unsigned long start, end;
	unsigned long nr_pages;
	unsigned long remaining;
	unsigned long cur;
	unsigned long chunk_pages;
	unsigned int gup_flags;
	int ret = 0;

retry:
	*pages = NULL;
	total_pinned = 0;

	mmap_read_lock(mm);
	expected_pages = mm->total_vm;
	mmap_read_unlock(mm);

	if (!expected_pages)
		return 0;

	*pages = kvmalloc_array(expected_pages, sizeof(struct page *),
				GFP_KERNEL);
	if (!*pages) {
		pr_err("Failed to allocate page pointer array for %lu pages\n",
		       expected_pages);
		return -ENOMEM;
	}

	mmap_read_lock(mm);

	/*
	 * If the address space grew after allocation, retry with a larger page
	 * pointer array instead of risking writes past the allocation.
	 */
	if (mm->total_vm > expected_pages) {
		mmap_read_unlock(mm);
		kvfree(*pages);
		*pages = NULL;
		cond_resched();
		goto retry;
	}

	VMA_ITERATOR(vmi, mm, 0);
	for_each_vma(vmi, vma) {
		start = vma->vm_start;
		end = vma->vm_end;
		nr_pages = (end - start + PAGE_SIZE - 1) / PAGE_SIZE;
		gup_flags = FOLL_FORCE | FOLL_LONGTERM;

		/* Handle vDSO and vvar pages. */
		if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_DONTEXPAND)) {
			ret = fixup_user_fault(mm, start, FAULT_FLAG_USER,
					       NULL);
			if (ret < 0) {
				pr_warn("Failed to fault in special VMA at 0x%lx, err: %d\n",
					start, ret);
			}
			cond_resched();
			continue;
		}

		if (deko_vma_needs_write_prefault(vma))
			gup_flags |= FOLL_WRITE;

		remaining = nr_pages;
		cur = start;

		while (remaining) {
			int locked = 1;

			chunk_pages = min(remaining, 256UL);
			if (chunk_pages > expected_pages - total_pinned) {
				ret = -EOVERFLOW;
				pr_err("Page pin array overflow for VMA [0x%lx-0x%lx]: pinned=%lu chunk=%lu capacity=%lu\n",
				       start, end, total_pinned, chunk_pages,
				       expected_pages);
				goto out_err;
			}

			ret = pin_user_pages_remote(mm, cur, chunk_pages,
						    gup_flags,
						    (*pages) + total_pinned,
						    &locked);
			if (!locked) {
				pr_debug("Restarting Deko VMA pin walk after GUP dropped mmap_lock at 0x%lx\n",
					cur);
				if (ret > 0)
					unpin_user_pages((*pages) + total_pinned,
							 ret);
				if (ret == 0)
					ret = 1;
				goto out_retry_unlocked;
			}
			if (ret < 0) {
				pr_err("Failed to pin VMA [0x%lx-0x%lx] chunk at 0x%lx, err: %d\n",
				       start, end, cur, ret);
				goto out_err;
			}
			if (!ret) {
				pr_err("Failed to pin VMA [0x%lx-0x%lx] chunk at 0x%lx: zero pages pinned\n",
				       start, end, cur);
				ret = -EFAULT;
				goto out_err;
			}

			total_pinned += ret;
			remaining -= ret;
			cur += (unsigned long)ret * PAGE_SIZE;
			cond_resched();
		}

		pr_debug("Pinned %lu pages for VMA [0x%lx-0x%lx]\n", nr_pages,
			 start, end);
	}

	mmap_read_unlock(mm);

	pr_debug("Successfully pinned %lu pages out of total_vm %lu\n",
		 total_pinned, expected_pages);

	return total_pinned;

out_err:
	mmap_read_unlock(mm);

out_retry_unlocked:
	if (total_pinned > 0)
		unpin_user_pages(*pages, total_pinned);

	kvfree(*pages);
	*pages = NULL;

	if (ret > 0) {
		cond_resched();
		goto retry;
	}

	return ret;
}

/*
 * When the old CPU is detected to be different from the current CPU, we need to notify
 * the monitor of the migration and update the CPU information in the monitor so that
 * the monitor can update the corresponding CPU bitmask and thus ensure the correct VMPL1
 * is scheduled on the new CPU.
 */
static int
deko_notify_monitor_migration(unsigned int old_cpu,
			      const struct deko_handoff_checkpoint *checkpoint,
			      unsigned int *new_cpu, u64 *staged_generation)
{
	struct svsm_call call = { 0 };
	struct deko_migration_call_args args = {
		.old_cpu = old_cpu,
		.current_cpu = raw_smp_processor_id(),
		.checkpoint = checkpoint,
	};
	int ret;

	if (!current->is_monitored)
		return 0;

	ret = deko_svsm_call_locked(&call, deko_prepare_monitor_migration_call,
				    &args);
	if (unlikely(ret < 0)) {
		pr_warn("Failed to notify monitor for task migration (tid=%d, tgid=%d, old_cpu=%u, new_cpu=%u, err=%d)\n",
			current->pid, current->tgid, old_cpu, args.current_cpu,
			ret);
		return ret;
	}

	if (staged_generation)
		*staged_generation = call.rdx_out;
	if (new_cpu)
		*new_cpu = args.current_cpu;

	return 0;
}

static int deko_prepare_monitor_migration_call(struct svsm_call *call,
					       struct svsm_ca *caa, void *arg)
{
	struct deko_migration_req *req;
	struct deko_migration_call_args *migration = arg;
	unsigned int current_cpu;

	current_cpu = smp_processor_id();
	migration->current_cpu = current_cpu;

	req = (struct deko_migration_req *)caa->svsm_buffer;
	req->old_cpu = migration->old_cpu;
	req->new_cpu = current_cpu;
	req->pid = current->pid;
	req->kernel_gs_base = (u64)(cpu_kernelmode_gs_base(current_cpu) +
				    (unsigned long)__per_cpu_start);
	req->user_gs_base = migration->checkpoint->user_gs_base;

	call->rax = SVSM_EXTEND_CALL(SVSM_EXTEND_TASK_MIGRATE);

	return 0;
}

static int deko_prepare_launch_app_call(struct svsm_call *call,
					struct svsm_ca *caa, void *arg)
{
	const struct deko_launch_app_call_args *launch = arg;
	struct deko_launch_app_req *req;
	unsigned int current_cpu;

	current_cpu = raw_smp_processor_id();
	req = (struct deko_launch_app_req *)caa->svsm_buffer;
	memset(req, 0, sizeof(*req));
	memcpy(&req->regs, launch->regs, sizeof(*launch->regs));
	req->launch_type = launch->launch_type;
	req->fs_base = x86_fsbase_read_task(current);
	req->user_gs_base = x86_gsbase_read_task(current);
	req->kernel_gs_base = (u64)(cpu_kernelmode_gs_base(current_cpu) +
				    (unsigned long)__per_cpu_start);
	call->r8 = launch->migration_version;

	return 0;
}

static void
deko_publish_handoff_checkpoint(struct deko_handoff_checkpoint *checkpoint,
				const struct deko_migration_state *migration,
				unsigned int current_cpu)
{
	u64 seq = READ_ONCE(checkpoint->seq);

	/* Publish writer-in-progress before rewriting the checkpoint. */
	WRITE_ONCE(checkpoint->seq, seq + 1);
	smp_wmb();

	WRITE_ONCE(checkpoint->pid, current->pid);
	WRITE_ONCE(checkpoint->owner_cpu, migration->committed_owner_cpu);
	WRITE_ONCE(checkpoint->generation, migration->committed_generation);
	WRITE_ONCE(checkpoint->user_rsp, this_cpu_read(deko_user_rsp));
	WRITE_ONCE(checkpoint->user_gs_base, x86_gsbase_read_task(current));
	WRITE_ONCE(checkpoint->kernel_gs_base,
		   (u64)(cpu_kernelmode_gs_base(current_cpu) +
			 (unsigned long)__per_cpu_start));
	WRITE_ONCE(checkpoint->valid, true);
	smp_store_release(&checkpoint->seq, seq + 2);
}

static bool
deko_load_handoff_checkpoint(const struct deko_handoff_checkpoint *checkpoint,
			     struct deko_handoff_checkpoint *snapshot)
{
	u64 start_seq, end_seq;

	for (;;) {
		start_seq = smp_load_acquire(&checkpoint->seq);
		if (start_seq & 1) {
			cpu_relax();
			continue;
		}

		snapshot->pid = READ_ONCE(checkpoint->pid);
		snapshot->owner_cpu = READ_ONCE(checkpoint->owner_cpu);
		snapshot->generation = READ_ONCE(checkpoint->generation);
		snapshot->user_rsp = READ_ONCE(checkpoint->user_rsp);
		snapshot->user_gs_base = READ_ONCE(checkpoint->user_gs_base);
		snapshot->kernel_gs_base =
			READ_ONCE(checkpoint->kernel_gs_base);
		snapshot->valid = READ_ONCE(checkpoint->valid);

		end_seq = smp_load_acquire(&checkpoint->seq);
		if (likely(start_seq == end_seq))
			break;

		cpu_relax();
	}

	return snapshot->valid;
}

static int deko_validate_handoff_checkpoint(
	const struct deko_handoff_checkpoint *checkpoint,
	const struct deko_migration_state *migration)
{
	if (!checkpoint->valid) {
		pr_warn("handoff checkpoint invalid for pid=%d\n",
			current->pid);
		return -EINVAL;
	}
	if (checkpoint->pid != current->pid) {
		pr_warn("handoff checkpoint pid mismatch: expected=%d actual=%u\n",
			current->pid, checkpoint->pid);
		return -EINVAL;
	}
	if (checkpoint->owner_cpu != migration->committed_owner_cpu) {
		pr_warn("handoff checkpoint owner mismatch: expected=%u actual=%u pid=%d\n",
			migration->committed_owner_cpu, checkpoint->owner_cpu,
			current->pid);
		return -EINVAL;
	}
	if (checkpoint->generation != migration->committed_generation) {
		pr_warn("handoff checkpoint generation mismatch: expected=%llu actual=%llu pid=%d\n",
			(unsigned long long)migration->committed_generation,
			(unsigned long long)checkpoint->generation,
			current->pid);
		return -EINVAL;
	}
	if (migration->pending &&
	    (migration->expected_owner_cpu != migration->committed_owner_cpu ||
	     migration->expected_source_generation !=
		     migration->committed_generation)) {
		pr_warn("handoff pending state stale: expected_owner=%u committed_owner=%u expected_gen=%llu committed_gen=%llu pid=%d\n",
			migration->expected_owner_cpu,
			migration->committed_owner_cpu,
			(unsigned long long)
				migration->expected_source_generation,
			(unsigned long long)migration->committed_generation,
			current->pid);
		return -EINVAL;
	}
	if (migration->pending &&
	    (checkpoint->owner_cpu != migration->expected_owner_cpu ||
	     checkpoint->generation != migration->expected_source_generation)) {
		pr_warn("handoff checkpoint staging mismatch: expected_owner=%u actual_owner=%u expected_gen=%llu actual_gen=%llu pid=%d\n",
			migration->expected_owner_cpu, checkpoint->owner_cpu,
			(unsigned long long)
				migration->expected_source_generation,
			(unsigned long long)checkpoint->generation,
			current->pid);
		return -EINVAL;
	}

	return 0;
}

static void deko_restore_local_handoff_state(
	const struct deko_handoff_checkpoint *checkpoint)
{
	this_cpu_write(deko_user_rsp, checkpoint->user_rsp);
	this_cpu_write(deko_kernel_vmpl1_rsp, current->thread.kernel_vmpl1_rsp);
}

static int
deko_check_and_handle_migration(struct svsm_call *call,
				struct deko_migration_state *migration,
				struct deko_handoff_checkpoint *checkpoint)
{
	struct deko_handoff_checkpoint snapshot = { 0 };
	unsigned int current_cpu;
	int ret;

	current_cpu = smp_processor_id();

	/*
	 * Before the first successful VMPL1 round there is no published
	 * checkpoint yet. Claim the current CPU as the initial owner only after
	 * the outer loop has pinned this task to a CPU.
	 */
	if (!migration->pending && !READ_ONCE(checkpoint->valid)) {
		migration->committed_owner_cpu = current_cpu;
		call->rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
		return 0;
	}

	if (!migration->pending &&
	    current_cpu == migration->committed_owner_cpu)
		return 0;

	trace_deko_monitor_migration_detected(
		current->pid, migration->committed_owner_cpu, current_cpu);

	if (!deko_load_handoff_checkpoint(checkpoint, &snapshot)) {
		pr_warn("handoff checkpoint missing for pid=%d owner=%u current_cpu=%u\n",
			current->pid, migration->committed_owner_cpu,
			current_cpu);
		return -EINVAL;
	}

	ret = deko_validate_handoff_checkpoint(&snapshot, migration);
	if (unlikely(ret < 0))
		return ret;

	if (migration->pending || current_cpu != migration->committed_owner_cpu)
		deko_restore_local_handoff_state(&snapshot);

	call->rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);

	if (migration->pending && current_cpu == migration->staged_target_cpu)
		return 0;

	ret = deko_notify_monitor_migration(migration->committed_owner_cpu,
					    &snapshot, &current_cpu,
					    &migration->staged_generation);
	if (unlikely(ret < 0))
		return ret;

	trace_deko_monitor_migration_notified(current->pid,
					      migration->staged_generation);

	migration->staged_target_cpu = current_cpu;
	migration->expected_owner_cpu = snapshot.owner_cpu;
	migration->expected_source_generation = snapshot.generation;
	migration->pending = true;

	return 0;
}

static void deko_commit_handoff_adoption(struct deko_migration_state *migration,
					 unsigned int current_cpu)
{
	pr_debug(
		"handoff commit pid=%d old_owner=%u new_owner=%u old_gen=%llu new_gen=%llu\n",
		current->pid, migration->committed_owner_cpu, current_cpu,
		(unsigned long long)migration->committed_generation,
		(unsigned long long)migration->staged_generation);

	migration->committed_owner_cpu = current_cpu;
	migration->committed_generation = migration->staged_generation;
	migration->staged_target_cpu = 0;
	migration->expected_owner_cpu = 0;
	migration->expected_source_generation = 0;
	migration->staged_generation = 0;
	migration->pending = false;
}

static int
deko_finalize_launch_round(struct svsm_call *call,
			   struct deko_migration_state *migration,
			   struct deko_handoff_checkpoint *checkpoint,
			   bool adopting, unsigned int current_cpu)
{
	switch (call->rax_out) {
	case DEKO_SERVICE_APP_ENTER_OK:
	case DEKO_TIMER_SERVICE:
	case DEKO_PAGE_FAULT_SERVICE:
		if (adopting)
			deko_commit_handoff_adoption(migration, current_cpu);
		if (current_cpu == migration->committed_owner_cpu) {
			/*
			 * Publish the VMPL1 exit snapshot before this task is
			 * allowed to migrate again so passive migration can
			 * only observe a fresh restart point.
			 */
			deko_publish_handoff_checkpoint(checkpoint, migration,
							current_cpu);
		}
		return 0;
	default:
		pr_warn("Received unknown call return value: 0x%llx\n",
			call->rax_out);
		return -EINVAL;
	}
}

static unsigned int
deko_page_fault_flags_from_req(const struct deko_page_fault_req *req)
{
	unsigned int flags = FAULT_FLAG_USER;

	if (req->access & DEKO_PF_ACCESS_WRITE)
		flags |= FAULT_FLAG_WRITE;
	if (req->access & DEKO_PF_ACCESS_INSTR)
		flags |= FAULT_FLAG_INSTRUCTION;

	return flags;
}

static bool deko_page_fault_exec_needs_unshare(struct mm_struct *mm,
					       unsigned long address)
{
	struct vm_area_struct *vma;
	bool needs_unshare = false;

	if (!mm)
		return false;

	mmap_read_lock(mm);
	vma = find_vma(mm, address);
	if (vma && address >= vma->vm_start &&
	    (vma->vm_flags & VM_EXEC) &&
	    !(vma->vm_flags & (VM_IO | VM_PFNMAP)) &&
	    is_cow_mapping(vma->vm_flags))
		needs_unshare = true;
	mmap_read_unlock(mm);

	return needs_unshare;
}

static bool deko_lookup_user_page_state(struct mm_struct *mm,
					unsigned long address,
					u64 *page_gpa,
					bool *anon_exclusive)
{
	struct vm_area_struct *vma;
	spinlock_t *ptl;
	struct page *page;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	pte_t pte;
	bool ok = false;

	*page_gpa = 0;
	*anon_exclusive = false;

	if (!mm)
		return false;

	mmap_read_lock(mm);
	vma = find_vma(mm, address);
	if (!vma || address < vma->vm_start)
		goto out_unlock;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto out_unlock;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || p4d_bad(*p4d) || p4d_leaf(*p4d))
		goto out_unlock;
	pud = pud_offset(p4d, address);
	if (pud_none(*pud) || pud_bad(*pud) || pud_leaf(*pud))
		goto out_unlock;
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_leaf(*pmd))
		goto out_unlock;

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (!ptep)
		goto out_unlock;
	pte = ptep_get(ptep);
	if (!pte_present(pte))
		goto out_pte;

	page = vm_normal_page(vma, address, pte);
	if (!page)
		goto out_pte;

	*page_gpa = ((u64)page_to_pfn(page) << PAGE_SHIFT) |
		    (address & ~PAGE_MASK);
	*page_gpa = __sme_clr(*page_gpa);
	*anon_exclusive = PageAnon(page) && PageAnonExclusive(page);
	ok = true;

out_pte:
	pte_unmap_unlock(ptep, ptl);
out_unlock:
	mmap_read_unlock(mm);
	return ok;
}

static int deko_fixup_user_fault(struct mm_struct *mm, unsigned long address,
				 unsigned int flags)
{
	bool unlocked = false;
	int ret;

	mmap_read_lock(mm);
	ret = fixup_user_fault(mm, address, flags, &unlocked);
	if (ret != -EFAULT) {
		/*
		 * fixup_user_fault() may drop and retake mmap_lock internally,
		 * but it does not return with mmap_lock unlocked.
		 */
		mmap_read_unlock(mm);
		return ret;
	}

	/*
	 * fixup_user_fault() uses the GUP VMA lookup path, which no longer
	 * expands grow-down stacks. Mirror the regular user fault path enough
	 * to grow a valid stack VMA, then fault the page in normally.
	 */
	if (!expand_stack(mm, address)) {
		mmap_read_unlock(mm);
		return -EFAULT;
	}

	unlocked = false;
	ret = fixup_user_fault(mm, address, flags, &unlocked);
	mmap_read_unlock(mm);
	return ret;
}

static int deko_prefault_private_exec_range(struct mm_struct *mm,
					    unsigned long start,
					    unsigned long end,
					    const char *reason)
{
	unsigned long cur;
	unsigned int flags = FAULT_FLAG_USER | FAULT_FLAG_INSTRUCTION;
	int ret;

	for (cur = start; cur < end; cur += PAGE_SIZE) {
		u64 page_gpa = 0;
		bool anon_exclusive = false;

		ret = deko_fixup_user_fault(mm, cur, flags);
		if (ret < 0) {
			pr_err("Deko %s exec prefault failed pid=%d addr=0x%lx ret=%d\n",
			       reason, current->pid, cur, ret);
			return ret;
		}

		ret = deko_fixup_user_fault(mm, cur,
					    flags | FAULT_FLAG_UNSHARE);
		if (ret < 0) {
			pr_err("Deko %s exec unshare failed pid=%d addr=0x%lx ret=%d\n",
			       reason, current->pid, cur, ret);
			return ret;
		}

			if (!deko_lookup_user_page_state(mm, cur, &page_gpa,
							 &anon_exclusive) ||
			    !anon_exclusive) {
				pr_err("Deko %s exec prefault did not produce private page pid=%d addr=0x%lx gpa=0x%llx anon_exclusive=%d\n",
				       reason, current->pid, cur,
				       (unsigned long long)page_gpa,
				       anon_exclusive ? 1 : 0);
				return -EFAULT;
			}

			ret = deko_pin_private_exec_page(mm, cur, reason);
			if (ret < 0)
				return ret;
		}

		return 0;
	}

int deko_prefault_private_exec_vmas(struct mm_struct *mm, const char *reason)
{
	unsigned long cur = 0;

	if (!mm)
		return 0;

	for (;;) {
		struct vm_area_struct *vma;
		unsigned long start;
		unsigned long end;
		vm_flags_t vm_flags;
		int ret;

		mmap_read_lock(mm);
		vma = find_vma(mm, cur);
		if (!vma) {
			mmap_read_unlock(mm);
			return 0;
		}

		if (cur < vma->vm_start)
			cur = vma->vm_start;
		start = cur;
		end = vma->vm_end;
		vm_flags = vma->vm_flags;
		mmap_read_unlock(mm);

		if ((vm_flags & VM_EXEC) && !(vm_flags & (VM_IO | VM_PFNMAP))) {
			if (!is_cow_mapping(vm_flags)) {
				pr_err("Deko %s exec VMA is not private-COW eligible pid=%d range=[0x%lx-0x%lx) flags=0x%lx\n",
				       reason, current->pid, start, end,
				       vm_flags);
				return -EACCES;
			}

			ret = deko_prefault_private_exec_range(mm, start, end,
							      reason);
			if (ret < 0)
				return ret;
		}

		if (end <= cur)
			return -EFAULT;
		cur = end;
	}
}

static int deko_prefault_lift_exec_user_range(struct mm_struct *mm,
					      unsigned long start_addr,
					      unsigned long length,
					      const char *reason)
{
	unsigned long end_addr;
	unsigned long cur;

	if (!mm || !length)
		return 0;
	if (check_add_overflow(start_addr, length, &end_addr))
		return -EINVAL;

	start_addr = PAGE_ALIGN_DOWN(start_addr);
	end_addr = PAGE_ALIGN(end_addr);
	if (!start_addr || start_addr >= end_addr)
		return 0;

	cur = start_addr;
	while (cur < end_addr) {
		struct vm_area_struct *vma;
		unsigned long sub_start;
		unsigned long sub_end;
		unsigned long next;
		vm_flags_t vm_flags;
		int ret;

		mmap_read_lock(mm);
		vma = find_vma(mm, cur);
		if (!vma) {
			mmap_read_unlock(mm);
			break;
		}

		if (cur < vma->vm_start)
			cur = vma->vm_start;
		if (cur >= end_addr) {
			mmap_read_unlock(mm);
			break;
		}

		sub_start = max(cur, vma->vm_start);
		sub_end = min(end_addr, vma->vm_end);
		next = sub_end;
		vm_flags = vma->vm_flags;
		if (!(vm_flags & VM_EXEC) || (vm_flags & (VM_IO | VM_PFNMAP))) {
			mmap_read_unlock(mm);
			cur = next;
			continue;
		}
		if (!is_cow_mapping(vm_flags)) {
			pr_err("Deko %s exec range VMA is not private-COW eligible pid=%d range=[0x%lx-0x%lx) vma=[0x%lx-0x%lx) flags=0x%lx\n",
			       reason, current->pid, sub_start, sub_end,
			       vma->vm_start, vma->vm_end, vm_flags);
			mmap_read_unlock(mm);
			return -EACCES;
		}
		mmap_read_unlock(mm);

		deko_clamp_file_tail_populate_range(mm, sub_start, &sub_end,
						    PROT_READ | PROT_EXEC,
						    reason);
			if (sub_start < sub_end) {
				ret = deko_prefault_private_exec_range(mm, sub_start,
								      sub_end, reason);
				if (ret < 0) {
					mutex_lock(&deko_exec_pin_lock);
					deko_unpin_exec_user_range_locked(mm,
									  sub_start,
									  sub_end);
					mutex_unlock(&deko_exec_pin_lock);
					return ret;
				}

				ret = deko_notify_monitor_exec_range_ready(sub_start,
									  sub_end,
									  reason);
				if (ret < 0) {
					int cleanup_ret;

					cleanup_ret = deko_unlift_exec_user_range(
						mm, sub_start, sub_end - sub_start,
						"lift-fail");
					if (cleanup_ret < 0)
						pr_err("Deko %s exec lift cleanup failed pid=%d range=[0x%lx-0x%lx) ret=%d\n",
						       reason, current->pid,
						       sub_start, sub_end,
						       cleanup_ret);
					return ret;
				}
			}

		if (next <= cur)
			return -EFAULT;
		cur = next;
	}

	return 0;
}

static int deko_handle_page_fault_service(struct deko_shared_buf *buf)
{
	struct deko_page_fault_frame *frame;
	struct deko_page_fault_req *req;
	struct deko_page_fault_resp *resp;
	struct mm_struct *mm = current->mm;

	unsigned int flags;
	unsigned int resolve_flags = 0;
	u64 page_gpa = 0;
	bool anon_exclusive = false;
	bool unshare_exec = false;
	int ret;

	if (unlikely(!buf || !mm))
		return -EFAULT;

	frame = &buf->page_fault;
	req = &frame->req;
	resp = &frame->resp;

	resp->version = DEKO_PAGE_FAULT_RESP_VERSION_V1;
	resp->resp_size = sizeof(*resp);
	resp->seq = req->seq;
	resp->status = -EINVAL;
	resp->resolution = DEKO_PF_RESOLUTION_DENY;
	resp->page_flags = 0;
	resp->page_va = req->page_va;
	resp->page_gpa = 0;
	resp->page_len = 0;
	resp->backing_id = 0;
	resp->backing_offset = 0;

	if (unlikely(req->version != DEKO_PAGE_FAULT_REQ_VERSION_V1 ||
		     req->req_size != sizeof(*req)))
		return -EINVAL;
	if (unlikely(req->access & DEKO_PF_ACCESS_RSVD))
		return -EFAULT;
	if (unlikely(req->fault_va >= TASK_SIZE_MAX))
		return -EFAULT;
	if (unlikely(req->pid && req->pid != current->pid))
		pr_warn("page fault pid mismatch req_pid=%u current_pid=%d fault=0x%llx\n",
			req->pid, current->pid,
			(unsigned long long)req->fault_va);

	flags = deko_page_fault_flags_from_req(req);
	if (req->access & DEKO_PF_ACCESS_INSTR) {
		unshare_exec = deko_page_fault_exec_needs_unshare(mm,
								  req->fault_va);
	}
	pr_info("Deko page fault service begin pid=%d seq=%llu fault=0x%llx rip=0x%llx access=0x%x reason=%u flags=0x%x unshare_exec=%d\n",
		current->pid, (unsigned long long)req->seq,
		(unsigned long long)req->fault_va,
		(unsigned long long)req->rip, req->access, req->reason,
		flags, unshare_exec ? 1 : 0);

	ret = deko_fixup_user_fault(mm, req->fault_va, flags);
	pr_info("Deko page fault service after fixup pid=%d seq=%llu ret=%d unshare_exec=%d\n",
		current->pid, (unsigned long long)req->seq, ret,
		unshare_exec ? 1 : 0);
	if (!ret && unshare_exec) {
		ret = deko_fixup_user_fault(mm, req->fault_va,
					    (flags & ~FAULT_FLAG_WRITE) |
						    FAULT_FLAG_UNSHARE);
		pr_info("Deko page fault service after unshare pid=%d seq=%llu ret=%d\n",
			current->pid, (unsigned long long)req->seq, ret);
		if (!ret &&
		    deko_lookup_user_page_state(mm, req->fault_va, &page_gpa,
						&anon_exclusive) &&
		    anon_exclusive) {
			pr_info("Deko page fault service private page pid=%d seq=%llu gpa=0x%llx\n",
				current->pid, (unsigned long long)req->seq,
				(unsigned long long)page_gpa);
			resolve_flags |= DEKO_PF_RESOLVE_F_FRESH_PAGE |
					 DEKO_PF_RESOLVE_F_PRIVATE_CANDIDATE;
		}
	}

	resp->status = ret;
	resp->resolution = ret ? DEKO_PF_RESOLUTION_DENY :
		((resolve_flags & DEKO_PF_RESOLVE_F_PRIVATE_CANDIDATE) ?
			 DEKO_PF_RESOLUTION_ANON_PRIVATE :
			 DEKO_PF_RESOLUTION_NONE);
	resp->page_flags = ret ? 0 : resolve_flags;
	resp->page_gpa = ret ? 0 : page_gpa;
	resp->page_len = ret ? 0 : PAGE_SIZE;

	if (unlikely(ret))
		pr_warn("page fault resolve failed pid=%d fault=0x%llx access=0x%x reason=%u ret=%d\n",
			current->pid, (unsigned long long)req->fault_va,
			req->access, req->reason, ret);

	return ret;
}

static int
deko_track_page_fault_progress(struct deko_shared_buf *buf,
			       struct deko_page_fault_progress *progress)
{
	struct deko_page_fault_req *req = &buf->page_fault.req;
	struct deko_page_fault_resp *resp = &buf->page_fault.resp;

	if (req->fault_va == progress->fault_va &&
	    req->rip == progress->rip &&
	    req->error_code == progress->error_code &&
	    req->access == progress->access &&
	    req->reason == progress->reason) {
		progress->repeats++;
	} else {
		progress->fault_va = req->fault_va;
		progress->rip = req->rip;
		progress->error_code = req->error_code;
		progress->access = req->access;
		progress->reason = req->reason;
		progress->repeats = 1;
	}

	if (progress->repeats <= 256)
		return 0;

	pr_err("Deko page fault made no progress pid=%d fault=0x%llx rip=0x%llx access=0x%x reason=%u error=0x%llx seq=%llu status=%lld resolution=%u\n",
	       current->pid, (unsigned long long)req->fault_va,
	       (unsigned long long)req->rip, req->access, req->reason,
	       (unsigned long long)req->error_code,
	       (unsigned long long)req->seq, resp->status, resp->resolution);
	return -ELOOP;
}

static int deko_run_launch_iteration(struct svsm_call *call,
				     const struct pt_regs *regs,
				     u32 launch_type,
				     struct deko_migration_state *migration,
				     bool *adopting, unsigned int *launch_cpu)
{
	struct deko_launch_app_call_args args = {
		.regs = regs,
		.launch_type = launch_type,
	};
	unsigned int current_cpu;
	int ret;
	u64 generation = 0;

	current_cpu = smp_processor_id();
	*launch_cpu = current_cpu;
	*adopting = false;

	if (migration->pending && current_cpu != migration->staged_target_cpu) {
		return -EAGAIN;
	}

	if (migration->pending) {
		generation = migration->staged_generation;
		*adopting = true;
	}

	args.migration_version = generation;
	ret = deko_svsm_call_locked(call, deko_prepare_launch_app_call, &args);
	if (unlikely(ret < 0)) {
		pr_err("Failed to perform call launch protocol for task %d, err: %d pending=%d current_cpu=%u staged_target=%u staged_gen=%llu committed_owner=%u committed_gen=%llu\n",
		       current->pid, ret, migration->pending, current_cpu,
		       migration->staged_target_cpu,
		       (unsigned long long)migration->staged_generation,
		       migration->committed_owner_cpu,
		       (unsigned long long)migration->committed_generation);
		return ret;
	}

	return 0;
}

static int deko_handle_vmpl1_exit_reason(struct svsm_call *call,
					 struct deko_shared_buf *buf,
					 bool *normal_exit,
					 struct deko_ring_poller *poller)
{
	u64 handled_syscall_nr;
	unsigned long flags;
	int ret;

	*normal_exit = false;

	switch (call->rax_out) {
	case DEKO_SERVICE_APP_ENTER_OK:
		{
			bool ring_handled = false;
			bool ring_present = false;

			ret = deko_syscall_ring_drain(buf, normal_exit,
						      &ring_handled,
						      &ring_present);
			if (ret != 0)
				return ret;
			if (ring_present && poller && poller->task)
				wake_up_process(poller->task);
			if (ring_present) {
				/*
				 * A present syscall ring owns ENTER_OK delivery.
				 * Falling through here can re-execute a stale
				 * legacy syscall body after the poller already
				 * completed the ring entry.
				 */
				break;
			}
		}

		/* Handle one legacy shared-buffer syscall when no ring exists. */
		handled_syscall_nr = buf->syscall_body.ax;
		ret = deko_app_handle_system_calls(&buf->syscall_body);
		if (ret != 0) {
			pr_err("Error handling system calls: %d\n", ret);
			return ret;
		}
		*normal_exit = is_exit_syscall(handled_syscall_nr);
		break;

	case DEKO_TIMER_SERVICE:
		trace_deko_timer_service(current->pid);

		/*
		 * VMPL1 consumes the restricted timer event outside Linux's
		 * normal irq-entry tick path. Synthesize the reschedule bit that
		 * the tick would otherwise set, then use the regular voluntary
		 * reschedule point. Keep the VMPL1 task pinned while doing so:
		 * timer delivery is per-CPU doorbell state, and passive migration
		 * in the middle of this synthetic tick can strand the next event
		 * on the wrong CPU.
		 */
		migrate_disable();
		local_irq_save(flags);
		set_need_resched_current();
		local_irq_restore(flags);
		cond_resched();
		migrate_enable();
		break;
	case DEKO_PAGE_FAULT_SERVICE:
		ret = deko_handle_page_fault_service(buf);
		if (ret != 0)
			return ret;
		cond_resched();
		break;
	default:
		return -EINVAL;
	}

	if (!*normal_exit)
		call->rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);

	return 0;
}

struct deko_map_vmpl1_state {
	int ret;
};

static void deko_map_vmpl1_on_cpu(void *info)
{
	struct deko_map_vmpl1_state *state = info;
	enum es_result res;

	res = svsm_map_vmpl1();
	if (res != ES_OK) {
		pr_err("Failed to map VMPL1 trampoline on this CPU, err: %d\n",
		       res);
		cmpxchg(&state->ret, 0, -EIO);
	}
}

void deko_proxy_loop(struct callback_head *work)
{
	int errno = 0;
	struct svsm_call call = { 0 };
	struct pt_regs *regs = task_pt_regs(current);
	unsigned long long iteration = 0;
	u64 launch_identity = ((u64)(u32)current->tgid << 32) |
			      (u32)current->pid;
	struct deko_shared_buf *buf = NULL;
	unsigned long alias_addr = 0;
	bool normal_exit = false;
	bool adopting = false;
	bool iteration_cpu_pinned = false;
	unsigned int launch_cpu = 0;
	struct deko_migration_state migration = { 0 };
	struct deko_handoff_checkpoint checkpoint = { 0 };
	struct deko_page_fault_progress page_fault_progress = { 0 };
	struct deko_ring_poller *poller = NULL;

	struct deko_task_work *dw =
		container_of(work, struct deko_task_work, work);

	if (unlikely(!current->mm || fatal_signal_pending(current))) {
		pr_debug("Skipping Deko proxy loop for exiting task pid=%d tgid=%d comm=%s mm=%px fatal_signal=%d\n",
			current->pid, current->tgid, current->comm, current->mm,
			fatal_signal_pending(current));
		kfree(dw);
		return;
	}

	if (unlikely(!current->thread.kernel_vmpl1_rsp)) {
		errno = deko_register_current_clone_child();
		if (errno < 0) {
			current->is_monitored = false;
			goto err_pin;
		}
		pr_debug("Deko proxy loop registered missing clone context pid=%d tgid=%d kernel_vmpl1_rsp=0x%lx\n",
			current->pid, current->tgid,
			current->thread.kernel_vmpl1_rsp);
	}

	current->is_monitored = true;
	pr_debug("Deko proxy loop start pid=%d tgid=%d comm=%s task=%px current_cpu=%u monitored=%d launch_type=%u\n",
		current->pid, current->tgid, current->comm, current,
		raw_smp_processor_id(), current->is_monitored,
		dw->launch_type);

	errno = deko_alloc_hidden_user_alias(current->mm, &alias_addr,
					     DEKO_DEFAULT_SHARED_BUF_SIZE);
	if (errno < 0) {
		pr_err("Failed to allocate hidden alias VMA for task %d, err: %d\n",
		       current->pid, errno);
		goto err_pin;
	}
	pr_debug("Deko proxy loop allocated hidden alias pid=%d tgid=%d alias=0x%lx len=0x%lx\n",
		current->pid, current->tgid, alias_addr,
		(unsigned long)DEKO_DEFAULT_SHARED_BUF_SIZE);

	/*
	 * Do not prefault or pin application memory here. VMPL1 page faults
	 * are reported back through DEKO_PAGE_FAULT_SERVICE and resolved by
	 * Linux on demand before VMPL1 retries the faulting instruction.
	 */

	buf = kzalloc(sizeof(struct deko_shared_buf), GFP_KERNEL);
	if (!buf) {
		pr_err("Failed to allocate shared buffer for task %d\n",
		       current->pid);
		errno = -ENOMEM;
		goto err_alias;
	}

	buf->buf = kzalloc(DEKO_DEFAULT_SHARED_BUF_SIZE, GFP_KERNEL);
	if (!buf->buf) {
		pr_err("Failed to allocate shared buffer for task %d\n",
		       current->pid);
		errno = -ENOMEM;
		goto err_inner_buf;
	}
	deko_syscall_ring_init((struct deko_syscall_ring *)buf->buf);

	buf->alias_buf = (void *)alias_addr;
	buf->alias_len = DEKO_DEFAULT_SHARED_BUF_SIZE;
	pr_debug("Deko proxy loop shared buffer pid=%d tgid=%d buf=%px payload=%px alias=%px alias_len=0x%lx ring_enabled=%d ring_poll=%d launch_identity=0x%llx\n",
		current->pid, current->tgid, buf, buf->buf, buf->alias_buf,
		(unsigned long)buf->alias_len,
		READ_ONCE(deko_syscall_ring_enabled) ? 1 : 0,
		READ_ONCE(deko_ring_poll) ? 1 : 0,
		(unsigned long long)launch_identity);

	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	/* Shared buffer between VMPL1 and VMPL2. */
	call.rcx = (u64)buf;
	call.rdx = launch_identity;
	call.r8 = 0;

	errno = deko_pin_current_proxy_task();
	if (unlikely(errno < 0))
		goto err_loop;

	errno = deko_syscall_ring_poller_start(&poller, buf);
	if (unlikely(errno < 0)) {
		pr_err("Failed to start Deko syscall ring poller pid=%d err=%d\n",
		       current->pid, errno);
		goto err_loop;
	}

	/* Application main loop. */
	for (;;) {
		iteration++;
		if (fatal_signal_pending(current)) {
			errno = -EINTR;
			pr_debug("Deko proxy loop exiting pid=%d tgid=%d comm=%s due to pending fatal signal\n",
				current->pid, current->tgid, current->comm);
			goto err_loop;
		}

		migrate_disable();
		iteration_cpu_pinned = true;

		errno = deko_check_and_handle_migration(&call, &migration,
							&checkpoint);
		if (errno == -EAGAIN) {
			migrate_enable();
			iteration_cpu_pinned = false;

			cond_resched();
			continue;
		}
		if (unlikely(errno < 0)) {
			migrate_enable();
			iteration_cpu_pinned = false;
			pr_err("Deko proxy migration check failed pid=%d iter=%llu err=%d cpu=%u pending=%d committed_owner=%u staged_target=%u\n",
			       current->pid, iteration, errno,
			       raw_smp_processor_id(), migration.pending,
			       migration.committed_owner_cpu,
			       migration.staged_target_cpu);
			goto err_loop;
		}

		errno = deko_run_launch_iteration(
			&call, regs, dw->launch_type, &migration, &adopting,
			&launch_cpu);
		if (iteration <= 3)
			pr_debug("Deko proxy launch iteration returned pid=%d tgid=%d iter=%llu err=%d rax_out=0x%llx rcx_out=0x%llx launch_cpu=%u adopting=%d\n",
				current->pid, current->tgid, iteration,
				errno, call.rax_out, call.rcx_out,
				launch_cpu, adopting ? 1 : 0);
		if (errno == -EAGAIN) {
			migrate_enable();
			iteration_cpu_pinned = false;
			cond_resched();
			continue;
		}
		if (unlikely(errno < 0)) {
			migrate_enable();
			iteration_cpu_pinned = false;
			pr_err("Deko proxy launch failed pid=%d iter=%llu err=%d cpu=%u pending=%d staged_target=%u committed_owner=%u\n",
			       current->pid, iteration, errno,
			       raw_smp_processor_id(), migration.pending,
			       migration.staged_target_cpu,
			       migration.committed_owner_cpu);
			goto err_loop;
		}

		errno = deko_finalize_launch_round(
			&call, &migration, &checkpoint, adopting, launch_cpu);
		migrate_enable();
		iteration_cpu_pinned = false;

		if (unlikely(errno < 0))
			goto err_loop;

		errno = deko_handle_vmpl1_exit_reason(
			&call, buf, &normal_exit, poller);

		if (unlikely(errno < 0) || normal_exit)
			goto err_loop;
		if (call.rax_out == DEKO_PAGE_FAULT_SERVICE) {
			errno = deko_track_page_fault_progress(
				buf, &page_fault_progress);
			if (unlikely(errno < 0))
				goto err_loop;
		} else {
			page_fault_progress.repeats = 0;
		}
	}

err_loop:
	if (iteration_cpu_pinned)
		migrate_enable();

	if (normal_exit)
		pr_debug("Deko proxy loop normal exit pid=%d tgid=%d comm=%s iter=%llu rax_out=0x%llx errno=%d\n",
			current->pid, current->tgid, current->comm, iteration,
			call.rax_out, errno);
	else
		pr_err("Deko proxy loop abnormal exit pid=%d tgid=%d comm=%s iter=%llu rax_out=0x%llx errno=%d shared_buf=%px payload=%px alias=0x%lx\n",
		       current->pid, current->tgid, current->comm, iteration,
		       call.rax_out, errno, buf, buf ? buf->buf : NULL,
		       alias_addr);

	deko_syscall_ring_poller_stop(poller);

	if (buf)
		kfree(buf->buf);

err_inner_buf:
err_alias:
	kfree(buf);

	deko_free_hidden_user_alias(alias_addr, DEKO_DEFAULT_SHARED_BUF_SIZE);

err_pin:
	kfree(dw);

	/*
	 * Exit can also cause end of loop so we need to check if this is a "normal" exit, which
	 * will enter this path with an exit syscall; or an error that happens during the loop and
	 * the loop is exited by a non-exit syscall.
	 *
	 * In the former case, we should not treat it as an error and just exit normally; while in
	 * the latter case, we should kill the process with the appropriate error code.
	 *
	 */
	if (!normal_exit) {
		exit_lifecycle_handler(current->mm, errno);
		do_exit(errno);
	}
}

int deko_bootstrap(void)
{
	int ret;
	enum es_result res;
	struct deko_map_vmpl1_state map_state = { 0 };

	pr_info("Bootstrapping Deko once\n");

	ret = alloc_isolated_trampoline();
	if (ret) {
		pr_err("Failed to allocate isolated trampoline, err: %d\n",
		       ret);
		return ret;
	}

	res = svsm_handle_trampoline_setup((u64)entry_SYSCALL_64);
	if (res != ES_OK) {
		pr_err("Failed to set up VMPL1 trampoline, err: %d\n", res);
		return -EIO;
	}

	pr_info("Mapping VMPL1 on all CPUs\n");

	on_each_cpu(deko_map_vmpl1_on_cpu, &map_state, 1);
	if (map_state.ret)
		return map_state.ret;

	return 0;
}
