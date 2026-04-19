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

#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sizes.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/sched/task_stack.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <asm-generic/mman-common.h>
#include <asm/mem_encrypt.h>
#include <asm/processor.h>
#include <asm/sev.h>
#include <asm/syscall.h>
#include <asm/current.h>

extern char __per_cpu_start[];

#define DEKO_DEFAULT_SHARED_BUF_SIZE SZ_2M
#define DEKO_RING_CAPACITY 32
#define DEKO_DOMAIN_BITS 8

struct deko_domain_entry {
	u64 mnt_ns_id;
	u32 domain_id;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(deko_domain_table, DEKO_DOMAIN_BITS);
static DEFINE_MUTEX(deko_domain_lock);

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

	pr_info("bind mnt_ns_id=%llu domain_id=%u\n", mnt_ns_id, domain_id);
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
	pr_info("unbind mnt_ns_id=%llu domain_id=%u\n", entry->mnt_ns_id,
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
};

struct deko_ring_buf {
	u32 head;
	u32 tail;
	struct deko_syscall_entry entries[DEKO_RING_CAPACITY];
};

struct deko_shared_ring_buf {
	struct deko_ring_buf tx;
	struct deko_ring_buf rx;
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

static int eager_fault_user_range(struct mm_struct *mm,
				  unsigned long start_addr,
				  unsigned long length, unsigned long prot,
				  const char *reason)
{
	unsigned long end_addr;
	int ret;

	if (!mm || !length || !prot)
		return 0;

	if (check_add_overflow(start_addr, length, &end_addr))
		return -EINVAL;

	end_addr = PAGE_ALIGN(end_addr);
	start_addr = PAGE_ALIGN_DOWN(start_addr);

	if (start_addr >= end_addr)
		return 0;

	trace_deko_eager_paging(reason, start_addr, length, prot);

	ret = __mm_populate(start_addr, end_addr - start_addr, 0);
	if (ret < 0)
		pr_warn("Failed to populate range for %s at 0x%lx len 0x%lx, err: %d\n",
			reason, start_addr, end_addr - start_addr, ret);

	return 0;
}

static inline int mmap_post_handler(struct mm_struct *mm,
				    unsigned long start_addr,
				    unsigned long length, unsigned long prot,
				    unsigned long ax)
{
	if (IS_ERR_VALUE(ax))
		return 0;

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
					unsigned long prot)
{
	if (!mm || !length || !(prot & (PROT_READ | PROT_WRITE | PROT_EXEC)))
		return 0;

	return eager_fault_user_range(mm, start_addr, length, prot, "mprotect");
}

static int exit_post_handler(struct mm_struct *mm, unsigned long ax)
{
	enum es_result res = ES_OK;
	struct svsm_call call = { 0 };
	struct deko_new_app_req *req;
	unsigned long flags;

	local_irq_save(flags);

	req = (struct deko_new_app_req *)svsm_get_caa()->svsm_buffer;
	memset(req, 0, sizeof(*req));
	req->version = DEKO_NEW_APP_REQ_VERSION_V3;
	req->req_size = sizeof(*req);

	req->tgid = current->tgid;
	req->pid = current->tgid;
	req->ppid = current->real_parent->pid;
	req->app_type = DEKO_DOCKER_APPS;

	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_REPORT_APP);
	call.r9 = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);
	call.r8 = 0; /* Not a creation event */

	res = svsm_perform_call_protocol(&call);

	local_irq_restore(flags);

	if (res != ES_OK) {
		pr_err("Failed to report app exit to SVSM for process %s (pid: %d), err: %d\n",
		       current->comm, current->pid, res);

		return -EINVAL;
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
					    syscall_body->si, syscall_body->dx);
		if (ret < 0)
			return ret;
		break;
	case __NR_exit:
	case __NR_exit_group:
		/* Notify us that this thread has exited. */
		ret = exit_post_handler(mm, ax);
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

static int deko_pin_pages(struct mm_struct *mm, struct page ***pages)
{
	struct vm_area_struct *vma;
	unsigned long expected_pages = mm->total_vm;
	unsigned long total_pinned = 0;
	unsigned long start, end;
	unsigned long nr_pages;
	unsigned long remaining;
	unsigned long cur;
	unsigned long chunk_pages;
	unsigned int gup_flags;
	int ret = 0;

	*pages = kvmalloc_array(expected_pages, sizeof(struct page *),
				GFP_KERNEL);
	if (!*pages) {
		pr_err("Failed to allocate page pointer array\n");
		return -ENOMEM;
	}

	mmap_read_lock(mm);

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

		if (vma->vm_flags & VM_WRITE)
			gup_flags |= FOLL_WRITE;

		remaining = nr_pages;
		cur = start;

		while (remaining) {
			chunk_pages = min(remaining, 256UL);
			ret = pin_user_pages_remote(mm, cur, chunk_pages,
						    gup_flags,
						    (*pages) + total_pinned,
						    NULL);
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

		pr_info("Pinned %lu pages for VMA [0x%lx-0x%lx]\n", nr_pages,
			start, end);
	}

	mmap_read_unlock(mm);

	pr_info("Successfully pinned %lu pages out of total_vm %lu\n",
		total_pinned, expected_pages);

	return total_pinned;

out_err:
	mmap_read_unlock(mm);

	if (total_pinned > 0)
		unpin_user_pages(*pages, total_pinned);

	kvfree(*pages);
	*pages = NULL;

	return ret;
}

/*
 * When the old CPU is detected to be different from the current CPU, we need to notify
 * the monitor of the migration and update the CPU information in the monitor so that
 * the monitor can update the corresponding CPU bitmask and thus ensure the correct VMPL1
 * is scheduled on the new CPU. 
 */
static int deko_notify_monitor_migration(unsigned int old_cpu,
					 unsigned int *new_cpu,
					 u64 *migration_version)
{
	enum es_result res = ES_OK;
	struct svsm_call call = { 0 };
	struct deko_migration_req *req;
	unsigned int current_cpu;
	unsigned long old_user_rsp;
	unsigned long flags;

	if (!current->is_monitored)
		return 0;

	local_irq_save(flags);
	current_cpu = smp_processor_id();

	if (old_cpu == current_cpu) {
		local_irq_restore(flags);

		return 0;
	}

	call.caa = svsm_get_caa();
	if (unlikely(!call.caa)) {
		local_irq_restore(flags);

		return -ENODEV;
	}

	req = (struct deko_migration_req *)call.caa->svsm_buffer;
	old_user_rsp = per_cpu(deko_user_rsp, old_cpu);
	this_cpu_write(deko_user_rsp, old_user_rsp);

	req->old_cpu = old_cpu;
	req->new_cpu = current_cpu;
	req->pid = current->tgid;

	req->kernel_gs_base = (u64)(cpu_kernelmode_gs_base(current_cpu) +
				    (unsigned long)__per_cpu_start);
	req->user_gs_base = x86_gsbase_read_task(current);

	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_TASK_MIGRATE);
	call.r9 = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);

	res = svsm_perform_call_protocol(&call);

	local_irq_restore(flags);

	if (unlikely(res != ES_OK)) {
		pr_warn("Failed to notify monitor for task migration (app_id=%d, pid=%d, old_cpu=%u, new_cpu=%u, err=%d)\n",
			current->tgid, current->pid, old_cpu, current_cpu, res);
		return -EIO;
	}

	if (migration_version)
		*migration_version = call.rdx_out;
	if (new_cpu)
		*new_cpu = current_cpu;

	return 0;
}

static int deko_refresh_launch_app_context(struct svsm_call *call,
					   struct svsm_ca **caa)
{
	*caa = svsm_get_caa();
	if (unlikely(!*caa))
		return -ENODEV;

	call->caa = *caa;
	call->r9 = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);

	return 0;
}

static int deko_prepare_launch_app_call(struct svsm_call *call,
					struct svsm_ca *caa,
					const struct pt_regs *regs,
					u64 migration_version)
{
	if (unlikely(!caa))
		return -ENODEV;

	memcpy(caa->svsm_buffer, regs, sizeof(*regs));
	call->r8 = migration_version;

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
	pid_t tgid = current->tgid;
	struct deko_shared_buf *buf = NULL;
	int pinned_count;
	struct page **pages = NULL;
	unsigned long alias_addr = 0;
	unsigned int monitored_cpu;
	u64 migration_version = 0;
	u64 handled_syscall_nr = 0;
	bool normal_exit = false;
	enum es_result res;
	struct svsm_ca *caa;

	struct deko_task_work *dw =
		container_of(work, struct deko_task_work, work);

	pr_info("launch app CR3 snapshot pid=%d hw_cr3_pa=0x%llx mm_pgd_pa=0x%llx mm_pgd=%px\n",
		current->pid, (unsigned long long)read_cr3_pa(),
		current->mm ? (unsigned long long)__sme_pa(current->mm->pgd) :
			      0ULL,
		current->mm ? current->mm->pgd : NULL);

	errno = deko_alloc_hidden_user_alias(current->mm, &alias_addr,
					     DEKO_DEFAULT_SHARED_BUF_SIZE);
	if (errno < 0) {
		pr_err("Failed to allocate hidden alias VMA for task %d, err: %d\n",
		       current->pid, errno);
		goto err_pin;
	}

	/*
	 * At first we need to pin all the memories of the newly launched
	 * application to prevent page fault that cannot be handled inside
	 * VMPL1 and thus the application will crash immediately. This is
	 * because by default Linux lazily loads the application code.
	 *
	 * The hidden alias VMA must already exist here so it is included in
	 * the pinned user range visible to VMPL1.
	 */
	if ((pinned_count = deko_pin_pages(current->mm, &pages)) < 0) {
		errno = pinned_count;
		goto err_alias_vma;
	}

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

	buf->alias_buf = (void *)alias_addr;
	buf->alias_len = DEKO_DEFAULT_SHARED_BUF_SIZE;

	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	/* Shared buffer between VMPL1 and VMPL2. */
	call.rcx = (u64)buf;
	call.rdx = tgid;
	call.r8 = 0;

	current->is_monitored = true;
	monitored_cpu = smp_processor_id();
	errno = deko_refresh_launch_app_context(&call, &caa);
	if (unlikely(errno < 0))
		goto err_loop;

	/* Application main loop. */
	for (;;) {
		preempt_disable();

		unsigned int current_cpu = smp_processor_id();

		if (unlikely(current_cpu != monitored_cpu)) {
			preempt_enable();

			trace_deko_monitor_migration_detected(
				current->pid, monitored_cpu, current_cpu);
			/* Read the version number of the migrated CPU. */
			errno = deko_notify_monitor_migration(
				monitored_cpu, &current_cpu,
				&migration_version);

			if (unlikely(errno < 0)) {
				goto err_loop;
			}

			trace_deko_monitor_migration_notified(
				current->pid, migration_version);
			monitored_cpu = current_cpu;
			errno = deko_refresh_launch_app_context(&call, &caa);
			if (unlikely(errno < 0))
				goto err_loop;
			call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);

			continue;
		}
		errno = deko_prepare_launch_app_call(&call, caa, regs,
						     migration_version);
		if (unlikely(errno < 0)) {
			preempt_enable();

			goto err_loop;
		}
		res = svsm_perform_call_protocol(&call);
		preempt_enable();
		if (res != ES_OK) {
			pr_err("Failed to perform call launch protocol for task %d, err: %d\n",
			       current->pid, res);
			errno = -EINVAL;
			goto err_loop;
		}

		migration_version = 0;
		switch (call.rax_out) {
		case DEKO_SERVICE_APP_ENTER_OK:
			/* Handle system calls; if any. */
			handled_syscall_nr = buf->syscall_body.ax;
			if ((errno = deko_app_handle_system_calls(
				     &buf->syscall_body)) != 0) {
				pr_err("Error handling system calls: %d\n",
				       errno);
				goto err_loop;
			}

			break;

		case DEKO_TIMER_SERVICE:
			trace_deko_timer_service(current->pid);

			/* Timer is hot-path: avoid log storm and always offer a
			 * voluntary reschedule point to keep RCU/softirq forward progress. */
			cond_resched();

			break;
		default:
			pr_warn("Received unknown call return value: 0x%llx\n",
				call.rax_out);
			errno = -EINVAL;
			goto err_loop;
		}

		if (is_exit_syscall(handled_syscall_nr)) {
			normal_exit = true;
			goto err_loop;
		}

		/* Call again the protocol until the application requests exit. */
		call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	}

err_loop:
	if (buf)
		kfree(buf->buf);

err_inner_buf:
err_alias:
	kfree(buf);

	unpin_user_pages(pages, pinned_count);
	kvfree(pages);

err_alias_vma:
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
	if (!normal_exit)
		do_exit(errno);
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
