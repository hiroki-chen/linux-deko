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
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/kernel.h>
#include <linux/local_lock.h>
#include <linux/mutex.h>
#include <linux/irqflags.h>
#include <linux/sizes.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/sched.h>
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
static DEFINE_PER_CPU(local_lock_t,
		      deko_svsm_caa_lock) = INIT_LOCAL_LOCK(deko_svsm_caa_lock);

struct deko_launch_app_call_args {
	const struct pt_regs *regs;
	u64 migration_version;
};

struct deko_migration_call_args {
	unsigned int old_cpu;
	unsigned int current_cpu;
	const struct deko_handoff_checkpoint *checkpoint;
};

static int deko_prepare_monitor_migration_call(struct svsm_call *call,
					       struct svsm_ca *caa, void *arg);

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
	req->pid = current->tgid;
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

static void deko_log_vma_attrs_for_range(struct mm_struct *mm,
					 unsigned long start_addr,
					 unsigned long end_addr,
					 unsigned long prot, const char *reason)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, start_addr);

	if (!mm)
		return;

	for_each_vma_range(vmi, vma, end_addr) {
		unsigned long overlap_start;
		unsigned long overlap_end;

		overlap_start = max(start_addr, vma->vm_start);
		overlap_end = min(end_addr, vma->vm_end);
		if (overlap_start >= overlap_end)
			continue;

		if (vma->vm_file) {
			pr_warn("Populate failure attrs for %s: req=[0x%lx-0x%lx) prot=0x%lx overlap=[0x%lx-0x%lx) vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=%pD\n",
				reason, start_addr, end_addr, prot,
				overlap_start, overlap_end, vma->vm_start,
				vma->vm_end, vma->vm_flags, vma->vm_pgoff,
				vma->vm_file);
		} else {
			pr_warn("Populate failure attrs for %s: req=[0x%lx-0x%lx) prot=0x%lx overlap=[0x%lx-0x%lx) vma=[0x%lx-0x%lx) flags=0x%lx pgoff=0x%lx file=<anon>\n",
				reason, start_addr, end_addr, prot,
				overlap_start, overlap_end, vma->vm_start,
				vma->vm_end, vma->vm_flags, vma->vm_pgoff);
		}
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
			pr_info("Clamping populate range for %s: req=[0x%lx-0x%lx) prot=0x%lx file=%pD size=0x%llx pgoff=0x%lx clamped=[0x%lx-0x%lx)\n",
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

	deko_clamp_file_tail_populate_range(mm, start_addr, &end_addr, prot,
					    reason);
	if (start_addr >= end_addr)
		return 0;

	trace_deko_eager_paging(reason, start_addr, length, prot);

	ret = __mm_populate(start_addr, end_addr - start_addr, 0);
	if (ret < 0) {
		pr_warn("Failed to populate range for %s at 0x%lx len 0x%lx, err: %d\n",
			reason, start_addr, end_addr - start_addr, ret);
		mmap_read_lock(mm);
		deko_log_vma_attrs_for_range(mm, start_addr, end_addr, prot,
					     reason);
		mmap_read_unlock(mm);
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
	struct svsm_call call = { 0 };
	int ret;

	(void)mm;
	(void)ax;

	ret = deko_svsm_call_locked(&call, deko_prepare_exit_call, NULL);
	if (ret < 0) {
		pr_err("Failed to report app exit to SVSM for process %s (pid: %d), err: %d\n",
		       current->comm, current->pid, ret);
		return ret;
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

		if (vma->vm_flags & VM_WRITE)
			gup_flags |= FOLL_WRITE;

		remaining = nr_pages;
		cur = start;

		while (remaining) {
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
		pr_warn("Failed to notify monitor for task migration (app_id=%d, pid=%d, old_cpu=%u, new_cpu=%u, err=%d)\n",
			current->tgid, current->pid, old_cpu, args.current_cpu,
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
	req->pid = current->tgid;
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
	memcpy(&req->regs, launch->regs, sizeof(*launch->regs));
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

	WRITE_ONCE(checkpoint->pid, current->tgid);
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
			current->tgid);
		return -EINVAL;
	}
	if (checkpoint->pid != current->tgid) {
		pr_warn("handoff checkpoint pid mismatch: expected=%d actual=%u\n",
			current->tgid, checkpoint->pid);
		return -EINVAL;
	}
	if (checkpoint->owner_cpu != migration->committed_owner_cpu) {
		pr_warn("handoff checkpoint owner mismatch: expected=%u actual=%u pid=%d\n",
			migration->committed_owner_cpu, checkpoint->owner_cpu,
			current->tgid);
		return -EINVAL;
	}
	if (checkpoint->generation != migration->committed_generation) {
		pr_warn("handoff checkpoint generation mismatch: expected=%llu actual=%llu pid=%d\n",
			(unsigned long long)migration->committed_generation,
			(unsigned long long)checkpoint->generation,
			current->tgid);
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
			current->tgid);
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
			current->tgid);
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
			current->tgid, migration->committed_owner_cpu,
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
		current->tgid, migration->committed_owner_cpu, current_cpu,
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

static int deko_run_launch_iteration(struct svsm_call *call,
				     const struct pt_regs *regs,
				     struct deko_migration_state *migration,
				     bool *adopting, unsigned int *launch_cpu)
{
	struct deko_launch_app_call_args args = {
		.regs = regs,
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
					 bool *normal_exit)
{
	u64 handled_syscall_nr;
	unsigned long flags;
	int ret;

	*normal_exit = false;

	switch (call->rax_out) {
	case DEKO_SERVICE_APP_ENTER_OK:
		/* Handle system calls; if any. */
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
	pid_t tgid = current->tgid;
	struct deko_shared_buf *buf = NULL;
	int pinned_count;
	struct page **pages = NULL;
	unsigned long alias_addr = 0;
	bool normal_exit = false;
	bool adopting = false;
	bool iteration_cpu_pinned = false;
	unsigned int launch_cpu = 0;
	struct deko_migration_state migration = { 0 };
	struct deko_handoff_checkpoint checkpoint = { 0 };

	struct deko_task_work *dw =
		container_of(work, struct deko_task_work, work);

	pr_info("Deko proxy loop start pid=%d tgid=%d comm=%s task=%px current_cpu=%u monitored=%d\n",
		current->pid, current->tgid, current->comm, current,
		raw_smp_processor_id(), current->is_monitored);

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

	/* Application main loop. */
	for (;;) {
		iteration++;
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

		errno = deko_run_launch_iteration(&call, regs, &migration,
						  &adopting, &launch_cpu);
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

		errno = deko_handle_vmpl1_exit_reason(&call, buf, &normal_exit);

		if (unlikely(errno < 0) || normal_exit)
			goto err_loop;
	}

err_loop:
	if (iteration_cpu_pinned)
		migrate_enable();

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
