// SPDX-License-Identifier: GPL-2.0-only
/*
 * Deko extension for AMD SEV-SNP support
 *
 * Copyright (C) 2026 Hiroki Chen
 *
 * Author: Hiroki Chen <haobchen@iu.edu>
 */

#include "linux/mm.h"
#include "linux/mm_types.h"
#include "linux/mmap_lock.h"
#define CREATE_TRACE_POINTS

#include <trace/events/deko.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sched/task_stack.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <asm/sev.h>
#include <asm/syscall.h>

#define DEKO_SERVICE_APP_ENTER_OK 0x0

#define DEKO_DEFAULT_SHARED_BUF_SIZE SZ_2M
#define DEKO_RING_CAPACITY 32

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

struct deko_shared_buf {
	struct deko_syscall_body syscall_body;
	void *buf;
};

static int deko_app_handle_system_calls(struct deko_syscall_body *syscall_body)
{
	struct pt_regs tmp_regs = { 0 };
	sys_call_ptr_t syscall_fn;

	if (unlikely(syscall_body->ax >= NR_syscalls)) {
		pr_warn("Deko: Invalid syscall number %llu from VMPL1\n",
			syscall_body->ax);
		syscall_body->ax = -ENOSYS;
		return 0;
	}

	trace_deko_syscall_entry(syscall_body->ax, syscall_body->di,
				 syscall_body->si, syscall_body->dx);

	tmp_regs.di = syscall_body->di;
	tmp_regs.si = syscall_body->si;
	tmp_regs.dx = syscall_body->dx;
	tmp_regs.r10 = syscall_body->r10;
	tmp_regs.r8 = syscall_body->r8;
	tmp_regs.r9 = syscall_body->r9;
	tmp_regs.orig_ax = syscall_body->ax;

	syscall_fn = sys_call_table[syscall_body->ax];
	syscall_body->ax = syscall_fn(&tmp_regs);

	trace_deko_syscall_exit(tmp_regs.orig_ax, syscall_body->ax);

	return 0;
}

static int deko_pin_pages(struct mm_struct *mm, struct page ***pages)
{
	struct vm_area_struct *vma;
	unsigned long expected_pages = mm->total_vm;
	unsigned long total_pinned = 0;
	unsigned long start, end;
	unsigned long nr_pages;
	unsigned int gup_flags;
	int ret = 0;

	*pages = kvmalloc_array(expected_pages, sizeof(struct page *),
				GFP_KERNEL);
	if (!*pages) {
		pr_err("Deko: Failed to allocate page pointer array\n");
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
			ret = fixup_user_fault(mm, start, FAULT_FLAG_USER, NULL);
			if (ret < 0) {
				pr_warn("Deko: Failed to fault in special VMA at 0x%lx, err: %d\n",
					start, ret);
			}

			total_pinned += nr_pages;

			continue;
		}

		if (vma->vm_flags & VM_WRITE)
			gup_flags |= FOLL_WRITE;

		ret = pin_user_pages_remote(mm, start, nr_pages, gup_flags,
					    (*pages) + total_pinned, NULL);
		if (ret < 0) {
			pr_err("Deko: Failed to pin VMA [0x%lx-0x%lx], err: %d\n",
			       start, end, ret);
			goto out_err;
		}

		pr_info("Deko: Pinned %d pages for VMA [0x%lx-0x%lx]\n", ret,
			start, end);

		total_pinned += ret;
	}

	mmap_read_unlock(mm);

	pr_info("Deko: Successfully pinned %lu pages out of total_vm %lu\n",
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

void deko_proxy_loop(struct callback_head *work)
{
	int errno = 0;
	struct svsm_call call = { 0 };
	struct pt_regs *regs = task_pt_regs(current);
	pid_t tgid = current->tgid;
	struct deko_shared_buf *buf;
	int pinned_count;
	struct page **pages = NULL;

	/*
	 * At first we need to pin all the memories of the newly launched
	 * application to prevent page fault that cannot be handled inside
	 * VMPL1 and thus the application will crash immediately. This is
	 * because by default Linux lazily loads the application code.
	 */
	if ((pinned_count = deko_pin_pages(current->mm, &pages)) < 0) {
		errno = pinned_count;
		goto err_pin;
	}

	buf = kzalloc(sizeof(struct deko_shared_buf), GFP_KERNEL);
	if (!buf) {
		pr_err("Deko: Failed to allocate shared buffer for task %d\n",
		       current->pid);
		errno = -ENOMEM;
		goto err_buf;
	}

	pr_info("Allocated buf at %px for task %d\n", buf, current->pid);

	buf->buf = kzalloc(DEKO_DEFAULT_SHARED_BUF_SIZE, GFP_KERNEL);
	if (!buf->buf) {
		pr_err("Deko: Failed to allocate shared buffer for task %d\n",
		       current->pid);
		errno = -ENOMEM;
		goto err_inner_buf;
	}

	struct deko_task_work *dw =
		container_of(work, struct deko_task_work, work);

	pr_info("Deko: Entering proxy loop for task %d\n", current->pid);

	call.caa = svsm_get_caa();
	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	memcpy(svsm_get_caa()->svsm_buffer, regs, sizeof(struct pt_regs));
	call.r9 = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);
	/* Shared buffer between VMPL1 and VMPL2. */
	call.rcx = (u64)buf;
	call.rdx = tgid;

	/* Application main loop. */
	for (;;) {
		/*
     * Special handling of the return value: we discard the MSR's value.
     * This is because the protocol call involve multiple VMPL switches
     * that modify the MSR values and the final value might get corrupted.
     * 
     * However, since the rax_out will eventually gets modified by VMPL0,
     * we treat this as the ground truth for the return value.
     */
		svsm_perform_msr_protocol(&call);

		switch (call.rax_out) {
		case DEKO_SERVICE_APP_ENTER_OK:
			/* Handle system calls; if any. */
			if ((errno = deko_app_handle_system_calls(
				     &buf->syscall_body)) != 0) {
				pr_err("Deko: Error handling system calls: %d\n",
				       errno);
				goto err_loop;
			}

			break;
		default:
			pr_warn("Deko: Received unknown call return value: 0x%llx\n",
				call.rax_out);
			errno = -EINVAL;
			goto err_loop;
		}

		/* Call again the protocol until the application requests exit. */
		call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	}

err_loop:
	kfree(buf->buf);

err_inner_buf:
	kfree(buf);

err_buf:
	unpin_user_pages(pages, pinned_count);
	kvfree(pages);

err_pin:
	kfree(dw);

	do_exit(errno);
}
