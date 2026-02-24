// SPDX-License-Identifier: GPL-2.0-only
/*
 * Deko extension for AMD SEV-SNP support
 *
 * Copyright (C) 2026 Hiroki Chen
 *
 * Author: Hiroki Chen <haobchen@iu.edu>
 */

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

extern const sys_call_ptr_t sys_call_table[];

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

void deko_proxy_loop(struct callback_head *work)
{
	int errno = 0;
	struct svsm_call call = { 0 };
	struct pt_regs *regs = task_pt_regs(current);
	pid_t tgid = current->tgid;
	struct deko_shared_buf *buf;

	buf = kzalloc(sizeof(struct deko_shared_buf), GFP_KERNEL);
	if (!buf) {
		pr_err("Deko: Failed to allocate shared buffer for task %d\n",
		       current->pid);
		errno = -ENOMEM;
		goto out;
	}

	pr_info("Allocated buf at %px for task %d\n", buf, current->pid);

	buf->buf = kzalloc(DEKO_DEFAULT_SHARED_BUF_SIZE, GFP_KERNEL);
	if (!buf->buf) {
		pr_err("Deko: Failed to allocate shared buffer for task %d\n",
		       current->pid);
		errno = -ENOMEM;
		goto out_no_buf;
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
				goto out;
			}

			break;
		default:
			pr_warn("Deko: Received unknown call return value: 0x%llx\n",
				call.rax_out);
			errno = -EINVAL;
			goto out;
		}

		/* Call again the protocol until the application requests exit. */
		call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	}

out_no_buf:
	kfree(buf);

out:
	kfree(dw);

	do_exit(errno);
}
