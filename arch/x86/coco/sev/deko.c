// SPDX-License-Identifier: GPL-2.0-only
/*
 * Deko extension for AMD SEV-SNP support
 *
 * Copyright (C) 2026 Hiroki Chen
 *
 * Author: Hiroki Chen <haobchen@iu.edu>
 */

#include "asm/io.h"
#include "linux/kernel.h"
#include "linux/slab.h"
#include <linux/sched/task_stack.h>
#include <linux/types.h>
#include <asm/sev.h>

#define DEKO_SERVICE_APP_ENTER_OK 0x90000001
#define DEKO_SERVICE_APP_EXIT 0x90000002

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
};

static int deko_app_handle_system_calls(struct deko_syscall_body *syscall_body)
{
	int errno = 0;

	pr_info("Deko: Handling system call for task %d: ax=0x%llx, di=0x%llx, si=0x%llx, dx=0x%llx\n",
		current->pid, syscall_body->ax, syscall_body->di,
		syscall_body->si, syscall_body->dx);

	return errno;
}

void deko_proxy_loop(struct callback_head *work)
{
	int errno = 0;
	struct svsm_call call = { 0 };
	struct pt_regs *regs = task_pt_regs(current);
	struct deko_syscall_body syscall_body = { 0 };
	struct deko_task_work *dw =
		container_of(work, struct deko_task_work, work);

	pr_info("Deko: Entering proxy loop for task %d\n", current->pid);

	call.caa = svsm_get_caa();
	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	memcpy(svsm_get_caa()->svsm_buffer, regs, sizeof(struct pt_regs));
	call.r9 = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);
	call.rcx = get_anything_pa((void *)&syscall_body);

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
				     &syscall_body)) != 0) {
				pr_err("Deko: Error handling system calls: %d\n",
				       errno);
				goto out;
			}

			break;
		case DEKO_SERVICE_APP_EXIT:
			/* This application requests to exit, break the loop and exit the task. */
			goto out;
		default:
			pr_warn("Deko: Received unknown call return value: 0x%llx\n",
				call.rax_out);
			errno = -EINVAL;
			goto out;
		}

		/* Handle system calls, if any. */

		/* Call again the protocol until the application requests exit. */
		call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LAUNCH_APP);
	}

out:
	kfree(dw);

	do_exit(errno);
}
