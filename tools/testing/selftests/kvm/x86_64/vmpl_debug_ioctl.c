// SPDX-License-Identifier: GPL-2.0-only
/*
 * Simple userspace helper for the KVM VMPL debug doorbell protocol.
 *
 * Usage:
 *   vmpl_debug_ioctl --vcpu-fd 17 --vmpl 1 --cookie 0x1234
 *   vmpl_debug_ioctl --qemu-pid 1234 --qemu-vcpu-fd 17 --vmpl 1 --payload 0x1,0x2,0x3
 */
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef KVM_CAP_X86_VMPL_DEBUG
#define KVM_CAP_X86_VMPL_DEBUG 239
#endif

#ifndef KVM_X86_INJECT_VMPL_DEBUG
struct kvm_vmpl_debug {
	__u32 vmpl;
	__u32 flags;
	__u32 dr_mask;
	__u32 pad;
	__u64 reserved[9];
};

#define KVM_X86_INJECT_VMPL_DEBUG _IOW(KVMIO, 0xd6, struct kvm_vmpl_debug)
#define KVM_X86_RECV_VMPL_DEBUG   _IOWR(KVMIO, 0xd7, struct kvm_vmpl_debug)
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s (--vcpu-fd <fd> | --qemu-pid <pid> --qemu-vcpu-fd <fd>) --vmpl <n> [options]\n"
		"\n"
		"Options:\n"
		"  --vcpu-fd <fd>        Use an already-local vcpu fd\n"
		"  --qemu-pid <pid>      QEMU pid for pidfd_getfd mode\n"
		"  --qemu-vcpu-fd <fd>   vcpu fd number in the QEMU process\n"
		"  --cookie <u64>        Set reserved[0] before inject\n"
		"  --payload <list>      Comma-separated u64 list for reserved[]\n"
		"  --poll-us <usec>      Sleep between recv retries (default: 10000)\n"
		"  --max-tries <n>       Stop after n recv attempts (default: infinite)\n"
		"  --help                Show this message\n",
		prog);
}

static int parse_u64(const char *arg, __u64 *out)
{
	char *end;
	unsigned long long val;

	errno = 0;
	val = strtoull(arg, &end, 0);
	if (errno || *end != '\0')
		return -1;

	*out = val;
	return 0;
}

static int pidfd_open_wrap(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_getfd_wrap(int pidfd, int targetfd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

static int import_vcpu_fd_from_qemu(pid_t qemu_pid, int qemu_vcpu_fd)
{
	int pidfd, local_vcpu_fd;

	pidfd = pidfd_open_wrap(qemu_pid, 0);
	if (pidfd < 0) {
		perror("pidfd_open");
		return -1;
	}

	local_vcpu_fd = pidfd_getfd_wrap(pidfd, qemu_vcpu_fd, 0);
	if (local_vcpu_fd < 0)
		perror("pidfd_getfd");

	close(pidfd);
	return local_vcpu_fd;
}

static int parse_u32(const char *arg, uint32_t *out)
{
	__u64 val;

	if (parse_u64(arg, &val))
		return -1;
	if (val > UINT32_MAX)
		return -1;

	*out = val;
	return 0;
}

static int parse_payload(char *arg, struct kvm_vmpl_debug *dbg)
{
	char *tok;
	unsigned int i = 0;

	for (tok = strtok(arg, ","); tok; tok = strtok(NULL, ",")) {
		if (i >= ARRAY_SIZE(dbg->reserved)) {
			fprintf(stderr, "too many payload entries, max=%zu\n",
				ARRAY_SIZE(dbg->reserved));
			return -1;
		}

		if (parse_u64(tok, &dbg->reserved[i])) {
			fprintf(stderr, "invalid payload entry: %s\n", tok);
			return -1;
		}
		i++;
	}

	return 0;
}

static void dump_debug_response(const struct kvm_vmpl_debug *dbg)
{
	size_t i;

	printf("response: vmpl=%u flags=%u dr_mask=%u\n",
	       dbg->vmpl, dbg->flags, dbg->dr_mask);
	for (i = 0; i < ARRAY_SIZE(dbg->reserved); i++)
		printf("reserved[%zu]=0x%016llx\n", i,
		       (unsigned long long)dbg->reserved[i]);
}

int main(int argc, char *argv[])
{
	static const struct option long_opts[] = {
		{ "vcpu-fd", required_argument, NULL, 'f' },
		{ "qemu-pid", required_argument, NULL, 'q' },
		{ "qemu-vcpu-fd", required_argument, NULL, 'F' },
		{ "vmpl", required_argument, NULL, 'v' },
		{ "cookie", required_argument, NULL, 'c' },
		{ "payload", required_argument, NULL, 'p' },
		{ "poll-us", required_argument, NULL, 'u' },
		{ "max-tries", required_argument, NULL, 'm' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	struct kvm_vmpl_debug dbg = {};
	unsigned int tries = 0;
	unsigned int max_tries = 0;
	unsigned int poll_us = 10000;
	uint32_t vcpu_fd = UINT32_MAX;
	uint32_t qemu_vcpu_fd = UINT32_MAX;
	uint32_t qemu_pid_u32 = UINT32_MAX;
	pid_t qemu_pid = -1;
	int local_vcpu_fd = -1;
	bool have_vmpl = false;
	bool have_payload = false;
	bool have_qemu_pid = false;
	bool have_qemu_vcpu_fd = false;
	int opt;

	while ((opt = getopt_long(argc, argv, "f:q:F:v:c:p:u:m:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			if (parse_u32(optarg, &vcpu_fd)) {
				fprintf(stderr, "invalid --vcpu-fd: %s\n", optarg);
				return 1;
			}
			break;
		case 'q':
			if (parse_u32(optarg, &qemu_pid_u32)) {
				fprintf(stderr, "invalid --qemu-pid: %s\n", optarg);
				return 1;
			}
			have_qemu_pid = true;
			break;
		case 'F':
			if (parse_u32(optarg, &qemu_vcpu_fd)) {
				fprintf(stderr, "invalid --qemu-vcpu-fd: %s\n", optarg);
				return 1;
			}
			have_qemu_vcpu_fd = true;
			break;
		case 'v':
			if (parse_u32(optarg, &dbg.vmpl)) {
				fprintf(stderr, "invalid --vmpl: %s\n", optarg);
				return 1;
			}
			have_vmpl = true;
			break;
		case 'c':
			if (parse_u64(optarg, &dbg.reserved[0])) {
				fprintf(stderr, "invalid --cookie: %s\n", optarg);
				return 1;
			}
			break;
		case 'p':
			if (parse_payload(optarg, &dbg)) {
				return 1;
			}
			have_payload = true;
			break;
		case 'u':
			if (parse_u32(optarg, &poll_us)) {
				fprintf(stderr, "invalid --poll-us: %s\n", optarg);
				return 1;
			}
			break;
		case 'm':
			if (parse_u32(optarg, &max_tries)) {
				fprintf(stderr, "invalid --max-tries: %s\n", optarg);
				return 1;
			}
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!have_vmpl) {
		usage(argv[0]);
		return 1;
	}

	if (vcpu_fd != UINT32_MAX && (have_qemu_pid || have_qemu_vcpu_fd)) {
		fprintf(stderr, "use either --vcpu-fd or --qemu-pid/--qemu-vcpu-fd, not both\n");
		return 1;
	}

	if (vcpu_fd == UINT32_MAX) {
		if (!have_qemu_pid || !have_qemu_vcpu_fd) {
			usage(argv[0]);
			return 1;
		}

		qemu_pid = (pid_t)qemu_pid_u32;
		local_vcpu_fd = import_vcpu_fd_from_qemu(qemu_pid, qemu_vcpu_fd);
		if (local_vcpu_fd < 0)
			return 1;

		vcpu_fd = local_vcpu_fd;
		printf("imported vcpu fd from qemu: pid=%u qemu_vcpu_fd=%u local_vcpu_fd=%u\n",
		       qemu_pid_u32, qemu_vcpu_fd, vcpu_fd);
	}

	dbg.flags = 0;
	dbg.dr_mask = 0;

	if (!have_payload)
		printf("inject: vmpl=%u cookie=0x%016llx\n",
		       dbg.vmpl, (unsigned long long)dbg.reserved[0]);

	if (ioctl(vcpu_fd, KVM_X86_INJECT_VMPL_DEBUG, &dbg) < 0) {
		perror("KVM_X86_INJECT_VMPL_DEBUG");
		return 1;
	}

	printf("inject queued, polling for response...\n");

	for (;;) {
		struct kvm_vmpl_debug resp = {
			.vmpl = dbg.vmpl,
		};

		if (ioctl(vcpu_fd, KVM_X86_RECV_VMPL_DEBUG, &resp) == 0) {
			dump_debug_response(&resp);
			if (local_vcpu_fd >= 0)
				close(local_vcpu_fd);
			return 0;
		}

		if (errno != EAGAIN) {
			perror("KVM_X86_RECV_VMPL_DEBUG");
			if (local_vcpu_fd >= 0)
				close(local_vcpu_fd);
			return 1;
		}

		tries++;
		if (max_tries && tries >= max_tries) {
			fprintf(stderr, "timed out waiting for response after %u tries\n",
				tries);
			if (local_vcpu_fd >= 0)
				close(local_vcpu_fd);
			return 1;
		}

		usleep(poll_us);
	}
}
