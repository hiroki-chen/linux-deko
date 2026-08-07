/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#ifndef __ASM_ENCRYPTED_STATE_H
#define __ASM_ENCRYPTED_STATE_H

#include <linux/types.h>
#include <linux/sev-guest.h>

#include <asm/insn.h>
#include <asm/sev-common.h>
#include <asm/coco.h>
#include <asm/set_memory.h>
#include <asm/svm.h>

#define GHCB_PROTOCOL_MIN 1ULL
#define GHCB_PROTOCOL_MAX 2ULL
#define GHCB_DEFAULT_USAGE 0ULL

#define VMGEXIT()                                 \
	{                                         \
		asm volatile("rep; vmmcall\n\r"); \
	}

struct boot_params;

enum es_result {
	ES_OK, /* All good */
	ES_UNSUPPORTED, /* Requested operation not supported */
	ES_VMM_ERROR, /* Unexpected state from the VMM */
	ES_DECODE_FAILED, /* Instruction decoding failed */
	ES_EXCEPTION, /* Instruction caused exception */
	ES_RETRY, /* Retry instruction emulation */
};

enum deko_new_app_type {
	DEKO_DOCKER_INFRA = 0,
	DEKO_DOCKER_APPS = 1,
};

#define DEKO_NEW_APP_REQ_VERSION_V3 3
#define DEKO_NEW_APP_REQ_VERSION_V4 4
#define DEKO_PROTOCOL_NEGOTIATE_REQ_VERSION_V1 1
#define DEKO_PAGE_FAULT_REQ_VERSION_V1 1
#define DEKO_PAGE_FAULT_RESP_VERSION_V1 1
#define DEKO_ASPACE_OP_REQ_VERSION_V1 1
#define DEKO_EXEC_RANGE_READY_REQ_VERSION_V1 1
#define DEKO_EXEC_RANGE_UNLIFT_REQ_VERSION_V1 1
#define DEKO_MAX_BASE_REGIONS 96
#define DEKO_REPORT_APP_LIFECYCLE 0
#define DEKO_REPORT_APP_EXEC_CREATE 1
#define DEKO_REPORT_APP_FORK_CREATE 2

#define DEKO_EXEC_SPAN_SHIFT 39
#define DEKO_EXEC_SPAN_SIZE BIT(39)
#define DEKO_EXEC_SPAN_ASLR_SIZE BIT(30)
#define DEKO_MAP_ELF_IMAGE BIT(63)

enum deko_launch_type {
	DEKO_LAUNCH_TYPE_LEGACY = 0,
	DEKO_LAUNCH_TYPE_EXEC = 1,
	DEKO_LAUNCH_TYPE_PROCESS_FORK = 2,
	DEKO_LAUNCH_TYPE_THREAD = 3,
};

enum deko_base_region_kind {
	DEKO_BASE_REGION_CODE = 1,
	DEKO_BASE_REGION_RODATA = 2,
	DEKO_BASE_REGION_DATA = 3,
	DEKO_BASE_REGION_BSS = 4,
	DEKO_BASE_REGION_HEAP = 5,
	DEKO_BASE_REGION_STACK = 6,
};

enum deko_region_perm {
	DEKO_REGION_R = 1u << 0,
	DEKO_REGION_W = 1u << 1,
	DEKO_REGION_X = 1u << 2,
};

enum deko_region_flags {
	DEKO_REGION_F_ZERO_INIT = 1u << 0,
	DEKO_REGION_F_GROWSDOWN = 1u << 1,
	DEKO_REGION_F_TEMPLATE_RW = 1u << 2,
	DEKO_REGION_F_LAZY = 1u << 3,
	DEKO_REGION_F_COW_ELIGIBLE = 1u << 4,
	DEKO_REGION_F_MEASURE_ON_FAULT = 1u << 5,
	DEKO_REGION_F_DATA_PINNED = 1u << 6,
};

enum deko_feature_flags {
	DEKO_FEATURE_PAGE_FAULT_EXIT = 1ULL << 0,
	DEKO_FEATURE_MONITOR_COW = 1ULL << 1,
	DEKO_FEATURE_NO_EAGER_FAULT = 1ULL << 2,
	DEKO_FEATURE_SHADOW_USER_CR3 = 1ULL << 3,
	DEKO_FEATURE_ASPACE_VERSIONING = 1ULL << 4,
	DEKO_FEATURE_FAST_ROLLBACK = 1ULL << 5,
	DEKO_FEATURE_REWIND = 1ULL << 6,
};

enum deko_exec_range_flags {
	DEKO_EXEC_RANGE_F_PRIVATE_CANDIDATE = 1u << 0,
};

#define DEKO_EXEC_RANGE_UNLIFT_MAX_PAGES	32

enum deko_page_fault_access {
	DEKO_PF_ACCESS_PRESENT = 1u << 0,
	DEKO_PF_ACCESS_WRITE = 1u << 1,
	DEKO_PF_ACCESS_USER = 1u << 2,
	DEKO_PF_ACCESS_RSVD = 1u << 3,
	DEKO_PF_ACCESS_INSTR = 1u << 4,
};

enum deko_page_fault_reason {
	DEKO_PF_REASON_UNKNOWN = 0,
	DEKO_PF_REASON_DEMAND = 1,
	DEKO_PF_REASON_COW = 2,
	DEKO_PF_REASON_PERMISSION = 3,
	DEKO_PF_REASON_MEASURE = 4,
};

enum deko_page_fault_resolution {
	DEKO_PF_RESOLUTION_NONE = 0,
	DEKO_PF_RESOLUTION_ANON_PRIVATE = 1,
	DEKO_PF_RESOLUTION_ZERO_PAGE = 2,
	DEKO_PF_RESOLUTION_FILE_BACKED = 3,
	DEKO_PF_RESOLUTION_DENY = 4,
};

enum deko_page_fault_resolve_flags {
	DEKO_PF_RESOLVE_F_FRESH_PAGE = 1u << 0,
	DEKO_PF_RESOLVE_F_ZEROED = 1u << 1,
	DEKO_PF_RESOLVE_F_PRIVATE_CANDIDATE = 1u << 2,
	DEKO_PF_RESOLVE_F_FILE_BACKED = 1u << 3,
	DEKO_PF_RESOLVE_F_DATA_PINNED = 1u << 4,
};

enum deko_aspace_op {
	DEKO_ASPACE_OP_CREATE_CHECKPOINT = 1,
	DEKO_ASPACE_OP_ROLLBACK = 2,
	DEKO_ASPACE_OP_REWIND = 3,
	DEKO_ASPACE_OP_DROP_VERSION = 4,
	DEKO_ASPACE_OP_FORK_VERSION = 5,
};

struct deko_base_region_desc {
	u16 kind;
	u16 perm;
	u32 flags;
	u64 mapped_start;
	u64 mapped_end;
	u64 exact_start;
	u64 exact_end;
} __attribute__((aligned(8)));

struct deko_new_app_req {
	u16 version;
	u16 region_count;
	u32 req_size;

	u32 pid;
	u32 tgid;
	u32 ppid;
	u32 uid;

	u64 mnt_ns_id;
	u64 start_brk;
	u64 brk;
	char comm[16];
	char launch_identity[64];
	u64 kernel_vmpl1_rsp;
	u64 fs_base;
	u64 gs_base;
	u64 kernel_gs_base;
	enum deko_new_app_type app_type;
	u32 domain_id;
	struct deko_base_region_desc regions[DEKO_MAX_BASE_REGIONS];
	__u64 exec_span_base;
	__u64 exec_span_size;
	__u32 exec_span_pml4_index;
	__u32 reserved;
} __attribute__((aligned(8)));

#define DEKO_NEW_APP_REQ_SIZE_V3 \
	((u32)offsetof(struct deko_new_app_req, exec_span_base))

static inline bool deko_range_within_exec_span(unsigned long span_base,
					       unsigned long addr,
					       unsigned long len)
{
	return len && len <= DEKO_EXEC_SPAN_SIZE &&
	       addr >= span_base &&
	       addr - span_base <= DEKO_EXEC_SPAN_SIZE - len;
}

static inline bool deko_range_overlaps_exec_span(unsigned long span_base,
						 unsigned long addr,
						 unsigned long len)
{
	if (!len || addr >= span_base + DEKO_EXEC_SPAN_SIZE)
		return false;
	if (addr >= span_base)
		return true;

	return len > span_base - addr;
}

struct deko_launch_app_req {
	struct pt_regs regs;
	u32 launch_type;
	u32 _reserved;
	u64 fs_base;
	u64 user_gs_base;
	u64 kernel_gs_base;
} __attribute__((aligned(8)));

struct deko_protocol_negotiate_req {
	u16 version;
	u16 flags;
	u32 req_size;
	u16 linux_abi_major;
	u16 linux_abi_minor;
	u16 monitor_abi_major;
	u16 monitor_abi_minor;
	u64 required_features;
	u64 requested_features;
	u64 linux_features;
	u64 monitor_features;
	u64 negotiated_features;
} __attribute__((aligned(8)));

struct deko_page_fault_req {
	u16 version;
	u16 flags;
	u32 req_size;
	u64 seq;
	u32 pid;
	u32 tgid;
	u32 access;
	u32 reason;
	u64 fault_va;
	u64 page_va;
	u64 error_code;
	u64 rip;
	u64 rsp;
	u64 address_space_id;
	u64 version_id;
} __attribute__((aligned(8)));

struct deko_page_fault_resp {
	u16 version;
	u16 flags;
	u32 resp_size;
	u64 seq;
	s64 status;
	u32 resolution;
	u32 page_flags;
	u64 page_va;
	u64 page_gpa;
	u64 page_len;
	u64 backing_id;
	u64 backing_offset;
} __attribute__((aligned(8)));

struct deko_page_fault_frame {
	struct deko_page_fault_req req;
	struct deko_page_fault_resp resp;
} __attribute__((aligned(8)));

struct deko_address_space_op_req {
	u16 version;
	u16 op;
	u32 req_size;
	u64 flags;
	u32 pid;
	u32 tgid;
	u64 address_space_id;
	u64 base_version_id;
	u64 target_version_id;
	u64 out_version_id;
	u64 checkpoint_id;
	u64 vmsa_gpa;
} __attribute__((aligned(8)));

struct deko_exec_range_ready_req {
	u16 version;
	u16 flags;
	u32 req_size;
	u32 pid;
	u32 tgid;
	u64 start_va;
	u64 end_va;
	u64 lifted_pages;
} __attribute__((aligned(8)));

struct deko_exec_range_unlift_req {
	u16 version;
	u16 flags;
	u32 req_size;
	u32 pid;
	u32 tgid;
	u64 start_va;
	u64 end_va;
	u64 page_count;
	u64 restored_pages;
	u64 page_gpas[DEKO_EXEC_RANGE_UNLIFT_MAX_PAGES];
} __attribute__((aligned(8)));

struct deko_load_policy_req {
	u32 domain_id;
	u32 reserved;
	u64 blob_gpa;
	u64 blob_len;
} __attribute__((aligned(8)));

struct es_fault_info {
	unsigned long vector;
	unsigned long error_code;
	unsigned long cr2;
};

struct pt_regs;

/* ES instruction emulation context */
struct es_em_ctxt {
	struct pt_regs *regs;
	struct insn insn;
	struct es_fault_info fi;
};

/*
 * AMD SEV Confidential computing blob structure. The structure is
 * defined in OVMF UEFI firmware header:
 * https://github.com/tianocore/edk2/blob/master/OvmfPkg/Include/Guid/ConfidentialComputingSevSnpBlob.h
 */
#define CC_BLOB_SEV_HDR_MAGIC 0x45444d41
struct cc_blob_sev_info {
	u32 magic;
	u16 version;
	u16 reserved;
	u64 secrets_phys;
	u32 secrets_len;
	u32 rsvd1;
	u64 cpuid_phys;
	u32 cpuid_len;
	u32 rsvd2;
} __packed;

void do_vc_no_ghcb(struct pt_regs *regs, unsigned long exit_code);

static inline u64 lower_bits(u64 val, unsigned int bits)
{
	u64 mask = (1ULL << bits) - 1;

	return (val & mask);
}

struct real_mode_header;
enum stack_type;
struct file;

extern enum es_result svsm_deko_new_app_req(struct task_struct *tas, u64 ns_id,
					    const char *launch_identity,
					    u64 report_kind,
					    unsigned long *token_low,
					    unsigned long *token_high,
					    enum deko_new_app_type ty);
extern int deko_prefault_private_exec_vmas(struct mm_struct *mm,
					   const char *reason);
extern int deko_unlift_exec_user_range(struct mm_struct *mm,
				       unsigned long start_addr,
				       unsigned long length,
				       const char *reason);
extern int deko_unlift_all_exec_user_ranges(struct mm_struct *mm,
					    const char *reason);
bool deko_exec_span_area(unsigned long addr, unsigned long len,
			 unsigned long flags, unsigned long vm_flags,
			 unsigned long align_mask,
			 unsigned long align_offset,
			 unsigned long start_gap,
			 unsigned long *result);
int deko_select_exec_span(struct mm_struct *mm);
int deko_prepare_exec_root(struct mm_struct *mm);
bool deko_exec_span_elf_image(struct file *file, unsigned long pgoff,
			      unsigned long len);
extern int deko_pin_present_private_data_vmas(struct mm_struct *mm,
					       const char *reason);
extern unsigned long deko_unpin_all_data_user_ranges(struct mm_struct *mm,
						      const char *reason);
extern int deko_prepare_clone_child_before_wake(struct task_struct *child);
extern void deko_task_exit(void);
extern enum es_result svsm_handle_trampoline_setup(u64 sysenter_addr);

extern int svsm_prepare_vmpl1_current_mm(struct mm_struct *mm);
extern int svsm_deko_load_policy(u32 domain_id, const void *buf, u64 len);
extern int deko_domain_bind(u64 mnt_ns_id, u32 domain_id);
extern int deko_domain_lookup(u64 mnt_ns_id, u32 *domain_id);
extern int deko_domain_unbind(u64 mnt_ns_id, u32 domain_id);

/* Early IDT entry points for #VC handler */
extern void vc_no_ghcb(void);
extern void vc_boot_ghcb(void);
extern bool handle_vc_boot_ghcb(struct pt_regs *regs);

/*
 * Individual entries of the SNP CPUID table, as defined by the SNP
 * Firmware ABI, Revision 0.9, Section 7.1, Table 14.
 */
struct snp_cpuid_fn {
	u32 eax_in;
	u32 ecx_in;
	u64 xcr0_in;
	u64 xss_in;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
	u64 __reserved;
} __packed;

/*
 * SNP CPUID table, as defined by the SNP Firmware ABI, Revision 0.9,
 * Section 8.14.2.6. Also noted there is the SNP firmware-enforced limit
 * of 64 entries per CPUID table.
 */
#define SNP_CPUID_COUNT_MAX 64

struct snp_cpuid_table {
	u32 count;
	u32 __reserved1;
	u64 __reserved2;
	struct snp_cpuid_fn fn[SNP_CPUID_COUNT_MAX];
} __packed;

/* PVALIDATE return codes */
#define PVALIDATE_FAIL_SIZEMISMATCH 6

/* Software defined (when rFlags.CF = 1) */
#define PVALIDATE_FAIL_NOUPDATE 255

/* RMUPDATE detected 4K page and 2MB page overlap. */
#define RMPUPDATE_FAIL_OVERLAP 4

/* PSMASH failed due to concurrent access by another CPU */
#define PSMASH_FAIL_INUSE 3

/* RMP page size */
#define RMP_PG_SIZE_4K 0
#define RMP_PG_SIZE_2M 1
#define RMP_TO_PG_LEVEL(level) \
	(((level) == RMP_PG_SIZE_4K) ? PG_LEVEL_4K : PG_LEVEL_2M)
#define PG_LEVEL_TO_RMP(level) \
	(((level) == PG_LEVEL_4K) ? RMP_PG_SIZE_4K : RMP_PG_SIZE_2M)

struct rmp_state {
	u64 gpa;
	u8 assigned;
	u8 pagesize;
	u8 immutable;
	u8 rsvd;
	u32 asid;
} __packed;

#define RMPADJUST_VMSA_PAGE_BIT BIT(16)

DECLARE_PER_CPU(u64, deko_kernel_vmpl1_rsp);
DECLARE_PER_CPU(unsigned long, deko_user_rsp);

/* SNP Guest message request */
struct snp_req_data {
	unsigned long req_gpa;
	unsigned long resp_gpa;
	unsigned long data_gpa;
	unsigned int data_npages;
};

int deko_bootstrap(void);

#define MAX_AUTHTAG_LEN 32
#define AUTHTAG_LEN 16
#define AAD_LEN 48
#define MSG_HDR_VER 1

#define SNP_REQ_MAX_RETRY_DURATION (60 * HZ)
#define SNP_REQ_RETRY_DELAY (2 * HZ)

/* See SNP spec SNP_GUEST_REQUEST section for the structure */
enum msg_type {
	SNP_MSG_TYPE_INVALID = 0,
	SNP_MSG_CPUID_REQ,
	SNP_MSG_CPUID_RSP,
	SNP_MSG_KEY_REQ,
	SNP_MSG_KEY_RSP,
	SNP_MSG_REPORT_REQ,
	SNP_MSG_REPORT_RSP,
	SNP_MSG_EXPORT_REQ,
	SNP_MSG_EXPORT_RSP,
	SNP_MSG_IMPORT_REQ,
	SNP_MSG_IMPORT_RSP,
	SNP_MSG_ABSORB_REQ,
	SNP_MSG_ABSORB_RSP,
	SNP_MSG_VMRK_REQ,
	SNP_MSG_VMRK_RSP,

	SNP_MSG_TSC_INFO_REQ = 17,
	SNP_MSG_TSC_INFO_RSP,

	SNP_MSG_TYPE_MAX
};

enum aead_algo {
	SNP_AEAD_INVALID,
	SNP_AEAD_AES_256_GCM,
};

struct snp_guest_msg_hdr {
	u8 authtag[MAX_AUTHTAG_LEN];
	u64 msg_seqno;
	u8 rsvd1[8];
	u8 algo;
	u8 hdr_version;
	u16 hdr_sz;
	u8 msg_type;
	u8 msg_version;
	u16 msg_sz;
	u32 rsvd2;
	u8 msg_vmpck;
	u8 rsvd3[35];
} __packed;

struct snp_guest_msg {
	struct snp_guest_msg_hdr hdr;
	u8 payload[PAGE_SIZE - sizeof(struct snp_guest_msg_hdr)];
} __packed;

#define SNP_TSC_INFO_REQ_SZ 128

struct snp_tsc_info_req {
	u8 rsvd[SNP_TSC_INFO_REQ_SZ];
} __packed;

struct snp_tsc_info_resp {
	u32 status;
	u32 rsvd1;
	u64 tsc_scale;
	u64 tsc_offset;
	u32 tsc_factor;
	u8 rsvd2[100];
} __packed;

/*
 * Obtain the mean TSC frequency by decreasing the nominal TSC frequency with
 * TSC_FACTOR as documented in the SNP Firmware ABI specification:
 *
 * GUEST_TSC_FREQ * (1 - (TSC_FACTOR * 0.00001))
 *
 * which is equivalent to:
 *
 * GUEST_TSC_FREQ -= (GUEST_TSC_FREQ * TSC_FACTOR) / 100000;
 */
#define SNP_SCALE_TSC_FREQ(freq, factor) ((freq) - (freq) * (factor) / 100000)

struct snp_guest_req {
	void *req_buf;
	size_t req_sz;

	void *resp_buf;
	size_t resp_sz;

	u64 exit_code;
	u64 exitinfo2;
	unsigned int vmpck_id;
	u8 msg_version;
	u8 msg_type;

	struct snp_req_data input;
	void *certs_data;
};

/*
 * The secrets page contains 96-bytes of reserved field that can be used by
 * the guest OS. The guest OS uses the area to save the message sequence
 * number for each VMPCK.
 *
 * See the GHCB spec section Secret page layout for the format for this area.
 */
struct secrets_os_area {
	u32 msg_seqno_0;
	u32 msg_seqno_1;
	u32 msg_seqno_2;
	u32 msg_seqno_3;
	u64 ap_jump_table_pa;
	u8 rsvd[40];
	u8 guest_usage[32];
} __packed;

#define VMPCK_KEY_LEN 32

/* See the SNP spec version 0.9 for secrets page format */
struct snp_secrets_page {
	u32 version;
	u32 imien : 1, rsvd1 : 31;
	u32 fms;
	u32 rsvd2;
	u8 gosvw[16];
	u8 vmpck0[VMPCK_KEY_LEN];
	u8 vmpck1[VMPCK_KEY_LEN];
	u8 vmpck2[VMPCK_KEY_LEN];
	u8 vmpck3[VMPCK_KEY_LEN];
	struct secrets_os_area os_area;

	u8 vmsa_tweak_bitmap[64];

	/* SVSM fields */
	u64 svsm_base;
	u64 svsm_size;
	u64 svsm_caa;
	u32 svsm_max_version;
	u8 svsm_guest_vmpl;
	u8 rsvd3[3];

	/* The percentage decrease from nominal to mean TSC frequency. */
	u32 tsc_factor;

	/* Remainder of page */
	u8 rsvd4[3740];
} __packed;

struct snp_msg_desc {
	/* request and response are in unencrypted memory */
	struct snp_guest_msg *request, *response;

	/*
	 * Avoid information leakage by double-buffering shared messages
	 * in fields that are in regular encrypted memory.
	 */
	struct snp_guest_msg secret_request, secret_response;

	struct snp_secrets_page *secrets;

	struct aesgcm_ctx *ctx;

	u32 *os_area_msg_seqno;
	u8 *vmpck;
	int vmpck_id;
};

/*
 * The SVSM Calling Area (CA) related structures.
 */
struct svsm_ca {
	u8 call_pending;
	u8 mem_available;
	u8 rsvd1[6];

	u8 svsm_buffer[PAGE_SIZE - 8];
};

#define SVSM_SUCCESS 0
#define SVSM_ERR_INCOMPLETE 0x80000000
#define SVSM_ERR_UNSUPPORTED_PROTOCOL 0x80000001
#define SVSM_ERR_UNSUPPORTED_CALL 0x80000002
#define SVSM_ERR_INVALID_ADDRESS 0x80000003
#define SVSM_ERR_INVALID_FORMAT 0x80000004
#define SVSM_ERR_INVALID_PARAMETER 0x80000005
#define SVSM_ERR_INVALID_REQUEST 0x80000006
#define SVSM_ERR_BUSY 0x80000007
#define SVSM_ERR_PERMISSION_DENIED 0x80000008
#define SVSM_PVALIDATE_FAIL_SIZEMISMATCH 0x80001006

#define DEKO_TIMER_SERVICE 0x70000001
#define DEKO_PAGE_FAULT_SERVICE 0x70000002
#define DEKO_SERVICE_APP_ENTER_OK 0x0

/*
 * The SVSM PVALIDATE related structures
 */
struct svsm_pvalidate_entry {
	u64 page_size : 2, action : 1, ignore_cf : 1, rsvd : 8, pfn : 52;
};

struct svsm_pvalidate_call {
	u16 num_entries;
	u16 cur_index;

	u8 rsvd1[4];

	struct svsm_pvalidate_entry entry[];
};

#define SVSM_PVALIDATE_MAX_COUNT                         \
	((sizeof_field(struct svsm_ca, svsm_buffer) -    \
	  offsetof(struct svsm_pvalidate_call, entry)) / \
	 sizeof(struct svsm_pvalidate_entry))

/*
 * The SVSM Attestation related structures
 */
struct svsm_loc_entry {
	u64 pa;
	u32 len;
	u8 rsvd[4];
};

struct svsm_attest_call {
	struct svsm_loc_entry report_buf;
	struct svsm_loc_entry nonce;
	struct svsm_loc_entry manifest_buf;
	struct svsm_loc_entry certificates_buf;

	/* For attesting a single service */
	u8 service_guid[16];
	u32 service_manifest_ver;
	u8 rsvd[4];
};

/* PTE descriptor used for the prepare_pte_enc() operations. */
struct pte_enc_desc {
	pte_t *kpte;
	int pte_level;
	bool encrypt;
	/* pfn of the kpte above */
	unsigned long pfn;
	/* physical address of @pfn */
	unsigned long pa;
	/* virtual address of @pfn */
	void *va;
	/* memory covered by the pte */
	unsigned long size;
	pgprot_t new_pgprot;
};

/*
 * SVSM protocol structure
 */
struct svsm_call {
	struct svsm_ca *caa;
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 rax_out;
	u64 rcx_out;
	u64 rdx_out;
	u64 r8_out;
	u64 r9_out;
};

struct deko_task_work {
	struct callback_head work;
	u32 launch_type;
};

extern struct svsm_ca *svsm_get_caa(void);
extern u64 svsm_get_caa_pa(void);
extern int svsm_perform_call_protocol(struct svsm_call *call);
extern int svsm_perform_msr_protocol(struct svsm_call *call);
extern void deko_proxy_loop(struct callback_head *work);
extern phys_addr_t get_anything_pa(void *vaddr);

#define SVSM_CORE_CALL(x) ((0ULL << 32) | (x))
#define SVSM_CORE_REMAP_CA 0
#define SVSM_CORE_PVALIDATE 1
#define SVSM_CORE_CREATE_VCPU 2
#define SVSM_CORE_DELETE_VCPU 3

#define SVSM_ATTEST_CALL(x) ((1ULL << 32) | (x))
#define SVSM_ATTEST_SERVICES 0
#define SVSM_ATTEST_SINGLE_SERVICE 1

#define SVSM_VTPM_CALL(x) ((2ULL << 32) | (x))
#define SVSM_VTPM_QUERY 0
#define SVSM_VTPM_CMD 1

#define SVSM_EXTEND_CALL(x) ((4ULL << 32) | (x))
#define SVSM_EXTEND_TRAMPOLINE_SETUP 0
#define SVSM_EXTEND_SYSCALL_ANALYSIS 1
#define SVSM_EXTEND_REPORT_APP 2
#define SVSM_EXTEND_LAUNCH_APP 3
#define SVSM_EXTEND_MAP_IFC 4
#define SVSM_EXTEND_TASK_MIGRATE 5
#define SVSM_EXTEND_LOAD_POLICY 8
#define SVSM_EXTEND_CONFIG_LOG_LEVEL 9
#define SVSM_EXTEND_NEGOTIATE_PROTOCOL 10
#define SVSM_EXTEND_PAGE_FAULT 11
#define SVSM_EXTEND_ASPACE_OP 12
#define SVSM_EXTEND_EXEC_RANGE_READY 13
#define SVSM_EXTEND_EXEC_RANGE_UNLIFT 14

#ifdef CONFIG_AMD_MEM_ENCRYPT

extern u8 snp_vmpl;

extern void __sev_es_ist_enter(struct pt_regs *regs);
extern void __sev_es_ist_exit(void);
static __always_inline void sev_es_ist_enter(struct pt_regs *regs)
{
	if (cc_vendor == CC_VENDOR_AMD &&
	    cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		__sev_es_ist_enter(regs);
}
static __always_inline void sev_es_ist_exit(void)
{
	if (cc_vendor == CC_VENDOR_AMD &&
	    cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		__sev_es_ist_exit();
}
extern int sev_es_setup_ap_jump_table(struct real_mode_header *rmh);
extern void __sev_es_nmi_complete(void);
static __always_inline void sev_es_nmi_complete(void)
{
	if (cc_vendor == CC_VENDOR_AMD &&
	    cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		__sev_es_nmi_complete();
}
extern int __init sev_es_efi_map_ghcbs_cas(pgd_t *pgd);
extern void sev_enable(struct boot_params *bp);

/*
 * RMPADJUST modifies the RMP permissions of a page of a lesser-
 * privileged (numerically higher) VMPL.
 *
 * If the guest is running at a higher-privilege than the privilege
 * level the instruction is targeting, the instruction will succeed,
 * otherwise, it will fail.
 */
static inline int rmpadjust(unsigned long vaddr, bool rmp_psize,
			    unsigned long attrs)
{
	int rc;

	/* "rmpadjust" mnemonic support in binutils 2.36 and newer */
	asm volatile(".byte 0xF3,0x0F,0x01,0xFE\n\t"
		     : "=a"(rc)
		     : "a"(vaddr), "c"(rmp_psize), "d"(attrs)
		     : "memory", "cc");

	return rc;
}
static inline int pvalidate(unsigned long vaddr, bool rmp_psize, bool validate)
{
	bool no_rmpupdate;
	int rc;

	/* "pvalidate" mnemonic support in binutils 2.36 and newer */
	asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
		     : "=@ccc"(no_rmpupdate), "=a"(rc)
		     : "a"(vaddr), "c"(rmp_psize), "d"(validate)
		     : "memory", "cc");

	if (no_rmpupdate)
		return PVALIDATE_FAIL_NOUPDATE;

	return rc;
}

void setup_ghcb(void);
void snp_register_ghcb_early(unsigned long paddr);
void early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr,
				  unsigned long npages);
void early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr,
				 unsigned long npages);
void snp_set_memory_shared(unsigned long vaddr, unsigned long npages);
void snp_set_memory_private(unsigned long vaddr, unsigned long npages);
void snp_set_wakeup_secondary_cpu(void);
bool snp_init(struct boot_params *bp);
void snp_dmi_setup(void);
int snp_issue_svsm_attest_req(u64 call_id, struct svsm_call *call,
			      struct svsm_attest_call *input);
void snp_accept_memory(phys_addr_t start, phys_addr_t end);
u64 snp_get_unsupported_features(u64 status);
u64 sev_get_status(void);
void sev_show_status(void);
int prepare_pte_enc(struct pte_enc_desc *d);
void set_pte_enc_mask(pte_t *kpte, unsigned long pfn, pgprot_t new_prot);
void snp_kexec_finish(void);
void snp_kexec_begin(void);

int snp_msg_init(struct snp_msg_desc *mdesc, int vmpck_id);
struct snp_msg_desc *snp_msg_alloc(void);
void snp_msg_free(struct snp_msg_desc *mdesc);
int snp_send_guest_request(struct snp_msg_desc *mdesc,
			   struct snp_guest_req *req);

int snp_svsm_vtpm_send_command(u8 *buffer);

void __init snp_secure_tsc_prepare(void);
void __init snp_secure_tsc_init(void);
enum es_result savic_register_gpa(u64 gpa);
enum es_result savic_unregister_gpa(u64 *gpa);
u64 savic_ghcb_msr_read(u32 reg);
void savic_ghcb_msr_write(u32 reg, u64 value);

static __always_inline void vc_ghcb_invalidate(struct ghcb *ghcb)
{
	ghcb->save.sw_exit_code = 0;
	__builtin_memset(ghcb->save.valid_bitmap, 0,
			 sizeof(ghcb->save.valid_bitmap));
}

/* I/O parameters for CPUID-related helpers */
struct cpuid_leaf {
	u32 fn;
	u32 subfn;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
};

int svsm_perform_msr_protocol(struct svsm_call *call);
int __pi_svsm_perform_msr_protocol(struct svsm_call *call);
int snp_cpuid(void (*cpuid_fn)(void *ctx, struct cpuid_leaf *leaf), void *ctx,
	      struct cpuid_leaf *leaf);

void svsm_issue_call(struct svsm_call *call, u8 *pending);
int svsm_process_result_codes(struct svsm_call *call);

void __noreturn sev_es_terminate(unsigned int set, unsigned int reason);
enum es_result sev_es_ghcb_hv_call(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
				   u64 exit_code, u64 exit_info_1,
				   u64 exit_info_2);

bool sev_es_negotiate_protocol(void);
bool sev_es_check_cpu_features(void);

extern u16 ghcb_version;
extern struct ghcb *boot_ghcb;
extern bool sev_snp_needs_sfw;

struct psc_desc {
	enum psc_op op;
	struct svsm_ca *ca;
	u64 caa_pa;
};

static inline void sev_evict_cache(void *va, int npages)
{
	volatile u8 val __always_unused;
	u8 *bytes = va;
	int page_idx;

	/*
	 * For SEV guests, a read from the first/last cache-lines of a 4K page
	 * using the guest key is sufficient to cause a flush of all cache-lines
	 * associated with that 4K page without incurring all the overhead of a
	 * full CLFLUSH sequence.
	 */
	for (page_idx = 0; page_idx < npages; page_idx++) {
		val = bytes[page_idx * PAGE_SIZE];
		val = bytes[page_idx * PAGE_SIZE + PAGE_SIZE - 1];
	}
}

#else /* !CONFIG_AMD_MEM_ENCRYPT */

#define snp_vmpl 0
static inline void sev_es_ist_enter(struct pt_regs *regs)
{
}
static inline void sev_es_ist_exit(void)
{
}
static inline int sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	return 0;
}
static inline void sev_es_nmi_complete(void)
{
}
static inline int sev_es_efi_map_ghcbs_cas(pgd_t *pgd)
{
	return 0;
}
static inline void sev_enable(struct boot_params *bp)
{
}
static inline int pvalidate(unsigned long vaddr, bool rmp_psize, bool validate)
{
	return 0;
}
static inline int rmpadjust(unsigned long vaddr, bool rmp_psize,
			    unsigned long attrs)
{
	return 0;
}
static inline void setup_ghcb(void)
{
}
static inline void __init early_snp_set_memory_private(unsigned long vaddr,
						       unsigned long paddr,
						       unsigned long npages)
{
}
static inline void __init early_snp_set_memory_shared(unsigned long vaddr,
						      unsigned long paddr,
						      unsigned long npages)
{
}
static inline void snp_set_memory_shared(unsigned long vaddr,
					 unsigned long npages)
{
}
static inline void snp_set_memory_private(unsigned long vaddr,
					  unsigned long npages)
{
}
static inline void snp_set_wakeup_secondary_cpu(void)
{
}
static inline bool snp_init(struct boot_params *bp)
{
	return false;
}
static inline void snp_dmi_setup(void)
{
}
static inline int snp_issue_svsm_attest_req(u64 call_id, struct svsm_call *call,
					    struct svsm_attest_call *input)
{
	return -ENOTTY;
}
static inline void snp_accept_memory(phys_addr_t start, phys_addr_t end)
{
}
static inline u64 snp_get_unsupported_features(u64 status)
{
	return 0;
}
static inline u64 sev_get_status(void)
{
	return 0;
}
static inline void sev_show_status(void)
{
}
static inline int prepare_pte_enc(struct pte_enc_desc *d)
{
	return 0;
}
static inline void set_pte_enc_mask(pte_t *kpte, unsigned long pfn,
				    pgprot_t new_prot)
{
}
static inline void snp_kexec_finish(void)
{
}
static inline void snp_kexec_begin(void)
{
}
static inline int snp_msg_init(struct snp_msg_desc *mdesc, int vmpck_id)
{
	return -1;
}
static inline struct snp_msg_desc *snp_msg_alloc(void)
{
	return NULL;
}
static inline void snp_msg_free(struct snp_msg_desc *mdesc)
{
}
static inline int snp_send_guest_request(struct snp_msg_desc *mdesc,
					 struct snp_guest_req *req)
{
	return -ENODEV;
}
static inline int snp_svsm_vtpm_send_command(u8 *buffer)
{
	return -ENODEV;
}
static inline void __init snp_secure_tsc_prepare(void)
{
}
static inline void __init snp_secure_tsc_init(void)
{
}
static inline void sev_evict_cache(void *va, int npages)
{
}
static inline enum es_result savic_register_gpa(u64 gpa)
{
	return ES_UNSUPPORTED;
}
static inline enum es_result savic_unregister_gpa(u64 *gpa)
{
	return ES_UNSUPPORTED;
}
static inline void savic_ghcb_msr_write(u32 reg, u64 value)
{
}
static inline u64 savic_ghcb_msr_read(u32 reg)
{
	return 0;
}

#endif /* CONFIG_AMD_MEM_ENCRYPT */

#ifdef CONFIG_KVM_AMD_SEV
bool snp_probe_rmptable_info(void);
int snp_rmptable_init(void);
int snp_lookup_rmpentry(u64 pfn, bool *assigned, int *level);
void snp_dump_hva_rmpentry(unsigned long address);
int psmash(u64 pfn);
int rmp_make_private(u64 pfn, u64 gpa, enum pg_level level, u32 asid,
		     bool immutable);
int rmp_make_shared(u64 pfn, enum pg_level level);
void __snp_leak_pages(u64 pfn, unsigned int npages, bool dump_rmp);
void kdump_sev_callback(void);
void snp_fixup_e820_tables(void);
static inline void snp_leak_pages(u64 pfn, unsigned int pages)
{
	__snp_leak_pages(pfn, pages, true);
}
#else
static inline bool snp_probe_rmptable_info(void)
{
	return false;
}
static inline int snp_rmptable_init(void)
{
	return -ENOSYS;
}
static inline int snp_lookup_rmpentry(u64 pfn, bool *assigned, int *level)
{
	return -ENODEV;
}
static inline void snp_dump_hva_rmpentry(unsigned long address)
{
}
static inline int psmash(u64 pfn)
{
	return -ENODEV;
}
static inline int rmp_make_private(u64 pfn, u64 gpa, enum pg_level level,
				   u32 asid, bool immutable)
{
	return -ENODEV;
}
static inline int rmp_make_shared(u64 pfn, enum pg_level level)
{
	return -ENODEV;
}
static inline void __snp_leak_pages(u64 pfn, unsigned int npages, bool dump_rmp)
{
}
static inline void snp_leak_pages(u64 pfn, unsigned int npages)
{
}
static inline void kdump_sev_callback(void)
{
}
static inline void snp_fixup_e820_tables(void)
{
}
#endif

#endif
