// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#define pr_fmt(fmt) "SEV: " fmt

#include <linux/sched/debug.h> /* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/cc_platform.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/efi.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/psp-sev.h>
#include <linux/dmi.h>
#include <linux/sizes.h>
#include <uapi/linux/sev-guest.h>
#include <crypto/gcm.h>

#include <asm/init.h>
#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/sev.h>
#include <asm/sev-internal.h>
#include <asm/insn-eval.h>
#include <asm/fpu/xcr.h>
#include <asm/processor.h>
#include <asm/realmode.h>
#include <asm/setup.h>
#include <asm/traps.h>

extern char __per_cpu_start[];
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/cpuid/api.h>
#include <asm/cmdline.h>
#include <asm/msr.h>

/* Bitmap of SEV features supported by the hypervisor */
u64 sev_hv_features __ro_after_init;
SYM_PIC_ALIAS(sev_hv_features);

/* Secrets page physical address from the CC blob */
u64 sev_secrets_pa __ro_after_init;
SYM_PIC_ALIAS(sev_secrets_pa);

/* For early boot SVSM communication */
struct svsm_ca boot_svsm_ca_page __aligned(PAGE_SIZE);
SYM_PIC_ALIAS(boot_svsm_ca_page);

/* The reserved pages for re-constructing the page table later. */
static phys_addr_t page_l3 = 0, page_l2, page_l1 = 0;

/* The reserved memory for the IFC policy engine. */
static phys_addr_t deko_ifc_policy_engine_mem = 0;

/*
 * Policy loads can be larger than the SVSM CAA scratch buffer. Keep the CAA
 * for the fixed request and stage the policy bytes in guest memory instead.
 */
#define DEKO_MAX_POLICY_BLOB_SIZE SZ_1M

/* The base address for the trampoline code's physical address. */
static phys_addr_t trampoline_pa_base = 0;
static unsigned long trampoline_va_base = 0;

static void log_report_app_cpu_tss_sp2(struct task_struct *task,
				       struct deko_new_app_req *req)
{
	int cpu = task_cpu(task);
	struct tss_struct *cpu_tss = per_cpu_ptr(&cpu_tss_rw, cpu);
	unsigned long kernel_gs_base = cpu_kernelmode_gs_base(cpu) +
		(unsigned long)__per_cpu_start;
	unsigned long cpu_tss_rw_addr = (unsigned long)cpu_tss;
	unsigned long cpu_tss_rw_off = cpu_tss_rw_addr - kernel_gs_base;
	unsigned long sp2_off = offsetof(struct tss_struct, x86_tss.sp2);
	unsigned long sp2_addr = cpu_tss_rw_addr + sp2_off;
	u64 sp2_percpu = READ_ONCE(cpu_tss->x86_tss.sp2);
	u64 sp2_direct = READ_ONCE(*(u64 *)sp2_addr);
	unsigned long gs_sp2_addr = req->kernel_gs_base + cpu_tss_rw_off + sp2_off;
	u64 gs_sp2_direct = READ_ONCE(*(u64 *)gs_sp2_addr);

	pr_info("report app cpu_tss_rw snapshot pid=%d comm=%s target_cpu=%d current_cpu=%u kernel_gs_base=0x%lx cpu_tss_rw=%px cpu_tss_rw_off=0x%lx sp2_addr=0x%lx sp2_percpu=0x%llx sp2_direct=0x%llx gs_sp2_addr=0x%lx gs_sp2_direct=0x%llx\n",
		task->pid, task->comm, cpu, smp_processor_id(), kernel_gs_base,
		cpu_tss, cpu_tss_rw_off, sp2_addr,
		(unsigned long long)sp2_percpu,
		(unsigned long long)sp2_direct, gs_sp2_addr,
		(unsigned long long)gs_sp2_direct);
}

/*
 * SVSM related information:
 *   During boot, the page tables are set up as identity mapped and later
 *   changed to use kernel virtual addresses. Maintain separate virtual and
 *   physical addresses for the CAA to allow SVSM functions to be used during
 *   early boot, both with identity mapped virtual addresses and proper kernel
 *   virtual addresses.
 */
u64 boot_svsm_caa_pa __ro_after_init;
SYM_PIC_ALIAS(boot_svsm_caa_pa);

DEFINE_PER_CPU(struct svsm_ca *, svsm_caa);
DEFINE_PER_CPU(u64, svsm_caa_pa);

struct svsm_ca *svsm_get_caa(void)
{
	if (sev_cfg.use_cas)
		return this_cpu_read(svsm_caa);
	else
		return rip_rel_ptr(&boot_svsm_ca_page);
}

u64 svsm_get_caa_pa(void)
{
	if (sev_cfg.use_cas)
		return this_cpu_read(svsm_caa_pa);
	else
		return boot_svsm_caa_pa;
}

/* AP INIT values as documented in the APM2  section "Processor Initialization State" */
#define AP_INIT_CS_LIMIT 0xffff
#define AP_INIT_DS_LIMIT 0xffff
#define AP_INIT_LDTR_LIMIT 0xffff
#define AP_INIT_GDTR_LIMIT 0xffff
#define AP_INIT_IDTR_LIMIT 0xffff
#define AP_INIT_TR_LIMIT 0xffff
#define AP_INIT_RFLAGS_DEFAULT 0x2
#define AP_INIT_DR6_DEFAULT 0xffff0ff0
#define AP_INIT_GPAT_DEFAULT 0x0007040600070406ULL
#define AP_INIT_XCR0_DEFAULT 0x1
#define AP_INIT_X87_FTW_DEFAULT 0x5555
#define AP_INIT_X87_FCW_DEFAULT 0x0040
#define AP_INIT_CR0_DEFAULT 0x60000010
#define AP_INIT_MXCSR_DEFAULT 0x1f80

#define SVSM_PERCPU_BASE 0xffffffff00000000UL

#define DEKO_IFC_POLICY_ENGINE_MEM_SIZE ((SZ_64M))

static const char trampoline_init_magic[] __read_mostly = "TRAMPOLINE_INIT";

static const char *const sev_status_feat_names[] = {
	[MSR_AMD64_SEV_ENABLED_BIT] = "SEV",
	[MSR_AMD64_SEV_ES_ENABLED_BIT] = "SEV-ES",
	[MSR_AMD64_SEV_SNP_ENABLED_BIT] = "SEV-SNP",
	[MSR_AMD64_SNP_VTOM_BIT] = "vTom",
	[MSR_AMD64_SNP_REFLECT_VC_BIT] = "ReflectVC",
	[MSR_AMD64_SNP_RESTRICTED_INJ_BIT] = "RI",
	[MSR_AMD64_SNP_ALT_INJ_BIT] = "AI",
	[MSR_AMD64_SNP_DEBUG_SWAP_BIT] = "DebugSwap",
	[MSR_AMD64_SNP_PREVENT_HOST_IBS_BIT] = "NoHostIBS",
	[MSR_AMD64_SNP_BTB_ISOLATION_BIT] = "BTBIsol",
	[MSR_AMD64_SNP_VMPL_SSS_BIT] = "VmplSSS",
	[MSR_AMD64_SNP_SECURE_TSC_BIT] = "SecureTSC",
	[MSR_AMD64_SNP_VMGEXIT_PARAM_BIT] = "VMGExitParam",
	[MSR_AMD64_SNP_IBS_VIRT_BIT] = "IBSVirt",
	[MSR_AMD64_SNP_VMSA_REG_PROT_BIT] = "VMSARegProt",
	[MSR_AMD64_SNP_SMT_PROT_BIT] = "SMTProt",
	[MSR_AMD64_SNP_SECURE_AVIC_BIT] = "SecureAVIC",
};

/*
 * For Secure TSC guests, the BSP fetches TSC_INFO using SNP guest messaging and
 * initializes snp_tsc_scale and snp_tsc_offset. These values are replicated
 * across the APs VMSA fields (TSC_SCALE and TSC_OFFSET).
 */
static u64 snp_tsc_scale __ro_after_init;
static u64 snp_tsc_offset __ro_after_init;
static unsigned long snp_tsc_freq_khz __ro_after_init;

DEFINE_PER_CPU(struct sev_es_runtime_data *, runtime_data);
DEFINE_PER_CPU(struct sev_es_save_area *, sev_vmsa);
static DEFINE_PER_CPU(phys_addr_t, svsm_vmpl1_percpu_pa);
static DEFINE_PER_CPU(unsigned long, svsm_vmpl1_ghcb_va);
static DEFINE_PER_CPU(unsigned long, svsm_vmpl1_db_va);

struct svsm_sev_trampoline_setup_req {
	u64 syscall_enter_addr;
	u64 trampoline_gva;
	u64 trampoline_gpa;
} __attribute__((aligned(8)));

struct svsm_map_ifc_single_req {
	u64 va_start;
	u64 va_end;
	u64 pa_start;
	u64 pa_end;
	bool is_per_cpu;
} __attribute__((aligned(8)));

struct svsm_map_ifc_req {
	u16 req_len;
	u16 __reserved[3];
	u64 ghcb_va;
	u64 db_va;
	struct svsm_map_ifc_single_req reqs[16];
} __attribute__((packed, aligned(8)));

static struct svsm_map_ifc_single_req svsm_vmpl1_global_maps[16];
static u16 svsm_vmpl1_global_map_count;

/*
 * SVSM related information:
 *   When running under an SVSM, the VMPL that Linux is executing at must be
 *   non-zero. The VMPL is therefore used to indicate the presence of an SVSM.
 */
u8 snp_vmpl __ro_after_init;
EXPORT_SYMBOL_GPL(snp_vmpl);
SYM_PIC_ALIAS(snp_vmpl);

/*
 * Since feature negotiation related variables are set early in the boot
 * process they must reside in the .data section so as not to be zeroed
 * out when the .bss section is later cleared.
 *
 * GHCB protocol version negotiated with the hypervisor.
 */
u16 ghcb_version __ro_after_init;
SYM_PIC_ALIAS(ghcb_version);

/* For early boot hypervisor communication in SEV-ES enabled guests */
static struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
struct ghcb *boot_ghcb __section(".data");

static phys_addr_t alloc_stolen_mem(unsigned long size)
{
	struct page *pages;
	unsigned long nr_pages;
	unsigned int order;

	size = PAGE_ALIGN(size);
	nr_pages = size >> PAGE_SHIFT;
	order = get_order(size);
	if (order <= MAX_PAGE_ORDER) {
		pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
		if (!pages)
			return 0;
	} else {
		pages = alloc_contig_pages(nr_pages, GFP_KERNEL, numa_node_id(),
					   NULL);
		if (!pages)
			return 0;

		memset(page_address(pages), 0, size);
	}

	return page_to_phys(pages);
}

static unsigned long find_empty_pgd_slot(unsigned long start, unsigned long end)
{
	unsigned long addr;

	start = ALIGN(start, PGDIR_SIZE);
	end &= PGDIR_MASK;
	if (start >= end)
		return 0;

	for (addr = end - PGDIR_SIZE;; addr -= PGDIR_SIZE) {
		pgd_t *pgd = pgd_offset_k(addr);
		p4d_t *p4d = p4d_offset(pgd, addr);

		if (pgtable_l5_enabled()) {
			if (pgd_none(*pgd))
				return addr;
		} else if (p4d_none(*p4d)) {
			return addr;
		}

		if (addr == start)
			break;
	}

	return 0;
}

static unsigned long choose_trampoline_va_base(void)
{
	unsigned long addr;

	/*
	 * Prefer the fixed 2 TB hole immediately below cpu_entry_area.
	 * Unlike the vmalloc/vmemmap gaps, this space is not shuffled by the
	 * x86 memory-layout randomization.
	 */
	addr = find_empty_pgd_slot(CPU_ENTRY_AREA_BASE - (4UL * P4D_SIZE),
				   CPU_ENTRY_AREA_BASE);
	if (addr)
		return addr;

	/*
	 * Fall back to the entropy gap before the direct map if KASLR left one.
	 * That range is also outside Linux-managed regions once boot layout is
	 * finalized.
	 */
	return find_empty_pgd_slot(LDT_END_ADDR, page_offset_base);
}

static int set_up_deko_ifc_policy_engine_mapping(void)
{
	int ret = 0;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long va_start = trampoline_va_base + PMD_SIZE;
	unsigned long cur_va;
	phys_addr_t cur_pa;
	int i;

	if (!deko_ifc_policy_engine_mem ||
	    !IS_ALIGNED(deko_ifc_policy_engine_mem, PAGE_SIZE) ||
	    !trampoline_va_base)
		return -EINVAL;

	pgd = pgd_offset_k(va_start);
	if (pgd_none(*pgd))
		return -ENOMEM;
	p4d = p4d_offset(pgd, va_start);

	if (p4d_none(*p4d)) {
		unsigned long new_pud = alloc_stolen_mem(PAGE_SIZE);
		if (!new_pud)
			return -ENOMEM;

		set_p4d(p4d, __p4d(__pa(new_pud) | 0x67 | _ENC));
	}

	pud = pud_offset(p4d, va_start);
	if (pud_none(*pud)) {
		unsigned long new_pmd = alloc_stolen_mem(PAGE_SIZE);
		if (!new_pmd)
			return -ENOMEM;
		set_pud(pud, __pud(__pa(new_pmd) | 0x63 | _ENC));
	}

	cur_pa = deko_ifc_policy_engine_mem;
	cur_va = va_start;
	for (i = 0; i < (DEKO_IFC_POLICY_ENGINE_MEM_SIZE / PMD_SIZE); i++) {
		pmd = pmd_offset(pud, cur_va);
		pgprot_t prot = __pgprot(_PAGE_PRESENT | _PAGE_RW |
					 _PAGE_GLOBAL | _PAGE_PSE | _ENC);
		set_pmd(pmd, pfn_pmd(cur_pa >> PAGE_SHIFT, prot));

		cur_pa += PMD_SIZE;
		cur_va += PMD_SIZE;
	}

	__flush_tlb_all();

	return ret;
}

static int claim_whole_pgd_entry(void)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int i;
	int ret = 0;

	if (!trampoline_pa_base || !IS_ALIGNED(trampoline_pa_base, PMD_SIZE))
		return -EINVAL;

	if (!trampoline_va_base)
		return -EINVAL;

	pgd = pgd_offset_k(trampoline_va_base);
	p4d = p4d_offset(pgd, trampoline_va_base);
	if (pgtable_l5_enabled()) {
		if (!pgd_none(*pgd))
			return -EBUSY;
	} else if (!p4d_none(*p4d)) {
		return -EBUSY;
	}

	/* --- Level 3 (PUD Table) --- */
	page_l3 = alloc_stolen_mem(PAGE_SIZE);
	if (!page_l3) {
		ret = -ENOMEM;
		goto free_pages;
	}
	memset(__va(page_l3), 0, PAGE_SIZE);

	set_pgd(pgd, __pgd((page_l3 | 0x67 | _ENC)));

	p4d = p4d_offset(pgd, trampoline_va_base);

	/* --- Level 2 (PMD Table) --- */
	page_l2 = alloc_stolen_mem(PAGE_SIZE);
	if (!page_l2) {
		ret = -ENOMEM;
		goto free_pages;
	}
	memset(__va(page_l2), 0, PAGE_SIZE);

	pud = pud_offset(p4d, trampoline_va_base);
	set_pud(pud, __pud((page_l2 | 0x63 | _ENC)));

	page_l1 = alloc_stolen_mem(PAGE_SIZE);
	if (!page_l1) {
		ret = -ENOMEM;
		goto free_pages;
	}
	memset(__va(page_l1), 0, PAGE_SIZE);

	pmd = pmd_offset(pud, trampoline_va_base);

	set_pmd(pmd, __pmd((page_l1 | 0x67 | _ENC)));
	pte = pte_offset_kernel(pmd, trampoline_va_base);

	for (i = 0; i < PTRS_PER_PTE; i++) {
		phys_addr_t slice_pa = trampoline_pa_base + (i * PAGE_SIZE);
		set_pte(&pte[i], __pte(slice_pa | 0x163 | _ENC));
	}

	// __flush_tlb_all();

	goto out;

free_pages:
	if (ret < 0) {
		if (page_l1)
			free_pages((unsigned long)__va(page_l1), 0);
		if (page_l2)
			free_pages((unsigned long)__va(page_l2), 0);
		if (page_l3)
			free_pages((unsigned long)__va(page_l3), 0);
		if (pgd)
			pgd_clear(pgd);
	}

out:
	return ret;
}

static u64 __init get_snp_jump_table_addr(void)
{
	struct snp_secrets_page *secrets;
	void __iomem *mem;
	u64 addr;

	mem = ioremap_encrypted(sev_secrets_pa, PAGE_SIZE);
	if (!mem) {
		pr_err("Unable to locate AP jump table address: failed to map the SNP secrets page.\n");
		return 0;
	}

	secrets = (__force struct snp_secrets_page *)mem;

	addr = secrets->os_area.ap_jump_table_pa;
	iounmap(mem);

	return addr;
}

static u64 __init get_jump_table_addr(void)
{
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	u64 ret = 0;

	if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return get_snp_jump_table_addr();

	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_1(ghcb, SVM_VMGEXIT_GET_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (ghcb_sw_exit_info_1_is_valid(ghcb) &&
	    ghcb_sw_exit_info_2_is_valid(ghcb))
		ret = ghcb->save.sw_exit_info_2;

	__sev_put_ghcb(&state);

	local_irq_restore(flags);

	return ret;
}

static int svsm_perform_ghcb_protocol(struct ghcb *ghcb, struct svsm_call *call)
{
	struct es_em_ctxt ctxt;
	u8 pending = 0;

	vc_ghcb_invalidate(ghcb);

	/*
	 * Fill in protocol and format specifiers. This can be called very early
	 * in the boot, so use rip-relative references as needed.
	 */
	ghcb->protocol_version = ghcb_version;
	ghcb->ghcb_usage = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_SNP_RUN_VMPL);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa(ghcb));

	svsm_issue_call(call, &pending);

	if (pending)
		return -EINVAL;

	switch (verify_exception_info(ghcb, &ctxt)) {
	case ES_OK:
		break;
	case ES_EXCEPTION:
		vc_forward_exception(&ctxt);
		fallthrough;
	default:
		return -EINVAL;
	}

	return svsm_process_result_codes(call);
}

int svsm_perform_call_protocol(struct svsm_call *call)
{
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	int ret;

	flags = native_local_irq_save();

	if (sev_cfg.ghcbs_initialized)
		ghcb = __sev_get_ghcb(&state);
	else if (boot_ghcb)
		ghcb = boot_ghcb;
	else
		ghcb = NULL;

	do {
		ret = ghcb ? svsm_perform_ghcb_protocol(ghcb, call) :
			     __pi_svsm_perform_msr_protocol(call);
	} while (ret == -EAGAIN);

	if (sev_cfg.ghcbs_initialized)
		__sev_put_ghcb(&state);

	native_local_irq_restore(flags);

	return ret;
}

static inline void __pval_terminate(u64 pfn, bool action,
				    unsigned int page_size, int ret,
				    u64 svsm_ret)
{
	WARN(1,
	     "PVALIDATE failure: pfn: 0x%llx, action: %u, size: %u, ret: %d, svsm_ret: 0x%llx\n",
	     pfn, action, page_size, ret, svsm_ret);

	sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PVALIDATE);
}

static void svsm_pval_terminate(struct svsm_pvalidate_call *pc, int ret,
				u64 svsm_ret)
{
	unsigned int page_size;
	bool action;
	u64 pfn;

	pfn = pc->entry[pc->cur_index].pfn;
	action = pc->entry[pc->cur_index].action;
	page_size = pc->entry[pc->cur_index].page_size;

	__pval_terminate(pfn, action, page_size, ret, svsm_ret);
}

static void pval_pages(struct snp_psc_desc *desc)
{
	struct psc_entry *e;
	unsigned long vaddr;
	unsigned int size;
	unsigned int i;
	bool validate;
	u64 pfn;
	int rc;

	for (i = 0; i <= desc->hdr.end_entry; i++) {
		e = &desc->entries[i];

		pfn = e->gfn;
		vaddr = (unsigned long)pfn_to_kaddr(pfn);
		size = e->pagesize ? RMP_PG_SIZE_2M : RMP_PG_SIZE_4K;
		validate = e->operation == SNP_PAGE_STATE_PRIVATE;

		rc = pvalidate(vaddr, size, validate);
		if (!rc)
			continue;

		if (rc == PVALIDATE_FAIL_SIZEMISMATCH &&
		    size == RMP_PG_SIZE_2M) {
			unsigned long vaddr_end = vaddr + PMD_SIZE;

			for (; vaddr < vaddr_end; vaddr += PAGE_SIZE, pfn++) {
				rc = pvalidate(vaddr, RMP_PG_SIZE_4K, validate);
				if (rc)
					__pval_terminate(pfn, validate,
							 RMP_PG_SIZE_4K, rc, 0);
			}
		} else {
			__pval_terminate(pfn, validate, size, rc, 0);
		}
	}
}

static u64 svsm_build_ca_from_pfn_range(u64 pfn, u64 pfn_end, bool action,
					struct svsm_pvalidate_call *pc)
{
	struct svsm_pvalidate_entry *pe;

	/* Nothing in the CA yet */
	pc->num_entries = 0;
	pc->cur_index = 0;

	pe = &pc->entry[0];

	while (pfn < pfn_end) {
		pe->page_size = RMP_PG_SIZE_4K;
		pe->action = action;
		pe->ignore_cf = 0;
		pe->rsvd = 0;
		pe->pfn = pfn;

		pe++;
		pfn++;

		pc->num_entries++;
		if (pc->num_entries == SVSM_PVALIDATE_MAX_COUNT)
			break;
	}

	return pfn;
}

static int svsm_build_ca_from_psc_desc(struct snp_psc_desc *desc,
				       unsigned int desc_entry,
				       struct svsm_pvalidate_call *pc)
{
	struct svsm_pvalidate_entry *pe;
	struct psc_entry *e;

	/* Nothing in the CA yet */
	pc->num_entries = 0;
	pc->cur_index = 0;

	pe = &pc->entry[0];
	e = &desc->entries[desc_entry];

	while (desc_entry <= desc->hdr.end_entry) {
		pe->page_size = e->pagesize ? RMP_PG_SIZE_2M : RMP_PG_SIZE_4K;
		pe->action = e->operation == SNP_PAGE_STATE_PRIVATE;
		pe->ignore_cf = 0;
		pe->rsvd = 0;
		pe->pfn = e->gfn;

		pe++;
		e++;

		desc_entry++;
		pc->num_entries++;
		if (pc->num_entries == SVSM_PVALIDATE_MAX_COUNT)
			break;
	}

	return desc_entry;
}

static void svsm_pval_pages(struct snp_psc_desc *desc)
{
	struct svsm_pvalidate_entry pv_4k[VMGEXIT_PSC_MAX_ENTRY];
	unsigned int i, pv_4k_count = 0;
	struct svsm_pvalidate_call *pc;
	struct svsm_call call = {};
	unsigned long flags;
	bool action;
	u64 pc_pa;
	int ret;

	/*
	 * This can be called very early in the boot, use native functions in
	 * order to avoid paravirt issues.
	 */
	flags = native_local_irq_save();

	/*
	 * The SVSM calling area (CA) can support processing 510 entries at a
	 * time. Loop through the Page State Change descriptor until the CA is
	 * full or the last entry in the descriptor is reached, at which time
	 * the SVSM is invoked. This repeats until all entries in the descriptor
	 * are processed.
	 */
	call.caa = svsm_get_caa();

	pc = (struct svsm_pvalidate_call *)call.caa->svsm_buffer;
	pc_pa = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);

	/* Protocol 0, Call ID 1 */
	call.rax = SVSM_CORE_CALL(SVSM_CORE_PVALIDATE);
	call.rcx = pc_pa;

	for (i = 0; i <= desc->hdr.end_entry;) {
		i = svsm_build_ca_from_psc_desc(desc, i, pc);

		do {
			ret = svsm_perform_call_protocol(&call);
			if (!ret)
				continue;

			/*
			 * Check if the entry failed because of an RMP mismatch (a
			 * PVALIDATE at 2M was requested, but the page is mapped in
			 * the RMP as 4K).
			 */

			if (call.rax_out == SVSM_PVALIDATE_FAIL_SIZEMISMATCH &&
			    pc->entry[pc->cur_index].page_size ==
				    RMP_PG_SIZE_2M) {
				/* Save this entry for post-processing at 4K */
				pv_4k[pv_4k_count++] = pc->entry[pc->cur_index];

				/* Skip to the next one unless at the end of the list */
				pc->cur_index++;
				if (pc->cur_index < pc->num_entries)
					ret = -EAGAIN;
				else
					ret = 0;
			}
		} while (ret == -EAGAIN);

		if (ret)
			svsm_pval_terminate(pc, ret, call.rax_out);
	}

	/* Process any entries that failed to be validated at 2M and validate them at 4K */
	for (i = 0; i < pv_4k_count; i++) {
		u64 pfn, pfn_end;

		action = pv_4k[i].action;
		pfn = pv_4k[i].pfn;
		pfn_end = pfn + 512;

		while (pfn < pfn_end) {
			pfn = svsm_build_ca_from_pfn_range(pfn, pfn_end, action,
							   pc);

			ret = svsm_perform_call_protocol(&call);
			if (ret)
				svsm_pval_terminate(pc, ret, call.rax_out);
		}
	}

	native_local_irq_restore(flags);
}

static void pvalidate_pages(struct snp_psc_desc *desc)
{
	struct psc_entry *e;
	unsigned int i;

	if (snp_vmpl)
		svsm_pval_pages(desc);
	else
		pval_pages(desc);

	/*
	 * If not affected by the cache-coherency vulnerability there is no need
	 * to perform the cache eviction mitigation.
	 */
	if (cpu_feature_enabled(X86_FEATURE_COHERENCY_SFW_NO))
		return;

	for (i = 0; i <= desc->hdr.end_entry; i++) {
		e = &desc->entries[i];

		/*
		 * If validating memory (making it private) perform the cache
		 * eviction mitigation.
		 */
		if (e->operation == SNP_PAGE_STATE_PRIVATE)
			sev_evict_cache(pfn_to_kaddr(e->gfn),
					e->pagesize ? 512 : 1);
	}
}

static int vmgexit_psc(struct ghcb *ghcb, struct snp_psc_desc *desc)
{
	int cur_entry, end_entry, ret = 0;
	struct snp_psc_desc *data;
	struct es_em_ctxt ctxt;

	vc_ghcb_invalidate(ghcb);

	/* Copy the input desc into GHCB shared buffer */
	data = (struct snp_psc_desc *)ghcb->shared_buffer;
	memcpy(ghcb->shared_buffer, desc,
	       min_t(int, GHCB_SHARED_BUF_SIZE, sizeof(*desc)));

	/*
	 * As per the GHCB specification, the hypervisor can resume the guest
	 * before processing all the entries. Check whether all the entries
	 * are processed. If not, then keep retrying. Note, the hypervisor
	 * will update the data memory directly to indicate the status, so
	 * reference the data->hdr everywhere.
	 *
	 * The strategy here is to wait for the hypervisor to change the page
	 * state in the RMP table before guest accesses the memory pages. If the
	 * page state change was not successful, then later memory access will
	 * result in a crash.
	 */
	cur_entry = data->hdr.cur_entry;
	end_entry = data->hdr.end_entry;

	while (data->hdr.cur_entry <= data->hdr.end_entry) {
		ghcb_set_sw_scratch(ghcb, (u64)__pa(data));

		/* This will advance the shared buffer data points to. */
		ret = sev_es_ghcb_hv_call(ghcb, &ctxt, SVM_VMGEXIT_PSC, 0, 0);

		/*
		 * Page State Change VMGEXIT can pass error code through
		 * exit_info_2.
		 */
		if (WARN(ret || ghcb->save.sw_exit_info_2,
			 "SNP: PSC failed ret=%d exit_info_2=%llx\n", ret,
			 ghcb->save.sw_exit_info_2)) {
			ret = 1;
			goto out;
		}

		/* Verify that reserved bit is not set */
		if (WARN(data->hdr.reserved,
			 "Reserved bit is set in the PSC header\n")) {
			ret = 1;
			goto out;
		}

		/*
		 * Sanity check that entry processing is not going backwards.
		 * This will happen only if hypervisor is tricking us.
		 */
		if (WARN(data->hdr.end_entry > end_entry ||
				 cur_entry > data->hdr.cur_entry,
			 "SNP: PSC processing going backward, end_entry %d (got %d) cur_entry %d (got %d)\n",
			 end_entry, data->hdr.end_entry, cur_entry,
			 data->hdr.cur_entry)) {
			ret = 1;
			goto out;
		}
	}

out:
	return ret;
}

static unsigned long __set_pages_state(struct snp_psc_desc *data,
				       unsigned long vaddr,
				       unsigned long vaddr_end, int op)
{
	struct ghcb_state state;
	bool use_large_entry;
	struct psc_hdr *hdr;
	struct psc_entry *e;
	unsigned long flags;
	unsigned long pfn;
	struct ghcb *ghcb;
	int i;

	hdr = &data->hdr;
	e = data->entries;

	memset(data, 0, sizeof(*data));
	i = 0;

	while (vaddr < vaddr_end && i < ARRAY_SIZE(data->entries)) {
		hdr->end_entry = i;

		if (is_vmalloc_addr((void *)vaddr)) {
			pfn = vmalloc_to_pfn((void *)vaddr);
			use_large_entry = false;
		} else {
			pfn = __pa(vaddr) >> PAGE_SHIFT;
			use_large_entry = true;
		}

		e->gfn = pfn;
		e->operation = op;

		if (use_large_entry && IS_ALIGNED(vaddr, PMD_SIZE) &&
		    (vaddr_end - vaddr) >= PMD_SIZE) {
			e->pagesize = RMP_PG_SIZE_2M;
			vaddr += PMD_SIZE;
		} else {
			e->pagesize = RMP_PG_SIZE_4K;
			vaddr += PAGE_SIZE;
		}

		e++;
		i++;
	}

	/* Page validation must be rescinded before changing to shared */
	if (op == SNP_PAGE_STATE_SHARED)
		pvalidate_pages(data);

	local_irq_save(flags);

	if (sev_cfg.ghcbs_initialized)
		ghcb = __sev_get_ghcb(&state);
	else
		ghcb = boot_ghcb;

	/* Invoke the hypervisor to perform the page state changes */
	if (!ghcb || vmgexit_psc(ghcb, data))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PSC);

	if (sev_cfg.ghcbs_initialized)
		__sev_put_ghcb(&state);

	local_irq_restore(flags);

	/* Page validation must be performed after changing to private */
	if (op == SNP_PAGE_STATE_PRIVATE)
		pvalidate_pages(data);

	return vaddr;
}

static void *alloc_page_table_safe(void)
{
	void *ptr;

	if (slab_is_available()) {
		ptr = (void *)get_zeroed_page(GFP_ATOMIC);
	} else {
		phys_addr_t pa = alloc_stolen_mem(PAGE_SIZE);
		if (pa) {
			ptr = __va(pa);
			memset(ptr, 0, PAGE_SIZE);
		} else {
			ptr = NULL;
		}
	}
	return ptr;
}

static void set_pages_state(unsigned long vaddr, unsigned long npages, int op)
{
	struct snp_psc_desc desc;
	unsigned long vaddr_end;

	/* Use the MSR protocol when a GHCB is not available. */
	if (!boot_ghcb) {
		struct psc_desc d = { op, svsm_get_caa(), svsm_get_caa_pa() };

		return early_set_pages_state(vaddr, __pa(vaddr), npages, &d);
	}

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	while (vaddr < vaddr_end)
		vaddr = __set_pages_state(&desc, vaddr, vaddr_end, op);
}

void snp_set_memory_shared(unsigned long vaddr, unsigned long npages)
{
	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return;

	set_pages_state(vaddr, npages, SNP_PAGE_STATE_SHARED);
}

void snp_set_memory_private(unsigned long vaddr, unsigned long npages)
{
	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return;

	set_pages_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE);
}

void snp_accept_memory(phys_addr_t start, phys_addr_t end)
{
	unsigned long vaddr, npages;

	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return;

	vaddr = (unsigned long)__va(start);
	npages = (end - start) >> PAGE_SHIFT;

	set_pages_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE);
}

static int vmgexit_ap_control(u64 event, struct sev_es_save_area *vmsa,
			      u32 apic_id)
{
	bool create = event != SVM_VMGEXIT_AP_DESTROY;
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	int ret = 0;

	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);

	if (create)
		ghcb_set_rax(ghcb, vmsa->sev_features);

	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_CREATION);
	ghcb_set_sw_exit_info_1(ghcb, ((u64)apic_id << 32) |
					      ((u64)snp_vmpl << 16) | event);
	ghcb_set_sw_exit_info_2(ghcb, __pa(vmsa));

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (!ghcb_sw_exit_info_1_is_valid(ghcb) ||
	    lower_32_bits(ghcb->save.sw_exit_info_1)) {
		pr_err("SNP AP %s error\n", (create ? "CREATE" : "DESTROY"));
		ret = -EINVAL;
	}

	__sev_put_ghcb(&state);

	local_irq_restore(flags);

	return ret;
}

static int snp_set_vmsa(void *va, void *caa, int apic_id, bool make_vmsa)
{
	int ret;

	if (snp_vmpl) {
		struct svsm_call call = {};
		unsigned long flags;

		local_irq_save(flags);

		call.caa = this_cpu_read(svsm_caa);
		call.rcx = __pa(va);

		if (make_vmsa) {
			/* Protocol 0, Call ID 2 */
			call.rax = SVSM_CORE_CALL(SVSM_CORE_CREATE_VCPU);
			call.rdx = __pa(caa);
			call.r8 = apic_id;
		} else {
			/* Protocol 0, Call ID 3 */
			call.rax = SVSM_CORE_CALL(SVSM_CORE_DELETE_VCPU);
		}

		ret = svsm_perform_call_protocol(&call);

		local_irq_restore(flags);
	} else {
		/*
		 * If the kernel runs at VMPL0, it can change the VMSA
		 * bit for a page using the RMPADJUST instruction.
		 * However, for the instruction to succeed it must
		 * target the permissions of a lesser privileged (higher
		 * numbered) VMPL level, so use VMPL1.
		 */
		u64 attrs = 1;

		if (make_vmsa)
			attrs |= RMPADJUST_VMSA_PAGE_BIT;

		ret = rmpadjust((unsigned long)va, RMP_PG_SIZE_4K, attrs);
	}

	return ret;
}

static int force_map_va_range_in_pgd(pgd_t *pgd_base, unsigned long va_start,
				     unsigned long va_end, phys_addr_t pa_start,
				     unsigned long flags, bool overwrite_present)
{
	unsigned long addr;
	phys_addr_t paddr = pa_start;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	for (addr = va_start; addr < va_end;
	     addr += PAGE_SIZE, paddr += PAGE_SIZE) {
		/* --- Level 4: PGD --- */
		pgd = pgd_base + pgd_index(addr);

		if (pgd_none(*pgd)) {
			void *new_page = alloc_page_table_safe();
			if (!new_page)
				return -ENOMEM;

			set_pgd(pgd, __pgd(__pa(new_page) | 0x67 | _ENC));
		}

		p4d = p4d_offset(pgd, addr);

		/* --- Level 3: PUD --- */
		if (pud_none(*pud_offset(p4d, addr))) {
			void *new_page = alloc_page_table_safe();
			if (!new_page)
				return -ENOMEM;
			set_pud(pud_offset(p4d, addr),
				__pud(__pa(new_page) | 0x63 | _ENC));
		}
		pud = pud_offset(p4d, addr);

		/* --- Level 2: PMD --- */
		if (pmd_none(*pmd_offset(pud, addr))) {
			void *new_page = alloc_page_table_safe();
			if (!new_page)
				return -ENOMEM;

			set_pmd(pmd_offset(pud, addr),
				__pmd(__pa(new_page) | 0x67 | _ENC));
		}
		pmd = pmd_offset(pud, addr);

		/* --- Level 1: PTE --- */
		pte = pte_offset_kernel(pmd, addr);

		if (!overwrite_present && !pte_none(*pte))
			continue;

		set_pte(pte, __pte(paddr | 0x167 | _ENC));
	}

	return 0;
}

static int force_map_va_range(unsigned long va_start, unsigned long va_end,
			      phys_addr_t pa_start, unsigned long flags)
{
	return force_map_va_range_in_pgd(init_mm.pgd, va_start, va_end,
					 pa_start, flags, true);
}

static int map_vmpl1_percpu_current_mm(struct mm_struct *mm)
{
	int cpu = smp_processor_id();
	phys_addr_t pa = this_cpu_read(svsm_vmpl1_percpu_pa);
	unsigned long va = SVSM_PERCPU_BASE + (cpu * PMD_SIZE);
	int ret;

	if (!mm || !pa)
		return -EINVAL;

	ret = force_map_va_range_in_pgd(mm->pgd, va, va + PAGE_SIZE, pa,
					0x163, true);
	if (ret)
		pr_err("SVSM: CPU%d failed to map VMPL1 per-cpu VA %lx into current mm, PA %llx ret=%d\n",
		       cpu, va, (unsigned long long)pa, ret);
	else
		pr_debug("SVSM: CPU%d mapped VMPL1 per-cpu VA %lx into current mm -> PA %llx\n",
			 cpu, va, (unsigned long long)pa);

	return ret;
}

int svsm_deko_load_policy(u32 domain_id, const void *buf, u64 len)
{
	struct svsm_call call = { 0 };
	struct deko_load_policy_req *req;
	void *policy_buf;
	phys_addr_t req_pa;
	unsigned long flags;
	int ret = 0;

	if (!domain_id || !buf || !len)
		return -EINVAL;
	if (len > DEKO_MAX_POLICY_BLOB_SIZE)
		return -E2BIG;

	policy_buf = alloc_pages_exact(len, GFP_KERNEL);
	if (!policy_buf)
		return -ENOMEM;

	memcpy(policy_buf, buf, len);

	local_irq_save(flags);

	req = (struct deko_load_policy_req *)(svsm_get_caa()->svsm_buffer);
	req_pa = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);

	req->domain_id = domain_id;
	req->reserved = 0;
	req->blob_gpa = __pa(policy_buf);
	req->blob_len = len;

	call.caa = svsm_get_caa();
	call.r9 = req_pa;
	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_LOAD_POLICY);

	if (svsm_perform_call_protocol(&call))
		ret = -EOPNOTSUPP;

	local_irq_restore(flags);
	free_pages_exact(policy_buf, len);
	return ret;
}
EXPORT_SYMBOL_GPL(svsm_deko_load_policy);

static void make_va_decrypted_in_pgd(pgd_t *pgd_base, unsigned long va)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* 1. Walk PGD */
	pgd = pgd_base + pgd_index(va);
	if (pgd_none(*pgd))
		return;

	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d))
		return;

	/* 2. Walk PUD */
	pud = pud_offset(p4d, va);
	if (pud_none(*pud))
		return;

	/* 3. Walk PMD */
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
		return;

	if ((pmd_val(*pmd) & _PAGE_PSE)) {
		unsigned long val = pmd_val(*pmd);

		val &= ~_ENC;
		set_pmd(pmd, __pmd(val));
		pr_debug("SVSM: GHCB VA %lx (PMD Huge) marked as Decrypted to %lx.\n",
			 va, val);
		return;
	}

	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
		return;

	unsigned long val = pte_val(*pte);
	val &= ~_ENC;
	set_pte(pte, __pte(val));

	pr_debug("SVSM: GHCB VA %lx (PTE 4K) marked as Decrypted to %lx.\n", va,
		 val);
}

static void make_va_decrypted(unsigned long va)
{
	make_va_decrypted_in_pgd(init_mm.pgd, va);
}

int svsm_prepare_vmpl1_current_mm(struct mm_struct *mm)
{
	unsigned long ghcb_va = this_cpu_read(svsm_vmpl1_ghcb_va);
	unsigned long db_va = this_cpu_read(svsm_vmpl1_db_va);
	u16 i, map_count = READ_ONCE(svsm_vmpl1_global_map_count);
	int ret;

	if (!mm)
		return -EINVAL;

	for (i = 0; i < map_count; i++) {
		struct svsm_map_ifc_single_req *map = &svsm_vmpl1_global_maps[i];

		ret = force_map_va_range_in_pgd(mm->pgd, map->va_start,
						map->va_end, map->pa_start,
						0x163, false);
		if (ret) {
			pr_err("SVSM: failed to map VMPL1 global VA %llx..%llx into current mm, PA %llx ret=%d\n",
			       map->va_start, map->va_end, map->pa_start, ret);
			return ret;
		}
	}

	ret = map_vmpl1_percpu_current_mm(mm);
	if (ret)
		return ret;

	if (ghcb_va)
		make_va_decrypted_in_pgd(mm->pgd, ghcb_va);
	if (db_va)
		make_va_decrypted_in_pgd(mm->pgd, db_va);

	__flush_tlb_all();
	return 0;
}
EXPORT_SYMBOL_GPL(svsm_prepare_vmpl1_current_mm);

static void process_map_vmpl1(struct svsm_map_ifc_req *req)
{
	size_t i;
	struct svsm_map_ifc_single_req *cur;
	int cpu;
	u64 ghcb_va, db_va;
	unsigned long calculated_va;
	u16 global_map_count = 0;

	for (i = 0; i < req->req_len; i++) {
		cur = &req->reqs[i];

		if (!cur->is_per_cpu) {
			if (smp_processor_id() == 0) {
				if (global_map_count <
				    ARRAY_SIZE(svsm_vmpl1_global_maps))
					svsm_vmpl1_global_maps[global_map_count++] =
						*cur;
				force_map_va_range(cur->va_start, cur->va_end,
						   cur->pa_start, 0x163);
			}
		} else {
			cpu = smp_processor_id();
			calculated_va = SVSM_PERCPU_BASE + (cpu * PMD_SIZE);

			pr_debug("SVSM: CPU%d Mapping Per-CPU VA %lx -> PA %llx\n",
				 cpu, calculated_va, cur->pa_start);
			this_cpu_write(svsm_vmpl1_percpu_pa, cur->pa_start);

			if (force_map_va_range(calculated_va,
					       calculated_va + PAGE_SIZE,
					       cur->pa_start, 0x163))
				pr_err("Mapping PER-CPU failed.");
		}
	}
	if (smp_processor_id() == 0)
		WRITE_ONCE(svsm_vmpl1_global_map_count, global_map_count);

	ghcb_va = req->ghcb_va;
	db_va = req->db_va;
	this_cpu_write(svsm_vmpl1_ghcb_va, ghcb_va);
	this_cpu_write(svsm_vmpl1_db_va, db_va);
	make_va_decrypted(ghcb_va);
	make_va_decrypted(db_va);

	__flush_tlb_all();
}

/*
 * Leverage Linux's support for mapping the VMPL1 GHCB within it.
 *
 * The kernel cannot see the content nor write to the GHCB due to RMP protections
 * but it can help us manage the mapping in its kernel space so that we can utilize
 * the GHCB protocol for SVSM calls when VMPL1 is active.
 */
enum es_result svsm_map_vmpl1(void)
{
	struct svsm_call call = { 0 };

	call.caa = svsm_get_caa();
	struct svsm_map_ifc_req req = { 0 };
	unsigned long pa = get_anything_pa(&req);

	call.caa = svsm_get_caa();
	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_MAP_IFC);
	call.rcx = pa;

	if (svsm_perform_call_protocol(&call))
		return ES_UNSUPPORTED;

	process_map_vmpl1(&req);

	return ES_OK;
}

static void snp_cleanup_vmsa(struct sev_es_save_area *vmsa, int apic_id)
{
	int err;

	err = snp_set_vmsa(vmsa, NULL, apic_id, false);
	if (err)
		pr_err("clear VMSA page failed (%u), leaking page\n", err);
	else
		free_page((unsigned long)vmsa);
}

static void set_pte_enc(pte_t *kpte, int level, void *va)
{
	struct pte_enc_desc d = {
		.kpte = kpte, .pte_level = level, .va = va, .encrypt = true
	};

	prepare_pte_enc(&d);
	set_pte_enc_mask(kpte, d.pfn, d.new_pgprot);
}

static bool deko_append_region(struct deko_new_app_req *req, u16 kind, u16 perm,
			       u32 flags, unsigned long mapped_start,
			       unsigned long mapped_end,
			       unsigned long exact_start,
			       unsigned long exact_end)
{
	struct deko_base_region_desc *prev;
	u16 idx;

	if (mapped_start >= mapped_end || exact_start >= exact_end)
		return true;

	if (req->region_count > 0) {
		prev = &req->regions[req->region_count - 1];
		if (prev->kind == kind && prev->perm == perm &&
		    prev->flags == flags && prev->mapped_end == mapped_start &&
		    prev->exact_end == exact_start) {
			prev->mapped_end = mapped_end;
			prev->exact_end = exact_end;
			return true;
		}
	}

	if (req->region_count >= DEKO_MAX_BASE_REGIONS)
		return false;

	idx = req->region_count;
	req->regions[idx].kind = kind;
	req->regions[idx].perm = perm;
	req->regions[idx].flags = flags;
	req->regions[idx].mapped_start = mapped_start;
	req->regions[idx].mapped_end = mapped_end;
	req->regions[idx].exact_start = exact_start;
	req->regions[idx].exact_end = exact_end;
	req->region_count = idx + 1;

	return true;
}

static u16 deko_region_perm_from_vma(const struct vm_area_struct *vma)
{
	u16 perm = 0;

	if (vma->vm_flags & VM_READ)
		perm |= DEKO_REGION_R;
	if (vma->vm_flags & VM_WRITE)
		perm |= DEKO_REGION_W;
	if (vma->vm_flags & VM_EXEC)
		perm |= DEKO_REGION_X;

	return perm;
}

static u16 deko_region_kind_from_vma(const struct vm_area_struct *vma,
				     const struct mm_struct *mm)
{
	if (vma_is_initial_stack(vma))
		return DEKO_BASE_REGION_STACK;
	if (vma->vm_flags & VM_EXEC)
		return DEKO_BASE_REGION_CODE;
	if (!(deko_region_perm_from_vma(vma) & DEKO_REGION_W))
		return vma->vm_file ? DEKO_BASE_REGION_RODATA :
				      DEKO_BASE_REGION_DATA;
	if (mm && vma->vm_start < mm->brk && vma->vm_end > mm->start_brk)
		return DEKO_BASE_REGION_HEAP;
	return DEKO_BASE_REGION_DATA;
}

static bool deko_should_log_report_vmas(const char *launch_identity)
{
	(void)launch_identity;
	return false;
}

static void deko_log_report_vmas_locked(const struct deko_new_app_req *req,
					struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	struct vma_iterator vmi;
	int i = 0;

	if (!mm)
		return;

	pr_info("report_app vma dump begin: pid=%d comm=%s launch_identity=%s mnt_ns_id=%llu domain_id=%u region_count=%u start_code=0x%lx end_code=0x%lx start_data=0x%lx end_data=0x%lx start_brk=0x%lx brk=0x%lx start_stack=0x%lx total_vm=%lu\n",
		task->pid, task->comm, req->launch_identity,
		(unsigned long long)req->mnt_ns_id, req->domain_id,
		req->region_count, mm->start_code, mm->end_code,
		mm->start_data, mm->end_data, mm->start_brk, mm->brk,
		mm->start_stack, mm->total_vm);

	for (i = 0; i < req->region_count; i++) {
		const struct deko_base_region_desc *r = &req->regions[i];

		pr_info("report_app req_region[%d]: kind=%u perm=0x%x flags=0x%x mapped=[0x%llx-0x%llx) exact=[0x%llx-0x%llx)\n",
			i, r->kind, r->perm, r->flags,
			(unsigned long long)r->mapped_start,
			(unsigned long long)r->mapped_end,
			(unsigned long long)r->exact_start,
			(unsigned long long)r->exact_end);
	}

	i = 0;
	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma) {
		u16 perm = deko_region_perm_from_vma(vma);

		if (vma->vm_file) {
			pr_info("report_app vma[%d]: range=[0x%lx-0x%lx) flags=0x%lx perm=0x%x pgoff=0x%lx file=%pD\n",
				i, vma->vm_start, vma->vm_end, vma->vm_flags,
				perm, vma->vm_pgoff, vma->vm_file);
		} else {
			pr_info("report_app vma[%d]: range=[0x%lx-0x%lx) flags=0x%lx perm=0x%x pgoff=0x%lx file=<anon>\n",
				i, vma->vm_start, vma->vm_end, vma->vm_flags,
				perm, vma->vm_pgoff);
		}

		i++;
	}

	pr_info("report_app vma dump end: pid=%d comm=%s launch_identity=%s vma_count=%d\n",
		task->pid, task->comm, req->launch_identity, i);
}

static void deko_fill_req_regions(struct deko_new_app_req *req,
				  struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	struct vma_iterator vmi;

	if (!mm)
		return;

	vma_iter_init(&vmi, mm, 0);

	for_each_vma(vmi, vma) {
		u16 perm = deko_region_perm_from_vma(vma);
		u16 kind;
		u32 flags = 0;
		unsigned long start = vma->vm_start;
		unsigned long end = vma->vm_end;

		if (!perm) {
			if (req->region_count >= DEKO_MAX_BASE_REGIONS)
				break;
			continue;
		}

		kind = deko_region_kind_from_vma(vma, mm);

		if (kind == DEKO_BASE_REGION_STACK &&
		    (vma->vm_flags & VM_GROWSDOWN))
			flags |= DEKO_REGION_F_GROWSDOWN;
		else if (kind == DEKO_BASE_REGION_DATA &&
			 (perm & DEKO_REGION_W))
			flags |= DEKO_REGION_F_TEMPLATE_RW;
		if ((perm & DEKO_REGION_X) && is_cow_mapping(vma->vm_flags))
			flags |= DEKO_REGION_F_COW_ELIGIBLE |
				 DEKO_REGION_F_MEASURE_ON_FAULT;

		if (!deko_append_region(req, kind, perm, flags, start, end,
					start, end))
			break;
	}
}

enum es_result svsm_deko_new_app_req(struct task_struct *task, u64 ns_id,
				     const char *launch_identity,
				     u64 report_kind, unsigned long *token_low,
				     unsigned long *token_high,
				     enum deko_new_app_type ty)
{
	enum es_result ret = ES_OK;
	phys_addr_t req_pa;
	struct deko_new_app_req *req;
	struct deko_new_app_req *tmp;
	struct svsm_call call = { 0 };
	bool creation = report_kind != DEKO_REPORT_APP_LIFECYCLE;
	unsigned long flags;
	int call_ret;

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return ES_UNSUPPORTED;

	tmp->version = DEKO_NEW_APP_REQ_VERSION_V3;
	tmp->req_size = sizeof(*tmp);
	tmp->pid = task->pid;
	tmp->ppid = (task == current) ? task->real_parent->pid : current->pid;
	tmp->tgid = task->tgid;
	tmp->uid = current_cred()->uid.val;
	tmp->domain_id = 0;
	tmp->mnt_ns_id = 0;
	tmp->start_brk = task->mm ? task->mm->start_brk : 0;
	tmp->brk = task->mm ? task->mm->brk : 0;

	tmp->fs_base = x86_fsbase_read_task(task);
	tmp->gs_base = x86_gsbase_read_task(task);
	tmp->kernel_gs_base = cpu_kernelmode_gs_base(task_cpu(task)) +
		(unsigned long)__per_cpu_start;
	tmp->app_type = ty;

	strscpy(tmp->comm, task->comm, sizeof(tmp->comm));
	if (launch_identity && launch_identity[0])
		strscpy(tmp->launch_identity, launch_identity,
			sizeof(tmp->launch_identity));
	else
		strscpy(tmp->launch_identity, task->comm,
			sizeof(tmp->launch_identity));

	if (task->nsproxy && task->nsproxy->mnt_ns)
		tmp->mnt_ns_id = ns_id;

	if (ty == DEKO_DOCKER_APPS) {
		if (deko_domain_lookup(tmp->mnt_ns_id, &tmp->domain_id)) {
			pr_err("report_app domain lookup failed: pid=%d comm=%s mnt_ns_id=%llu creation=%u\n",
			       task->pid, task->comm,
			       (unsigned long long)tmp->mnt_ns_id,
			       creation ? 1 : 0);
			ret = ES_UNSUPPORTED;
			goto out_free;
		}
	}

	if (task->mm) {
		if (task == current) {
			int prepare_ret;

			migrate_disable();
			prepare_ret = svsm_prepare_vmpl1_current_mm(task->mm);
			migrate_enable();
			if (prepare_ret) {
				ret = ES_UNSUPPORTED;
				goto out_free;
			}
		}

		mmap_read_lock(task->mm);
		deko_fill_req_regions(tmp, task);
		if (deko_should_log_report_vmas(tmp->launch_identity))
			deko_log_report_vmas_locked(tmp, task);
		mmap_read_unlock(task->mm);
	}

	pr_info("report app live state pid=%d comm=%s hw_cr3_pa=0x%llx mm_pgd_pa=0x%llx mm_pgd=%px fs_base=0x%llx gs_base=0x%llx kernel_gs_base=0x%llx creation=%u\n",
		task->pid, task->comm, (unsigned long long)read_cr3_pa(),
		task->mm ? (unsigned long long)__sme_pa(task->mm->pgd) : 0ULL,
		task->mm ? task->mm->pgd : NULL,
		(unsigned long long)tmp->fs_base,
		(unsigned long long)tmp->gs_base,
		(unsigned long long)tmp->kernel_gs_base,
		creation ? 1 : 0);
	log_report_app_cpu_tss_sp2(task, tmp);

	local_irq_save(flags);

	/* Re-use the SVSM buffer for allocating the request body. */
	req = (struct deko_new_app_req *)(svsm_get_caa()->svsm_buffer);
	req_pa = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);
	memcpy(req, tmp, sizeof(*tmp));

	pr_info("report_app submitting: pid=%d tgid=%d ppid=%d comm=%s launch_identity=%s report_kind=0x%llx app_type=%u req_pa=0x%llx mnt_ns_id=%llu domain_id=%u region_count=%u current_pid=%d current_tgid=%d\n",
		task->pid, task->tgid, tmp->ppid, task->comm,
		tmp->launch_identity, (unsigned long long)report_kind,
		tmp->app_type, (unsigned long long)req_pa,
		(unsigned long long)tmp->mnt_ns_id, tmp->domain_id,
		tmp->region_count, current->pid, current->tgid);

	call.caa = svsm_get_caa();
	call.r9 = req_pa;
	call.r8 = report_kind;
	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_REPORT_APP);

	call_ret = svsm_perform_call_protocol(&call);
	memcpy(tmp, req, sizeof(*tmp));

	local_irq_restore(flags);

	if (call_ret) {
		pr_err("report_app rejected: pid=%d comm=%s launch_identity=%s creation=%u call_ret=%d rax_out=0x%llx rcx_out=0x%llx rdx_out=0x%llx r8_out=0x%llx r9_out=0x%llx domain_id=%u mnt_ns_id=%llu version=%u req_size=%u region_count=%u hw_cr3_pa=0x%llx mm_pgd_pa=0x%llx fs_base=0x%llx gs_base=0x%llx kernel_gs_base=0x%llx\n",
		       task->pid, task->comm, tmp->launch_identity,
		       creation ? 1 : 0, call_ret, call.rax_out,
		       call.rcx_out, call.rdx_out, call.r8_out,
		       call.r9_out, tmp->domain_id,
		       (unsigned long long)tmp->mnt_ns_id, tmp->version,
		       tmp->req_size, tmp->region_count,
		       (unsigned long long)read_cr3_pa(),
		       task->mm ? (unsigned long long)__sme_pa(task->mm->pgd) :
				  0ULL,
		       (unsigned long long)tmp->fs_base,
		       (unsigned long long)tmp->gs_base,
		       (unsigned long long)tmp->kernel_gs_base);
		ret = ES_UNSUPPORTED;
	} else {
		pr_info("report_app accepted: pid=%d tgid=%d ppid=%d comm=%s launch_identity=%s report_kind=0x%llx app_type=%u rax_out=0x%llx rcx_out=0x%llx rdx_out=0x%llx r8_out=0x%llx r9_out=0x%llx domain_id=%u mnt_ns_id=%llu region_count=%u kernel_vmpl1_rsp=0x%llx\n",
			task->pid, task->tgid, tmp->ppid, task->comm,
			tmp->launch_identity, (unsigned long long)report_kind,
			tmp->app_type, call.rax_out, call.rcx_out,
			call.rdx_out, call.r8_out, call.r9_out,
			tmp->domain_id, (unsigned long long)tmp->mnt_ns_id,
			tmp->region_count,
			(unsigned long long)tmp->kernel_vmpl1_rsp);
	}

	if (creation && ty == DEKO_DOCKER_APPS) {
		*token_low = tmp->kernel_vmpl1_rsp;
		*token_high = 0;
	}

out_free:
	kfree(tmp);
	return ret;
}

static void unshare_all_memory(void)
{
	unsigned long addr, end, size, ghcb;
	struct sev_es_runtime_data *data;
	unsigned int npages, level;
	bool skipped_addr;
	pte_t *pte;
	int cpu;

	/* Unshare the direct mapping. */
	addr = PAGE_OFFSET;
	end = PAGE_OFFSET + get_max_mapped();

	while (addr < end) {
		pte = lookup_address(addr, &level);
		size = page_level_size(level);
		npages = size / PAGE_SIZE;
		skipped_addr = false;

		if (!pte || !pte_decrypted(*pte) || pte_none(*pte)) {
			addr += size;
			continue;
		}

		/*
		 * Ensure that all the per-CPU GHCBs are made private at the
		 * end of the unsharing loop so that the switch to the slower
		 * MSR protocol happens last.
		 */
		for_each_possible_cpu(cpu) {
			data = per_cpu(runtime_data, cpu);
			ghcb = (unsigned long)&data->ghcb_page;

			/* Handle the case of a huge page containing the GHCB page */
			if (addr <= ghcb && ghcb < addr + size) {
				skipped_addr = true;
				break;
			}
		}

		if (!skipped_addr) {
			set_pte_enc(pte, level, (void *)addr);
			snp_set_memory_private(addr, npages);
		}
		addr += size;
	}

	/* Unshare all bss decrypted memory. */
	addr = (unsigned long)__start_bss_decrypted;
	end = (unsigned long)__start_bss_decrypted_unused;
	npages = (end - addr) >> PAGE_SHIFT;

	for (; addr < end; addr += PAGE_SIZE) {
		pte = lookup_address(addr, &level);
		if (!pte || !pte_decrypted(*pte) || pte_none(*pte))
			continue;

		set_pte_enc(pte, level, (void *)addr);
	}
	addr = (unsigned long)__start_bss_decrypted;
	snp_set_memory_private(addr, npages);

	__flush_tlb_all();
}

/* Stop new private<->shared conversions */
void snp_kexec_begin(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return;

	if (!IS_ENABLED(CONFIG_KEXEC_CORE))
		return;

	/*
	 * Crash kernel ends up here with interrupts disabled: can't wait for
	 * conversions to finish.
	 *
	 * If race happened, just report and proceed.
	 */
	if (!set_memory_enc_stop_conversion())
		pr_warn("Failed to stop shared<->private conversions\n");
}

/*
 * Shutdown all APs except the one handling kexec/kdump and clearing
 * the VMSA tag on AP's VMSA pages as they are not being used as
 * VMSA page anymore.
 */
static void shutdown_all_aps(void)
{
	struct sev_es_save_area *vmsa;
	int apic_id, this_cpu, cpu;

	this_cpu = get_cpu();

	/*
	 * APs are already in HLT loop when enc_kexec_finish() callback
	 * is invoked.
	 */
	for_each_present_cpu(cpu) {
		vmsa = per_cpu(sev_vmsa, cpu);

		/*
		 * The BSP or offlined APs do not have guest allocated VMSA
		 * and there is no need  to clear the VMSA tag for this page.
		 */
		if (!vmsa)
			continue;

		/*
		 * Cannot clear the VMSA tag for the currently running vCPU.
		 */
		if (this_cpu == cpu) {
			unsigned long pa;
			struct page *p;

			pa = __pa(vmsa);
			/*
			 * Mark the VMSA page of the running vCPU as offline
			 * so that is excluded and not touched by makedumpfile
			 * while generating vmcore during kdump.
			 */
			p = pfn_to_online_page(pa >> PAGE_SHIFT);
			if (p)
				__SetPageOffline(p);
			continue;
		}

		apic_id = cpuid_to_apicid[cpu];

		/*
		 * Issue AP destroy to ensure AP gets kicked out of guest mode
		 * to allow using RMPADJUST to remove the VMSA tag on it's
		 * VMSA page.
		 */
		vmgexit_ap_control(SVM_VMGEXIT_AP_DESTROY, vmsa, apic_id);
		snp_cleanup_vmsa(vmsa, apic_id);
	}

	put_cpu();
}

/*
 * "Allocate" an isolated region from the VM hole for the trampoline code.
 * This region shall never interfere with any other memory used by the linux
 * kernel so we can reduce the overhead of page faults handling etc. if
 * any other code is trying to R/W the data/code that coincidentally share
 * the same intermedate page translation paths.
 */
int alloc_isolated_trampoline(void)
{
	char *cpu_trampoline_va;
	int ret;

	if (!trampoline_pa_base) {
		trampoline_pa_base = alloc_stolen_mem(PMD_SIZE);
		if (!trampoline_pa_base) {
			pr_err("Failed to allocate trampoline backing memory\n");
			return -ENOMEM;
		}
	}

	if (!deko_ifc_policy_engine_mem) {
		deko_ifc_policy_engine_mem =
			alloc_stolen_mem(DEKO_IFC_POLICY_ENGINE_MEM_SIZE);
		if (!deko_ifc_policy_engine_mem) {
			pr_err("Failed to allocate IFC policy engine memory\n");
			/*
			 * Need to free the memory but returning this eventually
			 * panics the system so should be fine.
			 */
			return -ENOMEM;
		}
	}

	if (!trampoline_va_base) {
		trampoline_va_base = choose_trampoline_va_base();
		if (!trampoline_va_base) {
			pr_err("Failed to find an empty trampoline PGD slot\n");
			return -ENOMEM;
		}

		pr_info("Selected trampoline VA base: 0x%lx\n",
			trampoline_va_base);
	}

	cpu_trampoline_va = __va(trampoline_pa_base);

	/* Copy the trampoline code to the allocated region. */
	memcpy(cpu_trampoline_va, trampoline_init_magic,
	       sizeof(trampoline_init_magic));

	/*
	 * Now we utilize the "hole" for placing the trampoline code.
	 *
	 * This avoids interference with other kernel functionalities and ensure
	 * no potential #PF will occur.
	 */
	ret = claim_whole_pgd_entry();
	if (ret) {
		pr_err("Failed to claim trampoline PGD slot @ 0x%lx, err: %d\n",
		       trampoline_va_base, ret);
		return ret;
	}

	ret = set_up_deko_ifc_policy_engine_mapping();
	if (ret) {
		pr_err("Failed to map IFC policy engine memory, err: %d\n",
		       ret);
		return ret;
	}

	return 0;
}

void snp_kexec_finish(void)
{
	struct sev_es_runtime_data *data;
	unsigned long size, addr;
	unsigned int level, cpu;
	struct ghcb *ghcb;
	pte_t *pte;

	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return;

	if (!IS_ENABLED(CONFIG_KEXEC_CORE))
		return;

	shutdown_all_aps();

	unshare_all_memory();

	/*
	 * Switch to using the MSR protocol to change per-CPU GHCBs to
	 * private. All the per-CPU GHCBs have been switched back to private,
	 * so can't do any more GHCB calls to the hypervisor beyond this point
	 * until the kexec'ed kernel starts running.
	 */
	boot_ghcb = NULL;
	sev_cfg.ghcbs_initialized = false;

	for_each_possible_cpu(cpu) {
		data = per_cpu(runtime_data, cpu);
		ghcb = &data->ghcb_page;
		pte = lookup_address((unsigned long)ghcb, &level);
		size = page_level_size(level);
		/* Handle the case of a huge page containing the GHCB page */
		addr = (unsigned long)ghcb & page_level_mask(level);
		set_pte_enc(pte, level, (void *)addr);
		snp_set_memory_private(addr, (size / PAGE_SIZE));
	}
}

#define __ATTR_BASE (SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK)
#define INIT_CS_ATTRIBS \
	(__ATTR_BASE | SVM_SELECTOR_READ_MASK | SVM_SELECTOR_CODE_MASK)
#define INIT_DS_ATTRIBS (__ATTR_BASE | SVM_SELECTOR_WRITE_MASK)

#define INIT_LDTR_ATTRIBS (SVM_SELECTOR_P_MASK | 2)
#define INIT_TR_ATTRIBS (SVM_SELECTOR_P_MASK | 3)

static void *snp_alloc_vmsa_page(int cpu)
{
	struct page *p;

	/*
	 * Allocate VMSA page to work around the SNP erratum where the CPU will
	 * incorrectly signal an RMP violation #PF if a large page (2MB or 1GB)
	 * collides with the RMP entry of VMSA page. The recommended workaround
	 * is to not use a large page.
	 *
	 * Allocate an 8k page which is also 8k-aligned.
	 */
	p = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL_ACCOUNT | __GFP_ZERO,
			     1);
	if (!p)
		return NULL;

	split_page(p, 1);

	/* Free the first 4k. This page may be 2M/1G aligned and cannot be used. */
	__free_page(p);

	return page_address(p + 1);
}

static int wakeup_cpu_via_vmgexit(u32 apic_id, unsigned long start_ip,
				  unsigned int cpu)
{
	struct sev_es_save_area *cur_vmsa, *vmsa;
	struct svsm_ca *caa;
	u8 sipi_vector;
	int ret;
	u64 cr4;

	/*
	 * The hypervisor SNP feature support check has happened earlier, just check
	 * the AP_CREATION one here.
	 */
	if (!(sev_hv_features & GHCB_HV_FT_SNP_AP_CREATION))
		return -EOPNOTSUPP;

	/*
	 * Verify the desired start IP against the known trampoline start IP
	 * to catch any future new trampolines that may be introduced that
	 * would require a new protected guest entry point.
	 */
	if (WARN_ONCE(start_ip != real_mode_header->trampoline_start,
		      "Unsupported SNP start_ip: %lx\n", start_ip))
		return -EINVAL;

	/* Override start_ip with known protected guest start IP */
	start_ip = real_mode_header->sev_es_trampoline_start;
	cur_vmsa = per_cpu(sev_vmsa, cpu);

	/*
	 * A new VMSA is created each time because there is no guarantee that
	 * the current VMSA is the kernels or that the vCPU is not running. If
	 * an attempt was done to use the current VMSA with a running vCPU, a
	 * #VMEXIT of that vCPU would wipe out all of the settings being done
	 * here.
	 */
	vmsa = (struct sev_es_save_area *)snp_alloc_vmsa_page(cpu);
	if (!vmsa)
		return -ENOMEM;

	/* If an SVSM is present, the SVSM per-CPU CAA will be !NULL */
	caa = per_cpu(svsm_caa, cpu);

	/* CR4 should maintain the MCE value */
	cr4 = native_read_cr4() & X86_CR4_MCE;

	/* Set the CS value based on the start_ip converted to a SIPI vector */
	sipi_vector = (start_ip >> 12);
	vmsa->cs.base = sipi_vector << 12;
	vmsa->cs.limit = AP_INIT_CS_LIMIT;
	vmsa->cs.attrib = INIT_CS_ATTRIBS;
	vmsa->cs.selector = sipi_vector << 8;

	/* Set the RIP value based on start_ip */
	vmsa->rip = start_ip & 0xfff;

	/* Set AP INIT defaults as documented in the APM */
	vmsa->ds.limit = AP_INIT_DS_LIMIT;
	vmsa->ds.attrib = INIT_DS_ATTRIBS;
	vmsa->es = vmsa->ds;
	vmsa->fs = vmsa->ds;
	vmsa->gs = vmsa->ds;
	vmsa->ss = vmsa->ds;

	vmsa->gdtr.limit = AP_INIT_GDTR_LIMIT;
	vmsa->ldtr.limit = AP_INIT_LDTR_LIMIT;
	vmsa->ldtr.attrib = INIT_LDTR_ATTRIBS;
	vmsa->idtr.limit = AP_INIT_IDTR_LIMIT;
	vmsa->tr.limit = AP_INIT_TR_LIMIT;
	vmsa->tr.attrib = INIT_TR_ATTRIBS;

	vmsa->cr4 = cr4;
	vmsa->cr0 = AP_INIT_CR0_DEFAULT;
	vmsa->dr7 = DR7_RESET_VALUE;
	vmsa->dr6 = AP_INIT_DR6_DEFAULT;
	vmsa->rflags = AP_INIT_RFLAGS_DEFAULT;
	vmsa->g_pat = AP_INIT_GPAT_DEFAULT;
	vmsa->xcr0 = AP_INIT_XCR0_DEFAULT;
	vmsa->mxcsr = AP_INIT_MXCSR_DEFAULT;
	vmsa->x87_ftw = AP_INIT_X87_FTW_DEFAULT;
	vmsa->x87_fcw = AP_INIT_X87_FCW_DEFAULT;

	if (cc_platform_has(CC_ATTR_SNP_SECURE_AVIC))
		vmsa->vintr_ctrl |= V_GIF_MASK | V_NMI_ENABLE_MASK;

	/* SVME must be set. */
	vmsa->efer = EFER_SVME;

	/*
	 * Set the SNP-specific fields for this VMSA:
	 *   VMPL level
	 *   SEV_FEATURES (matches the SEV STATUS MSR right shifted 2 bits)
	 */
	vmsa->vmpl = snp_vmpl;
	vmsa->sev_features = sev_status >> 2;

	/* Populate AP's TSC scale/offset to get accurate TSC values. */
	if (cc_platform_has(CC_ATTR_GUEST_SNP_SECURE_TSC)) {
		vmsa->tsc_scale = snp_tsc_scale;
		vmsa->tsc_offset = snp_tsc_offset;
	}

	/* Switch the page over to a VMSA page now that it is initialized */
	ret = snp_set_vmsa(vmsa, caa, apic_id, true);
	if (ret) {
		pr_err("set VMSA page failed (%u)\n", ret);
		free_page((unsigned long)vmsa);

		return -EINVAL;
	}

	/* Issue VMGEXIT AP Creation NAE event */
	ret = vmgexit_ap_control(SVM_VMGEXIT_AP_CREATE, vmsa, apic_id);
	if (ret) {
		snp_cleanup_vmsa(vmsa, apic_id);
		vmsa = NULL;
	}

	/* Free up any previous VMSA page */
	if (cur_vmsa)
		snp_cleanup_vmsa(cur_vmsa, apic_id);

	/* Record the current VMSA page */
	per_cpu(sev_vmsa, cpu) = vmsa;

	return ret;
}

void __init snp_set_wakeup_secondary_cpu(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return;

	/*
	 * Always set this override if SNP is enabled. This makes it the
	 * required method to start APs under SNP. If the hypervisor does
	 * not support AP creation, then no APs will be started.
	 */
	apic_update_callback(wakeup_secondary_cpu, wakeup_cpu_via_vmgexit);
}

int __init sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	u16 startup_cs, startup_ip;
	phys_addr_t jump_table_pa;
	u64 jump_table_addr;
	u16 __iomem *jump_table;

	jump_table_addr = get_jump_table_addr();

	/* On UP guests there is no jump table so this is not a failure */
	if (!jump_table_addr)
		return 0;

	/* Check if AP Jump Table is page-aligned */
	if (jump_table_addr & ~PAGE_MASK)
		return -EINVAL;

	jump_table_pa = jump_table_addr & PAGE_MASK;

	startup_cs = (u16)(rmh->trampoline_start >> 4);
	startup_ip =
		(u16)(rmh->sev_es_trampoline_start - rmh->trampoline_start);

	jump_table = ioremap_encrypted(jump_table_pa, PAGE_SIZE);
	if (!jump_table)
		return -EIO;

	writew(startup_ip, &jump_table[0]);
	writew(startup_cs, &jump_table[1]);

	iounmap(jump_table);

	return 0;
}

phys_addr_t get_anything_pa(void *vaddr)
{
	unsigned long addr = (unsigned long)vaddr;
	struct page *page;

	if (is_vmalloc_addr(vaddr)) {
		page = vmalloc_to_page(vaddr);
		if (!page)
			return 0;
		return (page_to_pfn(page) << PAGE_SHIFT) | (addr & ~PAGE_MASK);
	}

	return __pa(addr);
}

/*
 * This is needed by the OVMF UEFI firmware which will use whatever it finds in
 * the GHCB MSR as its GHCB to talk to the hypervisor. So make sure the per-cpu
 * runtime GHCBs used by the kernel are also mapped in the EFI page-table.
 *
 * When running under SVSM the CA page is needed too, so map it as well.
 */
int __init sev_es_efi_map_ghcbs_cas(pgd_t *pgd)
{
	unsigned long address, pflags, pflags_enc;
	struct sev_es_runtime_data *data;
	int cpu;
	u64 pfn;

	if (!cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		return 0;

	pflags = _PAGE_NX | _PAGE_RW;
	pflags_enc = cc_mkenc(pflags);

	for_each_possible_cpu(cpu) {
		data = per_cpu(runtime_data, cpu);

		address = __pa(&data->ghcb_page);
		pfn = address >> PAGE_SHIFT;

		if (kernel_map_pages_in_pgd(pgd, pfn, address, 1, pflags))
			return 1;

		if (snp_vmpl) {
			address = per_cpu(svsm_caa_pa, cpu);
			if (!address)
				return 1;

			pfn = address >> PAGE_SHIFT;
			if (kernel_map_pages_in_pgd(pgd, pfn, address, 1,
						    pflags_enc))
				return 1;
		}
	}

	return 0;
}

/*
 * Sets up the syscall entry point for the SVSM. This is needed for the SVSM to be able
 * to handle syscalls when running at VMPL1.
 *
 * The trampolien replaces the original syscall's body with a jump to the IFC engine, and
 * then re-uses the entry point to handle the syscalls.
 */
enum es_result svsm_handle_trampoline_setup(u64 sysenter_addr)
{
	enum es_result ret = ES_OK;
	struct svsm_sev_trampoline_setup_req *req;
	struct svsm_call call = { 0 };
	phys_addr_t req_pa;

	if (!trampoline_va_base || !trampoline_pa_base)
		return ES_UNSUPPORTED;

	call.caa = svsm_get_caa();

	/* Re-use the SVSM buffer for allocating the request body. */
	req = (struct svsm_sev_trampoline_setup_req *)(call.caa->svsm_buffer);
	req_pa = svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);
	call.r9 = req_pa;
	call.rax = SVSM_EXTEND_CALL(SVSM_EXTEND_TRAMPOLINE_SETUP);

	req->syscall_enter_addr = sysenter_addr;
	req->trampoline_gva = trampoline_va_base;
	req->trampoline_gpa = trampoline_pa_base;

	if (svsm_perform_call_protocol(&call)) {
		ret = ES_UNSUPPORTED;
		goto out;
	}

out:
	return ret;
}

u64 savic_ghcb_msr_read(u32 reg)
{
	u64 msr = APIC_BASE_MSR + (reg >> 4);
	struct pt_regs regs = { .cx = msr };
	struct es_em_ctxt ctxt = { .regs = &regs };
	struct ghcb_state state;
	enum es_result res;
	struct ghcb *ghcb;

	guard(irqsave)();

	ghcb = __sev_get_ghcb(&state);
	vc_ghcb_invalidate(ghcb);

	res = sev_es_ghcb_handle_msr(ghcb, &ctxt, false);
	if (res != ES_OK) {
		pr_err("Secure AVIC MSR (0x%llx) read returned error (%d)\n",
		       msr, res);
		/* MSR read failures are treated as fatal errors */
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_SAVIC_FAIL);
	}

	__sev_put_ghcb(&state);

	return regs.ax | regs.dx << 32;
}

void savic_ghcb_msr_write(u32 reg, u64 value)
{
	u64 msr = APIC_BASE_MSR + (reg >> 4);
	struct pt_regs regs = { .cx = msr,
				.ax = lower_32_bits(value),
				.dx = upper_32_bits(value) };
	struct es_em_ctxt ctxt = { .regs = &regs };
	struct ghcb_state state;
	enum es_result res;
	struct ghcb *ghcb;

	guard(irqsave)();

	ghcb = __sev_get_ghcb(&state);
	vc_ghcb_invalidate(ghcb);

	res = sev_es_ghcb_handle_msr(ghcb, &ctxt, true);
	if (res != ES_OK) {
		pr_err("Secure AVIC MSR (0x%llx) write returned error (%d)\n",
		       msr, res);
		/* MSR writes should never fail. Any failure is fatal error for SNP guest */
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_SAVIC_FAIL);
	}

	__sev_put_ghcb(&state);
}

enum es_result savic_register_gpa(u64 gpa)
{
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result res;
	struct ghcb *ghcb;

	guard(irqsave)();

	ghcb = __sev_get_ghcb(&state);
	vc_ghcb_invalidate(ghcb);

	ghcb_set_rax(ghcb, SVM_VMGEXIT_SAVIC_SELF_GPA);
	ghcb_set_rbx(ghcb, gpa);
	res = sev_es_ghcb_hv_call(ghcb, &ctxt, SVM_VMGEXIT_SAVIC,
				  SVM_VMGEXIT_SAVIC_REGISTER_GPA, 0);

	__sev_put_ghcb(&state);

	return res;
}

enum es_result savic_unregister_gpa(u64 *gpa)
{
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result res;
	struct ghcb *ghcb;

	guard(irqsave)();

	ghcb = __sev_get_ghcb(&state);
	vc_ghcb_invalidate(ghcb);

	ghcb_set_rax(ghcb, SVM_VMGEXIT_SAVIC_SELF_GPA);
	res = sev_es_ghcb_hv_call(ghcb, &ctxt, SVM_VMGEXIT_SAVIC,
				  SVM_VMGEXIT_SAVIC_UNREGISTER_GPA, 0);
	if (gpa && res == ES_OK)
		*gpa = ghcb->save.rbx;

	__sev_put_ghcb(&state);

	return res;
}

static void snp_register_per_cpu_ghcb(void)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	snp_register_ghcb_early(__pa(ghcb));
}

void setup_ghcb(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		return;

	/*
	 * Check whether the runtime #VC exception handler is active. It uses
	 * the per-CPU GHCB page which is set up by sev_es_init_vc_handling().
	 *
	 * If SNP is active, register the per-CPU GHCB page so that the runtime
	 * exception handler can use it.
	 */
	if (initial_vc_handler == (unsigned long)kernel_exc_vmm_communication) {
		if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
			snp_register_per_cpu_ghcb();

		sev_cfg.ghcbs_initialized = true;

		return;
	}

	/*
	 * Make sure the hypervisor talks a supported protocol.
	 * This gets called only in the BSP boot phase.
	 */
	if (!sev_es_negotiate_protocol())
		sev_es_terminate(SEV_TERM_SET_GEN, GHCB_SEV_ES_GEN_REQ);

	/*
	 * Clear the boot_ghcb. The first exception comes in before the bss
	 * section is cleared.
	 */
	memset(&boot_ghcb_page, 0, PAGE_SIZE);

	/* Alright - Make the boot-ghcb public */
	boot_ghcb = &boot_ghcb_page;

	/* SNP guest requires that GHCB GPA must be registered. */
	if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		snp_register_ghcb_early(__pa(&boot_ghcb_page));
}

#ifdef CONFIG_HOTPLUG_CPU
static void sev_es_ap_hlt_loop(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = __sev_get_ghcb(&state);

	while (true) {
		vc_ghcb_invalidate(ghcb);
		ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_HLT_LOOP);
		ghcb_set_sw_exit_info_1(ghcb, 0);
		ghcb_set_sw_exit_info_2(ghcb, 0);

		sev_es_wr_ghcb_msr(__pa(ghcb));
		VMGEXIT();

		/* Wakeup signal? */
		if (ghcb_sw_exit_info_2_is_valid(ghcb) &&
		    ghcb->save.sw_exit_info_2)
			break;
	}

	__sev_put_ghcb(&state);
}

/*
 * Play_dead handler when running under SEV-ES. This is needed because
 * the hypervisor can't deliver an SIPI request to restart the AP.
 * Instead the kernel has to issue a VMGEXIT to halt the VCPU until the
 * hypervisor wakes it up again.
 */
static void sev_es_play_dead(void)
{
	play_dead_common();

	/* IRQs now disabled */

	sev_es_ap_hlt_loop();

	/*
	 * If we get here, the VCPU was woken up again. Jump to CPU
	 * startup code to get it back online.
	 */
	soft_restart_cpu();
}
#else /* CONFIG_HOTPLUG_CPU */
#define sev_es_play_dead native_play_dead
#endif /* CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_SMP
static void __init sev_es_setup_play_dead(void)
{
	smp_ops.play_dead = sev_es_play_dead;
}
#else
static inline void sev_es_setup_play_dead(void)
{
}
#endif

static void __init alloc_runtime_data(int cpu)
{
	struct sev_es_runtime_data *data;

	data = memblock_alloc_node(sizeof(*data), PAGE_SIZE, cpu_to_node(cpu));
	if (!data)
		panic("Can't allocate SEV-ES runtime data");

	per_cpu(runtime_data, cpu) = data;

	if (snp_vmpl) {
		struct svsm_ca *caa;

		/* Allocate the SVSM CA page if an SVSM is present */
		caa = cpu ? memblock_alloc_or_panic(sizeof(*caa), PAGE_SIZE) :
			    &boot_svsm_ca_page;

		per_cpu(svsm_caa, cpu) = caa;
		per_cpu(svsm_caa_pa, cpu) = __pa(caa);
	}
}

static void __init init_ghcb(int cpu)
{
	struct sev_es_runtime_data *data;
	int err;

	data = per_cpu(runtime_data, cpu);

	err = early_set_memory_decrypted((unsigned long)&data->ghcb_page,
					 sizeof(data->ghcb_page));
	if (err)
		panic("Can't map GHCBs unencrypted");

	memset(&data->ghcb_page, 0, sizeof(data->ghcb_page));

	data->ghcb_active = false;
	data->backup_ghcb_active = false;
}

void __init sev_es_init_vc_handling(void)
{
	int cpu;

	BUILD_BUG_ON(offsetof(struct sev_es_runtime_data, ghcb_page) %
		     PAGE_SIZE);

	if (!cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		return;

	if (!sev_es_check_cpu_features())
		panic("SEV-ES CPU Features missing");

	/*
	 * SNP is supported in v2 of the GHCB spec which mandates support for HV
	 * features.
	 */
	if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP)) {
		sev_hv_features = get_hv_features();

		if (!(sev_hv_features & GHCB_HV_FT_SNP))
			sev_es_terminate(SEV_TERM_SET_GEN,
					 GHCB_SNP_UNSUPPORTED);
	}

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		alloc_runtime_data(cpu);
		init_ghcb(cpu);
	}

	if (snp_vmpl)
		sev_cfg.use_cas = true;

	sev_es_setup_play_dead();

	/* Secondary CPUs use the runtime #VC handler */
	initial_vc_handler = (unsigned long)kernel_exc_vmm_communication;
}

/*
 * SEV-SNP guests should only execute dmi_setup() if EFI_CONFIG_TABLES are
 * enabled, as the alternative (fallback) logic for DMI probing in the legacy
 * ROM region can cause a crash since this region is not pre-validated.
 */
void __init snp_dmi_setup(void)
{
	if (efi_enabled(EFI_CONFIG_TABLES))
		dmi_setup();
}

static void dump_cpuid_table(void)
{
	const struct snp_cpuid_table *cpuid_table = snp_cpuid_get_table();
	int i = 0;

	pr_info("count=%d reserved=0x%x reserved2=0x%llx\n", cpuid_table->count,
		cpuid_table->__reserved1, cpuid_table->__reserved2);

	for (i = 0; i < SNP_CPUID_COUNT_MAX; i++) {
		const struct snp_cpuid_fn *fn = &cpuid_table->fn[i];

		pr_info("index=%3d fn=0x%08x subfn=0x%08x: eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x xcr0_in=0x%016llx xss_in=0x%016llx reserved=0x%016llx\n",
			i, fn->eax_in, fn->ecx_in, fn->eax, fn->ebx, fn->ecx,
			fn->edx, fn->xcr0_in, fn->xss_in, fn->__reserved);
	}
}

/*
 * It is useful from an auditing/testing perspective to provide an easy way
 * for the guest owner to know that the CPUID table has been initialized as
 * expected, but that initialization happens too early in boot to print any
 * sort of indicator, and there's not really any other good place to do it,
 * so do it here.
 *
 * If running as an SNP guest, report the current VM privilege level (VMPL).
 */
static int __init report_snp_info(void)
{
	const struct snp_cpuid_table *cpuid_table = snp_cpuid_get_table();

	if (cpuid_table->count) {
		pr_info("Using SNP CPUID table, %d entries present.\n",
			cpuid_table->count);

		if (sev_cfg.debug)
			dump_cpuid_table();
	}

	if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		pr_info("SNP running at VMPL%u.\n", snp_vmpl);

	return 0;
}
arch_initcall(report_snp_info);

static void update_attest_input(struct svsm_call *call,
				struct svsm_attest_call *input)
{
	/* If (new) lengths have been returned, propagate them up */
	if (call->rcx_out != call->rcx)
		input->manifest_buf.len = call->rcx_out;

	if (call->rdx_out != call->rdx)
		input->certificates_buf.len = call->rdx_out;

	if (call->r8_out != call->r8)
		input->report_buf.len = call->r8_out;
}

int snp_issue_svsm_attest_req(u64 call_id, struct svsm_call *call,
			      struct svsm_attest_call *input)
{
	struct svsm_attest_call *ac;
	unsigned long flags;
	u64 attest_call_pa;
	int ret;

	if (!snp_vmpl)
		return -EINVAL;

	local_irq_save(flags);

	call->caa = svsm_get_caa();

	ac = (struct svsm_attest_call *)call->caa->svsm_buffer;
	attest_call_pa =
		svsm_get_caa_pa() + offsetof(struct svsm_ca, svsm_buffer);

	*ac = *input;

	/*
	 * Set input registers for the request and set RDX and R8 to known
	 * values in order to detect length values being returned in them.
	 */
	call->rax = call_id;
	call->rcx = attest_call_pa;
	call->rdx = -1;
	call->r8 = -1;
	ret = svsm_perform_call_protocol(call);
	update_attest_input(call, input);

	local_irq_restore(flags);

	return ret;
}
EXPORT_SYMBOL_GPL(snp_issue_svsm_attest_req);

static int snp_issue_guest_request(struct snp_guest_req *req)
{
	struct snp_req_data *input = &req->input;
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	unsigned long flags;
	struct ghcb *ghcb;
	int ret;

	req->exitinfo2 = SEV_RET_NO_FW_CALL;

	/*
	 * __sev_get_ghcb() needs to run with IRQs disabled because it is using
	 * a per-CPU GHCB.
	 */
	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);
	if (!ghcb) {
		ret = -EIO;
		goto e_restore_irq;
	}

	vc_ghcb_invalidate(ghcb);

	if (req->exit_code == SVM_VMGEXIT_EXT_GUEST_REQUEST) {
		ghcb_set_rax(ghcb, input->data_gpa);
		ghcb_set_rbx(ghcb, input->data_npages);
	}

	ret = sev_es_ghcb_hv_call(ghcb, &ctxt, req->exit_code, input->req_gpa,
				  input->resp_gpa);
	if (ret)
		goto e_put;

	req->exitinfo2 = ghcb->save.sw_exit_info_2;
	switch (req->exitinfo2) {
	case 0:
		break;

	case SNP_GUEST_VMM_ERR(SNP_GUEST_VMM_ERR_BUSY):
		ret = -EAGAIN;
		break;

	case SNP_GUEST_VMM_ERR(SNP_GUEST_VMM_ERR_INVALID_LEN):
		/* Number of expected pages are returned in RBX */
		if (req->exit_code == SVM_VMGEXIT_EXT_GUEST_REQUEST) {
			input->data_npages = ghcb_get_rbx(ghcb);
			ret = -ENOSPC;
			break;
		}
		fallthrough;
	default:
		ret = -EIO;
		break;
	}

e_put:
	__sev_put_ghcb(&state);
e_restore_irq:
	local_irq_restore(flags);

	return ret;
}

/**
 * snp_svsm_vtpm_probe() - Probe if SVSM provides a vTPM device
 *
 * Check that there is SVSM and that it supports at least TPM_SEND_COMMAND
 * which is the only request used so far.
 *
 * Return: true if the platform provides a vTPM SVSM device, false otherwise.
 */
static bool snp_svsm_vtpm_probe(void)
{
	struct svsm_call call = {};

	/* The vTPM device is available only if a SVSM is present */
	if (!snp_vmpl)
		return false;

	call.caa = svsm_get_caa();
	call.rax = SVSM_VTPM_CALL(SVSM_VTPM_QUERY);

	if (svsm_perform_call_protocol(&call))
		return false;

	/* Check platform commands contains TPM_SEND_COMMAND - platform command 8 */
	return call.rcx_out & BIT_ULL(8);
}

/**
 * snp_svsm_vtpm_send_command() - Execute a vTPM operation on SVSM
 * @buffer: A buffer used to both send the command and receive the response.
 *
 * Execute a SVSM_VTPM_CMD call as defined by
 * "Secure VM Service Module for SEV-SNP Guests" Publication # 58019 Revision: 1.00
 *
 * All command request/response buffers have a common structure as specified by
 * the following table:
 *     Byte      Size       In/Out    Description
 *     Offset    (Bytes)
 *     0x000     4          In        Platform command
 *                          Out       Platform command response size
 *
 * Each command can build upon this common request/response structure to create
 * a structure specific to the command. See include/linux/tpm_svsm.h for more
 * details.
 *
 * Return: 0 on success, -errno on failure
 */
int snp_svsm_vtpm_send_command(u8 *buffer)
{
	struct svsm_call call = {};

	call.caa = svsm_get_caa();
	call.rax = SVSM_VTPM_CALL(SVSM_VTPM_CMD);
	call.rcx = __pa(buffer);

	return svsm_perform_call_protocol(&call);
}
EXPORT_SYMBOL_GPL(snp_svsm_vtpm_send_command);

static struct platform_device sev_guest_device = {
	.name = "sev-guest",
	.id = -1,
};

static struct platform_device tpm_svsm_device = {
	.name = "tpm-svsm",
	.id = -1,
};

static int __init snp_init_platform_device(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return -ENODEV;

	if (platform_device_register(&sev_guest_device))
		return -ENODEV;

	if (snp_svsm_vtpm_probe() && platform_device_register(&tpm_svsm_device))
		return -ENODEV;

	pr_info("SNP guest platform devices initialized.\n");
	return 0;
}
device_initcall(snp_init_platform_device);

void sev_show_status(void)
{
	int i;

	pr_info("Status: ");
	for (i = 0; i < MSR_AMD64_SNP_RESV_BIT; i++) {
		if (sev_status & BIT_ULL(i)) {
			if (!sev_status_feat_names[i])
				continue;

			pr_cont("%s ", sev_status_feat_names[i]);
		}
	}
	pr_cont("\n");
}

#ifdef CONFIG_SYSFS
static ssize_t vmpl_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sysfs_emit(buf, "%d\n", snp_vmpl);
}

static struct kobj_attribute vmpl_attr = __ATTR_RO(vmpl);

static struct attribute *vmpl_attrs[] = { &vmpl_attr.attr, NULL };

static struct attribute_group sev_attr_group = {
	.attrs = vmpl_attrs,
};

static int __init sev_sysfs_init(void)
{
	struct kobject *sev_kobj;
	struct device *dev_root;
	int ret;

	if (!cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		return -ENODEV;

	dev_root = bus_get_dev_root(&cpu_subsys);
	if (!dev_root)
		return -ENODEV;

	sev_kobj = kobject_create_and_add("sev", &dev_root->kobj);
	put_device(dev_root);

	if (!sev_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(sev_kobj, &sev_attr_group);
	if (ret)
		kobject_put(sev_kobj);

	return ret;
}
arch_initcall(sev_sysfs_init);
#endif // CONFIG_SYSFS

static void free_shared_pages(void *buf, size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;
	int ret;

	if (!buf)
		return;

	ret = set_memory_encrypted((unsigned long)buf, npages);
	if (ret) {
		WARN_ONCE(ret, "failed to restore encryption mask (leak it)\n");
		return;
	}

	__free_pages(virt_to_page(buf), get_order(sz));
}

static void *alloc_shared_pages(size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;
	struct page *page;
	int ret;

	page = alloc_pages(GFP_KERNEL_ACCOUNT, get_order(sz));
	if (!page)
		return NULL;

	ret = set_memory_decrypted((unsigned long)page_address(page), npages);
	if (ret) {
		pr_err("failed to mark page shared, ret=%d\n", ret);
		__free_pages(page, get_order(sz));
		return NULL;
	}

	return page_address(page);
}

static u8 *get_vmpck(int id, struct snp_secrets_page *secrets, u32 **seqno)
{
	u8 *key = NULL;

	switch (id) {
	case 0:
		*seqno = &secrets->os_area.msg_seqno_0;
		key = secrets->vmpck0;
		break;
	case 1:
		*seqno = &secrets->os_area.msg_seqno_1;
		key = secrets->vmpck1;
		break;
	case 2:
		*seqno = &secrets->os_area.msg_seqno_2;
		key = secrets->vmpck2;
		break;
	case 3:
		*seqno = &secrets->os_area.msg_seqno_3;
		key = secrets->vmpck3;
		break;
	default:
		break;
	}

	return key;
}

static struct aesgcm_ctx *snp_init_crypto(u8 *key, size_t keylen)
{
	struct aesgcm_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	if (aesgcm_expandkey(ctx, key, keylen, AUTHTAG_LEN)) {
		pr_err("Crypto context initialization failed\n");
		kfree(ctx);
		return NULL;
	}

	return ctx;
}

int snp_msg_init(struct snp_msg_desc *mdesc, int vmpck_id)
{
	/* Adjust the default VMPCK key based on the executing VMPL level */
	if (vmpck_id == -1)
		vmpck_id = snp_vmpl;

	mdesc->vmpck =
		get_vmpck(vmpck_id, mdesc->secrets, &mdesc->os_area_msg_seqno);
	if (!mdesc->vmpck) {
		pr_err("Invalid VMPCK%d communication key\n", vmpck_id);
		return -EINVAL;
	}

	/* Verify that VMPCK is not zero. */
	if (!memchr_inv(mdesc->vmpck, 0, VMPCK_KEY_LEN)) {
		pr_err("Empty VMPCK%d communication key\n", vmpck_id);
		return -EINVAL;
	}

	mdesc->vmpck_id = vmpck_id;

	mdesc->ctx = snp_init_crypto(mdesc->vmpck, VMPCK_KEY_LEN);
	if (!mdesc->ctx)
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL_GPL(snp_msg_init);

struct snp_msg_desc *snp_msg_alloc(void)
{
	struct snp_msg_desc *mdesc;
	void __iomem *mem;

	BUILD_BUG_ON(sizeof(struct snp_guest_msg) > PAGE_SIZE);

	mdesc = kzalloc(sizeof(struct snp_msg_desc), GFP_KERNEL);
	if (!mdesc)
		return ERR_PTR(-ENOMEM);

	mem = ioremap_encrypted(sev_secrets_pa, PAGE_SIZE);
	if (!mem)
		goto e_free_mdesc;

	mdesc->secrets = (__force struct snp_secrets_page *)mem;

	/* Allocate the shared page used for the request and response message. */
	mdesc->request = alloc_shared_pages(sizeof(struct snp_guest_msg));
	if (!mdesc->request)
		goto e_unmap;

	mdesc->response = alloc_shared_pages(sizeof(struct snp_guest_msg));
	if (!mdesc->response)
		goto e_free_request;

	return mdesc;

e_free_request:
	free_shared_pages(mdesc->request, sizeof(struct snp_guest_msg));
e_unmap:
	iounmap(mem);
e_free_mdesc:
	kfree(mdesc);

	return ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL_GPL(snp_msg_alloc);

void snp_msg_free(struct snp_msg_desc *mdesc)
{
	if (!mdesc)
		return;

	kfree(mdesc->ctx);
	free_shared_pages(mdesc->response, sizeof(struct snp_guest_msg));
	free_shared_pages(mdesc->request, sizeof(struct snp_guest_msg));
	iounmap((__force void __iomem *)mdesc->secrets);

	memset(mdesc, 0, sizeof(*mdesc));
	kfree(mdesc);
}
EXPORT_SYMBOL_GPL(snp_msg_free);

/* Mutex to serialize the shared buffer access and command handling. */
static DEFINE_MUTEX(snp_cmd_mutex);

/*
 * If an error is received from the host or AMD Secure Processor (ASP) there
 * are two options. Either retry the exact same encrypted request or discontinue
 * using the VMPCK.
 *
 * This is because in the current encryption scheme GHCB v2 uses AES-GCM to
 * encrypt the requests. The IV for this scheme is the sequence number. GCM
 * cannot tolerate IV reuse.
 *
 * The ASP FW v1.51 only increments the sequence numbers on a successful
 * guest<->ASP back and forth and only accepts messages at its exact sequence
 * number.
 *
 * So if the sequence number were to be reused the encryption scheme is
 * vulnerable. If the sequence number were incremented for a fresh IV the ASP
 * will reject the request.
 */
static void snp_disable_vmpck(struct snp_msg_desc *mdesc)
{
	pr_alert("Disabling VMPCK%d communication key to prevent IV reuse.\n",
		 mdesc->vmpck_id);
	memzero_explicit(mdesc->vmpck, VMPCK_KEY_LEN);
	mdesc->vmpck = NULL;
}

static inline u64 __snp_get_msg_seqno(struct snp_msg_desc *mdesc)
{
	u64 count;

	lockdep_assert_held(&snp_cmd_mutex);

	/* Read the current message sequence counter from secrets pages */
	count = *mdesc->os_area_msg_seqno;

	return count + 1;
}

/* Return a non-zero on success */
static u64 snp_get_msg_seqno(struct snp_msg_desc *mdesc)
{
	u64 count = __snp_get_msg_seqno(mdesc);

	/*
	 * The message sequence counter for the SNP guest request is a  64-bit
	 * value but the version 2 of GHCB specification defines a 32-bit storage
	 * for it. If the counter exceeds the 32-bit value then return zero.
	 * The caller should check the return value, but if the caller happens to
	 * not check the value and use it, then the firmware treats zero as an
	 * invalid number and will fail the  message request.
	 */
	if (count >= UINT_MAX) {
		pr_err("request message sequence counter overflow\n");
		return 0;
	}

	return count;
}

static void snp_inc_msg_seqno(struct snp_msg_desc *mdesc)
{
	/*
	 * The counter is also incremented by the PSP, so increment it by 2
	 * and save in secrets page.
	 */
	*mdesc->os_area_msg_seqno += 2;
}

static int verify_and_dec_payload(struct snp_msg_desc *mdesc,
				  struct snp_guest_req *req)
{
	struct snp_guest_msg *resp_msg = &mdesc->secret_response;
	struct snp_guest_msg *req_msg = &mdesc->secret_request;
	struct snp_guest_msg_hdr *req_msg_hdr = &req_msg->hdr;
	struct snp_guest_msg_hdr *resp_msg_hdr = &resp_msg->hdr;
	struct aesgcm_ctx *ctx = mdesc->ctx;
	u8 iv[GCM_AES_IV_SIZE] = {};

	pr_debug("response [seqno %lld type %d version %d sz %d]\n",
		 resp_msg_hdr->msg_seqno, resp_msg_hdr->msg_type,
		 resp_msg_hdr->msg_version, resp_msg_hdr->msg_sz);

	/* Copy response from shared memory to encrypted memory. */
	memcpy(resp_msg, mdesc->response, sizeof(*resp_msg));

	/* Verify that the sequence counter is incremented by 1 */
	if (unlikely(resp_msg_hdr->msg_seqno != (req_msg_hdr->msg_seqno + 1)))
		return -EBADMSG;

	/* Verify response message type and version number. */
	if (resp_msg_hdr->msg_type != (req_msg_hdr->msg_type + 1) ||
	    resp_msg_hdr->msg_version != req_msg_hdr->msg_version)
		return -EBADMSG;

	/*
	 * If the message size is greater than our buffer length then return
	 * an error.
	 */
	if (unlikely((resp_msg_hdr->msg_sz + ctx->authsize) > req->resp_sz))
		return -EBADMSG;

	/* Decrypt the payload */
	memcpy(iv, &resp_msg_hdr->msg_seqno,
	       min(sizeof(iv), sizeof(resp_msg_hdr->msg_seqno)));
	if (!aesgcm_decrypt(ctx, req->resp_buf, resp_msg->payload,
			    resp_msg_hdr->msg_sz, &resp_msg_hdr->algo, AAD_LEN,
			    iv, resp_msg_hdr->authtag))
		return -EBADMSG;

	return 0;
}

static int enc_payload(struct snp_msg_desc *mdesc, u64 seqno,
		       struct snp_guest_req *req)
{
	struct snp_guest_msg *msg = &mdesc->secret_request;
	struct snp_guest_msg_hdr *hdr = &msg->hdr;
	struct aesgcm_ctx *ctx = mdesc->ctx;
	u8 iv[GCM_AES_IV_SIZE] = {};

	memset(msg, 0, sizeof(*msg));

	hdr->algo = SNP_AEAD_AES_256_GCM;
	hdr->hdr_version = MSG_HDR_VER;
	hdr->hdr_sz = sizeof(*hdr);
	hdr->msg_type = req->msg_type;
	hdr->msg_version = req->msg_version;
	hdr->msg_seqno = seqno;
	hdr->msg_vmpck = req->vmpck_id;
	hdr->msg_sz = req->req_sz;

	/* Verify the sequence number is non-zero */
	if (!hdr->msg_seqno)
		return -ENOSR;

	pr_debug("request [seqno %lld type %d version %d sz %d]\n",
		 hdr->msg_seqno, hdr->msg_type, hdr->msg_version, hdr->msg_sz);

	if (WARN_ON((req->req_sz + ctx->authsize) > sizeof(msg->payload)))
		return -EBADMSG;

	memcpy(iv, &hdr->msg_seqno, min(sizeof(iv), sizeof(hdr->msg_seqno)));
	aesgcm_encrypt(ctx, msg->payload, req->req_buf, req->req_sz, &hdr->algo,
		       AAD_LEN, iv, hdr->authtag);

	return 0;
}

static int __handle_guest_request(struct snp_msg_desc *mdesc,
				  struct snp_guest_req *req)
{
	unsigned long req_start = jiffies;
	unsigned int override_npages = 0;
	u64 override_err = 0;
	int rc;

retry_request:
	/*
	 * Call firmware to process the request. In this function the encrypted
	 * message enters shared memory with the host. So after this call the
	 * sequence number must be incremented or the VMPCK must be deleted to
	 * prevent reuse of the IV.
	 */
	rc = snp_issue_guest_request(req);
	switch (rc) {
	case -ENOSPC:
		/*
		 * If the extended guest request fails due to having too
		 * small of a certificate data buffer, retry the same
		 * guest request without the extended data request in
		 * order to increment the sequence number and thus avoid
		 * IV reuse.
		 */
		override_npages = req->input.data_npages;
		req->exit_code = SVM_VMGEXIT_GUEST_REQUEST;

		/*
		 * Override the error to inform callers the given extended
		 * request buffer size was too small and give the caller the
		 * required buffer size.
		 */
		override_err = SNP_GUEST_VMM_ERR(SNP_GUEST_VMM_ERR_INVALID_LEN);

		/*
		 * If this call to the firmware succeeds, the sequence number can
		 * be incremented allowing for continued use of the VMPCK. If
		 * there is an error reflected in the return value, this value
		 * is checked further down and the result will be the deletion
		 * of the VMPCK and the error code being propagated back to the
		 * user as an ioctl() return code.
		 */
		goto retry_request;

	/*
	 * The host may return SNP_GUEST_VMM_ERR_BUSY if the request has been
	 * throttled. Retry in the driver to avoid returning and reusing the
	 * message sequence number on a different message.
	 */
	case -EAGAIN:
		if (jiffies - req_start > SNP_REQ_MAX_RETRY_DURATION) {
			rc = -ETIMEDOUT;
			break;
		}
		schedule_timeout_killable(SNP_REQ_RETRY_DELAY);
		goto retry_request;
	}

	/*
	 * Increment the message sequence number. There is no harm in doing
	 * this now because decryption uses the value stored in the response
	 * structure and any failure will wipe the VMPCK, preventing further
	 * use anyway.
	 */
	snp_inc_msg_seqno(mdesc);

	if (override_err) {
		req->exitinfo2 = override_err;

		/*
		 * If an extended guest request was issued and the supplied certificate
		 * buffer was not large enough, a standard guest request was issued to
		 * prevent IV reuse. If the standard request was successful, return -EIO
		 * back to the caller as would have originally been returned.
		 */
		if (!rc &&
		    override_err ==
			    SNP_GUEST_VMM_ERR(SNP_GUEST_VMM_ERR_INVALID_LEN))
			rc = -EIO;
	}

	if (override_npages)
		req->input.data_npages = override_npages;

	return rc;
}

int snp_send_guest_request(struct snp_msg_desc *mdesc,
			   struct snp_guest_req *req)
{
	u64 seqno;
	int rc;

	/*
	 * enc_payload() calls aesgcm_encrypt(), which can potentially offload to HW.
	 * The offload's DMA SG list of data to encrypt has to be in linear mapping.
	 */
	if (!virt_addr_valid(req->req_buf) || !virt_addr_valid(req->resp_buf)) {
		pr_warn("AES-GSM buffers must be in linear mapping");
		return -EINVAL;
	}

	guard(mutex)(&snp_cmd_mutex);

	/* Check if the VMPCK is not empty */
	if (!mdesc->vmpck || !memchr_inv(mdesc->vmpck, 0, VMPCK_KEY_LEN)) {
		pr_err_ratelimited("VMPCK is disabled\n");
		return -ENOTTY;
	}

	/* Get message sequence and verify that its a non-zero */
	seqno = snp_get_msg_seqno(mdesc);
	if (!seqno)
		return -EIO;

	/* Clear shared memory's response for the host to populate. */
	memset(mdesc->response, 0, sizeof(struct snp_guest_msg));

	/* Encrypt the userspace provided payload in mdesc->secret_request. */
	rc = enc_payload(mdesc, seqno, req);
	if (rc)
		return rc;

	/*
	 * Write the fully encrypted request to the shared unencrypted
	 * request page.
	 */
	memcpy(mdesc->request, &mdesc->secret_request,
	       sizeof(mdesc->secret_request));

	/* Initialize the input address for guest request */
	req->input.req_gpa = __pa(mdesc->request);
	req->input.resp_gpa = __pa(mdesc->response);
	req->input.data_gpa = req->certs_data ? __pa(req->certs_data) : 0;

	rc = __handle_guest_request(mdesc, req);
	if (rc) {
		if (rc == -EIO &&
		    req->exitinfo2 ==
			    SNP_GUEST_VMM_ERR(SNP_GUEST_VMM_ERR_INVALID_LEN))
			return rc;

		pr_alert(
			"Detected error from ASP request. rc: %d, exitinfo2: 0x%llx\n",
			rc, req->exitinfo2);

		snp_disable_vmpck(mdesc);
		return rc;
	}

	rc = verify_and_dec_payload(mdesc, req);
	if (rc) {
		pr_alert(
			"Detected unexpected decode failure from ASP. rc: %d\n",
			rc);
		snp_disable_vmpck(mdesc);
		return rc;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snp_send_guest_request);

static int __init snp_get_tsc_info(void)
{
	struct snp_tsc_info_resp *tsc_resp;
	struct snp_tsc_info_req *tsc_req;
	struct snp_msg_desc *mdesc;
	struct snp_guest_req req = {};
	int rc = -ENOMEM;

	tsc_req = kzalloc(sizeof(*tsc_req), GFP_KERNEL);
	if (!tsc_req)
		return rc;

	/*
	 * The intermediate response buffer is used while decrypting the
	 * response payload. Make sure that it has enough space to cover
	 * the authtag.
	 */
	tsc_resp = kzalloc(sizeof(*tsc_resp) + AUTHTAG_LEN, GFP_KERNEL);
	if (!tsc_resp)
		goto e_free_tsc_req;

	mdesc = snp_msg_alloc();
	if (IS_ERR_OR_NULL(mdesc))
		goto e_free_tsc_resp;

	rc = snp_msg_init(mdesc, snp_vmpl);
	if (rc)
		goto e_free_mdesc;

	req.msg_version = MSG_HDR_VER;
	req.msg_type = SNP_MSG_TSC_INFO_REQ;
	req.vmpck_id = snp_vmpl;
	req.req_buf = tsc_req;
	req.req_sz = sizeof(*tsc_req);
	req.resp_buf = (void *)tsc_resp;
	req.resp_sz = sizeof(*tsc_resp) + AUTHTAG_LEN;
	req.exit_code = SVM_VMGEXIT_GUEST_REQUEST;

	rc = snp_send_guest_request(mdesc, &req);
	if (rc)
		goto e_request;

	pr_debug(
		"%s: response status 0x%x scale 0x%llx offset 0x%llx factor 0x%x\n",
		__func__, tsc_resp->status, tsc_resp->tsc_scale,
		tsc_resp->tsc_offset, tsc_resp->tsc_factor);

	if (!tsc_resp->status) {
		snp_tsc_scale = tsc_resp->tsc_scale;
		snp_tsc_offset = tsc_resp->tsc_offset;
	} else {
		pr_err("Failed to get TSC info, response status 0x%x\n",
		       tsc_resp->status);
		rc = -EIO;
	}

e_request:
	/* The response buffer contains sensitive data, explicitly clear it. */
	memzero_explicit(tsc_resp, sizeof(*tsc_resp) + AUTHTAG_LEN);
e_free_mdesc:
	snp_msg_free(mdesc);
e_free_tsc_resp:
	kfree(tsc_resp);
e_free_tsc_req:
	kfree(tsc_req);

	return rc;
}

void __init snp_secure_tsc_prepare(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_SNP_SECURE_TSC))
		return;

	if (snp_get_tsc_info()) {
		pr_alert("Unable to retrieve Secure TSC info from ASP\n");
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_SECURE_TSC);
	}

	pr_debug("SecureTSC enabled");
}

static unsigned long securetsc_get_tsc_khz(void)
{
	return snp_tsc_freq_khz;
}

void __init snp_secure_tsc_init(void)
{
	struct snp_secrets_page *secrets;
	unsigned long tsc_freq_mhz;
	void *mem;

	if (!cc_platform_has(CC_ATTR_GUEST_SNP_SECURE_TSC))
		return;

	mem = early_memremap_encrypted(sev_secrets_pa, PAGE_SIZE);
	if (!mem) {
		pr_err("Unable to get TSC_FACTOR: failed to map the SNP secrets page.\n");
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_SECURE_TSC);
	}

	secrets = (__force struct snp_secrets_page *)mem;

	setup_force_cpu_cap(X86_FEATURE_TSC_KNOWN_FREQ);
	rdmsrq(MSR_AMD64_GUEST_TSC_FREQ, tsc_freq_mhz);

	/* Extract the GUEST TSC MHZ from BIT[17:0], rest is reserved space */
	tsc_freq_mhz &= GENMASK_ULL(17, 0);

	snp_tsc_freq_khz =
		SNP_SCALE_TSC_FREQ(tsc_freq_mhz * 1000, secrets->tsc_factor);

	x86_platform.calibrate_cpu = securetsc_get_tsc_khz;
	x86_platform.calibrate_tsc = securetsc_get_tsc_khz;

	early_memunmap(mem, PAGE_SIZE);
}
