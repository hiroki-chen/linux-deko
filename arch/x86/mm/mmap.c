// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Flexible mmap layout support
 *
 * Based on code by Ingo Molnar and Andi Kleen, copyrighted
 * as follows:
 *
 * Copyright 2003-2009 Red Hat Inc.
 * All Rights Reserved.
 * Copyright 2005 Andi Kleen, SUSE Labs.
 * Copyright 2007 Jiri Kosina, SUSE Labs.
 */

#include <linux/personality.h>
#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/limits.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/compat.h>
#include <linux/elf-randomize.h>
#include <asm/elf.h>
#include <asm/io.h>
#include <asm/pgtable.h>
#ifdef CONFIG_AMD_MEM_ENCRYPT
#include <asm/sev.h>
#endif

#include "physaddr.h"

struct va_alignment __read_mostly va_align = {
	.flags = -1,
};

unsigned long task_size_32bit(void)
{
	return IA32_PAGE_OFFSET;
}

unsigned long task_size_64bit(int full_addr_space)
{
	return full_addr_space ? TASK_SIZE_MAX : DEFAULT_MAP_WINDOW;
}

static unsigned long stack_maxrandom_size(unsigned long task_size)
{
	unsigned long max = 0;
	if (current->flags & PF_RANDOMIZE) {
		max = (-1UL) & __STACK_RND_MASK(task_size == task_size_32bit());
		max <<= PAGE_SHIFT;
	}

	return max;
}

#ifdef CONFIG_COMPAT
# define mmap32_rnd_bits  mmap_rnd_compat_bits
# define mmap64_rnd_bits  mmap_rnd_bits
#else
# define mmap32_rnd_bits  mmap_rnd_bits
# define mmap64_rnd_bits  mmap_rnd_bits
#endif

#define SIZE_128M    (128 * 1024 * 1024UL)

static int mmap_is_legacy(void)
{
	if (current->personality & ADDR_COMPAT_LAYOUT)
		return 1;

	return sysctl_legacy_va_layout;
}

static unsigned long arch_rnd(unsigned int rndbits)
{
	if (!(current->flags & PF_RANDOMIZE))
		return 0;
	return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
}

unsigned long arch_mmap_rnd(void)
{
	return arch_rnd(mmap_is_ia32() ? mmap32_rnd_bits : mmap64_rnd_bits);
}

static unsigned long mmap_base(unsigned long rnd, unsigned long task_size,
			       const struct rlimit *rlim_stack)
{
	unsigned long gap = rlim_stack->rlim_cur;
	unsigned long pad = stack_maxrandom_size(task_size) + stack_guard_gap;

	/* Values close to RLIM_INFINITY can overflow. */
	if (gap + pad > gap)
		gap += pad;

	/*
	 * Top of mmap area (just below the process stack).
	 * Leave an at least ~128 MB hole with possible stack randomization.
	 */
	gap = clamp(gap, SIZE_128M, (task_size / 6) * 5);

	return PAGE_ALIGN(task_size - gap - rnd);
}

static unsigned long mmap_legacy_base(unsigned long rnd,
				      unsigned long task_size)
{
	return __TASK_UNMAPPED_BASE(task_size) + rnd;
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
static void arch_pick_mmap_base(unsigned long *base, unsigned long *legacy_base,
		unsigned long random_factor, unsigned long task_size,
		const struct rlimit *rlim_stack)
{
	*legacy_base = mmap_legacy_base(random_factor, task_size);
	if (mmap_is_legacy())
		*base = *legacy_base;
	else
		*base = mmap_base(random_factor, task_size, rlim_stack);
}

void arch_pick_mmap_layout(struct mm_struct *mm, const struct rlimit *rlim_stack)
{
	if (mmap_is_legacy())
		mm_flags_clear(MMF_TOPDOWN, mm);
	else
		mm_flags_set(MMF_TOPDOWN, mm);

	arch_pick_mmap_base(&mm->mmap_base, &mm->mmap_legacy_base,
			arch_rnd(mmap64_rnd_bits), task_size_64bit(0),
			rlim_stack);

#ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
	/*
	 * The mmap syscall mapping base decision depends solely on the
	 * syscall type (64-bit or compat). This applies for 64bit
	 * applications and 32bit applications. The 64bit syscall uses
	 * mmap_base, the compat syscall uses mmap_compat_base.
	 */
	arch_pick_mmap_base(&mm->mmap_compat_base, &mm->mmap_compat_legacy_base,
			arch_rnd(mmap32_rnd_bits), task_size_32bit(),
			rlim_stack);
#endif
}

unsigned long get_mmap_base(int is_legacy)
{
	struct mm_struct *mm = current->mm;

#ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
	if (in_32bit_syscall()) {
		return is_legacy ? mm->mmap_compat_legacy_base
				 : mm->mmap_compat_base;
	}
#endif
	return is_legacy ? mm->mmap_legacy_base : mm->mmap_base;
}

#ifdef CONFIG_AMD_MEM_ENCRYPT
int deko_select_exec_span(struct mm_struct *mm)
{
	struct vm_unmapped_area_info info = {
		.length = DEKO_EXEC_SPAN_SIZE,
		/* Keep slot zero available for conventional low ELF/brk VMAs. */
		.low_limit = DEKO_EXEC_SPAN_SIZE,
		/* Stay in the conventional 47-bit userspace window on LA57 too. */
		.high_limit = DEFAULT_MAP_WINDOW,
		.align_mask = DEKO_EXEC_SPAN_SIZE - 1,
	};
	unsigned long addr;

	if (!mm || TASK_SIZE < DEKO_EXEC_SPAN_SIZE ||
	    info.low_limit >= info.high_limit)
		return -ENOMEM;

	mmap_read_lock(mm);
	addr = vm_unmapped_area(&info);
	mmap_read_unlock(mm);
	if (IS_ERR_VALUE(addr) || (addr & (DEKO_EXEC_SPAN_SIZE - 1)) ||
	    addr > TASK_SIZE - DEKO_EXEC_SPAN_SIZE)
		return -ENOMEM;

	WRITE_ONCE(mm->deko_exec_span_base, addr);
	WRITE_ONCE(mm->deko_exec_span, true);
	return 0;
}

/*
 * Prepare the present four-level user root entries before VMPL0 freezes the
 * PML4.  The selected executable slot remains executable; every other present
 * root entry is NX so writable lower-level data trees cannot create code
 * aliases.  Absent entries stay absent and consume no page-table memory.
 */
int deko_prepare_exec_root(struct mm_struct *mm)
{
	unsigned long exec_span_base;
	unsigned long exec_index;
	unsigned long index;
	pgd_t *vmpl1_pgd;
	p4d_t *exec_p4d;
	int ret = 0;

	if (!mm || !READ_ONCE(mm->deko_exec_span) || pgtable_l5_enabled() ||
	    !(__supported_pte_mask & _PAGE_NX))
		return -EINVAL;

	exec_span_base = READ_ONCE(mm->deko_exec_span_base);
	exec_index = exec_span_base >> DEKO_EXEC_SPAN_SHIFT;
	if (!exec_index || exec_index >= PTRS_PER_PGD / 2 ||
	    exec_span_base != exec_index << DEKO_EXEC_SPAN_SHIFT)
		return -EINVAL;

	vmpl1_pgd = mm->pgd;
#ifdef CONFIG_MITIGATION_PAGE_TABLE_ISOLATION
	if (boot_cpu_has(X86_FEATURE_PTI))
		vmpl1_pgd = kernel_to_user_pgdp(mm->pgd);
#endif

	mmap_write_lock(mm);
	spin_lock(&mm->page_table_lock);
	for (index = 0; index < PTRS_PER_PGD / 2; index++) {
		unsigned long addr = index << DEKO_EXEC_SPAN_SHIFT;
		pgd_t *pgd = vmpl1_pgd + pgd_index(addr);
		p4d_t *p4d = p4d_offset(pgd, addr);
		p4dval_t value = p4d_val(*p4d);

		if (!p4d_present(*p4d))
			continue;
		value |= _PAGE_ACCESSED;
		if (index == exec_index)
			value &= ~_PAGE_NX;
		else
			value |= _PAGE_NX;
		/*
		 * Write Linux's PTI user root directly.  set_p4d() is intended
		 * for the kernel root: its PTI helper copies the pre-NX value to
		 * the user root and then forces NX only in the kernel copy, which
		 * is the opposite of this executable-commitment policy.
		 */
		WRITE_ONCE(*p4d, __p4d(value));
	}
	spin_unlock(&mm->page_table_lock);

	/*
	 * An RMP permission change invalidates cached translations.  The first
	 * subsequent VMPL1 walk would therefore try to set Accessed bits
	 * in every paging entry it consumes (and Dirty in a writable leaf).
	 * Settle the hardware-owned A/D bits before handing the tree to VMPL0;
	 * VMPL1 also retains write permission for any later hardware updates.
	 */
	exec_p4d = p4d_offset(vmpl1_pgd + pgd_index(exec_span_base),
			       exec_span_base);
	if (!p4d_present(*exec_p4d)) {
		ret = -EFAULT;
		goto out_unlock;
	}

	for (index = 0; index < PTRS_PER_PUD; index++) {
		unsigned long pud_addr = exec_span_base + index * PUD_SIZE;
		pud_t *pud = pud_offset(exec_p4d, pud_addr);
		unsigned long pmd_index;

		if (pud_none(*pud))
			continue;
		if (!pud_present(*pud) || pud_leaf(*pud)) {
			ret = -E2BIG;
			goto out_unlock;
		}

		spin_lock(&mm->page_table_lock);
		set_pud_at(mm, pud_addr, pud,
			   __pud(pud_val(*pud) | _PAGE_ACCESSED));
		spin_unlock(&mm->page_table_lock);

		for (pmd_index = 0; pmd_index < PTRS_PER_PMD; pmd_index++) {
			unsigned long pmd_addr = pud_addr + pmd_index * PMD_SIZE;
			pmd_t *pmd = pmd_offset(pud, pmd_addr);
			spinlock_t *ptl;
			pte_t *pte;
			unsigned long pte_index;

			if (pmd_none(*pmd))
				continue;
			if (!pmd_present(*pmd) || pmd_leaf(*pmd)) {
				ret = -E2BIG;
				goto out_unlock;
			}

			spin_lock(&mm->page_table_lock);
			set_pmd_at(mm, pmd_addr, pmd,
				   __pmd(pmd_val(*pmd) | _PAGE_ACCESSED));
			spin_unlock(&mm->page_table_lock);

			pte = pte_offset_map_lock(mm, pmd, pmd_addr, &ptl);
			if (!pte) {
				ret = -EAGAIN;
				goto out_unlock;
			}
			for (pte_index = 0; pte_index < PTRS_PER_PTE;
			     pte_index++, pte++) {
				pte_t entry = ptep_get(pte);

				if (!pte_present(entry))
					continue;
				entry = pte_mkyoung(entry);
				if (pte_write(entry))
					entry = pte_mkdirty(entry);
				set_pte_at(mm, pmd_addr + pte_index * PAGE_SIZE,
					   pte, entry);
			}
			pte_unmap_unlock(pte - PTRS_PER_PTE, ptl);
		}
	}

	flush_tlb_mm(mm);

out_unlock:
	mmap_write_unlock(mm);
	return ret;
}

bool deko_exec_span_elf_image(struct file *file, unsigned long pgoff,
			      unsigned long len)
{
	struct elfhdr ehdr;
	struct elf_phdr phdr;
	elf_addr_t image_start = (elf_addr_t)-1;
	elf_addr_t image_end = 0;
	elf_addr_t first_offset = 0;
	loff_t pos = 0;
	u64 map_offset = (u64)pgoff << PAGE_SHIFT;
	bool has_exec = false;
	int i;

	if (!file || !S_ISREG(file_inode(file)->i_mode) ||
	    kernel_read(file, &ehdr, sizeof(ehdr), &pos) != sizeof(ehdr) ||
	    memcmp(ehdr.e_ident, ELFMAG, SELFMAG) ||
	    ehdr.e_ident[EI_CLASS] != ELF_CLASS || !elf_check_arch(&ehdr) ||
	    (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC) ||
	    ehdr.e_phentsize != sizeof(phdr) || !ehdr.e_phnum ||
	    ehdr.e_phnum > 128 ||
	    ehdr.e_phoff > S64_MAX - ehdr.e_phnum * sizeof(phdr))
		return false;

	for (i = 0; i < ehdr.e_phnum; i++) {
		elf_addr_t end;

		pos = ehdr.e_phoff + i * sizeof(phdr);
		if (kernel_read(file, &phdr, sizeof(phdr), &pos) != sizeof(phdr))
			return false;
		if (phdr.p_type != PT_LOAD)
			continue;
		if (check_add_overflow(phdr.p_vaddr, phdr.p_memsz, &end))
			return false;
		if (round_down(phdr.p_vaddr, PAGE_SIZE) < image_start) {
			image_start = round_down(phdr.p_vaddr, PAGE_SIZE);
			first_offset = round_down(phdr.p_offset, PAGE_SIZE);
		}
		image_end = max(image_end, end);
		if (phdr.p_flags & PF_X)
			has_exec = true;
	}

	if (!has_exec || image_start == (elf_addr_t)-1 ||
	    image_end > ULONG_MAX - (PAGE_SIZE - 1) ||
	    len > ULONG_MAX - (PAGE_SIZE - 1))
		return false;
	image_end = PAGE_ALIGN(image_end);

	return map_offset == first_offset && image_end > image_start &&
	       PAGE_ALIGN(len) >= image_end - image_start;
}

static bool deko_exec_span_range_mapped(struct mm_struct *mm,
					unsigned long start,
					unsigned long len)
{
	unsigned long end = start + len;
	struct vm_area_struct *vma;

	vma = find_vma(mm, start);
	if (!vma || vma->vm_start > start)
		return false;
	while (vma->vm_end < end) {
		unsigned long next = vma->vm_end;

		vma = find_vma(mm, next);
		if (!vma || vma->vm_start != next)
			return false;
	}

	return true;
}

/*
 * Return true when the Deko exec-span policy handled this placement request.
 * The caller already holds mmap_lock through do_mmap().  Kernel PT_LOAD maps
 * and fixed replacements within a userspace loader's validated ELF-image
 * reservation may carry non-executable data with the image.  Other
 * non-executable mappings are never admitted into the reserved slot.
 */
bool deko_exec_span_area(unsigned long addr, unsigned long len,
			 unsigned long flags, unsigned long vm_flags,
			 unsigned long align_mask,
			 unsigned long align_offset,
			 unsigned long start_gap,
			 unsigned long *result)
{
	struct mm_struct *mm = current->mm;
	struct vm_unmapped_area_info info = {};
	struct vm_area_struct *vma;
	unsigned long span_base;
	bool executable = vm_flags & VM_EXEC;
	bool elf_image = flags & DEKO_MAP_ELF_IMAGE;

	if (!mm || !READ_ONCE(mm->deko_exec_span))
		return false;
	span_base = READ_ONCE(mm->deko_exec_span_base);

	if (!executable) {
		if (current->in_execve && (flags & MAP_FIXED) &&
		    deko_range_within_exec_span(span_base, addr, len))
			return false;
		if ((flags & MAP_FIXED) &&
		    deko_range_within_exec_span(span_base, addr, len) &&
		    deko_exec_span_range_mapped(mm, addr, len))
			return false;
		if (elf_image)
			goto allocate_in_span;
		if (addr && deko_range_overlaps_exec_span(span_base, addr, len)) {
			*result = -ENOMEM;
			return true;
		}
		return false;
	}

allocate_in_span:
	if (in_32bit_syscall() || (flags & MAP_32BIT) ||
	    len > DEKO_EXEC_SPAN_SIZE) {
		*result = -ENOMEM;
		return true;
	}

	if (flags & MAP_FIXED) {
		*result = deko_range_within_exec_span(span_base, addr, len) ?
			  addr : -ENOMEM;
		return true;
	}

	if (addr) {
		addr = PAGE_ALIGN(addr);
		if (deko_range_within_exec_span(span_base, addr, len)) {
			vma = find_vma(mm, addr);
			if (!vma || addr + len <= vm_start_gap(vma)) {
				*result = addr;
				return true;
			}
		}
	}

	info.length = len;
	info.low_limit = span_base;
	info.high_limit = span_base + DEKO_EXEC_SPAN_SIZE;
	info.align_mask = align_mask;
	info.align_offset = align_offset;
	info.start_gap = start_gap;
	*result = vm_unmapped_area(&info);

	return true;
}
#endif

/**
 * mmap_address_hint_valid - Validate the address hint of mmap
 * @addr:	Address hint
 * @len:	Mapping length
 *
 * Check whether @addr and @addr + @len result in a valid mapping.
 *
 * On 32bit this only checks whether @addr + @len is <= TASK_SIZE.
 *
 * On 64bit with 5-level page tables another sanity check is required
 * because mappings requested by mmap(@addr, 0) which cross the 47-bit
 * virtual address boundary can cause the following theoretical issue:
 *
 *  An application calls mmap(addr, 0), i.e. without MAP_FIXED, where @addr
 *  is below the border of the 47-bit address space and @addr + @len is
 *  above the border.
 *
 *  With 4-level paging this request succeeds, but the resulting mapping
 *  address will always be within the 47-bit virtual address space, because
 *  the hint address does not result in a valid mapping and is
 *  ignored. Hence applications which are not prepared to handle virtual
 *  addresses above 47-bit work correctly.
 *
 *  With 5-level paging this request would be granted and result in a
 *  mapping which crosses the border of the 47-bit virtual address
 *  space. If the application cannot handle addresses above 47-bit this
 *  will lead to misbehaviour and hard to diagnose failures.
 *
 * Therefore ignore address hints which would result in a mapping crossing
 * the 47-bit virtual address boundary.
 *
 * Note, that in the same scenario with MAP_FIXED the behaviour is
 * different. The request with @addr < 47-bit and @addr + @len > 47-bit
 * fails on a 4-level paging machine but succeeds on a 5-level paging
 * machine. It is reasonable to expect that an application does not rely on
 * the failure of such a fixed mapping request, so the restriction is not
 * applied.
 */
bool mmap_address_hint_valid(unsigned long addr, unsigned long len)
{
	if (TASK_SIZE - len < addr)
		return false;

	return (addr > DEFAULT_MAP_WINDOW) == (addr + len > DEFAULT_MAP_WINDOW);
}

/* Can we access it for direct reading/writing? Must be RAM: */
int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count - 1 <= __pa(high_memory - 1);
}

/* Can we access it through mmap? Must be a valid physical address: */
int valid_mmap_phys_addr_range(unsigned long pfn, size_t count)
{
	phys_addr_t addr = (phys_addr_t)pfn << PAGE_SHIFT;

	return phys_addr_valid(addr + count - 1);
}

/*
 * Only allow root to set high MMIO mappings to PROT_NONE.
 * This prevents an unpriv. user to set them to PROT_NONE and invert
 * them, then pointing to valid memory for L1TF speculation.
 *
 * Note: for locked down kernels may want to disable the root override.
 */
bool pfn_modify_allowed(unsigned long pfn, pgprot_t prot)
{
	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return true;
	if (!__pte_needs_invert(pgprot_val(prot)))
		return true;
	/* If it's real memory always allow */
	if (pfn_valid(pfn))
		return true;
	if (pfn >= l1tf_pfn_limit() && !capable(CAP_SYS_ADMIN))
		return false;
	return true;
}
