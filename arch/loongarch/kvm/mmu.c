// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/page-flags.h>
#include <linux/kvm_host.h>
#include <linux/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>
#include "kvm_compat.h"

/*
 * KVM_MMU_CACHE_MIN_PAGES is the number of GPA page table translation levels
 * for which pages need to be cached.
 */
#if defined(__PAGETABLE_PMD_FOLDED)
#define KVM_MMU_CACHE_MIN_PAGES 1
#else
#define KVM_MMU_CACHE_MIN_PAGES 2
#endif

/* If the page entry has a write attribute,
 * we use the page entry 50bit(KVM_RECORD_PAGE_WRITE_ABLE)
 * to record it to restore the write attribute of the page entry,
 * in the fast path kvm_map_page_fast for page table processing
 */
#define	KVM_RECORD_PAGE_WRITE_ABLE_SHIFT	50
#define KVM_RECORD_PAGE_WRITE_ABLE		(_ULCAST_(1) << KVM_RECORD_PAGE_WRITE_ABLE_SHIFT)

static inline int kvm_pte_write(pte_t pte) { return pte_val(pte) & KVM_RECORD_PAGE_WRITE_ABLE; }
static inline int kvm_pte_dirty(pte_t pte) { return pte_val(pte) & _PAGE_DIRTY; }
static inline int kvm_pte_young(pte_t pte) { return pte_val(pte) & _PAGE_ACCESSED; }
static inline int kvm_pte_huge(pte_t pte) { return pte_val(pte) & _PAGE_HUGE; }

static inline pte_t kvm_pte_mkyoung(pte_t pte)
{
	pte_val(pte) |= _PAGE_ACCESSED;
	return pte;
}

static inline pte_t kvm_pte_mkold(pte_t pte)
{
	pte_val(pte) &= ~_PAGE_ACCESSED;
	return pte;
}

static inline pte_t kvm_pte_mkdirty(pte_t pte)
{
	pte_val(pte) |= _PAGE_DIRTY | _PAGE_WRITE | _PAGE_MODIFIED;
	return pte;
}

static inline unsigned long kvm_pte_mkdirty_val(unsigned long pte)
{
	return pte | _PAGE_DIRTY | _PAGE_WRITE | _PAGE_MODIFIED;
}

static inline pte_t kvm_pte_mkwrite(pte_t pte)
{
	pte_val(pte) |= KVM_RECORD_PAGE_WRITE_ABLE;
	return pte;
}

static inline unsigned kvm_pte_mkwrite_val(unsigned long pte)
{
	return pte | KVM_RECORD_PAGE_WRITE_ABLE;
}

static inline pte_t kvm_pte_mkclean(pte_t pte)
{
	pte_val(pte) &= (~(_PAGE_DIRTY | _PAGE_WRITE | _PAGE_MODIFIED));
	return pte;
}

static inline pte_t kvm_pte_mkhuge(pte_t pte)
{
	pte_val(pte) |= _PAGE_HUGE;
	return pte;
}

static inline pte_t kvm_pte_mksmall(pte_t pte)
{
	pte_val(pte) &= ~_PAGE_HUGE;
	return pte;
}

static inline pmd_t kvm_pmd_mkclean_val(pmd_t pmd)
{
	pmd_val(pmd) &= ~(_PAGE_DIRTY | _PAGE_WRITE | _PAGE_MODIFIED);
	return pmd;
}

static inline void kvm_set_pte(pte_t *ptep, pte_t val)
{
	WRITE_ONCE(*ptep, val);
}

int kvm_tlb_flush_gpa(struct kvm_vcpu *vcpu, unsigned long gpa)
{
	lockdep_assert_irqs_disabled();
	gpa &= (PAGE_MASK << 1);
	invtlb(INVTLB_GID_ADDR, kvm_read_csr_gstat() & KVM_GSTAT_GID, gpa);
	return 0;
}

static inline pmd_t kvm_pmd_mkhuge(pmd_t pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	return pmd_mkhuge(pmd);
#elif defined(CONFIG_HUGETLB_PAGE)
	pte_t entry;

	pte_val(entry) = pmd_val(pmd);
	entry = kvm_pte_mkhuge(entry);
	pmd_val(pmd) = pte_val(entry);
#endif
	return pmd;
}

static inline pmd_t kvm_pmd_mkclean(pmd_t pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	return kvm_pmd_mkclean_val(pmd);
#elif defined(CONFIG_HUGETLB_PAGE)
	pte_t entry;

	pte_val(entry) = pmd_val(pmd);
	entry = kvm_pte_mkclean(entry);
	pmd_val(pmd) = pte_val(entry);
#endif
	return pmd;
}

static inline pmd_t kvm_pmd_mkold(pmd_t pmd)
{
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	return pmd_mkold(pmd);
#elif defined(CONFIG_HUGETLB_PAGE)
	pte_t entry;

	pte_val(entry) = pmd_val(pmd);
	entry = kvm_pte_mkold(entry);
	pmd_val(pmd) = pte_val(entry);
#endif
	return pmd;
}

void kvm_mmu_free_memory_caches(struct kvm_vcpu *vcpu)
{
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_page_cache);
}

/**
 * kvm_pgd_alloc() - Allocate and initialise a KVM GPA page directory.
 *
 * Allocate a blank KVM GPA page directory (PGD) for representing guest physical
 * to host physical page mappings.
 *
 * Returns:	Pointer to new KVM GPA page directory.
 *		NULL on allocation failure.
 */
pgd_t *kvm_pgd_alloc(void)
{
	pgd_t *ret;
	struct page *page;

	page = alloc_pages(GFP_KERNEL, 0);
	if (!page)
		return NULL;
	ret = (pgd_t *) page_address(page);
	if (ret)
		pgd_init((unsigned long)ret);

	return ret;
}

/**
 * kvm_walk_pgd() - Walk page table with optional allocation.
 * @pgd:	Page directory pointer.
 * @addr:	Address to index page table using.
 * @cache:	MMU page cache to allocate new page tables from, or NULL.
 *
 * Walk the page tables pointed to by @pgd to find the PTE corresponding to the
 * address @addr. If page tables don't exist for @addr, they will be created
 * from the MMU cache if @cache is not NULL.
 *
 * Returns:	Pointer to pte_t corresponding to @addr.
 *		NULL if a page table doesn't exist for @addr and !@cache.
 *		NULL if a page table allocation failed.
 */
static pte_t *kvm_walk_pgd(pgd_t *pgd, struct kvm_mmu_memory_cache *cache,
				unsigned long addr)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd += pgd_index(addr);
	if (pgd_none(*pgd)) {
		/* Not used yet */
		BUG();
		return NULL;
	}
	p4d = p4d_offset(pgd, addr);
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud)) {
		pmd_t *new_pmd;

		if (!cache)
			return NULL;
		new_pmd = kvm_mmu_memory_cache_alloc(cache);
		pmd_init((unsigned long)new_pmd,
			 (unsigned long)invalid_pte_table);
		pud_populate(NULL, pud, new_pmd);
	}
	pmd = pmd_offset(pud, addr);
#ifdef CONFIG_HUGETLB_PAGE
	if (pmd_huge(*pmd) && pmd_present(*pmd))
		return (pte_t *)pmd;
#endif
	if (pmd_none(*pmd)) {
		pte_t *new_pte;

		if (!cache)
			return NULL;
		new_pte = kvm_mmu_memory_cache_alloc(cache);
		clear_page(new_pte);
		smp_wmb();
		pmd_populate_kernel(NULL, pmd, new_pte);
	}
	return pte_offset_kernel(pmd, addr);
}

/* Caller must hold kvm->mm_lock */
static pte_t *kvm_pte_for_gpa(struct kvm *kvm,
				struct kvm_mmu_memory_cache *cache,
				unsigned long addr)
{
	return kvm_walk_pgd(kvm->arch.gpa_mm.pgd, cache, addr);
}

/*
 * kvm_flush_gpa_{pte,pmd,pud,pgd,pt}.
 * Flush a range of guest physical address space from the VM's GPA page tables.
 */

static bool kvm_flush_gpa_pte(pte_t *pte, unsigned long start_gpa,
				   unsigned long end_gpa, unsigned long *data)
{
	int i_min = pte_index(start_gpa);
	int i_max = pte_index(end_gpa);
	bool safe_to_remove = (i_min == 0 && i_max == PTRS_PER_PTE - 1);
	int i;

	for (i = i_min; i <= i_max; ++i) {
		if (!pte_present(pte[i]))
			continue;

		kvm_set_pte(pte + i, __pte(0));
		if (data)
			*data = *data + 1;
	}
	return safe_to_remove;
}

static bool kvm_flush_gpa_pmd(pmd_t *pmd, unsigned long start_gpa,
				   unsigned long end_gpa, unsigned long *data)
{
	pte_t *pte;
	unsigned long end = ~0ul;
	int i_min = pmd_index(start_gpa);
	int i_max = pmd_index(end_gpa);
	bool safe_to_remove = (i_min == 0 && i_max == PTRS_PER_PMD - 1);
	int i;

	for (i = i_min; i <= i_max; ++i, start_gpa = 0) {
		if (!pmd_present(pmd[i]))
			continue;

		if (pmd_huge(pmd[i]) && pmd_present(pmd[i])) {
			pmd_clear(pmd + i);
			if (data)
				*data += PTRS_PER_PMD;
			continue;
		}

		pte = pte_offset_kernel(pmd + i, 0);
		if (i == i_max)
			end = end_gpa;

		if (kvm_flush_gpa_pte(pte, start_gpa, end, data)) {
			pmd_clear(pmd + i);
			pte_free_kernel(NULL, pte);
		} else {
			safe_to_remove = false;
		}
	}
	return safe_to_remove;
}

static bool kvm_flush_gpa_pud(pud_t *pud, unsigned long start_gpa,
				   unsigned long end_gpa, unsigned long *data)
{
	pmd_t *pmd;
	unsigned long end = ~0ul;
	int i_min = pud_index(start_gpa);
	int i_max = pud_index(end_gpa);
	bool safe_to_remove = (i_min == 0 && i_max == PTRS_PER_PUD - 1);
	int i;

	for (i = i_min; i <= i_max; ++i, start_gpa = 0) {
		if (!pud_present(pud[i]))
			continue;

		pmd = pmd_offset(pud + i, 0);
		if (i == i_max)
			end = end_gpa;

		if (kvm_flush_gpa_pmd(pmd, start_gpa, end, data)) {
			pud_clear(pud + i);
			pmd_free(NULL, pmd);
		} else {
			safe_to_remove = false;
		}
	}
	return safe_to_remove;
}

static bool kvm_flush_gpa_pgd(pgd_t *pgd, unsigned long start_gpa,
				unsigned long end_gpa, unsigned long *data)
{
	p4d_t *p4d;
	pud_t *pud;
	unsigned long end = ~0ul;
	int i_min = pgd_index(start_gpa);
	int i_max = pgd_index(end_gpa);
	bool safe_to_remove = (i_min == 0 && i_max == PTRS_PER_PGD - 1);
	int i;

	for (i = i_min; i <= i_max; ++i, start_gpa = 0) {
		if (!pgd_present(pgd[i]))
			continue;

		p4d = p4d_offset(pgd, 0);
		pud = pud_offset(p4d + i, 0);
		if (i == i_max)
			end = end_gpa;

		if (kvm_flush_gpa_pud(pud, start_gpa, end, data)) {
			pgd_clear(pgd + i);
			pud_free(NULL, pud);
		} else {
			safe_to_remove = false;
		}
	}
	return safe_to_remove;
}

/**
 * kvm_flush_gpa_pt() - Flush a range of guest physical addresses.
 * @kvm:	KVM pointer.
 * @start_gfn:	Guest frame number of first page in GPA range to flush.
 * @end_gfn:	Guest frame number of last page in GPA range to flush.
 *
 * Flushes a range of GPA mappings from the GPA page tables.
 *
 * The caller must hold the @kvm->mmu_lock spinlock.
 *
 * Returns:	Whether its safe to remove the top level page directory because
 *		all lower levels have been removed.
 */
static bool kvm_flush_gpa_pt(struct kvm *kvm, gfn_t start_gfn, gfn_t end_gfn, void *data)
{
	return kvm_flush_gpa_pgd(kvm->arch.gpa_mm.pgd,
				start_gfn << PAGE_SHIFT,
				end_gfn << PAGE_SHIFT, (unsigned long *)data);
}

/*
 * kvm_mkclean_gpa_pt.
 * Mark a range of guest physical address space clean (writes fault) in the VM's
 * GPA page table to allow dirty page tracking.
 */

static int kvm_mkclean_pte(pte_t *pte, unsigned long start, unsigned long end)
{
	int ret = 0;
	int i_min = pte_index(start);
	int i_max = pte_index(end);
	int i;
	pte_t val;

	for (i = i_min; i <= i_max; ++i) {
		val = pte[i];
		if (pte_present(val) && kvm_pte_dirty(val)) {
			kvm_set_pte(pte + i, kvm_pte_mkclean(val));
			ret = 1;
		}
	}
	return ret;
}

static int kvm_mkclean_pmd(pmd_t *pmd, unsigned long start, unsigned long end)
{
	int ret = 0;
	pte_t *pte;
	unsigned long cur_end = ~0ul;
	int i_min = pmd_index(start);
	int i_max = pmd_index(end);
	int i;
	pmd_t old, new;

	for (i = i_min; i <= i_max; ++i, start = 0) {
		if (!pmd_present(pmd[i]))
			continue;

		if (pmd_huge(pmd[i])) {
			old = pmd[i];
			new = kvm_pmd_mkclean(old);
			if (pmd_val(new) == pmd_val(old))
				continue;
			set_pmd(pmd + i, new);
			ret = 1;
			continue;
		}

		pte = pte_offset_kernel(pmd + i, 0);
		if (i == i_max)
			cur_end = end;

		ret |= kvm_mkclean_pte(pte, start, cur_end);
	}

	return ret;
}

static int kvm_mkclean_pud(pud_t *pud, unsigned long start, unsigned long end)
{
	int ret = 0;
	pmd_t *pmd;
	unsigned long cur_end = ~0ul;
	int i_min = pud_index(start);
	int i_max = pud_index(end);
	int i;

	for (i = i_min; i <= i_max; ++i, start = 0) {
		if (!pud_present(pud[i]))
			continue;

		pmd = pmd_offset(pud + i, 0);
		if (i == i_max)
			cur_end = end;

		ret |= kvm_mkclean_pmd(pmd, start, cur_end);
	}
	return ret;
}

static int kvm_mkclean_pgd(pgd_t *pgd, unsigned long start, unsigned long end)
{
	int ret = 0;
	p4d_t *p4d;							\
	pud_t *pud;
	unsigned long cur_end = ~0ul;
	int i_min = pgd_index(start);
	int i_max = pgd_index(end);
	int i;

	for (i = i_min; i <= i_max; ++i, start = 0) {
		if (!pgd_present(pgd[i]))
			continue;

		p4d = p4d_offset(pgd, 0);
		pud = pud_offset(p4d + i, 0);
		if (i == i_max)
			cur_end = end;

		ret |= kvm_mkclean_pud(pud, start, cur_end);
	}
	return ret;
}

/**
 * kvm_mkclean_gpa_pt() - Make a range of guest physical addresses clean.
 * @kvm:	KVM pointer.
 * @start_gfn:	Guest frame number of first page in GPA range to flush.
 * @end_gfn:	Guest frame number of last page in GPA range to flush.
 *
 * Make a range of GPA mappings clean so that guest writes will fault and
 * trigger dirty page logging.
 *
 * The caller must hold the @kvm->mmu_lock spinlock.
 *
 * Returns:	Whether any GPA mappings were modified, which would require
 *		derived mappings (GVA page tables & TLB enties) to be
 *		invalidated.
 */
static int kvm_mkclean_gpa_pt(struct kvm *kvm, gfn_t start_gfn, gfn_t end_gfn)
{
	return kvm_mkclean_pgd(kvm->arch.gpa_mm.pgd, start_gfn << PAGE_SHIFT,
				end_gfn << PAGE_SHIFT);
}

/**
 * kvm_arch_mmu_enable_log_dirty_pt_masked() - write protect dirty pages
 * @kvm:	The KVM pointer
 * @slot:	The memory slot associated with mask
 * @gfn_offset:	The gfn offset in memory slot
 * @mask:	The mask of dirty pages at offset 'gfn_offset' in this memory
 *		slot to be write protected
 *
 * Walks bits set in mask write protects the associated pte's. Caller must
 * acquire @kvm->mmu_lock.
 */
void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
		struct kvm_memory_slot *slot,
		gfn_t gfn_offset, unsigned long mask)
{
	gfn_t base_gfn = slot->base_gfn + gfn_offset;
	gfn_t start = base_gfn +  __ffs(mask);
	gfn_t end = base_gfn + __fls(mask);

	kvm_mkclean_gpa_pt(kvm, start, end);
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
				   const struct kvm_userspace_memory_region *mem,
				   struct kvm_memory_slot *old,
				   const struct kvm_memory_slot *new,
				   enum kvm_mr_change change)
{
	int needs_flush;

	kvm_debug("%s: kvm: %p slot: %d, GPA: %llx, size: %llx, QVA: %llx\n",
		  __func__, kvm, mem->slot, mem->guest_phys_addr,
		  mem->memory_size, mem->userspace_addr);

	/*
	 * If dirty page logging is enabled, write protect all pages in the slot
	 * ready for dirty logging.
	 *
	 * There is no need to do this in any of the following cases:
	 * CREATE:	No dirty mappings will already exist.
	 * MOVE/DELETE:	The old mappings will already have been cleaned up by
	 *		kvm_arch_flush_shadow_memslot()
	 */
	if (change == KVM_MR_FLAGS_ONLY &&
	    (!(old->flags & KVM_MEM_LOG_DIRTY_PAGES) &&
	     new->flags & KVM_MEM_LOG_DIRTY_PAGES)) {
		spin_lock(&kvm->mmu_lock);
		/* Write protect GPA page table entries */
		needs_flush = kvm_mkclean_gpa_pt(kvm, new->base_gfn,
					new->base_gfn + new->npages - 1);
		/* Let implementation do the rest */
		if (needs_flush)
			kvm_flush_remote_tlbs(kvm);
		spin_unlock(&kvm->mmu_lock);
	}
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	/* Flush whole GPA */
	kvm_flush_gpa_pt(kvm, 0, ~0UL, NULL);

	/* Flush vpid for each VCPU individually */
	kvm_flush_remote_tlbs(kvm);
}

void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
		struct kvm_memory_slot *slot)
{
	unsigned long npages;

	/*
	 * The slot has been made invalid (ready for moving or deletion), so we
	 * need to ensure that it can no longer be accessed by any guest VCPUs.
	 */

	npages = 0;
	spin_lock(&kvm->mmu_lock);
	/* Flush slot from GPA */
	kvm_flush_gpa_pt(kvm, slot->base_gfn,
			slot->base_gfn + slot->npages - 1, &npages);
	/* Let implementation do the rest */
	if (npages)
		kvm_flush_remote_tlbs(kvm);
	spin_unlock(&kvm->mmu_lock);
}

void _kvm_destroy_mm(struct kvm *kvm)
{
	/* It should always be safe to remove after flushing the whole range */
	WARN_ON(!kvm_flush_gpa_pt(kvm, 0, ~0UL, NULL));
	pgd_free(NULL, kvm->arch.gpa_mm.pgd);
	kvm->arch.gpa_mm.pgd = NULL;
}

/*
 * Mark a range of guest physical address space old (all accesses fault) in the
 * VM's GPA page table to allow detection of commonly used pages.
 */

static int kvm_mkold_pte(pte_t *pte, unsigned long start,
				 unsigned long end)
{
	int ret = 0;
	int i_min = pte_index(start);
	int i_max = pte_index(end);
	int i;
	pte_t old, new;

	for (i = i_min; i <= i_max; ++i) {
		if (!pte_present(pte[i]))
			continue;

		old = pte[i];
		new = kvm_pte_mkold(old);
		if (pte_val(new) == pte_val(old))
			continue;
		kvm_set_pte(pte + i, new);
		ret = 1;
	}

	return ret;
}

static int kvm_mkold_pmd(pmd_t *pmd, unsigned long start, unsigned long end)
{
	int ret = 0;
	pte_t *pte;
	unsigned long cur_end = ~0ul;
	int i_min = pmd_index(start);
	int i_max = pmd_index(end);
	int i;
	pmd_t old, new;

	for (i = i_min; i <= i_max; ++i, start = 0) {
		if (!pmd_present(pmd[i]))
			continue;

		if (pmd_huge(pmd[i])) {
			old = pmd[i];
			new = kvm_pmd_mkold(old);
			if (pmd_val(new) == pmd_val(old))
				continue;
			set_pmd(pmd + i, new);
			ret = 1;
			continue;
		}

		pte = pte_offset_kernel(pmd + i, 0);
		if (i == i_max)
			cur_end = end;

		ret |= kvm_mkold_pte(pte, start, cur_end);
	}

	return ret;
}

static int kvm_mkold_pud(pud_t *pud, unsigned long start, unsigned long end)
{
	int ret = 0;
	pmd_t *pmd;
	unsigned long cur_end = ~0ul;
	int i_min = pud_index(start);
	int i_max = pud_index(end);
	int i;

	for (i = i_min; i <= i_max; ++i, start = 0) {
		if (!pud_present(pud[i]))
			continue;

		pmd = pmd_offset(pud + i, 0);
		if (i == i_max)
			cur_end = end;

		ret |= kvm_mkold_pmd(pmd, start, cur_end);
	}

	return ret;
}

static int kvm_mkold_pgd(pgd_t *pgd, unsigned long start, unsigned long end)
{
	int ret = 0;
	p4d_t *p4d;
	pud_t *pud;
	unsigned long cur_end = ~0ul;
	int i_min = pgd_index(start);
	int i_max = pgd_index(end);
	int i;

	for (i = i_min; i <= i_max; ++i, start = 0) {
		if (!pgd_present(pgd[i]))
			continue;

		p4d = p4d_offset(pgd, 0);
		pud = pud_offset(p4d + i, 0);
		if (i == i_max)
			cur_end = end;

		ret |= kvm_mkold_pud(pud, start, cur_end);
	}

	return ret;
}

static int handle_hva_to_gpa(struct kvm *kvm,
			     unsigned long start,
			     unsigned long end,
			     int (*handler)(struct kvm *kvm, gfn_t gfn,
					    gpa_t gfn_end,
					    struct kvm_memory_slot *memslot,
					    void *data),
			     void *data)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int ret = 0;

	slots = kvm_memslots(kvm);

	/* we only care about the pages that the guest sees */
	kvm_for_each_memslot(memslot, slots) {
		unsigned long hva_start, hva_end;
		gfn_t gfn, gfn_end;

		hva_start = max(start, memslot->userspace_addr);
		hva_end = min(end, memslot->userspace_addr +
					(memslot->npages << PAGE_SHIFT));
		if (hva_start >= hva_end)
			continue;

		/*
		 * {gfn(page) | page intersects with [hva_start, hva_end)} =
		 * {gfn_start, gfn_start+1, ..., gfn_end-1}.
		 */
		gfn = hva_to_gfn_memslot(hva_start, memslot);
		gfn_end = hva_to_gfn_memslot(hva_end + PAGE_SIZE - 1, memslot);
		ret |= handler(kvm, gfn, gfn_end, memslot, data);
	}

	return ret;
}


static int kvm_unmap_hva_handler(struct kvm *kvm, gfn_t gfn, gfn_t gfn_end,
				 struct kvm_memory_slot *memslot, void *data)
{
	unsigned long npages;

	npages = 0;
	kvm_flush_gpa_pt(kvm, gfn, gfn_end - 1, &npages);
	*(unsigned long *)data = *(unsigned long *)data + npages;

	return npages > 0;
}

int kvm_unmap_hva_range(struct kvm *kvm, unsigned long start, unsigned long end, bool blockable)
{
	unsigned long npages;

	npages = 0;
	return handle_hva_to_gpa(kvm, start, end, &kvm_unmap_hva_handler, &npages);
}

static int kvm_set_spte_handler(struct kvm *kvm, gfn_t gfn, gfn_t gfn_end,
				struct kvm_memory_slot *memslot, void *data)
{
	gpa_t gpa = gfn << PAGE_SHIFT;
	pte_t hva_pte = *(pte_t *)data;
	pte_t *gpa_pte = kvm_pte_for_gpa(kvm, NULL, gpa);
	pte_t old_pte;

	if (!gpa_pte)
		return 0;

	/* Mapping may need adjusting depending on memslot flags */
	old_pte = *gpa_pte;
	if (memslot->flags & KVM_MEM_LOG_DIRTY_PAGES && !kvm_pte_dirty(old_pte))
		hva_pte = kvm_pte_mkclean(hva_pte);
	else if (memslot->flags & KVM_MEM_READONLY) {
		hva_pte = pte_wrprotect(hva_pte);
	}

	if (kvm_pte_dirty(old_pte)) {
		hva_pte = kvm_pte_mkwrite(hva_pte);
		hva_pte = kvm_pte_mkclean(hva_pte);
	}

	kvm_set_pte(gpa_pte, hva_pte);

	/* Replacing an absent or old page doesn't need flushes */
	if (!pte_present(old_pte) || !kvm_pte_young(old_pte))
		return 0;

	/* Pages swapped, aged, moved, or cleaned require flushes */
	return !pte_present(hva_pte) ||
	       !kvm_pte_young(hva_pte) ||
	       pte_pfn(old_pte) != pte_pfn(hva_pte) ||
	       (kvm_pte_dirty(old_pte) && !kvm_pte_dirty(hva_pte));
}

int kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	unsigned long end = hva + PAGE_SIZE;
	int ret;

	ret = handle_hva_to_gpa(kvm, hva, end, &kvm_set_spte_handler, &pte);
	if (ret)
		/* Flush vpid for each VCPU individually */
		kvm_flush_remote_tlbs(kvm);
	return 0;
}

static int kvm_age_hva_handler(struct kvm *kvm, gfn_t gfn, gfn_t gfn_end,
			       struct kvm_memory_slot *memslot, void *data)
{
	return kvm_mkold_pgd(kvm->arch.gpa_mm.pgd, gfn << PAGE_SHIFT,
				gfn_end << PAGE_SHIFT);
}

static int kvm_test_age_hva_handler(struct kvm *kvm, gfn_t gfn, gfn_t gfn_end,
				    struct kvm_memory_slot *memslot, void *data)
{
	gpa_t gpa = gfn << PAGE_SHIFT;
	pte_t *gpa_pte = kvm_pte_for_gpa(kvm, NULL, gpa);

	if (!gpa_pte)
		return 0;
	return kvm_pte_young(*gpa_pte);
}

int kvm_age_hva(struct kvm *kvm, unsigned long start, unsigned long end)
{
	return handle_hva_to_gpa(kvm, start, end, kvm_age_hva_handler, NULL);
}

int kvm_test_age_hva(struct kvm *kvm, unsigned long hva)
{
	return handle_hva_to_gpa(kvm, hva, hva, kvm_test_age_hva_handler, NULL);
}

static pud_t *kvm_get_pud(struct kvm *kvm,
		 struct kvm_mmu_memory_cache *cache, phys_addr_t addr)
{
	pgd_t *pgd;

	pgd = kvm->arch.gpa_mm.pgd + pgd_index(addr);
	if (pgd_none(*pgd)) {
		/* Not used yet */
		BUG();
		return NULL;
	}

	return pud_offset(p4d_offset(pgd, addr), addr);
}

static pmd_t *kvm_get_pmd(struct kvm *kvm,
		 struct kvm_mmu_memory_cache *cache, phys_addr_t addr)
{
	pud_t *pud;
	pmd_t *pmd;

	pud = kvm_get_pud(kvm, cache, addr);
	if (!pud || pud_huge(*pud))
		return NULL;

	if (pud_none(*pud)) {
		if (!cache)
			return NULL;
		pmd = kvm_mmu_memory_cache_alloc(cache);
		pmd_init((unsigned long)pmd,
				(unsigned long)invalid_pte_table);
		pud_populate(NULL, pud, pmd);
	}

	return pmd_offset(pud, addr);
}

static int kvm_set_pmd_huge(struct kvm_vcpu *vcpu, struct kvm_mmu_memory_cache
			       *cache, phys_addr_t addr, const pmd_t *new_pmd)
{
	pmd_t *pmd, old_pmd;

retry:
	pmd = kvm_get_pmd(vcpu->kvm, cache, addr);
	VM_BUG_ON(!pmd);

	old_pmd = *pmd;
	/*
	 * Multiple vcpus faulting on the same PMD entry, can
	 * lead to them sequentially updating the PMD with the
	 * same value. Following the break-before-make
	 * (pmd_clear() followed by tlb_flush()) process can
	 * hinder forward progress due to refaults generated
	 * on missing translations.
	 *
	 * Skip updating the page table if the entry is
	 * unchanged.
	 */
	if (pmd_val(old_pmd) == pmd_val(*new_pmd))
		return 0;

	if (pmd_present(old_pmd)) {
		/*
		 * If we already have PTE level mapping for this block,
		 * we must unmap it to avoid inconsistent TLB state and
		 * leaking the table page. We could end up in this situation
		 * if the memory slot was marked for dirty logging and was
		 * reverted, leaving PTE level mappings for the pages accessed
		 * during the period. So, unmap the PTE level mapping for this
		 * block and retry, as we could have released the upper level
		 * table in the process.
		 *
		 * Normal THP split/merge follows mmu_notifier callbacks and do
		 * get handled accordingly.
		 */
		if (!pmd_huge(old_pmd)) {
			++vcpu->stat.huge_merge_exits;
			kvm_flush_gpa_pt(vcpu->kvm,
				(addr & PMD_MASK) >> PAGE_SHIFT,
				((addr & PMD_MASK) + PMD_SIZE - 1) >> PAGE_SHIFT, NULL);
			goto retry;
		}
		/*
		 * Mapping in huge pages should only happen through a
		 * fault.  If a page is merged into a transparent huge
		 * page, the individual subpages of that huge page
		 * should be unmapped through MMU notifiers before we
		 * get here.
		 *
		 * Merging of CompoundPages is not supported; they
		 * should become splitting first, unmapped, merged,
		 * and mapped back in on-demand.
		 */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		WARN_ON_ONCE(pmd_pfn(old_pmd) != pmd_pfn(*new_pmd));
#endif
		pmd_clear(pmd);
	}

	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	set_pmd(pmd, *new_pmd);
	return 0;
}

static bool fault_supports_huge_mapping(struct kvm_memory_slot *memslot,
					unsigned long hva, bool write)
{
	gpa_t gpa_start;
	hva_t uaddr_start, uaddr_end;
	unsigned long map_size;
	size_t size;

	map_size = PMD_SIZE;
	/* Disable dirty logging on HugePages */
	if ((memslot->flags & KVM_MEM_LOG_DIRTY_PAGES) && write)
		return false;

	size = memslot->npages * PAGE_SIZE;
	gpa_start = memslot->base_gfn << PAGE_SHIFT;
	uaddr_start = memslot->userspace_addr;
	uaddr_end = uaddr_start + size;

	/*
	 * Pages belonging to memslots that don't have the same alignment
	 * within a PMD/PUD for userspace and GPA cannot be mapped with stage-2
	 * PMD/PUD entries, because we'll end up mapping the wrong pages.
	 *
	 * Consider a layout like the following:
	 *
	 *    memslot->userspace_addr:
	 *    +-----+--------------------+--------------------+---+
	 *    |abcde|fgh  Stage-1 block  |    Stage-1 block tv|xyz|
	 *    +-----+--------------------+--------------------+---+
	 *
	 *    memslot->base_gfn << PAGE_SIZE:
	 *      +---+--------------------+--------------------+-----+
	 *      |abc|def  Stage-2 block  |    Stage-2 block   |tvxyz|
	 *      +---+--------------------+--------------------+-----+
	 *
	 * If we create those stage-2 blocks, we'll end up with this incorrect
	 * mapping:
	 *   d -> f
	 *   e -> g
	 *   f -> h
	 */
	if ((gpa_start & (map_size - 1)) != (uaddr_start & (map_size - 1)))
		return false;

	/*
	 * Next, let's make sure we're not trying to map anything not covered
	 * by the memslot. This means we have to prohibit block size mappings
	 * for the beginning and end of a non-block aligned and non-block sized
	 * memory slot (illustrated by the head and tail parts of the
	 * userspace view above containing pages 'abcde' and 'xyz',
	 * respectively).
	 *
	 * Note that it doesn't matter if we do the check using the
	 * userspace_addr or the base_gfn, as both are equally aligned (per
	 * the check above) and equally sized.
	 */
	return (hva & ~(map_size - 1)) >= uaddr_start &&
	       (hva & ~(map_size - 1)) + map_size <= uaddr_end;
}

/**
 * kvm_map_page_fast() - Fast path GPA fault handler.
 * @vcpu:		VCPU pointer.
 * @gpa:		Guest physical address of fault.
 * @write:	Whether the fault was due to a write.
 *
 * Perform fast path GPA fault handling, doing all that can be done without
 * calling into KVM. This handles marking old pages young (for idle page
 * tracking), and dirtying of clean pages (for dirty page logging).
 *
 * Returns:	0 on success, in which case we can update derived mappings and
 *		resume guest execution.
 *		-EFAULT on failure due to absent GPA mapping or write to
 *		read-only page, in which case KVM must be consulted.
 */
static int kvm_map_page_fast(struct kvm_vcpu *vcpu, unsigned long gpa,
				   bool write)
{
	struct kvm *kvm = vcpu->kvm;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	pte_t *ptep;
	kvm_pfn_t pfn = 0;	/* silence bogus GCC warning */
	bool pfn_valid = false;
	int ret = 0;
	struct kvm_memory_slot *slot;

	spin_lock(&kvm->mmu_lock);

	/* Fast path - just check GPA page table for an existing entry */
	ptep = kvm_pte_for_gpa(kvm, NULL, gpa);
	if (!ptep || !pte_present(*ptep)) {
		ret = -EFAULT;
		goto out;
	}

	/* Track access to pages marked old */
	if (!kvm_pte_young(*ptep)) {
		kvm_set_pte(ptep, kvm_pte_mkyoung(*ptep));
		pfn = pte_pfn(*ptep);
		pfn_valid = true;
		/* call kvm_set_pfn_accessed() after unlock */
	}

	if (write && !kvm_pte_dirty(*ptep)) {
		if (!kvm_pte_write(*ptep)) {
			ret = -EFAULT;
			goto out;
		}

		if (kvm_pte_huge(*ptep)) {
			/*
			 * Do not set write permission when dirty logging is
			 * enabled for HugePages
			 */
			slot = gfn_to_memslot(kvm, gfn);
			if (slot->flags & KVM_MEM_LOG_DIRTY_PAGES) {
				ret = -EFAULT;
				goto out;
			}
		}

		/* Track dirtying of writeable pages */
		kvm_set_pte(ptep, kvm_pte_mkdirty(*ptep));
		pfn = pte_pfn(*ptep);
		if (pmd_huge(*((pmd_t *)ptep))) {
			int i;
			gfn_t base_gfn = (gpa & PMD_MASK) >> PAGE_SHIFT;

			for (i = 0; i < PTRS_PER_PTE; i++)
				mark_page_dirty(kvm, base_gfn + i);
		} else
			mark_page_dirty(kvm, gfn);
		kvm_set_pfn_dirty(pfn);
	}

out:
	spin_unlock(&kvm->mmu_lock);
	if (pfn_valid)
		kvm_set_pfn_accessed(pfn);
	return ret;
}

/*
 * Split huge page
 */
static pte_t *kvm_split_huge(struct kvm_vcpu *vcpu, pte_t *ptep, gfn_t gfn,
				unsigned long hva)
{
	int i;
	pte_t val, *child;
	struct kvm_mmu_memory_cache *memcache;

	memcache = &vcpu->arch.mmu_page_cache;
	child = kvm_mmu_memory_cache_alloc(memcache);
	val = kvm_pte_mksmall(*ptep);
	for (i = 0; i < PTRS_PER_PTE; i++) {
		kvm_set_pte(child + i, val);
		pte_val(val) += PAGE_SIZE;
	}

	/* The later kvm_flush_tlb_gpa() will flush hugepage tlb */
	pte_val(val) = (unsigned long)child;
	smp_wmb();
	kvm_set_pte(ptep, val);
	return child + (gfn & (PTRS_PER_PTE - 1));
}

static inline pmd_t pmdp_get(pmd_t *pmdp)
{
	return READ_ONCE(*pmdp);
}

static inline pud_t pudp_get(pud_t *pudp)
{
	return READ_ONCE(*pudp);
}

static inline p4d_t p4dp_get(p4d_t *p4dp)
{
	return READ_ONCE(*p4dp);
}

static inline pgd_t pgdp_get(pgd_t *pgdp)
{
	return READ_ONCE(*pgdp);
}

static int host_pfn_mapping_level(struct kvm *kvm, gfn_t gfn,
					struct kvm_memory_slot *slot)
{
	int level = 0;
	unsigned long hva;
	unsigned long flags;
	pgd_t pgd;
	p4d_t p4d;
	pud_t pud;
	pmd_t pmd;

	/*
	 * Note, using the already-retrieved memslot and __gfn_to_hva_memslot()
	 * is not solely for performance, it's also necessary to avoid the
	 * "writable" check in __gfn_to_hva_many(), which will always fail on
	 * read-only memslots due to gfn_to_hva() assuming writes.  Earlier
	 * page fault steps have already verified the guest isn't writing a
	 * read-only memslot.
	 */
	hva = __gfn_to_hva_memslot(slot, gfn);

	/*
	 * Disable IRQs to prevent concurrent tear down of host page tables,
	 * e.g. if the primary MMU promotes a P*D to a huge page and then frees
	 * the original page table.
	 */
	local_irq_save(flags);

	/*
	 * Read each entry once.  As above, a non-leaf entry can be promoted to
	 * a huge page _during_ this walk.  Re-reading the entry could send the
	 * walk into the weeks, e.g. p*d_leaf() returns false (sees the old
	 * value) and then p*d_offset() walks into the target huge page instead
	 * of the old page table (sees the new value).
	 */
	pgd = pgdp_get(pgd_offset(current->mm, hva));
	if (pgd_none(pgd))
		goto out;

	p4d = p4dp_get(p4d_offset(&pgd, hva));
	if (p4d_none(p4d) || !p4d_present(p4d))
		goto out;

	pud = pudp_get(pud_offset(&p4d, hva));
	if (pud_none(pud) || !pud_present(pud))
		goto out;

	pmd = pmdp_get(pmd_offset(&pud, hva));
	if (pmd_none(pmd) || !pmd_present(pmd))
		goto out;

	if (pmd_val(pmd) & _PAGE_HUGE)
		level = 1;

out:
	local_irq_restore(flags);
	return level;
}

/**
 * kvm_map_page() - Map a guest physical page.
 * @vcpu:		VCPU pointer.
 * @gpa:		Guest physical address of fault.
 * @write:	Whether the fault was due to a write.
 *
 * Handle GPA faults by creating a new GPA mapping (or updating an existing
 * one).
 *
 * This takes care of marking pages young or dirty (idle/dirty page tracking),
 * asking KVM for the corresponding PFN, and creating a mapping in the GPA page
 * tables. Derived mappings (GVA page tables and TLBs) must be handled by the
 * caller.
 *
 * Returns:	0 on success, in which case the caller may use the @out_entry
 *		and @out_buddy PTEs to update derived mappings and resume guest
 *		execution.
 *		-EFAULT if there is no memory region at @gpa or a write was
 *		attempted to a read-only memory region. This is usually handled
 *		as an MMIO access.
 */
static int kvm_map_page(struct kvm_vcpu *vcpu, unsigned long gpa,
			     bool write)
{
	bool writeable, is_device = false;
	int i, level, srcu_idx, err = 0, retry_no = 0;
	unsigned long hva;
	unsigned long mmu_seq;
	unsigned long prot_bits;
	pte_t *ptep;
	kvm_pfn_t pfn, head_pfn;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	struct vm_area_struct *vma;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *memslot;
	struct kvm_mmu_memory_cache *memcache = &vcpu->arch.mmu_page_cache;

	/* Try the fast path to handle old / clean pages */
	srcu_idx = srcu_read_lock(&kvm->srcu);
	err = kvm_map_page_fast(vcpu, gpa, write);
	if (!err)
		goto out;

	memslot = gfn_to_memslot(kvm, gfn);
	hva = gfn_to_hva_memslot_prot(memslot, gfn, &writeable);
	if (kvm_is_error_hva(hva) || (write && !writeable))
		goto out;

	/* Let's check if we will get back a huge page backed by hugetlbfs */
	mmap_read_lock(current->mm);
	vma = find_vma_intersection(current->mm, hva, hva + 1);
	if (unlikely(!vma)) {
		kvm_err("Failed to find VMA for hva 0x%lx\n", hva);
		mmap_read_unlock(current->mm);
		err = -EFAULT;
		goto out;
	}

	if (vma->vm_flags & (VM_IO | VM_PFNMAP))
		is_device = true;

	mmap_read_unlock(current->mm);

	/* We need a minimum of cached pages ready for page table creation */
	err = kvm_mmu_topup_memory_cache(memcache, KVM_MMU_CACHE_MIN_PAGES);
	if (err)
		goto out;

retry:
	/*
	 * Used to check for invalidations in progress, of the pfn that is
	 * returned by pfn_to_pfn_prot below.
	 */
	mmu_seq = kvm->mmu_notifier_seq;
	/*
	 * Ensure the read of mmu_notifier_seq isn't reordered with PTE reads in
	 * gfn_to_pfn_prot() (which calls get_user_pages()), so that we don't
	 * risk the page we get a reference to getting unmapped before we have a
	 * chance to grab the mmu_lock without mmu_notifier_retry() noticing.
	 *
	 * This smp_rmb() pairs with the effective smp_wmb() of the combination
	 * of the pte_unmap_unlock() after the PTE is zapped, and the
	 * spin_lock() in kvm_mmu_notifier_invalidate_<page|range_end>() before
	 * mmu_notifier_seq is incremented.
	 */
	smp_rmb();

	/* Slow path - ask KVM core whether we can access this GPA */
	pfn = gfn_to_pfn_prot(kvm, gfn, write, &writeable);
	if (is_error_noslot_pfn(pfn)) {
		err = -EFAULT;
		goto out;
	}

	spin_lock(&kvm->mmu_lock);
	/* Check if an invalidation has taken place since we got pfn */
	if (mmu_notifier_retry(kvm, mmu_seq)) {
		/*
		 * This can happen when mappings are changed asynchronously, but
		 * also synchronously if a COW is triggered by
		 * gfn_to_pfn_prot().
		 */
		spin_unlock(&kvm->mmu_lock);
		kvm_set_pfn_accessed(pfn);
		kvm_release_pfn_clean(pfn);
		if (retry_no > 100) {
			retry_no = 0;
			schedule();
		}
		retry_no++;
		goto retry;
	}

	/* Disable dirty logging on HugePages */
	level = 0;
	if (fault_supports_huge_mapping(memslot, hva, write)) {
		/* Check page level about host mmu*/
		level = host_pfn_mapping_level(kvm, gfn, memslot);
		if (level == 1) {
			/*
			 * Check page level about secondary mmu
			 * Disable hugepage if it is normal page on
			 * secondary mmu already
			 */
			ptep = kvm_pte_for_gpa(kvm, memcache, gpa);
			if (ptep && !kvm_pte_huge(*ptep))
				level = 0;
		}
		if (level == 1) {
			gfn = gfn & ~(PTRS_PER_PTE - 1);
			head_pfn = pfn & ~(PTRS_PER_PTE - 1);
			kvm_get_pfn(head_pfn);
			kvm_release_pfn_clean(pfn);
			pfn = head_pfn;
		}
	}

	/* Set up the prot bits */
	prot_bits = _PAGE_PRESENT | __READABLE;
	if (is_device)
		prot_bits |= _CACHE_SUC;
	else
		prot_bits |= _CACHE_CC;

	if (writeable) {
		/* If the page entry has a write attribute,
		 * we use the page entry 50bit(KVM_RECORD_PAGE_WRITE_ABLE)
		 * to record it to restore the write attribute of the page entry,
		 * in the fast path kvm_map_page_fast for page table processing
		 */
		prot_bits = kvm_pte_mkwrite_val(prot_bits);
		if (write) {
			prot_bits = kvm_pte_mkdirty_val(prot_bits);
			mark_page_dirty(kvm, gfn);
			kvm_set_pfn_dirty(pfn);
		}
	} else {
		prot_bits &= ~KVM_RECORD_PAGE_WRITE_ABLE;
	}

	if (level == 1) {
		pmd_t new_pmd = pfn_pmd(pfn, __pgprot(prot_bits));
		new_pmd = pmd_mkhuge(new_pmd);
		if (writeable && write) {
			gfn_t base_gfn = (gpa & PMD_MASK) >> PAGE_SHIFT;
			for (i = 0; i < PTRS_PER_PTE; i++)
				mark_page_dirty(kvm, base_gfn + i);
		}

		++vcpu->stat.huge_set_exits;
		kvm_set_pmd_huge(vcpu, memcache, gpa, &new_pmd);
	} else {
		pte_t new_pte = pfn_pte(pfn, __pgprot(prot_bits));
		if (writeable && write)
			mark_page_dirty(kvm, gfn);

		/* Ensure page tables are allocated */
		ptep = kvm_pte_for_gpa(kvm, memcache, gpa);
		if (ptep && kvm_pte_huge(*ptep) && write)
			ptep = kvm_split_huge(vcpu, ptep, gfn, hva);

		kvm_set_pte(ptep, new_pte);
		err = 0;
	}

	spin_unlock(&kvm->mmu_lock);
	kvm_release_pfn_clean(pfn);
	kvm_set_pfn_accessed(pfn);
out:
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return err;
}

int kvm_handle_mm_fault(struct kvm_vcpu *vcpu, unsigned long badv,
				      bool write)
{
	int ret;

	ret = kvm_map_page(vcpu, badv, write);
	if (ret)
		return ret;

	/* Invalidate this entry in the TLB */
	vcpu->arch.flush_gpa = badv;
	kvm_make_request(KVM_REQ_TLB_FLUSH_GPA, vcpu);
	return 0;
}

/**
 * kvm_flush_tlb_all() - Flush all root TLB entries for
 * guests.
 *
 * Invalidate all entries including GVA-->GPA and GPA-->HPA mappings.
 */
void kvm_flush_tlb_all(void)
{
	unsigned long flags;

	local_irq_save(flags);
	invtlb_all(INVTLB_ALLGID, 0, 0);
	local_irq_restore(flags);
}
