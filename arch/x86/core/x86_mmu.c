/*
 * Copyright (c) 2011-2014 Wind River Systems, Inc.
 * Copyright (c) 2017-2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <arch/x86/mmustructs.h>
#include <sys/mem_manage.h>
#include <sys/__assert.h>
#include <logging/log.h>
#include <errno.h>
#include <ctype.h>
#include <spinlock.h>
#include <kernel_arch_func.h>
#include <x86_mmu.h>
#include <init.h>
#include <kernel_internal.h>
#include <drivers/interrupt_controller/loapic.h>

LOG_MODULE_DECLARE(os);

/* We will use some ignored bits in the PTE to backup permission settings
 * when the mapping was made. This is used to un-apply memory domain memory
 * partitions to page tables when the partitions are removed.
 */
#define MMU_RW_ORIG	MMU_IGNORED0
#define MMU_US_ORIG	MMU_IGNORED1
#define MMU_XD_ORIG	MMU_IGNORED2

/* Bits in the PTE that form the set of permission bits, when resetting */
#define MASK_PERM	(MMU_RW | MMU_US | MMU_XD)

/* When we want to set up a new mapping, discarding any previous state */
#define MASK_ALL	(~((pentry_t)0U))

/* Bits to set at mapping time for particular permissions. We set the actual
 * page table bit effecting the policy and also the backup bit.
 */
#define ENTRY_RW	(MMU_RW | MMU_RW_ORIG)
#define ENTRY_US	(MMU_US | MMU_US_ORIG)
#define ENTRY_XD	(MMU_XD | MMU_XD_ORIG)

/* Bit position which is always zero in a PTE. We'll use the PAT bit.
 * This helps disambiguate PTEs that do not have the Present bit set (MMU_P):
 * - If the entire entry is zero, it's an un-mapped virtual page
 * - If MMU_PTE_ZERO is set, we flipped this page due to KPTI
 * - Otherwise, this was a page-out
 */
#define PTE_ZERO	MMU_PAT

/* Protects x86_domain_list and serializes any changes to page tables */
static struct k_spinlock x86_mmu_lock;

#ifdef CONFIG_USERSPACE
/* List of all active and initialized memory domains. This is used to make
 * sure all memory mappings are the same across all page tables when invoking
 * range_map()
 */
static sys_slist_t x86_domain_list;
#endif

/* "dummy" pagetables for the first-phase build. The real page tables
 * are produced by gen-mmu.py based on data read in zephyr-prebuilt.elf,
 * and this dummy array is discarded.
 */
Z_GENERIC_SECTION(.dummy_pagetables)
char z_x86_dummy_pagetables[Z_X86_INITIAL_PAGETABLE_SIZE];

/*
 * Definitions for building an ontology of paging levels and capabilities
 * at each level
 */

/* Data structure describing the characteristics of a particular paging
 * level
 */
struct paging_level {
	/* What bits are used to store physical address */
	pentry_t mask;

	/* Number of entries in this paging structure */
	size_t entries;

	/* How many bits to right-shift a virtual address to obtain the
	 * appropriate entry within this table.
	 *
	 * The memory scope of each entry in this table is 1 << shift.
	 */
	unsigned int shift;
#ifdef CONFIG_EXCEPTION_DEBUG
	/* Name of this level, for debug purposes */
	const char *name;
#endif
};

/* Flags for all entries in intermediate paging levels.
 * Fortunately, the same bits are set for all intermediate levels for all
 * three paging modes.
 *
 * Obviously P is set.
 *
 * We want RW and US bit always set; actual access control will be
 * done at the leaf level.
 *
 * XD (if supported) always 0. Disabling execution done at leaf level.
 *
 * PCD/PWT always 0. Caching properties again done at leaf level.
 */
#define INT_FLAGS	(MMU_P | MMU_RW | MMU_US)

/* Paging level ontology for the selected paging mode.
 *
 * See Figures 4-4, 4-7, 4-11 in the Intel SDM, vol 3A
 */
static const struct paging_level paging_levels[] = {
#ifdef CONFIG_X86_64
	/* Page Map Level 4 */
	{
		.mask = 0x7FFFFFFFFFFFF000ULL,
		.entries = 512U,
		.shift = 39U,
#ifdef CONFIG_EXCEPTION_DEBUG
		.name = "PML4"
#endif
	},
#endif /* CONFIG_X86_64 */
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
	/* Page Directory Pointer Table */
	{
		.mask = 0x7FFFFFFFFFFFF000ULL,
#ifdef CONFIG_X86_64
		.entries = 512U,
#else
		/* PAE version */
		.entries = 4U,
#endif
		.shift = 30U,
#ifdef CONFIG_EXCEPTION_DEBUG
		.name = "PDPT"
#endif
	},
#endif /* CONFIG_X86_64 || CONFIG_X86_PAE */
	/* Page Directory */
	{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
		.mask = 0x7FFFFFFFFFFFF000ULL,
		.entries = 512U,
		.shift = 21U,
#else
		/* 32-bit */
		.mask = 0xFFFFF000U,
		.entries = 1024U,
		.shift = 22U,
#endif /* CONFIG_X86_64 || CONFIG_X86_PAE */
#ifdef CONFIG_EXCEPTION_DEBUG
		.name = "PD"
#endif
	},
	/* Page Table */
	{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
		.mask = 0x07FFFFFFFFFFF000ULL,
		.entries = 512U,
		.shift = 12U,
#else
		/* 32-bit */
		.mask = 0xFFFFF000U,
		.entries = 1024U,
		.shift = 12U,
#endif /* CONFIG_X86_64 || CONFIG_X86_PAE */
#ifdef CONFIG_EXCEPTION_DEBUG
		.name = "PT"
#endif
	}
};

#define NUM_LEVELS	ARRAY_SIZE(paging_levels)

/*
 * Utility functions
 */

/* For a table at a particular level, get the entry index that corresponds to
 * the provided virtual address
 */
static inline int get_index(void *virt, int level)
{
	return (((uintptr_t)virt >> paging_levels[level].shift) %
		paging_levels[level].entries);
}

static inline pentry_t *get_entry_ptr(pentry_t *ptables, void *virt, int level)
{
	return &ptables[get_index(virt, level)];
}

static inline pentry_t get_entry(pentry_t *ptables, void *virt, int level)
{
	return ptables[get_index(virt, level)];
}

/* Get the physical memory address associated with this table entry */
static inline uintptr_t get_entry_phys(pentry_t entry, int level)
{
	return entry & paging_levels[level].mask;
}

/* Return the virtual address of a linked table stored in the provided entry */
static inline pentry_t *next_table(pentry_t entry, int level)
{
	return (pentry_t *)(get_entry_phys(entry, level));
}

/* Number of table entries at this level */
static inline size_t get_num_entries(int level)
{
	return paging_levels[level].entries;
}

/* 4K for everything except PAE PDPTs */
static inline size_t table_size(int level)
{
	return get_num_entries(level) * sizeof(pentry_t);
}

/* For a table at a particular level, size of the amount of virtual memory
 * that an entry within the table covers
 */
static inline size_t get_entry_scope(int level)
{
	return (1UL << paging_levels[level].shift);
}

/* For a table at a particular level, size of the amount of virtual memory
 * that this entire table covers
 */
static inline size_t get_table_scope(int level)
{
	return get_entry_scope(level) * get_num_entries(level);
}

/* Must have checked Present bit first! Non-present entries may have OS data
 * stored in any other bits
 */
static inline bool is_leaf(int level, pentry_t entry)
{
	if (level == NUM_LEVELS - 1) {
		/* Always true for PTE */
		return true;
	}

	return ((entry & MMU_PS) != 0U);
}

static inline void tlb_flush_page(void *addr)
{
	/* Invalidate TLB entries corresponding to the page containing the
	 * specified address
	 */
	char *page = (char *)addr;

	__asm__ ("invlpg %0" :: "m" (*page));

	/* TODO: Need to implement TLB shootdown for SMP */
}

#ifdef CONFIG_X86_KPTI
static inline bool is_flipped_pte(pentry_t pte)
{
	return (pte & MMU_P) == 0 && (pte & PTE_ZERO) != 0;
}
#endif

#if defined(CONFIG_SMP)
void z_x86_tlb_ipi(const void *arg)
{
	uintptr_t ptables;

	ARG_UNUSED(arg);

#ifdef CONFIG_X86_KPTI
	/* We're always on the kernel's set of page tables in this context
	 * if KPTI is turned on
	 */
	ptables = z_x86_cr3_get();
	__ASSERT(ptables == (uintptr_t)&z_x86_kernel_ptables, "");
#else
	/* We might have been moved to another memory domain, so always invoke
	 * z_x86_thread_page_tables_get() instead of using current CR3 value.
	 */
	ptables = (uintptr_t)z_x86_thread_page_tables_get(_current);
#endif
	/*
	 * In the future, we can consider making this smarter, such as
	 * propagating which page tables were modified (in case they are
	 * not active on this CPU) or an address range to call
	 * tlb_flush_page() on.
	 */
	LOG_DBG("%s on CPU %d\n", __func__, arch_curr_cpu()->id);

	z_x86_cr3_set(ptables);
}

static inline void tlb_shootdown(void)
{
	z_loapic_ipi(0, LOAPIC_ICR_IPI_OTHERS, CONFIG_TLB_IPI_VECTOR);
}
#endif /* CONFIG_SMP */

static inline void assert_addr_aligned(uintptr_t addr)
{
#if __ASSERT_ON
	__ASSERT((addr & (CONFIG_MMU_PAGE_SIZE - 1)) == 0U,
		 "unaligned address 0x%" PRIxPTR, addr);
#endif
}

static inline void assert_virt_addr_aligned(void *addr)
{
	assert_addr_aligned((uintptr_t)addr);
}

static inline void assert_region_page_aligned(void *addr, size_t size)
{
	assert_virt_addr_aligned(addr);
#if __ASSERT_ON
	__ASSERT((size & (CONFIG_MMU_PAGE_SIZE - 1)) == 0U,
		 "unaligned size %zu", size);
#endif
}

/*
 * Debug functions. All conditionally compiled with CONFIG_EXCEPTION_DEBUG.
 */
#ifdef CONFIG_EXCEPTION_DEBUG

/* Add colors to page table dumps to indicate mapping type */
#define COLOR_PAGE_TABLES	1

#if COLOR_PAGE_TABLES
#define ANSI_DEFAULT "\x1B[0m"
#define ANSI_RED     "\x1B[1;31m"
#define ANSI_GREEN   "\x1B[1;32m"
#define ANSI_YELLOW  "\x1B[1;33m"
#define ANSI_BLUE    "\x1B[1;34m"
#define ANSI_MAGENTA "\x1B[1;35m"
#define ANSI_CYAN    "\x1B[1;36m"
#define ANSI_GREY    "\x1B[1;90m"

#define COLOR(x)	printk(_CONCAT(ANSI_, x))
#else
#define COLOR(x)	do { } while (0)
#endif

static char get_entry_code(pentry_t value)
{
	char ret;

	if ((value & MMU_P) == 0U) {
		ret = '.';
	} else {
		if ((value & MMU_RW) != 0U) {
			/* Writable page */
			if ((value & MMU_XD) != 0U) {
				/* RW */
				ret = 'w';
			} else {
				/* RWX */
				ret = 'a';
			}
		} else {
			if ((value & MMU_XD) != 0U) {
				/* R */
				ret = 'r';
			} else {
				/* RX */
				ret = 'x';
			}
		}

		if ((value & MMU_US) != 0U) {
			/* Uppercase indicates user mode access */
			ret = toupper(ret);
		}
	}

	return ret;
}

static void print_entries(pentry_t entries_array[], uint8_t *base, int level,
			  size_t count)
{
	int column = 0;

	for (int i = 0; i < count; i++) {
		pentry_t entry = entries_array[i];

		uintptr_t phys = get_entry_phys(entry, level);
		uintptr_t virt =
			(uintptr_t)base + (get_entry_scope(level) * i);

		if (entry & MMU_P) {
			if (is_leaf(level, entry)) {
				if (phys == virt) {
					/* Identity mappings */
					COLOR(YELLOW);
				} else {
					/* Other mappings */
					COLOR(GREEN);
				}
			} else {
				COLOR(MAGENTA);
			}
		} else {
			COLOR(GREY);
		}

		printk("%c", get_entry_code(entry));

		column++;
		if (column == 64) {
			column = 0;
			printk("\n");
		}
	}
	COLOR(DEFAULT);

	if (column != 0) {
		printk("\n");
	}
}

static void dump_ptables(pentry_t *table, uint8_t *base, int level)
{
	const struct paging_level *info = &paging_levels[level];

#ifdef CONFIG_X86_64
	/* Account for the virtual memory "hole" with sign-extension */
	if (((uintptr_t)base & BITL(47)) != 0) {
		base = (uint8_t *)((uintptr_t)base | (0xFFFFULL << 48));
	}
#endif

	printk("%s at %p: ", info->name, table);
	if (level == 0) {
		printk("entire address space\n");
	} else {
		printk("for %p - %p\n", base,
		       base + get_table_scope(level) - 1);
	}

	print_entries(table, base, level, info->entries);

	/* Check if we're a page table */
	if (level == (NUM_LEVELS - 1)) {
		return;
	}

	/* Dump all linked child tables */
	for (int j = 0; j < info->entries; j++) {
		pentry_t entry = table[j];
		pentry_t *next;

		if ((entry & MMU_P) == 0U ||
			(entry & MMU_PS) != 0U) {
			/* Not present or big page, skip */
			continue;
		}

		next = next_table(entry, level);
		dump_ptables(next, base + (j * get_entry_scope(level)),
			     level + 1);
	}
}

void z_x86_dump_page_tables(pentry_t *ptables)
{
	dump_ptables(ptables, NULL, 0);
}

/* Enable to dump out the kernel's page table right before main() starts,
 * sometimes useful for deep debugging. May overwhelm sanitycheck.
 */
#define DUMP_PAGE_TABLES 0

#if DUMP_PAGE_TABLES
static int dump_kernel_tables(const struct device *unused)
{
	z_x86_dump_page_tables(z_x86_kernel_ptables);

	return 0;
}

SYS_INIT(dump_kernel_tables, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
#endif

static void str_append(char **buf, size_t *size, const char *str)
{
	int ret = snprintk(*buf, *size, "%s", str);

	if (ret >= *size) {
		/* Truncated */
		*size = 0U;
	} else {
		*size -= ret;
		*buf += ret;
	}

}

static void dump_entry(int level, void *virt, pentry_t entry)
{
	const struct paging_level *info = &paging_levels[level];
	char buf[24] = { 0 };
	char *pos = buf;
	size_t sz = sizeof(buf);
	uint8_t *virtmap = (uint8_t *)ROUND_DOWN(virt, get_entry_scope(level));

	#define DUMP_BIT(bit) do { \
			if ((entry & MMU_##bit) != 0U) { \
				str_append(&pos, &sz, #bit " "); \
			} \
		} while (0)

	DUMP_BIT(RW);
	DUMP_BIT(US);
	DUMP_BIT(PWT);
	DUMP_BIT(PCD);
	DUMP_BIT(A);
	DUMP_BIT(D);
	DUMP_BIT(G);
	DUMP_BIT(XD);

	LOG_ERR("%sE: %p -> " PRI_ENTRY ": %s", info->name,
		virtmap, entry & info->mask, log_strdup(buf));

	#undef DUMP_BIT
}

void z_x86_pentry_get(int *paging_level, pentry_t *val, pentry_t *ptables,
		      void *virt)
{
	pentry_t *table = ptables;

	for (int level = 0; level < NUM_LEVELS; level++) {
		pentry_t entry = get_entry(table, virt, level);

		if ((entry & MMU_P) == 0 || is_leaf(level, entry)) {
			*val = entry;
			*paging_level = level;
			break;
		} else {
			table = next_table(entry, level);
		}
	}
}

/*
 * Debug function for dumping out MMU table information to the LOG for a
 * specific virtual address, such as when we get an unexpected page fault.
 */
void z_x86_dump_mmu_flags(pentry_t *ptables, void *virt)
{
	pentry_t entry;
	int level;

	z_x86_pentry_get(&level, &entry, ptables, virt);

	if ((entry & MMU_P) == 0) {
		LOG_ERR("%sE: not present", paging_levels[level].name);
	} else {
		dump_entry(level, virt, entry);
	}
}
#endif /* CONFIG_EXCEPTION_DEBUG */

/* Page allocation function prototype, passed to map_page() */
typedef void * (*page_get_func_t)(void *);

/*
 * Pool of free memory pages for creating new page tables, as needed.
 *
 * This is very crude, once obtained, pages may not be returned. Fine for
 * permanent kernel mappings.
 */
static uint8_t __noinit
	page_pool[CONFIG_MMU_PAGE_SIZE * CONFIG_X86_MMU_PAGE_POOL_PAGES]
	__aligned(CONFIG_MMU_PAGE_SIZE);

static uint8_t *page_pos = page_pool + sizeof(page_pool);

/* Return a zeroed and suitably aligned memory page for page table data
 * from the global page pool
 */
static void *page_pool_get(void)
{
	void *ret;

	if (page_pos == page_pool) {
		ret = NULL;
	} else {
		page_pos -= CONFIG_MMU_PAGE_SIZE;
		ret = page_pos;
	}

	if (ret != NULL) {
		memset(ret, 0, CONFIG_MMU_PAGE_SIZE);
	}

	return ret;
}

/* Reset permissions on a PTE to original state when the mapping was made */
static inline pentry_t reset_pte(pentry_t old_val)
{
	pentry_t new_val;

	/* Clear any existing state in permission bits */
	new_val = old_val & (~K_MEM_PARTITION_PERM_MASK);

	/* Now set permissions based on the stashed original values */
	if ((old_val & MMU_RW_ORIG) != 0) {
		new_val |= MMU_RW;
	}
	if ((old_val & MMU_US_ORIG) != 0) {
		new_val |= MMU_US;
	}
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
	if ((old_val & MMU_XD_ORIG) != 0) {
		new_val |= MMU_XD;
	}
#endif
	return new_val;
}

/* Wrapper functionsfor some gross stuff we have to do for Kernel
 * page table isolation. If these are User mode page tables, the user bit
 * isn't set, and this is not the shared page, all the bits in the PTE
 * are flipped. This serves three purposes:
 *  - The page isn't present, implementing page table isolation
 *  - Flipping the physical address bits cheaply mitigates L1TF
 *  - State is preserved; to get original PTE, just complement again
 */
static inline void set_leaf_entry(pentry_t *entryp, pentry_t val,
				  bool user_table)
{
#ifdef CONFIG_X86_KPTI
	/* Ram is identity-mapped, so phys=virt for this page */
	uintptr_t shared_phys_addr = (uintptr_t)&z_shared_kernel_page_start;

	if (user_table && (val & MMU_US) == 0 && (val & MMU_P) != 0 &&
	    get_entry_phys(val, NUM_LEVELS - 1) != shared_phys_addr) {
		*entryp = ~val;
		return;
	}
#endif
	*entryp = val;
}

/* Indicates that the target page tables will be used by user mode threads.
 * This only has implications for CONFIG_X86_KPTI where user thread facing
 * page tables need nearly all pages that don't have the US bit to also
 * not be Present.
 */
#define OPTION_USER		BIT(0)

/* Indicates that the operation requires TLBs to be flushed as we are altering
 * existing mappings. Not needed for establishing new mappings
 */
#define OPTION_FLUSH		BIT(1)

/* Indicates that each PTE's permission bits should be restored to their
 * original state when the memory was mapped. All other bits in the PTE are
 * preserved.
 */
#define OPTION_RESET		BIT(2)

/* Indicates that allocations from the page pool are allowed to instantiate
 * new paging structures. Only necessary when establishing new mappings
 * and the entire address space isn't pre-allocated.
 */
#define OPTION_ALLOC		BIT(3)

/**
 * Low level page table update function for a virtual page
 *
 * For the provided set of page tables, update the PTE associated with the
 * virtual address to a new value, using the mask to control what bits
 * need to be preserved.
 *
 * It is permitted to set up mappings without the Present bit set, in which
 * case all other bits may be used for OS accounting.
 *
 * Must call this with x86_mmu_lock held.
 *
 * Common mask values:
 *  MASK_ALL  - Update all PTE bits. Exitsing state totally discarded.
 *  MASK_PERM - Only update permission bits. All other bits and physical
 *              mapping preserved.
 *
 * @param ptables Page tables to modify
 * @param virt Virtual page table entry to update
 * @param entry_val Value to update in the PTE (ignored if OPTION_RESET)
 * @param mask What bits to update in the PTE (ignored if OPTION_RESET)
 * @param options Control options, described above
 * @retval 0 Success
 * @retval -ENOMEM allocation required and no free pages (only if OPTION_ALLOC)
 */
static int page_map_set(pentry_t *ptables, void *virt, pentry_t entry_val,
			pentry_t mask, uint32_t options)
{
	pentry_t *table = ptables;
	bool user_table = (options & OPTION_USER) != 0U;
	bool reset = (options & OPTION_RESET) != 0U;
	bool flush = (options & OPTION_FLUSH) != 0U;

	assert_virt_addr_aligned(virt);

	for (int level = 0; level < NUM_LEVELS; level++) {
		int index;
		pentry_t *entryp;

		index = get_index(virt, level);
		entryp = &table[index];

		/* Check if we're a PTE */
		if (level == (NUM_LEVELS - 1)) {
			pentry_t cur_pte = *entryp;
			pentry_t new_pte;

#ifdef CONFIG_X86_KPTI
			if (is_flipped_pte(cur_pte)) {
				/* Page was flipped for KPTI. Un-flip it */
				cur_pte = ~cur_pte;
			}
#endif

			if (reset) {
				new_pte = reset_pte(cur_pte);
			} else {
				new_pte = ((cur_pte & ~mask) |
					   (entry_val & mask));
			}

			set_leaf_entry(entryp, new_pte, user_table);
			break;
		}

		/* This is a non-leaf entry */
		if ((*entryp & MMU_P) == 0U) {
			/* Not present. Never done a mapping here yet, need
			 * some RAM for linked tables
			 */
			void *new_table;

			__ASSERT((options & OPTION_ALLOC) != 0,
				 "missing page table and allocations disabled");

			new_table = page_pool_get();

			if (new_table == NULL) {
				return -ENOMEM;
			}
			*entryp = ((pentry_t)(uintptr_t)new_table) | INT_FLAGS;
			table = new_table;
		} else {
			/* We fail an assertion here due to no support for
			 * splitting existing bigpage mappings.
			 * If the PS bit is not supported at some level (like
			 * in a PML4 entry) it is always reserved and must be 0
			 */
			__ASSERT((*entryp & MMU_PS) == 0U,
				  "large page encountered");
			table = next_table(*entryp, level);
		}
	}

	if (flush) {
		tlb_flush_page(virt);
	}

	return 0;
}

/**
 * Map a physical region in a specific set of page tables.
 *
 * See documentation for page_map_set() for additional notes about masks and
 * supported options.
 *
 * Must call this with x86_mmu_lock held.
 *
 * It is vital to remember that all virtual-to-physical mappings must be
 * the same with respect to supervisor mode regardless of what thread is
 * scheduled (and therefore, if multiple sets of page tables exist, which one
 * is active).
 *
 * It is permitted to set up mappings without the Present bit set.
 *
 * @param ptables Page tables to modify
 * @param virt Base page-aligned virtual memory address to map the region.
 * @param phys Base page-aligned physical memory address for the region.
 *        Ignored if OPTION_RESET. Also affected by the mask parameter. This
 *        address is not directly examined, it will simply be programmed into
 *        the PTE.
 * @param size Size of the physical region to map
 * @param entry_flags Non-address bits to set in every PTE. Ignored if
 *        OPTION_RESET. Also affected by the mask parameter.
 * @param mask What bits to update in each PTE. Un-set bits will never be
 *        modified. Ignored if OPTION_RESET.
 * @param options Control options, described above
 * @retval 0 Success
 * @retval -ENOMEM allocation required and no free pages (only if OPTION_ALLOC)
 */
static int range_map_ptables(pentry_t *ptables, void *virt, uintptr_t phys,
			     size_t size, pentry_t entry_flags, pentry_t mask,
			     uint32_t options)
{
	int ret;
	bool reset = (options & OPTION_RESET) != 0U;

	assert_addr_aligned(phys);
	__ASSERT((size & (CONFIG_MMU_PAGE_SIZE - 1)) == 0U,
		 "unaligned size %zu", size);
	__ASSERT((entry_flags & paging_levels[0].mask) == 0U,
		 "entry_flags " PRI_ENTRY " overlaps address area",
		 entry_flags);

	/* This implementation is stack-efficient but not particularly fast.
	 * We do a full page table walk for every page we are updating.
	 * Recursive approaches are possible, but use much more stack space.
	 */
	for (size_t offset = 0; offset < size; offset += CONFIG_MMU_PAGE_SIZE) {
		uint8_t *dest_virt = (uint8_t *)virt + offset;
		pentry_t entry_val;

		if (reset) {
			entry_val = 0;
		} else {
			entry_val = (phys + offset) | entry_flags;
		}

		ret = page_map_set(ptables, dest_virt, entry_val, mask,
				   options);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

/**
 * Establish or update a memory mapping for all page tables
 *
 * The physical region noted from phys to phys + size will be mapped to
 * an equal sized virtual region starting at virt, with the provided flags.
 * The mask value denotes what bits in PTEs will actually be modified.
 *
 * See range_map_ptables() for additional details.
 *
 * @param virt Page-aligned starting virtual address
 * @param phys Page-aligned starting physical address. Ignored if the mask
 *             parameter does not enable address bits or OPTION_RESET used.
 *             This region is not directly examined, it will simply be
 *             programmed into the page tables.
 * @param size Size of the physical region to map
 * @param entry_flags Desired state of non-address PTE bits covered by mask,
 *                    ignored if OPTION_RESET
 * @param mask What bits in the PTE to actually modifiy; unset bits will
 *             be preserved. Ignored if OPTION_RESET.
 * @param options Control options. Do not set OPTION_USER here. OPTION_FLUSH
 *                will trigger a TLB shootdown after all tables are updated.
 * @retval 0 Success
 * @retval -ENOMEM page table allocation required, but no free pages
 */
static int range_map(void *virt, uintptr_t phys, size_t size,
		     pentry_t entry_flags, pentry_t mask, uint32_t options)
{
	k_spinlock_key_t key;
	int ret = 0;

	LOG_DBG("%s: %p -> %p (%zu) flags " PRI_ENTRY " mask "
		PRI_ENTRY " opt 0x%x", __func__, (void *)phys, virt, size,
		entry_flags, mask, options);

#ifdef CONFIG_X86_64
	/* There's a gap in the "64-bit" address space, as 4-level paging
	 * requires bits 48 to 63 to be copies of bit 47. Test this
	 * by treating as a signed value and shifting.
	 */
	__ASSERT(((((intptr_t)virt) << 16) >> 16) == (intptr_t)virt,
		 "non-canonical virtual address mapping %p (size %zu)",
		 virt, size);
#endif /* CONFIG_X86_64 */

	__ASSERT((options & OPTION_USER) == 0U, "invalid option for function");

	/* All virtual-to-physical mappings are the same in all page tables.
	 * What can differ is only access permissions, defined by the memory
	 * domain associated with the page tables, and the threads that are
	 * members of that domain.
	 *
	 * Any new mappings need to be applied to all page tables.
	 */
	key = k_spin_lock(&x86_mmu_lock);
#ifdef CONFIG_USERSPACE
	sys_snode_t *node;

	SYS_SLIST_FOR_EACH_NODE(&x86_domain_list, node) {
		struct arch_mem_domain *domain =
			CONTAINER_OF(node, struct arch_mem_domain, node);

		ret = range_map_ptables(domain->ptables, virt, phys, size,
					entry_flags, mask,
					options | OPTION_USER);
		if (ret != 0) {
			/* NOTE: Currently we do not un-map a partially
			 * completed mapping.
			 */
			goto out_unlock;
		}
	}
#endif /* CONFIG_USERSPACE */
	ret = range_map_ptables(z_x86_kernel_ptables, virt, phys, size,
				entry_flags, mask, options);
#ifdef CONFIG_USERSPACE
out_unlock:
#endif /* CONFIG_USERSPACE */
	k_spin_unlock(&x86_mmu_lock, key);

#ifdef CONFIG_SMP
	if ((options & OPTION_FLUSH) != 0U) {
		tlb_shootdown();
	}
#endif /* CONFIG_SMP */
	return ret;
}

static pentry_t flags_to_entry(uint32_t flags)
{
	pentry_t entry_flags = MMU_P;

	/* Translate flags argument into HW-recognized entry flags.
	 *
	 * Support for PAT is not implemented yet. Many systems may have
	 * BIOS-populated MTRR values such that these cache settings are
	 * redundant.
	 */
	switch (flags & K_MEM_CACHE_MASK) {
	case K_MEM_CACHE_NONE:
		entry_flags |= MMU_PCD;
		break;
	case K_MEM_CACHE_WT:
		entry_flags |= MMU_PWT;
		break;
	case K_MEM_CACHE_WB:
		break;
	default:
		return -ENOTSUP;
	}

	if ((flags & K_MEM_PERM_RW) != 0U) {
		entry_flags |= ENTRY_RW;
	}

	if ((flags & K_MEM_PERM_USER) != 0U) {
		entry_flags |= ENTRY_US;
	}

	if ((flags & K_MEM_PERM_EXEC) == 0U) {
		entry_flags |= ENTRY_XD;
	}

	return entry_flags;
}

/* map new region virt..virt+size to phys with provided arch-neutral flags */
int arch_mem_map(void *virt, uintptr_t phys, size_t size, uint32_t flags)
{
	return range_map(virt, phys, size, flags_to_entry(flags), MASK_ALL,
			 OPTION_ALLOC);
}

#if CONFIG_X86_STACK_PROTECTION
void z_x86_set_stack_guard(k_thread_stack_t *stack)
{
	/* Applied to all page tables as this affects supervisor mode.
	 * XXX: This never gets reset when the thread exits, which can
	 * cause problems if the memory is later used for something else.
	 *
	 * Guard page is always the first page of the stack object for both
	 * kernel and thread stacks.
	 */
	(void)range_map(stack, 0, CONFIG_MMU_PAGE_SIZE, MMU_P | ENTRY_XD,
			MASK_PERM, OPTION_FLUSH);
}
#endif /* CONFIG_X86_STACK_PROTECTION */

#ifdef CONFIG_USERSPACE
static bool page_validate(pentry_t *ptables, uint8_t *addr, bool write)
{
	pentry_t *table = (pentry_t *)ptables;

	for (int level = 0; level < NUM_LEVELS; level++) {
		pentry_t entry = get_entry(table, addr, level);

		if ((entry & MMU_P) == 0U) {
			/* Non-present, no access.
			 * TODO: will need re-visiting with demand paging
			 * implemented, could just be paged out
			 */
			return false;
		}

		if (is_leaf(level, entry)) {
			if (((entry & MMU_US) == 0U) ||
			    (write && ((entry & MMU_RW) == 0U))) {
				return false;
			}
		} else {
			table = next_table(entry, level);
		}
	}

	return true;
}

static inline void bcb_fence(void)
{
#ifdef CONFIG_X86_BOUNDS_CHECK_BYPASS_MITIGATION
	__asm__ volatile ("lfence" : : : "memory");
#endif
}

int arch_buffer_validate(void *addr, size_t size, int write)
{
	pentry_t *ptables = z_x86_thread_page_tables_get(_current);
	uint8_t *virt;
	size_t aligned_size;
	int ret = 0;

	/* addr/size arbitrary, fix this up into an aligned region */
	k_mem_region_align((uintptr_t *)&virt, &aligned_size,
			   (uintptr_t)addr, size, CONFIG_MMU_PAGE_SIZE);

	for (size_t offset = 0; offset < aligned_size;
	     offset += CONFIG_MMU_PAGE_SIZE) {
		if (!page_validate(ptables, virt + offset, write)) {
			ret = -1;
			break;
		}
	}

	bcb_fence();

	return ret;
}

/**
*  Duplicate an entire set of page tables
 *
 * Uses recursion, but depth at any given moment is limited by the number of
 * paging levels.
 *
 * x86_mmu_lock must be held.
 *
 * @param dst a zeroed out chunk of memory of sufficient size for the indicated
 *            paging level.
 * @param src some paging structure from within the source page tables to copy
 *            at the indicated paging level
 * @param level Current paging level
 * @retval 0 Success
 * @retval -ENOMEM Insufficient page pool memory
 */
static int copy_page_table(pentry_t *dst, pentry_t *src, int level)
{
	if (level == (NUM_LEVELS - 1)) {
		/* Base case: leaf page table */
		for (int i = 0; i < get_num_entries(level); i++) {
			set_leaf_entry(&dst[i], reset_pte(src[i]), true);
		}
	} else {
		/* Recursive case: allocate sub-structures as needed and
		 * make recursive calls on them
		 */
		for (int i = 0; i < get_num_entries(level); i++) {
			pentry_t *child_dst;
			int ret;

			if ((src[i] & MMU_P) == 0) {
				/* Non-present, skip */
				continue;
			}

			__ASSERT((src[i] & MMU_PS) == 0,
				 "large page encountered");

			child_dst = page_pool_get();
			if (child_dst == NULL) {
				return -ENOMEM;
			}

			/* Page table links are by physical address. RAM
			 * for page tables is identity-mapped, but double-
			 * cast needed for PAE case where sizeof(void *) and
			 * sizeof(pentry_t) are not the same.
			 */
			dst[i] = ((pentry_t)(uintptr_t)child_dst) | INT_FLAGS;

			ret = copy_page_table(child_dst,
					      next_table(src[i], level),
					      level + 1);
			if (ret != 0) {
				return ret;
			}
		}
	}

	return 0;
}

static void region_map_update(pentry_t *ptables, void *start,
			      size_t size, pentry_t flags, bool reset)
{
	uint32_t options = OPTION_USER;
	k_spinlock_key_t key;

	if (reset) {
		options |= OPTION_RESET;
	}
	if (ptables == z_x86_page_tables_get()) {
		options |= OPTION_FLUSH;
	}

	key = k_spin_lock(&x86_mmu_lock);
	(void)range_map_ptables(ptables, start, 0, size, flags, MASK_PERM,
				options);
	k_spin_unlock(&x86_mmu_lock, key);

#ifdef CONFIG_SMP
	tlb_shootdown();
#endif
}

static inline void reset_region(pentry_t *ptables, void *start, size_t size)
{
	LOG_DBG("%s(%p, %p, %zu)", __func__, ptables, start, size);
	region_map_update(ptables, start, size, 0, true);
}

static inline void apply_region(pentry_t *ptables, void *start,
				size_t size, pentry_t attr)
{
	LOG_DBG("%s(%p, %p, %zu, " PRI_ENTRY ")", __func__, ptables, start,
		size, attr);
	region_map_update(ptables, start, size, attr, false);
}

static void set_stack_perms(struct k_thread *thread, pentry_t *ptables)
{
	LOG_DBG("update stack permissions for thread %p", thread);
	apply_region(ptables, (void *)thread->stack_info.start,
		     thread->stack_info.size,
		     MMU_P | MMU_XD | MMU_RW | MMU_US);
}

/* Invoked from z_x86_userspace_enter after the stack is erased */
void z_x86_current_stack_perms(void)
{
	k_spinlock_key_t key;

	(void)memset((void *)_current->stack_info.start, 0xAA,
		     _current->stack_info.size - _current->stack_info.delta);
	key = k_spin_lock(&z_mem_domain_lock);
	set_stack_perms(_current,
			_current->mem_domain_info.mem_domain->arch.ptables);
	k_spin_unlock(&z_mem_domain_lock, key);
}

/*
 * Arch interface implementations for memory domains and userspace
 */

int arch_mem_domain_init(struct k_mem_domain *domain)
{
	int ret;
	k_spinlock_key_t key  = k_spin_lock(&x86_mmu_lock);

	LOG_DBG("%s(%p)", __func__, domain);
#if __ASSERT_ON
	sys_snode_t *node;

	/* Assert that we have not already initialized this domain */
	SYS_SLIST_FOR_EACH_NODE(&x86_domain_list, node) {
		struct arch_mem_domain *list_domain =
			CONTAINER_OF(node, struct arch_mem_domain, node);

		__ASSERT(list_domain != &domain->arch,
			 "%s(%p) called multiple times", __func__, domain);
	}
#endif /* __ASSERT_ON */
#ifndef CONFIG_X86_KPTI
	/* If we're not using KPTI then we can use the build time page tables
	 * (which are mutable) as the set of page tables for the default
	 * memory domain, saving us some memory.
	 *
	 * We skip adding this domain to x86_domain_list since we already
	 * update z_x86_kernel_ptables directly in range_map().
	 */
	if (domain == &k_mem_domain_default) {
		domain->arch.ptables = z_x86_kernel_ptables;
		k_spin_unlock(&x86_mmu_lock, key);
		return 0;
	}
#endif /* CONFIG_X86_KPTI */
#ifdef CONFIG_X86_PAE
	/* PDPT is stored within the memory domain itself since it is
	 * much smaller than a full page
	 */
	(void)memset(domain->arch.pdpt, 0, sizeof(domain->arch.pdpt));
	domain->arch.ptables = domain->arch.pdpt;
#else
	/* Allocate a page-sized top-level structure, either a PD or PML4 */
	domain->arch.ptables = page_pool_get();
	if (domain->arch.ptables == NULL) {
		k_spin_unlock(&x86_mmu_lock, key);
		return -ENOMEM;
	}
#endif /* CONFIG_X86_PAE */

	LOG_DBG("copy_page_table(%p, %p, 0)", domain->arch.ptables,
		z_x86_kernel_ptables);

	/* Make a copy of the boot page tables created by gen_mmu.py */
	ret = copy_page_table(domain->arch.ptables, z_x86_kernel_ptables, 0);
	if (ret == 0) {
		sys_slist_append(&x86_domain_list, &domain->arch.node);
	}
	k_spin_unlock(&x86_mmu_lock, key);

	return ret;
}

void arch_mem_domain_partition_remove(struct k_mem_domain *domain,
				      uint32_t partition_id)
{
	struct k_mem_partition *partition = &domain->partitions[partition_id];

	/* Reset the partition's region back to defaults */
	reset_region(domain->arch.ptables, (void *)partition->start,
		     partition->size);
}

void arch_mem_domain_destroy(struct k_mem_domain *domain)
{
	/* No-op, this is eventually getting removed in 2.5 */
}

/* Called on thread exit or when moving it to a different memory domain */
void arch_mem_domain_thread_remove(struct k_thread *thread)
{
	struct k_mem_domain *domain = thread->mem_domain_info.mem_domain;

	if ((thread->base.user_options & K_USER) == 0) {
		return;
	}

	if ((thread->base.thread_state & _THREAD_DEAD) == 0) {
		/* Thread is migrating to another memory domain and not
		 * exiting for good; we weren't called from
		 * z_thread_single_abort().  Resetting the stack region will
		 * take place in the forthcoming thread_add() call.
		 */
		return;
	}

	/* Restore permissions on the thread's stack area since it is no
	 * longer a member of the domain.
	 */
	reset_region(domain->arch.ptables, (void *)thread->stack_info.start,
		     thread->stack_info.size);
}

void arch_mem_domain_partition_add(struct k_mem_domain *domain,
				   uint32_t partition_id)
{
	struct k_mem_partition *partition = &domain->partitions[partition_id];

	/* Update the page tables with the partition info */
	apply_region(domain->arch.ptables, (void *)partition->start,
		     partition->size, partition->attr | MMU_P);
}

/* Invoked from memory domain API calls, as well as during thread creation */
void arch_mem_domain_thread_add(struct k_thread *thread)
{
	/* New memory domain we are being added to */
	struct k_mem_domain *domain = thread->mem_domain_info.mem_domain;
	/* This is only set for threads that were migrating from some other
	 * memory domain; new threads this is NULL
	 */
	pentry_t *old_ptables = (pentry_t *)thread->arch.ptables;
	bool is_user = (thread->base.user_options & K_USER) != 0;
	bool is_migration = (old_ptables != NULL) && is_user;
			     ;
	/* Allow US access to the thread's stack in its new domain */
	if (is_user) {
		set_stack_perms(thread, domain->arch.ptables);
	}

	thread->arch.ptables = (uintptr_t)domain->arch.ptables;

	/* Check if we're doing a migration from a different memory domain
	 * and have to remove permissions from its old domain.
	 *
	 * XXX: The checks we have to do here and in
	 * arch_mem_domain_thread_remove() are clumsy, it may be worth looking
	 * into adding a specific arch_mem_domain_thread_migrate() API.
	 */
	if (is_migration) {
		reset_region(old_ptables, (void *)thread->stack_info.start,
			     thread->stack_info.size);
	}
}

int arch_mem_domain_max_partitions_get(void)
{
	return CONFIG_MAX_DOMAIN_PARTITIONS;
}
#endif /* CONFIG_USERSPACE */
