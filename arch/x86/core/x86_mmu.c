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

LOG_MODULE_DECLARE(os);

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

/* For a physical address, return its permanent virtual mapping in the kernel's
 * address space
 */
static inline void *ram_phys_to_virt(uintptr_t phys)
{
	return (void *)(phys + Z_MEM_VM_OFFSET);
}

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
	return ram_phys_to_virt(get_entry_phys(entry, level));
}

/* 4K for everything except PAE PDPTs */
static inline size_t table_size(int level)
{
	return paging_levels[level].entries * sizeof(pentry_t);
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
	return get_entry_scope(level) * paging_levels[level].entries;
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
				} else if (phys + Z_MEM_VM_OFFSET == virt) {
					/* Permanent ram mappings */
					COLOR(GREEN);
				} else {
					/* general mapped pages */
					COLOR(CYAN);
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

	printk("%s at %p (0x%" PRIxPTR ") ", info->name, table,
		z_mem_phys_addr(table));
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
static int dump_kernel_tables(struct device *unused)
{
	z_x86_dump_page_tables(&z_x86_kernel_ptables);

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

static struct k_spinlock pool_lock;

/* Return a zeroed and suitably aligned memory page for page table data
 * from the global page pool
 */
static void *page_pool_get(void *context)
{
	void *ret;
	k_spinlock_key_t key;

	ARG_UNUSED(context);

	key = k_spin_lock(&pool_lock);
	if (page_pos == page_pool) {
		ret = NULL;
	} else {
		page_pos -= CONFIG_MMU_PAGE_SIZE;
		ret = page_pos;
	}
	k_spin_unlock(&pool_lock, key);

	if (ret != NULL) {
		memset(ret, 0, CONFIG_MMU_PAGE_SIZE);
	}

	return ret;
}

/**
 * Low-level mapping function
 *
 * Walk the provided page tables until we get to the PTE for the provided
 * virtual address, and set that to whatever is in 'entry_val'.
 *
 * If memory must be drawn to instantiate page table memory, it will be
 * obtained from the provided get_page() function. The function must
 * return a page-aligned pointer to a page-sized block of zeroed memory.
 * All intermediate tables have hard-coded flags of INT_FLAGS.
 *
 * Presumes we want to map a minimally sized page of CONFIG_MMU_PAGE_SIZE.
 * No support for mapping big pages yet; unclear if we will ever need it given
 * Zephyr's typical use-cases.
 *
 * TODO: There may be opportunities to optimize page table walks such as this
 * by using recusrive page table mappings, see for example
 * https://os.phil-opp.com/paging-implementation/#recursive-page-tables
 * May also help if we need fast virtual-to-physical translation outside of
 * the permanent memory mapping area.
 *
 * @param ptables Top-level page tables pointer
 * @param virt Virtual address to set mapping
 * @param entry_val Value to set PTE to
 * @param alloc_ok If allocations are permitted
 * @retval 0 success
 * @retval -ENOMEM get_page() failed
 */
static int page_map_set(pentry_t *ptables, void *virt, pentry_t entry_val
			bool alloc_ok)
{
	pentry_t *table = ptables;

	for (int level = 0; level < NUM_LEVELS; level++) {
		int index;
		pentry_t *entryp;

		index = get_index(virt, level);
		entryp = &table[index];

		/* Check if we're a PTE */
		if (level == (NUM_LEVELS - 1)) {
			*entryp = entry_val;
			break;
		}

		/* This is a non-leaf entry */
		if ((*entryp & MMU_P) == 0U) {
			/* Not present. Never done a mapping here yet, need
			 * some RAM for linked tables
			 */
			__ASSERT(alloc_ok, "allocation forbidden");
			void *new_table = page_pool_get();

			if (new_table == NULL) {
				return -ENOMEM;
			}
			*entryp = z_mem_phys_addr(new_table) | INT_FLAGS;
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

	return 0;
}

/* Establish the desired mapping in all active page tables */
static int map_memory_ptables(void *virt, uintptr_t phys,
			      size_t size, pentry_t entry_flags, bool alloc_ok)
{

	pentry_t *ptables = &z_x86_kernel_ptables;

	// foreach page table in the system....

	for (size_t offset = 0; offset < size; offset += CONFIG_MMU_PAGE_SIZE) {
		int ret;
		pentry_t entry_val = (phys + offset) | entry_flags;
		uint8_t *dest_virt = (uint8_t *)virt + offset;

		ret = page_map_set(ptables, dest_virt, entry_val, alloc_ok);

		/* Currently used for new mappings, no TLB flush. Re-visit
		 * as capabilities increase
		 */

		if (ret != 0) {
			/* NOTE: Currently we do not un-map a partially
			 * completed mapping.
			 */
			return ret;
		}
	}

	return 0;
}

/* map region virt..virt+size to phys with provided arch-neutral flags */
int arch_mem_map(void *virt, uintptr_t phys, size_t size, uint32_t flags)
{
	pentry_t entry_flags = MMU_P;

	LOG_DBG("%s: %p -> %p (%zu) flags 0x%x",
		__func__, (void *)phys, virt, size, flags);

#ifdef CONFIG_X86_64
	/* There's a gap in the "64-bit" address space, as 4-level paging
	 * requires bits 48 to 63 to be copies of bit 47. Test this
	 * by treating as a signed value and shifting.
	 */
	__ASSERT(((((intptr_t)virt) << 16) >> 16) == (intptr_t)virt,
		 "non-canonical virtual address mapping %p (size %zu)",
		 virt, size);
#endif /* CONFIG_X86_64 */

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
		entry_flags |= MMU_RW;
	}
	if ((flags & K_MEM_PERM_USER) != 0U) {
		entry_flags |= MMU_US;
	}
	if ((flags & K_MEM_PERM_EXEC) == 0U) {
		entry_flags |= MMU_XD;
	}

	return map_memory_ptables(virt, phys, size, entry_flags, true);
}

static void identity_map_remove(void)
{
#if CONFIG_SRAM_BASE_ADDRESS != CONFIG_KERNEL_VM_BASE
	size_t size, scope = get_entry_scope(0);
	uint8_t *pos;

	k_mem_region_align((uintptr_t *)&pos, &size,
			   (uintptr_t)CONFIG_SRAM_BASE_ADDRESS,
			   (size_t)CONFIG_SRAM_SIZE * 1024U, scope);

	/* We booted with RAM mapped both to its identity and virtual
	 * mapping starting at CONFIG_KERNEL_VM_BASE. This was done by
	 * double-linking the relevant tables in the top-level table.
	 * At this point we don't need the identity mapping(s) any more,
	 * zero the top-level table entries corresponding to the
	 * physical mapping.
	 */
	while (size) {
		pentry_t *entry = get_entry_ptr(&z_x86_kernel_ptables, pos, 0);

		/* set_pte */
		*entry = 0;
		pos += scope;
		size -= scope;
	}
#endif
}

/* Invoked to remove the identity mappings in the page tables,
 * they were only needed to tranisition the instruction pointer at early boot
 */
void z_x86_mmu_init(void)
{
	identity_map_remove();
}

#if CONFIG_X86_STACK_PROTECTION
/* Legacy stack guard function. This will eventually be replaced in favor
 * of memory-mapping stacks (with a non-present mapping immediately below each
 * one to catch overflows) instead of using in-place
 */
static void stack_guard_set(void *guard_page)
{
	pentry_t pte = z_mem_phys_addr(guard_page) | MMU_P | MMU_XD;
	int ret;

	assert_virt_addr_aligned(guard_page);


	(void)map_memory_ptables(guard_page, CONFIG_MMU_PAGE_SIZE, pte, false);
}

void z_x86_set_stack_guard(k_thread_stack_t *stack)
{
#ifdef CONFIG_USERSPACE
	if (z_stack_is_user_capable(stack)) {
		struct z_x86_thread_stack_header *header =
			(struct z_x86_thread_stack_header *)stack;

		stack_guard_set(&header->guard_page);
	} else
#endif /* CONFIG_USERSPACE */
	{
		stack_guard_set(stack);
	}
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

/* Get the kernel's PTE value for a particular virtual address, of particular
 * interest being mapping flags
 */
static pentry_t kernel_page_map_get(void *virt)
{
	pentry_t *table = &z_x86_kernel_ptables;

	for (int level = 0; level < NUM_LEVELS; level++) {
		pentry_t entry = get_entry(table, virt, level);

		if ((entry & MMU_P) == 0U) {
			break;
		}

		if (is_leaf(level, entry)) {
			__ASSERT((entry & MMU_PS) == 0, "bigpage found");
			return entry;
		}

		table = next_table(entry, level);
	}

	return 0;
}

/* For a particular linear data page, restore access policy bits to default
 */
static void page_reset(pentry_t *ptables, void *virt)
{
	pentry_t kern_pte = kernel_page_map_get(virt);
	int ret;

#ifdef CONFIG_X86_KPTI
	/* Shared kernel page needs to be mapped in page tables as it contains
	 * trampoline stack and important data structures. Otherwise, non-User
	 * pages aren't present.
	 */
	if ((kern_pte & MMU_US) == 0U && virt != &z_shared_kernel_page_start) {
		kern_pte = 0;
	}
#endif /* CONFIG_X86_KPTI */

	(void)page_map_set(thread_ptables, virt, kern_pte, false);
}

/* Called on creation of a user thread or when a supervisor thread drops to
 * user mode.
 *
 * Sets up the per-thread page tables, such that when they are activated on
 * context switch, everything is rseady to go. thread->arch.ptables is updated
 * to the thread-level tables instead of the kernel's page tbales.
 *
 * Memory for the per-thread page table structures is drawn from the stack
 * object, a buffer of size Z_X86_THREAD_PT_AREA starting from the beginning
 * of the stack object.
 */
void z_x86_thread_pt_init(struct k_thread *thread)
{
	pentry_t *ptables;

	__assert(thread->mem_domain_info.mem_domain != NULL);




	thread->arch.ptables = z_mem_phys_addr(ptables);

	setup_thread_tables(thread, ptables);

	/* Enable access to the thread's own stack buffer */
	thread_map(thread, (void *)thread->stack_info.start,
		   ROUND_UP(thread->stack_info.size,
			    CONFIG_MMU_PAGE_SIZE),
		   MMU_P | MMU_RW | MMU_US | MMU_XD, false);
}

/* Copy the page tables in src to the destination. The destination is an
 * uninitialized block of memory equal to the top-level paging structure
 * size.
 *
 * Return 0 on success, -ENOMEM if we're out of memory. Incomplete allocations
 * are not reclaimed.
 *
 * This is recursive but recursion depth is capped at the number of HW
 * paging levels.
 *
 * Destination page tables must never be active on any CPU!
 */
static int copy_page_table(pentry_t *dst, const pentry_t *src, int level)
{
	(void)memcpy(dst, src, table_size(level));

	for (int i = 0; i < paging_levels[level].entries) {
		pentry_t *entry = &dst[i];

		if ((*entry & MMU_P) == 0) {
			continue;
		}

		if (level == (NUM_LEVELS -1) || (*entry & MMU_PS) != 0) {
			/* Base case; leaf entry that maps an address and
			 * not a child table
			 */

			if (IS_ENABLED(CONFIG_X86_KPTI) &&
			    ((*entry & MMU_US) == 0U)) {
				/* We'll map the trampoline page in these page
				 * tables once we're all done
				 */
				*entry = (*entry) & (~MMU_P);
			}
		} else {
			/* Recursive case; allocate a child table, link it,
			 * and call ourselves on it
			 */
			pentry_t *dst_child = page_pool_get();
			const pentry_t *src_child = next_table(*entry, level);

			if (!dst_child) {
				return -ENOMEM;
			}

			*entry = z_mem_phys_addr(child) | INT_FLAGS;

			ret = copy_page_table(dst_child, src_child, level + 1);
			if (ret != 0) {
				return ret;
			}
		}
	}

	return 0;
}

int arch_mem_domain_init(struct k_mem_domain *domain)
{
	int ret;

#ifndef CONFIG_X86_PAE
	domain->arch.page_tables = page_pool_get();

	if (domain->arch.page_tables == NULL) {
		return -ENOMEM;
	}
#endif
	ret = copy_page_table(domain->arch.page_tables,
			      &z_x86_kernel_ptables, 0);

	if (ret != 0) {
		return ret;
	}

#ifdef CONFIG_X86_KPTI
	/* Need to re-map the trampoline page since it didn't have the User
	 * bit set
	 */
	pentry_t entry = kernel_page_map_get(&z_shared_kernel_page_start);

	(void)page_map_set(domain->arch_ptables,
			   &z_shared_kernel_page_start, entry, false);
#endif

	return 0;
}


static void reset_mem_partition(struct k_thread *thread,
				struct k_mem_partition *partition)
{
	uint8_t *addr = (uint8_t *)partition->start;
	size_t size = partition->size;

	assert_region_page_aligned(addr, size);
	for (size_t offset = 0; offset < size; offset += CONFIG_MMU_PAGE_SIZE) {
		page_reset(thread, addr + offset);
	}
}

void z_x86_apply_mem_domain(struct k_thread *thread,
			    struct k_mem_domain *mem_domain)
{
	for (int i = 0, pcount = 0; pcount < mem_domain->num_partitions; i++) {
		struct k_mem_partition *partition;

		partition = &mem_domain->partitions[i];
		if (partition->size == 0) {
			continue;
		}
		pcount++;

		apply_mem_partition(thread, partition);
	}
}

/*
 * Arch interface implementations for memory domains
 *
 * In all cases, if one of these arch_mem_domain_* APIs is called on a
 * supervisor thread, we don't need to do anything. If the thread later drops
 * into user mode the per-thread page tables will be generated and the memory
 * domain configuration applied.
 */
void arch_mem_domain_partition_remove(struct k_mem_domain *domain,
				      uint32_t partition_id)
{
	sys_dnode_t *node, *next_node;

	/* Removing a partition. Need to reset the relevant memory range
	 * to the defaults in USER_PDPT for each thread.
	 */
	SYS_DLIST_FOR_EACH_NODE_SAFE(&domain->mem_domain_q, node, next_node) {
		struct k_thread *thread =
			CONTAINER_OF(node, struct k_thread, mem_domain_info);

		if ((thread->base.user_options & K_USER) == 0) {
			continue;
		}

		reset_mem_partition(thread, &domain->partitions[partition_id]);
	}
}

void arch_mem_domain_destroy(struct k_mem_domain *domain)
{
	for (int i = 0, pcount = 0; pcount < domain->num_partitions; i++) {
		struct k_mem_partition *partition;

		partition = &domain->partitions[i];
		if (partition->size == 0) {
			continue;
		}
		pcount++;

		arch_mem_domain_partition_remove(domain, i);
	}
}

void arch_mem_domain_thread_remove(struct k_thread *thread)
{
	struct k_mem_domain *domain = thread->mem_domain_info.mem_domain;

	/* Non-user threads don't have per-thread page tables set up */
	if ((thread->base.user_options & K_USER) == 0) {
		return;
	}

	for (int i = 0, pcount = 0; pcount < domain->num_partitions; i++) {
		struct k_mem_partition *partition;

		partition = &domain->partitions[i];
		if (partition->size == 0) {
			continue;
		}
		pcount++;

		reset_mem_partition(thread, partition);
	}
}

void arch_mem_domain_partition_add(struct k_mem_domain *domain,
				   uint32_t partition_id)
{
	sys_dnode_t *node, *next_node;

	SYS_DLIST_FOR_EACH_NODE_SAFE(&domain->mem_domain_q, node, next_node) {
		struct k_thread *thread =
			CONTAINER_OF(node, struct k_thread, mem_domain_info);

		if ((thread->base.user_options & K_USER) == 0) {
			continue;
		}

		apply_mem_partition(thread, &domain->partitions[partition_id]);
	}
}

void arch_mem_domain_thread_add(struct k_thread *thread)
{
	if ((thread->base.user_options & K_USER) == 0) {
		return;
	}

	z_x86_apply_mem_domain(thread, thread->mem_domain_info.mem_domain);
}

int arch_mem_domain_max_partitions_get(void)
{
	return CONFIG_MAX_DOMAIN_PARTITIONS;
}
#endif /* CONFIG_USERSPACE */
