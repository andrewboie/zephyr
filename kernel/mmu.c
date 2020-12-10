/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Routines for managing virtual address spaces
 */

#include <stdint.h>
#include <kernel_arch_interface.h>
#include <spinlock.h>
#include <mmu.h>
#include <init.h>
#include <kernel_internal.h>
#include <logging/log.h>
LOG_MODULE_DECLARE(os, CONFIG_KERNEL_LOG_LEVEL);

/* Spinlock to protect any globals in this file and serialize page table
 * updates in arch code
 */
struct k_spinlock z_mm_lock;

/* Database of all RAM page frames */
struct z_page_frame z_page_frames[Z_NUM_PAGE_FRAMES];

/* Doubly-linked list of unused and available page frames.
 *
 * TODO: This is very simple and treats all free page frames as being equal.
 * However, there are use-cases to consolidate free pages such that entire
 * SRAM banks can be switched off to save power, and so obtaining free pages
 * may require a more complex ontology which prefers page frames in RAM banks
 * which are still active.
 *
 * This implies in the future there may be multiple dlists managing physical
 * pages. Each page frame will still just have one dnode link.
 */
static sys_dlist_t free_page_frame_list;

#if __ASSERT_ON
/* Indicator that z_page_frames has been initialized */
static bool page_frames_initialized;
#endif

/*
 * Overall virtual memory map. When the kernel starts, it is expected that all
 * memory regions are mapped into one large virtual region at the beginning of
 * CONFIG_KERNEL_VM_BASE. Unused virtual memory up to the limit noted by
 * CONFIG_KERNEL_VM_SIZE may be used for runtime memory mappings.
 *
 * +--------------+ <- CONFIG_KERNEL_VM_BASE
 * | Mapping for  |
 * | all RAM      |
 * |              |
 * |              |
 * +--------------+ <- Z_VIRT_RAM_END
 * | Available    |    also the mapping limit as mappings grown downward
 * | virtual mem  |
 * |              |
 * |..............| <- mapping_pos (grows downward as more mappings are made)
 * | Mapping      |
 * +--------------+
 * | Mapping      |
 * +--------------+
 * | ...          |
 * +--------------+
 * | Mapping      |
 * +--------------+ <- mappings start here
 * | Reserved     | <- special purpose virtual page(s) of size Z_VM_RESERVED
 * +--------------+ <- Z_VIRT_ADDR_END
 *
 * At the moment we just have one area for mappings and they are permanent.
 * This is under heavy development and may change.
 */

 /* Current position for memory mappings in kernel memory.
  * At the moment, all kernel memory mappings are permanent.
  * z_mem_map() mappings start at the end of the address space, and grow
  * downward.
  *
  * All of this is under heavy development and is subject to change.
  */
static uint8_t *mapping_pos =
		(uint8_t *)((uintptr_t)CONFIG_KERNEL_VM_BASE +
			    (uintptr_t)CONFIG_KERNEL_VM_SIZE) - Z_VM_RESERVED;

/* Lower-limit of virtual address mapping. Immediately below this is the
 * permanent identity mapping for all SRAM.
 */
static uint8_t *mapping_limit =
	(uint8_t *)((uintptr_t)CONFIG_KERNEL_VM_BASE +
		    (size_t)CONFIG_KERNEL_RAM_SIZE);

size_t k_mem_region_align(uintptr_t *aligned_phys, size_t *aligned_size,
			  uintptr_t phys_addr, size_t size, size_t align)
{
	size_t addr_offset;

	/* The actual mapped region must be page-aligned. Round down the
	 * physical address and pad the region size appropriately
	 */
	*aligned_phys = ROUND_DOWN(phys_addr, align);
	addr_offset = phys_addr - *aligned_phys;
	*aligned_size = ROUND_UP(size + addr_offset, align);

	return addr_offset;
}

/* Soon will be replaced with a virtual memory allocator which allows for
 * virtual regions to be un-mapped.
 *
 * call with z_mm_lock held.
 */
static void *virt_region_get_locked(size_t size)
{
	uint8_t *dest_addr;

	if ((mapping_pos - size) < mapping_limit) {
		LOG_ERR("insufficient kernel virtual address space");
		return NULL;
	}

	mapping_pos -= size;
	dest_addr = mapping_pos;

	return dest_addr;
}

/* Hook for when we are memory-mapping physical RAM, to update the page frame
 * ontology.
 *
 * call with z_mm_lock held */
static void ram_mapping_update_locked(uintptr_t phys,
				      uint8_t *dest_addr, size_t aligned_size)
{
	uintptr_t phys_pos;
	struct z_page_frame *pf;
	uint8_t *addr_pos;

	for (uintptr_t offset = 0; offset < aligned_size;
	     offset += CONFIG_MMU_PAGE_SIZE) {
		phys_pos = phys + offset;
		addr_pos = (uint8_t *)dest_addr + offset;

		__ASSERT(z_is_page_frame(phys_pos),
			 "0x%lx is not a main system RAM address", phys_pos);

		pf = z_phys_to_page_frame(phys_pos);
		__ASSERT(!z_page_frame_is_reserved(pf),
			 "physical page frame 0x%lu is reserved", phys_pos);

		/* We do allow multiple mappings for pinned page frames
		 * since we will never need to reverse map them.
		 * This is uncommon, use-cases are for things like the
		 * Zephyr equivalent of VSDOs
		 */
		__ASSERT(!z_page_frame_is_mapped(pf) ||
			 z_page_frame_is_pinned(pf),
			 "non-pinned page frame 0x%lu already mapped to %p",
			 phys_pos, pf->addr);

		if (z_page_frame_is_available(pf)) {
			sys_dlist_remove(&pf->node);
		}

		pf->flags |= Z_PAGE_FRAME_MAPPED;

		if (!z_page_frame_is_pinned(pf)) {
			pf->addr = addr_pos;
		}
	}
}

void z_mem_map(uint8_t **addr, uintptr_t phys_addr, size_t size,
	       uint32_t flags)
{
	uintptr_t aligned_phys, addr_offset;
	size_t aligned_size;
	int ret;
	k_spinlock_key_t key;
	uint8_t *dest_addr;

	addr_offset = k_mem_region_align(&aligned_phys, &aligned_size,
					 phys_addr, size,
					 CONFIG_MMU_PAGE_SIZE);
	__ASSERT(aligned_size != 0, "0-length mapping at 0x%lx", aligned_phys);
	__ASSERT(aligned_phys < (aligned_phys + (aligned_size - 1)),
		 "wraparound for physical address 0x%lx (size %zu)",
		 aligned_phys, aligned_size);

	key = k_spin_lock(&z_mm_lock);
	/* Obtain an appropriately sized chunk of virtual memory */
	dest_addr = virt_region_get_locked(aligned_size);
	if (!dest_addr) {
		goto fail;
	}

	/* If this fails there's something amiss with virt_region_get_locked */
	__ASSERT((uintptr_t)dest_addr <
		 ((uintptr_t)dest_addr + (size - 1)),
		 "wraparound for virtual address %p (size %zu)",
		 dest_addr, size);

	LOG_DBG("arch_mem_map(%p, 0x%lx, %zu, %x) offset %lu", dest_addr,
		aligned_phys, aligned_size, flags, addr_offset);

	ret = arch_mem_map(dest_addr, aligned_phys, aligned_size, flags);
	if (ret != 0) {
		LOG_ERR("arch_mem_map() failed with %d", ret);
		goto fail;
	}

	/* Update our page frame ontology to reflect the mapping we just made */
	if (z_is_page_frame(aligned_phys)) {
		/* We can map MMIO at any time, but page_frames_init() needs
		 * to run before we can map any RAM page frames
		 */
		__ASSERT(page_frames_initialized, "mapping RAM too early");
		ram_mapping_update_locked(aligned_phys, dest_addr,
					  aligned_size);
	}
	k_spin_unlock(&z_mm_lock, key);

	*addr = dest_addr + addr_offset;
	return;
fail:
	/* May re-visit this in the future, but for now running out of
	 * virtual address space or failing the arch_mem_map() call is
	 * an unrecoverable situation.
	 *
	 * Other problems not related to resource exhaustion we leave as
	 * assertions since they are clearly programming mistakes.
	 */
	LOG_ERR("memory mapping 0x%lx (size %zu, flags 0x%x) failed",
		phys_addr, size, flags);
	k_panic();
}

#define SECTION_PAGES_ITER(_phys, _pageframe, _addr, _sect) \
	for (uint8_t *_addr = &_CONCAT(_sect, _start); \
	     uintptr_t _phys = Z_MEM_PHYS_ADDR(_addr), \
	     struct z_page_frame *_pageframe = z_phys_to_page_frame(_phys); \
	     _addr < &_CONCAT(_sect, _end); \
	     _addr += CONFIG_MMU_PAGE_SIZE, \
	     _phys += Z_MEM_PHYS_ADDR(addr), z_phys_to_page_frame(_phys))

static struct z_page_frame *free_page_frame_get_locked(void)
{
	sys_dnode_t *node;

	node = sys_dlist_get(&free_page_frame_list);
	if (node != NULL) {
		return CONTAINER_OF(node, struct z_page_frame, node);
	}

	return NULL;
}

static int mem_manage_init(const struct device *unused)
{
	uintptr_t phys;
	uint8_t *addr;
	struct z_page_frame *pf;

	k_spinlock_key_t key = k_spin_lock(&z_mm_lock);
	sys_dlist_init(&free_page_frame_list);

#ifdef CONFIG_ARCH_HAS_RESERVED_PAGE_FRAMES
	/* If some page frames are unavailable for use as memory, arch
	 * code will mark Z_PAGE_FRAME_RESERVED in their flags
	 */
	arch_reserved_pages_update();
#endif /* CONFIG_ARCH_HAS_RESERVED_PAGE_FRAMES */

	/* At the moment, arches map all RAM into a continuous region in the
	 * virtual address space at boot. This may include reserved pages,
	 * although they will be at least marked as such.
	 *
	 * This policy will change soon to only map those pages which compose
	 * the kernel image.
	 */
	for (addr = (uint8_t *)CONFIG_KERNEL_VM_BASE, pf = z_page_frames;
	     addr < (uint8_t *)Z_VIRT_RAM_END;
	     addr += CONFIG_MMU_PAGE_SIZE, pf++) {
		pf->flags |= Z_PAGE_FRAME_MAPPED;
		pf->addr = addr;
	}

#ifdef CONFIG_DEMAND_PAGING
	/* TODO: for demand paging, we will need to setup linker regions for
	 * a subset of kernel code/data pages which are pinned in memory and
	 * may not be evicted. This will contain critical CPU data structures,
	 * and any code used to perform page fault handling, page-ins, etc
	 */
#endif
	/* Any remaining pages that aren't mapped, reserved, or pinned get
	 * added to the free pages list
	 */
	Z_PAGE_FRAME_FOREACH(phys, pf) {
		if (z_page_frame_is_available(pf)) {
			sys_dlist_append(&free_page_frame_list, &pf->node);
		}
	}

#ifdef CONFIG_DEMAND_PAGING
	z_backing_store_init();
	z_eviction_init();
#endif
#if __ASSERT_ON
	page_frames_initialized = true;
#endif
	k_spin_unlock(&z_mm_lock, key);
	return 0;
}

SYS_INIT(mem_manage_init, PRE_KERNEL_1, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);

#ifdef CONFIG_DEMAND_PAGING
/* Current implementation relies on interrupt locking to any prevent page table
 * access, which falls over if other CPUs are active. Addressing this is not
 * as simple as using spinlocks as regular memory reads/writes constitute
 * "access" in this sense.
 *
 * Current needs for demand paging are on uniprocessor systems.
 */
BUILD_ASSERT(!IS_ENABLED(CONFIG_SMP));

static void virt_region_foreach(void *addr, size_t size,
				void (*func)(void *))
{
	z_mem_assert_virtual_region(addr, size);

	for (size_t offset = 0; offset < size; offset += CONFIG_MMU_PAGE_SIZE) {
		func((uint8_t *)addr + offset);
	}
}

static void page_frame_free_locked(struct z_page_frame *pf)
{
	pf->flags &= ~Z_PAGE_FRAME_MAPPED;
	sys_dlist_append(&free_page_frame_list, &pf->node);
}

/*
 * - Map page frame to scratch area if requested
 * - If mapped:
 *    - obtain backing store location and populate location parameter
 *    - Update page tables with location
 * - Mark page frame as busy
 */
static void page_frame_prepare_locked(struct z_page_frame *pf,
				      bool scratch, uintptr_t *location_ptr)
{
	uintptr_t phys, location = 0;

	phys = z_page_frame_to_phys(pf);
	__ASSERT(!z_page_frame_is_pinned(pf), "page frame is pinned 0x%lu",
		 phys);
	if (scratch) {
		arch_mem_scratch(phys);
	}
	if (z_page_frame_is_mapped(pf)) {
		location = z_backing_store_location_get(pf->addr);
		arch_mem_page_out(pf->addr, location);
		*location_ptr = location;
	}
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	/* Mark as busy so that z_page_frame_is_evictable() returns false */
	pf->flags |= Z_PAGE_FRAME_BUSY;
#endif
}

static void do_mem_evict(void *addr)
{
	bool dirty;
	struct z_page_frame *pf;
	uintptr_t location;
	int key;
	uintptr_t flags, phys;

#if CONFIG_DEMAND_PAGING_ALLOW_IRQ
	__ASSERT(!k_is_in_isr(),
		 "%s is unavailable in ISRs with CONFIG_DEMAND_PAGING_ALLOW_IRQ",
		 __func__);
	k_sched_lock();
#endif /* CONFIG_DEMAND_PAGING_ALLOW_IRQ */
	key = irq_lock();
	flags = arch_page_info_get(addr, &phys, false);
	__ASSERT((flags & ARCH_DATA_PAGE_NOT_MAPPED) != 0,
		 "invalid address %p", addr);
	if ((flags & ARCH_DATA_PAGE_LOADED) == 0) {
		/* Un-mapped or already evicted. Nothing to do */
		goto out;
	}

	dirty = (flags & ARCH_DATA_PAGE_DIRTY) != 0;
	pf = z_phys_to_page_frame(phys);
	__ASSERT(pf->addr == addr, "page frame address mismatch");
	page_frame_prepare_locked(pf, dirty, &location);
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	irq_unlock(key);
#endif /* CONFIG_DEMAND_PAGING_IRQ */
	if (dirty) {
		z_backing_store_page_out(location);
	}
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	key = irq_lock();
#endif /* CONFIG_DEMAND_PAGING_IRQ */
	page_frame_free_locked(pf);
out:
	irq_unlock(key);
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	k_sched_unlock();
#endif /* CONFIG_DEMAND_PAGING_ALLOW_IRQ */
}

void z_mem_evict(void *addr, size_t size)
{
	virt_region_foreach(addr, size, do_mem_evict);
}

void z_page_frame_evict(uintptr_t phys)
{
	int key;
	struct z_page_frame *pf;
	bool dirty;
	uintptr_t flags, location;

	/* Implementation is similar to do_page_fault() except there is no
	 * data page to page-in, see comments in that function.
	 */

#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	__ASSERT(!k_is_in_isr(),
		 "%s is unavailable in ISRs with CONFIG_DEMAND_PAGING_ALLOW_IRQ",
		 __func__);
	k_sched_lock();
#endif /* CONFIG_DEMAND_PAGING_ALLOW_IRQ */
	key = irq_lock();
	pf = z_phys_to_page_frame(phys);
	if (!z_page_frame_is_mapped(pf)) {
		/* Nothing to do, free page */
		goto out;
	}
	flags = arch_page_info_get(pf->addr, NULL, false);
	/* Shouldn't ever happen */
	__ASSERT((flags & ARCH_DATA_PAGE_LOADED) != 0, "data page not loaded");
	dirty = (flags & ARCH_DATA_PAGE_DIRTY) != 0;
	page_frame_prepare_locked(pf, dirty, &location);
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	irq_unlock(key);
#endif /* CONFIG_DEMAND_PAGING_IRQ */
	if (dirty) {
		z_backing_store_page_out(location);
	}
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	key = irq_lock();
	/* Clear both busy and mapped states */
#endif /* CONFIG_DEMAND_PAGING_IRQ */
	page_frame_free_locked(pf);
out:
	irq_unlock(key);
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	k_sched_unlock();
#endif /* CONFIG_DEMAND_PAGING_ALLOW_IRQ */
}

static bool do_page_fault(void *addr, bool pin)
{
	struct z_page_frame *pf;
	int key;
	uintptr_t page_in_location, page_out_location;
	enum arch_page_location status;
	bool ret;
	bool dirty = false;

	/*
	 * TODO: Add performance accounting:
	 * - Number of pagefaults
	 *   * gathered on a per-thread basis:
	 *     . Pagefaults with IRQs locked in faulting thread (bad)
	 *     . Pagefaults with IRQs unlocked in faulting thread
	 *   * Pagefaults in ISRs (if allowed)
	 * - z_eviction_select() metrics
	 *   * Clean vs dirty page eviction counts
	 *   * execution time histogram
	 *   * periodic timer execution time histogram (if implemented)
	 * - z_backing_store_page_out() execution time histogram
	 * - z_backing_store_page_in() execution time histogram
	 */

#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	/* We lock the scheduler so that other threads are never scheduled
	 * during the page-in/out operation.
	 *
	 * We do however re-enable interrupts during the page-in/page-out
	 * operation iff interrupts were enabled when the exception was taken;
	 * in this configuration page faults in an ISR are a bug; all their
	 * code/data must be pinned.
	 *
	 * If interrupts were disabled when the exception was taken, the
	 * arch code is responsible for keeping them that way when entering
	 * this function.
	 *
	 * If this is not enabled, then interrupts are always locked for the
	 * entire operation. This is far worse for system interrupt latency
	 * but requires less pinned pages and ISRs may also take page faults.
	 *
	 * Support for allowing z_backing_store_page_out() and
	 * z_backing_store_page_in() to also sleep and allow other threads to
	 * run (such as in the case where the transfer is async DMA) is not
	 * implemented. Even if limited to thread context, arbitrary memory
	 * access triggering exceptions that put a thread to sleep on a
	 * contended page fault operation will break scheduling assumptions of
	 * cooperative threads or threads that implement crticial sections with
	 * spinlocks or disabling IRQs.
	 */
	k_sched_lock();
	__ASSERT(!k_is_in_isr(), "ISR page faults are forbidden");
#endif /* CONFIG_DEMAND_PAGING_ALLOW_IRQ */

	key = irq_lock();
	status = arch_page_location_get(addr, &page_in_location);
	if (status == ARCH_PAGE_LOCATION_BAD) {
		/* Return false to treat as a fatal error */
		ret = false;
		goto out;
	}
	ret = true;
	if (status == ARCH_PAGE_LOCATION_PAGED_IN) {
		if (pin) {
			/* It's a physical memory address */
			uintptr_t phys = page_in_location;
			pf = z_phys_to_page_frame(phys);
			pf->flags |= Z_PAGE_FRAME_PINNED;
		}
		/* We raced before locking IRQs, re-try */
		goto out;
	}
	__ASSERT(status == ARCH_PAGE_LOCATION_PAGED_OUT,
		 "unexpected status value %d", status);

	pf = free_page_frame_get_locked();
	if (pf == NULL) {
		/* Need to evict a page frame */
		pf = z_eviction_select(&dirty);
		__ASSERT(pf != NULL, "failed to get a page frame");
	}
	page_frame_prepare_locked(pf, true, &page_out_location);
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	irq_unlock(key);
	/* Interrupts are now unlocked if they were not locked when we entered
	 * this function, and we may service ISRs. The scheduler is still
	 * locked.
	 */
#endif /* CONFIG_DEMAND_PAGING_IRQ */
	if (dirty) {
		z_backing_store_page_out(page_out_location);
	}
	z_backing_store_page_in(page_in_location);

#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	key = irq_lock();
	/* Clear busy state and set that the paged-in data page is now
	 * mapped to this page frame
	 */
	pf->flags = (pf->flags & ~Z_PAGE_FRAME_BUSY) | Z_PAGE_FRAME_MAPPED;
#else
	pf->flags |= Z_PAGE_FRAME_MAPPED;
	if (pin) {
		pf->flags |= Z_PAGE_FRAME_PINNED;
	}
#endif /* CONFIG_DEMAND_PAGING_IRQ */
	pf->addr = addr;
	arch_mem_page_in(addr, z_page_frame_to_phys(pf));
out:
	irq_unlock(key);
#ifdef CONFIG_DEMAND_PAGING_ALLOW_IRQ
	k_sched_unlock();
#endif /* CONFIG_DEMAND_PAGING_ALLOW_IRQ */

	return ret;
}

static void do_page_in(void *addr)
{
	bool ret = do_page_fault(addr, false);
	__ASSERT(ret, "unmapped memory address %p", addr);
	(void)ret;
}

void z_mem_page_in(void *addr, size_t size)
{
	virt_region_foreach(addr, size, do_page_in);
}

static void do_mem_pin(void *addr)
{
	bool ret = do_page_fault(addr, true);
	__ASSERT(ret, "unmapped memory address %p", addr);
	(void)ret;
}

void z_mem_pin(void *addr, size_t size)
{
	virt_region_foreach(addr, size, do_mem_pin);
}

bool z_page_fault(void *addr)
{
	return do_page_fault(addr, false);
}

static void do_mem_unpin(void *addr)
{
	struct z_page_frame *pf;
	int key;
	uintptr_t flags, phys;

	key = irq_lock();
	flags = arch_page_info_get(addr, &phys, false);
	__ASSERT((flags & ARCH_DATA_PAGE_NOT_MAPPED) == 0,
		 "invalid data page at %p", addr);
	if ((flags & ARCH_DATA_PAGE_LOADED) != 0) {
		pf = z_phys_to_page_frame(phys);
		pf->flags &= ~Z_PAGE_FRAME_PINNED;
	}
	irq_unlock(key);
}

void z_mem_unpin(void *addr, size_t size)
{
	virt_region_foreach(addr, size, do_mem_unpin);
}
#endif /* CONFIG_DEMAND_PAGING */
