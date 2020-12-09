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

	/* Any remaining pages that aren't mapped, reserved, or pinned get
	 * added to the free pages list
	 */
	Z_PAGE_FRAME_FOREACH(phys, pf) {
		if (z_page_frame_is_available(pf)) {
			sys_dlist_append(&free_page_frame_list, &pf->node);
		}
	}

#if __ASSERT_ON
	page_frames_initialized = true;
#endif
	k_spin_unlock(&z_mm_lock, key);
	return 0;
}

SYS_INIT(mem_manage_init, PRE_KERNEL_1, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
