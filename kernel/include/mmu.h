/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef KERNEL_INCLUDE_MMU_H
#define KERNEL_INCLUDE_MMU_H

#include <stdint.h>
#include <sys/dlist.h>
#include <sys/__assert.h>
#include <sys/util.h>

/*
 * Macros and data structures for physical page frame accounting,
 * APIs for use by eviction and backing store algorithms. This code
 * is otherwise not application-facing.
 */

/*
 * z_page_frame flags bits
 */

/** This page contains critical kernel data and will never be swapped */
#define Z_PAGE_FRAME_PINNED		BIT(0)

/** This physical page is reserved by hardware; we will never use it */
#define Z_PAGE_FRAME_RESERVED		BIT(1)

/**
 * This physical page is mapped to some virtual memory address
 *
 * Currently, we just support one mapping per page frame. If a page frame
 * is mapped to multiple virtual pages then it must be pinned.
 */
#define Z_PAGE_FRAME_MAPPED		BIT(2)

/**
 * This page frame is currently involved in a page-in/out operation
 */
#define Z_PAGE_FRAME_BUSY		BIT(3)

/**
 * Data structure for physical page frames
 *
 * An array of these is instantiated, one element per physical RAM page.
 * Hence it's necessary to constrain its size as much as possible.
 */
struct z_page_frame {
	union {
		/* If mapped, virtual address this page is mapped to */
		void *addr;

		/* If unmapped and available, free pages list membership. */
		sys_dnode_t node;
	};

	/* Bits 0-15 reserved for kernel Z_PAGE_FRAME_* flags
	 * Bits 16-31 reserved for page eviction algorithm implementation, if
	 * needed.
	 */
	uint32_t flags;
};

static inline bool z_page_frame_is_pinned(struct z_page_frame *pf)
{
	return (pf->flags & Z_PAGE_FRAME_PINNED) != 0;
}

static inline bool z_page_frame_is_reserved(struct z_page_frame *pf)
{
	return (pf->flags & Z_PAGE_FRAME_RESERVED) != 0;
}

static inline bool z_page_frame_is_mapped(struct z_page_frame *pf)
{
	return (pf->flags & Z_PAGE_FRAME_MAPPED) != 0;
}

static inline bool z_page_frame_is_busy(struct z_page_frame *pf)
{
	return (pf->flags & Z_PAGE_FRAME_BUSY) != 0;
}

static inline bool z_page_frame_is_evictable(struct z_page_frame *pf)
{
	return (!z_page_frame_is_reserved(pf) && z_page_frame_is_mapped(pf) &&
		!z_page_frame_is_pinned(pf) && !z_page_frame_is_busy(pf));
}

/* If true, page is not being used for anything, is not reserved, is a member
 * of some free pages list, isn't busy, and may be mapped in memory
 */
static inline bool z_page_frame_is_available(struct z_page_frame *page)
{
	return (page->flags & 0xFFFFU) == 0;
}

static inline void z_assert_phys_aligned(uintptr_t phys)
{
	__ASSERT(phys % CONFIG_MMU_PAGE_SIZE == 0,
		 "physical address 0x%lu is not page-aligned", phys);
	(void)phys;
}

/*
 * At present, page frame management is only done for main system RAM,
 * and we generate paging structures based on CONFIG_SRAM_BASE_ADDRESS
 * and CONFIG_SRAM_SIZE.
 *
 * If we have other RAM regions (DCCM, etc) these typically have special
 * properties and shouldn't be used generically for demand paging or
 * anonymous mappings. We don't currently maintain an ontology of these in the
 * core kernel.
 */
#define Z_NUM_PAGE_FRAMES (KB(CONFIG_SRAM_SIZE) / CONFIG_MMU_PAGE_SIZE)

/** End physical address of system RAM */
#define Z_PHYS_RAM_END	((uintptr_t)(CONFIG_SRAM_BASE_ADDRESS + \
					   KB(CONFIG_SRAM_SIZE)))

/** End virtual address of physical RAM mapping in virtual address space */
#define Z_VIRT_RAM_END	((void *)(CONFIG_KERNEL_VM_BASE + \
				  KB(CONFIG_SRAM_SIZE)))

/** End virtual address of virtual address space */
#define Z_VIRT_ADDR_END	((void *)(CONFIG_KERNEL_VM_BASE + \
				  CONFIG_KERNEL_VM_SIZE))

extern struct z_page_frame z_page_frames[Z_NUM_PAGE_FRAMES];

static inline uintptr_t z_page_frame_to_phys(struct z_page_frame *pf)
{
	return (uintptr_t)((pf - z_page_frames) * CONFIG_MMU_PAGE_SIZE) +
			CONFIG_SRAM_BASE_ADDRESS;
}

static inline bool z_is_page_frame(uintptr_t phys)
{
	z_assert_phys_aligned(phys);
	return (phys >= CONFIG_SRAM_BASE_ADDRESS) && (phys < Z_PHYS_RAM_END);
}

static inline struct z_page_frame *z_phys_to_page_frame(uintptr_t phys)
{
	__ASSERT(z_is_page_frame(phys),
		 "0x%lx not an SRAM physical address", phys);

	return &z_page_frames[(phys - CONFIG_SRAM_BASE_ADDRESS) /
			      CONFIG_MMU_PAGE_SIZE];
}

static inline void z_mem_assert_virtual_region(void *addr, size_t size)
{
	__ASSERT((uintptr_t)addr % CONFIG_MMU_PAGE_SIZE == 0,
		 "unaligned addr %p", addr);
	__ASSERT(size % CONFIG_MMU_PAGE_SIZE == 0,
		 "unaligned size %zu", size);
	__ASSERT((uintptr_t)addr + size > (uintptr_t)addr,
		 "region %p size %zu zero or wraps around", addr, size);
	__ASSERT((uintptr_t)addr >= (uintptr_t)CONFIG_KERNEL_VM_BASE &&
		 ((uintptr_t)addr + size) < (uintptr_t)Z_VIRT_ADDR_END,
		 "invalid virtual address region %p (%zu)", addr, size);
}

/* Convenience macro for iterating over all page frames */
#define Z_PAGE_FRAME_FOREACH(_phys, _pageframe) \
	for (_phys = CONFIG_SRAM_BASE_ADDRESS, _pageframe = z_page_frames; \
	     _phys < Z_PHYS_RAM_END; \
	     _phys += CONFIG_MMU_PAGE_SIZE, _pageframe++)

#define Z_VM_RESERVED	0

#endif /* KERNEL_INCLUDE_MMU_H */