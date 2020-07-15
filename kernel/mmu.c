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

#define LOG_LEVEL CONFIG_KERNEL_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_DECLARE(os);

/* Spinlock to protect any globals in this file and serialize page table
 * updates in arch code
 */
static struct k_spinlock mm_lock;

#ifdef CONFIG_VIRTUAL_MEMORY
/*
 * Overall virtual memory map:
 *
 * +--------------+ <- CONFIG_KERNEL_VM_BASE
 * | Mapping for  |
 * | all RAM      |
 * |              |
 * |              |
 * +--------------+ <- mapping_limit
 * | Available    |
 * | virtual mem  |
 * |              |
 * |..............| <- mapping_pos
 * | Mapping      |
 * +--------------+
 * | Mapping      |
 * +--------------+
 * | ...          |
 * +--------------+
 * | Mapping      |
 * +--------------+ <- CONFIG_KERNEL_VM_LIMIT
 */

 /* Current position for memory mappings in kernel memory.
  * At the moment, all kernel memory mappings are permanent.
  * k_map() mappings start at the end of the address space, and grow
  * downward.
  *
  * The Kconfig value is inclusive so add one, even if it wraps around to 0.
  */
static uint8_t *mapping_pos =
		(uint8_t *)((uintptr_t)CONFIG_KERNEL_VM_LIMIT + 1UL);

/* Lower-limit of virtual address mapping. Immediately below this is the
 * permanent mapping for all SRAM.
 */
static uint8_t *mapping_limit = (uint8_t *)((uintptr_t)CONFIG_KERNEL_VM_BASE +
					    KB((size_t)CONFIG_SRAM_SIZE));
#endif

size_t k_map_region_align(uintptr_t *aligned_addr, size_t *aligned_size,
			  uintptr_t phys_addr, size_t size)
{
	size_t addr_offset;

	/* The actual mapped region must be page-aligned. Round down the
	 * physical address and pad the region size appropriately
	 */
	*aligned_addr = ROUND_DOWN(phys_addr, CONFIG_MMU_PAGE_SIZE);
	addr_offset = phys_addr - *aligned_addr;
	*aligned_size = ROUND_UP(size + addr_offset, CONFIG_MMU_PAGE_SIZE);

	return addr_offset;
}

void k_map(uint8_t **virt_addr, uintptr_t phys_addr, size_t size,
	   uint32_t flags)
{
	uintptr_t aligned_addr, addr_offset;
	size_t aligned_size;
	int ret;
	k_spinlock_key_t key;
	uint8_t *dest_virt;

	addr_offset = k_map_region_align(&aligned_addr, &aligned_size,
					 phys_addr, size);

	key = k_spin_lock(&mm_lock);
#ifdef CONFIG_VIRTUAL_MEMORY
	/* Carve out some unused virtual memory from the top of the
	 * address space
	 */
	if ((mapping_pos - aligned_size) < mapping_limit) {
		LOG_ERR("insufficient kernel virtual address space");
		goto fail;
	}
	mapping_pos -= aligned_size;
	dest_virt = mapping_pos;
#else
	/* Identity mapping */
	dest_virt = (uint8_t *)aligned_addr;
#endif

	LOG_DBG("arch_mem_map(%p, 0x%lx, %zu, %x) offset %lu\n", dest_virt,
		aligned_addr, aligned_size, flags, addr_offset);
	__ASSERT(dest_virt != NULL, "NULL memory mapping");
	__ASSERT(aligned_size != 0, "0-length mapping at 0x%lx", aligned_addr);
	ret = arch_mem_map(dest_virt, aligned_addr, aligned_size, flags);
	k_spin_unlock(&mm_lock, key);

	if (ret == 0) {
		*virt_addr = dest_virt + addr_offset;
	} else {
		/* This happens if there is an insurmountable problem
		 * with the selected cache modes or access flags
		 * with no safe fallback
		 */

		LOG_ERR("arch_mem_map() to %p returned %d", dest_virt, ret);
		goto fail;
	}
	return;
fail:
	LOG_ERR("memory mapping 0x%lx (size %zu, flags 0x%x) failed",
		phys_addr, size, flags);
	k_panic();
}
