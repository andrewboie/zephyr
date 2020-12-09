/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * RAM-based memory buffer backing store implementation for demo purposes
 */
#include <mmu.h>
#include <string.h>
#include <kernel_arch_interface.h>

uintptr_t z_backing_store_location_get(void *addr)
{
	uintptr_t loc = (uintptr_t) addr;

	z_mem_assert_virtual_region(addr, CONFIG_MMU_PAGE_SIZE);

	/* Get an offset from the beginning of virtual memory */
	loc -= (uintptr_t)CONFIG_KERNEL_VM_BASE;

	/* And apply that to where we mapped the RAM backing store */
	loc += (uintptr_t)Z_VIRT_ADDR_END;

	return loc;
}

void z_backing_store_location_free(void *addr)
{
	ARG_UNUSED(addr);
}

void z_backing_store_page_out(uintptr_t location)
{
	(void)memcpy((void *)location, Z_SCRATCH_PAGE, CONFIG_MMU_PAGE_SIZE);
}

void z_backing_store_page_in(uintptr_t location)
{
	(void)memcpy(Z_SCRATCH_PAGE, (void *)location, CONFIG_MMU_PAGE_SIZE);
}

void z_backing_store_init(void)
{
	/* Map a region the size of the virtual address space starting
	 * at the end of the kernel's concept of virtual memory, using
	 * physical RAM past what the kernel knows about.
	 *
	 * The true virtual address space will be two equally sized
	 * regions; Zephyr's defined address space plus an equally sized
	 * region immediately after it that maps all this otherwise unused
	 * RAM.
	 */
	int ret = arch_mem_map(Z_VIRT_ADDR_END, Z_PHYS_RAM_END,
			       CONFIG_KERNEL_VM_SIZE, K_MEM_PERM_RW);
	__ASSERT(ret == 0, "backing store memory mapping failed");
}
