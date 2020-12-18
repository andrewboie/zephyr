/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* This should be the last data section in memory */
SECTION_PROLOGUE(_NOINIT_SECTION_NAME,(NOLOAD),)
{
        /*
         * This section is used for non-initialized objects that
         * will not be cleared during the boot process.
         */
        *(.noinit)
        *(".noinit.*")

/* Located in generated directory. This file is populated by the
 * zephyr_linker_sources() Cmake function.
 */
#include <snippets-noinit.ld>

#ifdef CONFIG_USERSPACE
	z_user_stacks_start = .;
	*(.user_stacks*)
	z_user_stacks_end = .;
#ifdef CONFIG_GEN_PRIV_STACKS
        /* This must be the last thing in memory as these are not generated
         * until the second build pass, disturbing the memory addresses
         * of anything coming after it
         */
	z_priv_stacks_ram_start = .;
	*(".priv_stacks.noinit")
	z_priv_stacks_ram_end = .;
#endif /* CONFIG_GEN_PRIV_STACKS */
#endif /* CONFIG_USERSPACE */
#ifdef CONFIG_MMU
        /* End of RAM, align to page size as this will be the end of
         * kernel image mapping
         */
	. = ALIGN(CONFIG_MMU_PAGE_SIZE);
        z_mapped_end = .;
#endif
} GROUP_DATA_LINK_IN(RAMABLE_REGION, RAMABLE_REGION)

#ifdef CONFIG_MMU
z_mapped_size = z_mapped_end - z_mapped_start;
#endif