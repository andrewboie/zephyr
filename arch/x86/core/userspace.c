/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <sys/speculation.h>
#include <syscall_handler.h>
#include <kernel_arch_func.h>
#include <ksched.h>
#include <x86_mmu.h>

#ifndef CONFIG_X86_KPTI
/* Update the to the incoming thread's page table, and update the location of
 * the privilege elevation stack.
 *
 * May be called ONLY during context switch. Hot code path!
 *
 * Nothing to do here if KPTI is enabled. We are in supervisor mode, so the
 * active page tables are the kernel's page tables. If the incoming thread is
 * in user mode we are going to switch CR3 to the domain-specific tables when
 * we go through z_x86_trampoline_to_user.
 *
 * We don't need to update the privilege mode initial stack pointer either,
 * privilege elevation always lands on the trampoline stack and the irq/sycall
 * code has to manually transition off of it to the appropriate stack after
 * switching page tables.
 */
void z_x86_swap_update_page_tables(struct k_thread *incoming)
{
	uintptr_t ptables_phys;

#ifndef CONFIG_X86_64
	/* 64-bit uses syscall/sysret which switches stacks manually,
	 * tss64.psp is updated unconditionally in __resume
	 */
	if ((incoming->base.user_options & K_USER) != 0) {
		_main_tss.esp0 = (uintptr_t)incoming->arch.psp;
	}
#endif

	/* Check first that we actually need to do this, since setting
	 * CR3 involves an expensive full TLB flush.
	 */
	ptables_phys = incoming->arch.ptables;

	if (ptables_phys != z_x86_cr3_get()) {
		z_x86_cr3_set(ptables_phys);
	}
}
#endif /* CONFIG_X86_KPTI */

static FUNC_NORETURN void user_mode_enter(k_thread_entry_t user_entry,
					  void *p1, void *p2, void *p3)
{
	uint32_t stack_end;

	/* Transition will reset stack pointer to initial, discarding
	 * any old context since this is a one-way operation
	 */
	stack_end = Z_STACK_PTR_ALIGN(_current->stack_info.start +
				      _current->stack_info.size -
				      _current->stack_info.delta);

	z_x86_userspace_enter(user_entry, p1, p2, p3, stack_end,
			      _current->stack_info.start);
	CODE_UNREACHABLE;
}


/* Preparation steps needed for all threads if user mode is turned on.
 *
 * Returns the initial entry point to swap into.
 */
void *z_x86_userspace_prepare_thread(struct k_thread *thread)
{
	void *initial_entry;
	struct z_x86_thread_stack_header *header =
		(struct z_x86_thread_stack_header *)thread->stack_obj;

	thread->arch.psp =
		header->privilege_stack + sizeof(header->privilege_stack);

	if ((thread->base.user_options & K_USER) != 0U) {
		initial_entry = user_mode_enter;
	} else {
		initial_entry = z_thread_entry;
	}

	return initial_entry;
}

#if 0
/* Must be on the privilege elevation stack. Erase the thread stack contents
 * and allow User mode to access it
 */
void z_x86_user_stack_setup(void)
{
	memset(_current->stack_info.start, 0xAA,
	       _current->stack_info.size - _current->stack_info.delta);
}
#endif

FUNC_NORETURN void arch_user_mode_enter(k_thread_entry_t user_entry,
					void *p1, void *p2, void *p3)
{
	// XXX not safe to do here
	z_x86_stack_perms(_current);

	user_mode_enter(user_entry, p1, p2, p3);
}
