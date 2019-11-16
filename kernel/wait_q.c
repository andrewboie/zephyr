/*
 * Copyright (c) 2019 Intel corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <kernel_structs.h>
#include <spinlock.h>
#include <kswap.h>
#include <syscall_handler.h>
#include <init.h>
#include <ksched.h>
#include <wait_q.h>

int z_impl_k_wait_q_init(struct k_wait_q *wait_q)
{
	z_waitq_init(&wait_q->queue);
	z_object_init(wait_q);

	return 0;
}

#ifdef CONFIG_USERSPACE
static inline int z_vrfy_k_wait_q_init(struct k_wait_q *wait_q)
{
	if (Z_SYSCALL_OBJ_INIT(wait_q, K_OBJ_WAIT_Q)) {
		return -EINVAL;
	}

	return z_impl_k_wait_q_init(wait_q);
}
#include <syscalls/k_wait_q_init_mrsh.c>
#endif /* CONFIG_USERSPACE */

int z_impl_k_wait_q_wait(struct k_wait_q *wait_q, atomic_t *val,
			 atomic_t expected, s32_t timeout)
{
	k_spinlock_key_t key = k_spin_lock(&wait_q->lock);
	int ret;

	if (atomic_get(val) != (atomic_val_t)expected) {
		k_spin_unlock(&wait_q->lock, key);
		return -EAGAIN;
	}

	ret = z_pend_curr(&wait_q->lock, key, &wait_q->queue, timeout);
	if (ret == -EAGAIN) {
		ret = -ETIMEDOUT;
	}

	return ret;
}

#ifdef CONFIG_USERSPACE
static inline int z_vrfy_k_wait_q_wait(struct k_wait_q *wait_q, atomic_t *val,
				       atomic_t expected, s32_t timeout)
{
	if (Z_SYSCALL_OBJ(wait_q, K_OBJ_WAIT_Q)) {
		return -EINVAL;
	}

	if (Z_SYSCALL_MEMORY_READ(val, sizeof(*val)) != 0) {
		return -EACCES;
	}

	return z_impl_k_wait_q_wait(wait_q, val, expected, timeout);
}
#include <syscalls/k_wait_q_wait_mrsh.c>
#endif /* CONFIG_USERSPACE */

int z_impl_k_wait_q_wake(struct k_wait_q *wait_q, bool wake_all)
{
	k_spinlock_key_t key;
	unsigned int woken = 0;
	struct k_thread *thread;

	key = k_spin_lock(&wait_q->lock);

	do {
		thread = z_unpend_first_thread(&wait_q->queue);
		if (thread) {
			z_ready_thread(thread);
			arch_thread_return_value_set(thread, 0);
			woken++;
		}
	} while (thread && wake_all);

	z_reschedule(&wait_q->lock, key);

	return woken;
}

#ifdef CONFIG_USERSPACE
static inline int z_vrfy_k_wait_q_wake(struct k_wait_q *wait_q, bool wake_all)
{
	if (Z_SYSCALL_OBJ(wait_q, K_OBJ_WAIT_Q)) {
		return -EINVAL;
	}

	return z_impl_k_wait_q_wake(wait_q, wake_all);
}
#include <syscalls/k_wait_q_wake_mrsh.c>
#endif /* CONFIG_USERSPACE */
