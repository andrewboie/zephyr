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

static struct k_wait_q *k_futex_find_wait_q(struct k_futex *futex)
{
	struct _k_object *obj;

	obj = z_object_find(futex);
	if (obj == NULL || obj->type != K_OBJ_FUTEX) {
		return NULL;
	}

	return (struct k_wait_q *)obj->data;
}

int z_impl_k_futex_wake(struct k_futex *futex, bool wake_all)
{
	struct k_wait_q *wait_q;

	wait_q = k_futex_find_wait_q(futex);
	if (wait_q == NULL) {
		return -EINVAL;
	}

	return k_wait_q_wake(wait_q, wake_all);
}

static inline int z_vrfy_k_futex_wake(struct k_futex *futex, bool wake_all)
{
	if (Z_SYSCALL_MEMORY_WRITE(futex, sizeof(struct k_futex)) != 0) {
		return -EACCES;
	}

	return z_impl_k_futex_wake(futex, wake_all);
}
#include <syscalls/k_futex_wake_mrsh.c>

int z_impl_k_futex_wait(struct k_futex *futex, int expected, s32_t timeout)
{
	struct k_wait_q *wait_q;

	wait_q = k_futex_find_wait_q(futex);
	if (wait_q == NULL) {
		return -EINVAL;
	}

	return k_wait_q_wait(wait_q, &futex->val, (atomic_t)expected, timeout);
}

static inline int z_vrfy_k_futex_wait(struct k_futex *futex, int expected,
				      s32_t timeout)
{
	if (Z_SYSCALL_MEMORY_WRITE(futex, sizeof(struct k_futex)) != 0) {
		return -EACCES;
	}

	return z_impl_k_futex_wait(futex, expected, timeout);
}
#include <syscalls/k_futex_wait_mrsh.c>
