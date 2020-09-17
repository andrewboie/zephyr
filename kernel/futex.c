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
#include <sys/futex.h>

static struct z_futex_data *k_futex_find_data(struct k_futex *futex)
{
	struct z_object *obj;

	obj = z_object_find(futex);
	if (obj == NULL || obj->type != K_OBJ_FUTEX) {
		return NULL;
	}

	return obj->data.futex_data;
}

static struct k_mutex *get_k_mutex(struct z_user_mutex *mutex)
{
	struct z_object *obj;

	obj = z_object_find(mutex);
	if (obj == NULL || obj->type != K_OBJ_USER_MUTEX) {
		return NULL;
	}

	return obj->data.mutex;
}

int z_impl_k_futex_wake(struct k_futex *futex, bool wake_all)
{
	k_spinlock_key_t key;
	unsigned int woken = 0;
	struct k_thread *thread;
	struct z_futex_data *futex_data;

	futex_data = k_futex_find_data(futex);
	if (futex_data == NULL) {
		return -EINVAL;
	}

	key = k_spin_lock(&futex_data->lock);

	do {
		thread = z_unpend_first_thread(&futex_data->wait_q);
		if (thread) {
			z_ready_thread(thread);
			arch_thread_return_value_set(thread, 0);
			woken++;
		}
	} while (thread && wake_all);

	z_reschedule(&futex_data->lock, key);

	return woken;
}

static inline int z_vrfy_k_futex_wake(struct k_futex *futex, bool wake_all)
{
	if (Z_SYSCALL_MEMORY_WRITE(futex, sizeof(struct k_futex)) != 0) {
		return -EACCES;
	}

	return z_impl_k_futex_wake(futex, wake_all);
}
#include <syscalls/k_futex_wake_mrsh.c>

int z_impl_k_futex_wait(struct k_futex *futex, int expected,
			k_timeout_t timeout)
{
	int ret;
	k_spinlock_key_t key;
	struct z_futex_data *futex_data;

	futex_data = k_futex_find_data(futex);
	if (futex_data == NULL) {
		return -EINVAL;
	}

	key = k_spin_lock(&futex_data->lock);

	if (atomic_get(&futex->val) != (atomic_val_t)expected) {
		k_spin_unlock(&futex_data->lock, key);
		return -EAGAIN;
	}

	ret = z_pend_curr(&futex_data->lock,
			key, &futex_data->wait_q, timeout);
	if (ret == -EAGAIN) {
		ret = -ETIMEDOUT;
	}

	return ret;
}

static inline int z_vrfy_k_futex_wait(struct k_futex *futex, int expected,
				      k_timeout_t timeout)
{
	if (Z_SYSCALL_MEMORY_WRITE(futex, sizeof(struct k_futex)) != 0) {
		return -EACCES;
	}

	return z_impl_k_futex_wait(futex, expected, timeout);
}
#include <syscalls/k_futex_wait_mrsh.c>

static bool check_sys_mutex_addr(struct z_user_mutex *addr)
{
	/* z_user_mutex memory is never touched, just used to lookup the
	 * underlying k_mutex, but we don't want threads using mutexes
	 * that are outside their memory domain
	 */
	return Z_SYSCALL_MEMORY_WRITE(addr, sizeof(struct z_user_mutex));
}

int z_impl_z_sys_mutex_kernel_lock(struct z_user_mutex *mutex,
				   k_timeout_t timeout)
{
	struct k_mutex *kernel_mutex = get_k_mutex(mutex);

	if (kernel_mutex == NULL) {
		return -EINVAL;
	}

	return k_mutex_lock(kernel_mutex, timeout);
}

static inline int z_vrfy_z_sys_mutex_kernel_lock(struct z_user_mutex *mutex,
						 k_timeout_t timeout)
{
	if (check_sys_mutex_addr(mutex)) {
		return -EACCES;
	}

	return z_impl_z_sys_mutex_kernel_lock(mutex, timeout);
}
#include <syscalls/z_sys_mutex_kernel_lock_mrsh.c>

int z_impl_z_sys_mutex_kernel_unlock(struct z_user_mutex *mutex)
{
	struct k_mutex *kernel_mutex = get_k_mutex(mutex);

	if (kernel_mutex == NULL || kernel_mutex->lock_count == 0) {
		return -EINVAL;
	}

	if (kernel_mutex->owner != _current) {
		return -EPERM;
	}

	k_mutex_unlock(kernel_mutex);
	return 0;
}

static inline int z_vrfy_z_sys_mutex_kernel_unlock(struct z_user_mutex *mutex)
{
	if (check_sys_mutex_addr(mutex)) {
		return -EACCES;
	}

	return z_impl_z_sys_mutex_kernel_unlock(mutex);
}
#include <syscalls/z_sys_mutex_kernel_unlock_mrsh.c>
