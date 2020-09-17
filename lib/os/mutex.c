/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <sys/mutex.h>

#define LOG_LEVEL CONFIG_KERNEL_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(sys_mutex);

void sys_mutex_init(struct sys_mutex *mutex)
{
	mutex->recursive_lock_count = 0U;
	(void)atomic_ptr_set(&mutex->user_mutex.val, (atomic_ptr_t)0);
}



int sys_mutex_lock(struct sys_mutex *mutex, k_timeout_t timeout)
{
	/* Presumes k_current_get() is NOT a syscall and obtains the value
	 * in userspace from TLS or something like that
	 */
	atomic_ptr_t old_val;
	k_tid_t current = k_current_get();
	atomic_ptr_t new_val = (atomic_ptr_t)current;
	bool contended;

	LOG_DBG("%s on %p from %p", __func__, mutex, current);

	do {
		old_val = atomic_ptr_get(&mutex->user_mutex.val);
		contended = old_val != (atomic_ptr_t)0;

		if (contended) {
			k_tid_t old_owner = z_mutex_get_owner(old_val);

			/* Check if this is a recursive lock */
			if (old_owner == current) {
				if (mutex->recursive_lock_count > 0xFFFFU) {
					/* Too many recursive locks */
					LOG_ERR("too many recursive locks on %p",
						mutex);
					return -EINVAL;
				}
				mutex->recursive_lock_count++;
				return 0;
			}

			/* Mutex is held by some other thread */
			break;
		}
	} while (atomic_ptr_cas(&mutex->user_mutex.val, old_val, new_val));

	if (!contended) {
		/* We successfully locked an uncontended mutex */
		return 0;
	}

	if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
		/* Held but we're not going to wait for it */
		return -EBUSY;
	}

	/* Wait for mutex to be unlocked */
	return z_user_mutex_kernel_lock(&mutex->user_mutex, timeout);
}

int sys_mutex_unlock(struct sys_mutex *mutex)
{
	atomic_ptr_t old_val;
	k_tid_t old_owner;
	bool waiters;
	k_tid_t current = k_current_get();

	LOG_DBG("%s on %p from %p", __func__, mutex, current);

	do {
		old_val = atomic_ptr_get(&mutex->user_mutex.val);

		if (old_val == 0) {
			/* Wasn't locked */
			LOG_ERR("%p is not locked", mutex);
			return -EINVAL;
		}

		old_owner = z_mutex_get_owner(old_val);

		if (old_owner != current) {
			/* Not our mutex. Presumes k_current_get() is not
			 * a syscall
			 */
			LOG_ERR("%p is not our mutex %p owns it", mutex,
				old_owner);
			return -EINVAL;
		}

		if (mutex->recursive_lock_count > 0) {
			/* Recursive unlock, just decrement and return */
			mutex->recursive_lock_count--;
			return 0;
		}

		waiters = z_mutex_has_waiters(old_val);

		if (waiters) {
			/* Has waiters, need to make a syscall */
			break;
		}
	} while (atomic_ptr_cas(&mutex->user_mutex.val, old_val,
				(atomic_ptr_t)0));

	if (!waiters) {
		/* Successfully unlocked a mutex with no waiters,
		 * val is now 0
		 */
		return 0;
	}

	/* Wake up waiters */
	return z_user_mutex_kernel_unlock(&mutex->user_mutex);
}
