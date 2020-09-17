/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_SYS_FUTEX_H
#define ZEPHYR_INCLUDE_SYS_FUTEX_H

/**
 * @file
 *
 * System calls and data definitions for futex-based IPC
 */

#ifdef CONFIG_USERSPACE
#include <sys/atomic.h>
#include <zephyr/types.h>
#include <sys_clock.h>

#include <spinlock.h>
#include <kernel_structs.h>

 /**
 * @brief futex kernel internal data structure
 *
 * z_futex_data are the helper data structure for k_futex to complete
 * futex contended operation on kernel side, structure z_futex_data
 * of every futex object is invisible in user mode.
 *
 * TODO: Move these definitions under kernel/include/, the build for
 * the gperf table will need its include path adjusted
 */
struct z_futex_data {
	_wait_q_t wait_q;
	struct k_spinlock lock;
};

#define Z_FUTEX_DATA_INITIALIZER(obj) \
	{ \
	.wait_q = Z_WAIT_Q_INIT(&obj.wait_q) \
	}

struct z_user_mutex_data {
	struct k_mutex mutex;
};

#define Z_USER_MUTEX_DATA_INITIALIZER(obj) \
	{ \
		.mutex = Z_MUTEX_INITIALIZER(&obj.mutex) \
	}

/**
 * @brief futex structure
 *
 * A k_futex is a lightweight mutual exclusion primitive designed
 * to minimize kernel involvement. Uncontended operation relies
 * only on atomic access to shared memory. k_futex are tracked as
 * kernel objects and can live in user memory so any access bypass
 * the kernel object permission management mechanism.
 */
struct k_futex {
	atomic_t val;
};

/**
 * Placeholder structure for priority-inheriting mutexes
 *
 * This and k_futex will eventually be unified such that any atomic_t pointer
 * can be used for the syscalls in this header
 */
struct z_user_mutex {
	/* There is a specific policy on this value:
	 * - If the lock is free, value is 0
	 * - If the lock is held with no waiters, k_tid_t of the owner
	 * - If the lock is held with waiters,
	 *   owner k_tid_t | Z_USER_MUTEX_WAITERS, which works due to alignment
	 *   of the k_tid_t value
	 */
	atomic_ptr_t val;
};

/* Only bits 0 and 1 are free for flags due to 4-byte alignment of k_tid_t */
#define Z_USER_MUTEX_WAITERS	BIT(0)
#define Z_USER_MUTEX_BITS	0x3
/**
 * @defgroup futex_apis FUTEX APIs
 * @ingroup kernel_apis
 * @{
 */

/**
 * @brief Pend the current thread on a futex
 *
 * Tests that the supplied futex contains the expected value, and if so,
 * goes to sleep until some other thread calls k_futex_wake() on it.
 *
 * @param futex Address of the futex.
 * @param expected Expected value of the futex, if it is different the caller
 *		   will not wait on it.
 * @param timeout Non-negative waiting period on the futex, or
 *		  one of the special values K_NO_WAIT or K_FOREVER.
 * @retval -EACCES Caller does not have read access to futex address.
 * @retval -EAGAIN If the futex value did not match the expected parameter.
 * @retval -EINVAL Futex parameter address not recognized by the kernel.
 * @retval -ETIMEDOUT Thread woke up due to timeout and not a futex wakeup.
 * @retval 0 if the caller went to sleep and was woken up. The caller
 *	     should check the futex's value on wakeup to determine if it needs
 *	     to block again.
 */
__syscall int k_futex_wait(struct k_futex *futex, int expected,
			   k_timeout_t timeout);

/**
 * @brief Wake one/all threads pending on a futex
 *
 * Wake up the highest priority thread pending on the supplied futex, or
 * wakeup all the threads pending on the supplied futex, and the behavior
 * depends on wake_all.
 *
 * @param futex Futex to wake up pending threads.
 * @param wake_all If true, wake up all pending threads; If false,
 *                 wakeup the highest priority thread.
 * @retval -EACCES Caller does not have access to the futex address.
 * @retval -EINVAL Futex parameter address not recognized by the kernel.
 * @retval Number of threads that were woken up.
 */
__syscall int k_futex_wake(struct k_futex *futex, bool wake_all);

/**
 * @brief System call for locking a user mutex
 *
 * This gets invoked if the sys_mutex_lock code determines that this
 * mutex is probably contended.
 *
 * The value of the provided mutex is checked on the kernel side.
 * If 0, set the value to the caller's k_tid_t. This was an uncontended
 * mutex, and then return success.
 *
 * Otherwise, atomically set the Z_USER_MUTEX_WAITERS bit in the value.
 * Check that the remaining bits correspond to the k_tid_t of an owning
 * thread, and internally set up a k_mutex with that owner. Pend on that
 * k_mutex.
 *
 * @param mutex Address of mutex to lock
 * @param timeout Waiting period on the mutex, or K_FOREVER
 * @retval -EACCES Caller does not have write access to mutex address
 * @retval -EINVAL Mutex parameter address not recognized by the kernel,
 *                 or invalid owner value
 * @retval -EBUSY locked and K_NO_WAIT timeout provided
 * @retval -ETIMEDOUT Thread woke up due to timeout and not a mutex unlock
 * @retval 0 Mutex successfully locked
 */
__syscall int z_user_mutex_kernel_lock(struct z_user_mutex *mutex,
				       k_timeout_t timeout);

/**
 * @brief System call for unlocking a user mutex
 *
 * This gets invoked if the sys_mutex_lock code determines that this
 * mutex probably had waiters.
 *
 * Wake the top priority waiter that is in a z_user_muttex_kernel_lock()
 * call on the provided mutex, transferring ownership. If there were no
 * waiters, clear the mutex value.
 *
 * @param mutex Address of mutex to lock
 * @retval -EACCES Caller does not have write access to mutex address
 * @retval -EINVAL Mutex parameter address not recognized by the kernel,
 *                 invalid owner value, or mutex wasn't locked.
 * @retval -EPERM Wasn't our mutex
 * @retval 0 Mutex successfully unlocked
 */
__syscall int z_user_mutex_kernel_unlock(struct z_user_mutex *mutex);

static inline k_tid_t z_mutex_get_owner(atomic_ptr_t val)
{
	return (k_tid_t)((uintptr_t)val & ~Z_USER_MUTEX_BITS);
}

static inline bool z_mutex_has_waiters(atomic_ptr_t val)
{
	return ((uintptr_t)val & Z_USER_MUTEX_WAITERS) != 0;
}
/** @} */

#include <syscalls/futex.h>

#endif /* CONFIG_USERSPACE */
#endif /* ZEPHYR_INCLUDE_SYS_FUTEX_H */
