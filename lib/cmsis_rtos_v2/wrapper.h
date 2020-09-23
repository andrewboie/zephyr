/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __WRAPPER_H__
#define __WRAPPER_H__

#include <kernel.h>
#include <cmsis_os2.h>

#define TRUE    1
#define FALSE   0

struct cv2_thread {
	/* Reserve room for mem lab free list; we need freed slabs not to
	 * be corrupted
	 */
	char *slab_list;
	struct k_thread z_thread;
	struct k_poll_signal poll_signal;
	struct k_poll_event poll_event;
	uint32_t signal_results;
	char name[16];
	uint32_t attr_bits;
	struct k_sem join_guard;
	char has_joined;
	k_thread_stack_t *alloc_stack;
};

struct cv2_timer {
	struct k_timer z_timer;
	osTimerType_t type;
	uint32_t status;
	char name[16];
	void (*callback_function)(void *argument);
	void *arg;
};

struct cv2_mutex {
	struct k_mutex z_mutex;
	char name[16];
	uint32_t state;
};

struct cv2_sem {
	struct k_sem z_semaphore;
	char name[16];
};

struct cv2_mslab {
	struct k_mem_slab z_mslab;
	void *pool;
	char is_dynamic_allocation;
	char name[16];
};

struct cv2_msgq {
	struct k_msgq z_msgq;
	void *pool;
	char is_dynamic_allocation;
	char name[16];
};

struct cv2_event_flags {
	struct k_poll_signal poll_signal;
	struct k_poll_event poll_event;
	uint32_t signal_results;
	char name[16];
};

extern osThreadId_t get_cmsis_thread_id(k_tid_t tid);
extern bool is_cmsis_rtos_v2_thread(osThreadId_t thread_id);

#endif
