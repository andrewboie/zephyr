/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef COMMON_H
#define COMMON_H

extern void test_kernel_apis(void);
extern void test_delay(void);
extern void test_thread_apis(void);
extern void test_thread_apis_dynamic(void);
extern void test_thread_prio(void);
extern void test_thread_prio_dynamic(void);
extern void test_timer(void);
extern void test_mutex(void);
extern void test_mutex_lock_timeout(void);
extern void test_semaphore(void);
extern void test_mempool(void);
extern void test_mempool_dynamic(void);
extern void test_messageq(void);
extern void test_event_flags_no_wait_timeout(void);
extern void test_event_flags_signalled(void);
extern void test_event_flags_isr(void);
extern void test_thread_flags_no_wait_timeout(void);
extern void test_thread_flags_signalled(void);
extern void test_thread_flags_isr(void);
extern void test_thread_join(void);
extern void test_thread_detached(void);
extern void test_thread_joinable_detach(void);
extern void test_thread_joinable_terminate(void);
extern void test_thread_joinable_selfexit(void);
extern void test_thread_recycling(void);

#endif
