/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ztest.h>
#include <kernel.h>
#include <cmsis_os2.h>
#include "common.h"

void test_main(void)
{
	ztest_test_suite(test_cmsis_v2_apis,
			 ztest_unit_test(test_kernel_apis),
			 ztest_unit_test(test_delay),
			 ztest_unit_test(test_thread_apis),
			 ztest_unit_test(test_thread_apis_dynamic),
			 ztest_unit_test(test_thread_prio),
			 ztest_unit_test(test_thread_prio_dynamic),
			 ztest_unit_test(test_timer),
			 ztest_unit_test(test_mutex),
			 ztest_unit_test(test_mutex_lock_timeout),
			 ztest_unit_test(test_semaphore),
			 ztest_unit_test(test_mempool),
			 ztest_unit_test(test_mempool_dynamic),
			 ztest_unit_test(test_messageq),
			 ztest_unit_test(test_event_flags_no_wait_timeout),
			 ztest_unit_test(test_event_flags_signalled),
			 ztest_unit_test(test_event_flags_isr),
			 ztest_unit_test(test_thread_flags_no_wait_timeout),
			 ztest_unit_test(test_thread_flags_signalled),
			 ztest_unit_test(test_thread_flags_isr),
			 ztest_unit_test(test_thread_join),
			 ztest_unit_test(test_thread_detached),
			 ztest_unit_test(test_thread_joinable_detach),
			 ztest_unit_test(test_thread_joinable_terminate),
			 ztest_unit_test(test_thread_joinable_selfexit));

	ztest_run_test_suite(test_cmsis_v2_apis);
}
