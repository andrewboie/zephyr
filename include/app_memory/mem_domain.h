/*
 * Copyright (c) 2017 Linaro Limited
 * Copyright (c) 2018-2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INCLUDE_APP_MEMPORY_MEM_DOMAIN_H
#define INCLUDE_APP_MEMPORY_MEM_DOMAIN_H

#include <stdint.h>
#include <stddef.h>
#include <sys/dlist.h>
#include <toolchain.h>

/* Forward declaration */
struct k_thread;
typedef struct k_thread *k_tid_t;

/**
 * @defgroup mem_domain_apis Memory domain APIs
 * @ingroup kernel_apis
 * @{
 */

#ifdef CONFIG_MEMORY_PROTECTION
/**
 * @def K_MEM_PARTITION_DEFINE
 *
 * @brief Statically declare a memory partition
 */
#ifdef _ARCH_MEM_PARTITION_ALIGN_CHECK
#define K_MEM_PARTITION_DEFINE(name, start, size, attr) \
	_ARCH_MEM_PARTITION_ALIGN_CHECK(start, size); \
	struct k_mem_partition name =\
		{ (uintptr_t)start, size, attr}
#else
#define K_MEM_PARTITION_DEFINE(name, start, size, attr) \
	struct k_mem_partition name =\
		{ (uintptr_t)start, size, attr}
#endif /* _ARCH_MEM_PARTITION_ALIGN_CHECK */

/**
 * @brief Memory Partition
 *
 * A memory partition is a region of memory in the linear address space
 * with a specific access policy.
 *
 * The alignment of the starting address, and the alignment of the size
 * value may have varying requirements based on the capabilities of the
 * underlying memory management hardware; arbitrary values are unlikely
 * to work.
 */
struct k_mem_partition {
	/** start address of memory partition */
	uintptr_t start;
	/** size of memory partition */
	size_t size;
	/** attribute of memory partition */
	k_mem_partition_attr_t attr;
};
#else
/* To support use of IS_ENABLED for the APIs below */
struct k_mem_partition;
#endif /* CONFIG_MEMORY_PROTECTION */

#ifdef CONFIG_USERSPACE
/**
 * @brief Memory Domain
 *
 * A memory domain is a collection of memory partitions, used to represent
 * a user thread's access policy for the linear addresss space. A thread
 * may be a member of only one memory domain, but any memory domain may
 * have multiple threads that are members.
 *
 * Supervisor threads may also be a member of a memory domain; this has
 * no implications on their memory access but can be useful as any child
 * threads inherit the memory domain membership of the parent.
 *
 * A user thread belonging to a memory domain with no active partitions
 * will have guaranteed access to its own stack buffer, program text,
 * and read-only data.
 */
struct k_mem_domain {
#ifdef CONFIG_ARCH_MEM_DOMAIN_DATA
	struct arch_mem_domain arch;
#endif /* CONFIG_ARCH_MEM_DOMAIN_DATA */
	/** partitions in the domain */
	struct k_mem_partition partitions[CONFIG_MAX_DOMAIN_PARTITIONS];
	/** Doubly linked list of member threads */
	sys_dlist_t mem_domain_q;
	/** number of active partitions in the domain */
	uint8_t num_partitions;
};

/**
 * Default memory domain
 *
 * All threads are a member of some memory domain, even if running in
 * supervisor mode. Threads belong to this default memory domain if they
 * haven't been added to or inherited membership from some other domain.
 *
 * This memory domain has the z_libc_partition partition for the C library
 * added to it if exists.
 */
extern struct k_mem_domain k_mem_domain_default;
#else
/* To support use of IS_ENABLED for the APIs below */
struct k_mem_domain;
#endif /* CONFIG_USERSPACE */

/**
 * @brief Initialize a memory domain.
 *
 * Initialize a memory domain with given name and memory partitions.
 *
 * See documentation for k_mem_domain_add_partition() for details about
 * partition constraints.
 *
 * @param domain The memory domain to be initialized.
 * @param num_parts The number of array items of "parts" parameter.
 * @param parts An array of pointers to the memory partitions. Can be NULL
 *              if num_parts is zero.
 */
extern void k_mem_domain_init(struct k_mem_domain *domain, uint8_t num_parts,
			      struct k_mem_partition *parts[]);
/**
 * @brief Destroy a memory domain.
 *
 * Destroy a memory domain. All member threads will be re-assigned to the
 * default memory domain.
 *
 * The default memory domain may not be destroyed.
 *
 * This API is deprecated and will be removed in Zephyr 2.5.
 *
 * @param domain The memory domain to be destroyed.
 */
__deprecated
extern void k_mem_domain_destroy(struct k_mem_domain *domain);

/**
 * @brief Add a memory partition into a memory domain.
 *
 * Add a memory partition into a memory domain. Partitions must conform to
 * the following constraints:
 *
 * - Partition bounds must be within system RAM boundaries on MMU-based
 *   systems.
 * - Partitions in the same memory domain may not overlap each other.
 * - Partitions must not be defined which expose private kernel
 *   data structures or kernel objects.
 * - The starting address alignment, and the partition size must conform to
 *   the constraints of the underlying memory management hardware, which
 *   varies per architecture.
 * - Memory domain partitions are only intended to control access to memory
 *   from user mode threads.
 * - If CONFIG_EXECUTE_XOR_WRITE is enabled, the partition must not allow
 *   both writes and execution.
 *
 * Violating these constraints may lead to CPU exceptions or undefined
 * behavior.
 *
 * @param domain The memory domain to be added a memory partition.
 * @param part The memory partition to be added
 */
extern void k_mem_domain_add_partition(struct k_mem_domain *domain,
				      struct k_mem_partition *part);

/**
 * @brief Remove a memory partition from a memory domain.
 *
 * Remove a memory partition from a memory domain.
 *
 * @param domain The memory domain to be removed a memory partition.
 * @param part The memory partition to be removed
 */
extern void k_mem_domain_remove_partition(struct k_mem_domain *domain,
					 struct k_mem_partition *part);

/**
 * @brief Add a thread into a memory domain.
 *
 * Add a thread into a memory domain. It will be removed from whatever
 * memory domain it previously belonged to.
 *
 * @param domain The memory domain that the thread is going to be added into.
 * @param thread ID of thread going to be added into the memory domain.
 *
 */
extern void k_mem_domain_add_thread(struct k_mem_domain *domain,
				    k_tid_t thread);

/**
 * @brief Remove a thread from its memory domain.
 *
 * Remove a thread from its memory domain. It will be reassigned to the
 * default memory domain.
 *
 * @param thread ID of thread going to be removed from its memory domain.
 */
__deprecated
extern void k_mem_domain_remove_thread(k_tid_t thread);

/** @} */
#endif /* INCLUDE_APP_MEMORY_MEM_DOMAIN_H */
