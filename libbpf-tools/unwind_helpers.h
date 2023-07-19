// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2023 LG Electronics Inc.
#ifndef __UNWIND_HELPERS_H
#define __UNWIND_HELPERS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libunwind-ptrace.h>
#include "unwind_helpers_types.h"

/*
 * How to Use
 *
 * For the helloworld tool:
 *
 * For helloworld.bpf.c:
 * 1. Include "unwind_helpers.bpf.h"
 * 2. Use uw_get_stackid() to obtain the stack ID
 *
 * For helloworld.c:
 * 1. Include "unwind_helpers.h"
 * 2. Call UW_MAP_SET() before invoking *_bpf__load() to initialize resource sizes
 * 3. Call uw_map_lookup_elem() to retrieve IPs for the stack ID
 *
 * Additional Information:
 * - Register dumps and stack dumps are stored in internal maps within unwind_helpers.
 * - The size of these maps can be configured using UW_MAP_SET().
 */

/*
 * By default, the proc filesystem is used to read the target process memory
 * due to faster bulk reads via read().
 * Define PTRACE_READ_MEMORY_FOR_REMOTE_UNWIND to switch to ptrace, which is
 * useful when /proc access is restricted.
 */
//#define PTRACE_READ_MEMORY_FOR_REMOTE_UNWIND

/* Internal logs can be enabled by changing the UW_LOG_LEVEL */
#define UW_LOG_LEVEL UW_NO_LOG

/*
 * UW_MAP_SET(skel, user_stack_size, max_entries)
 *
 * Configures the BPF skeleton for DWARF-based unwinding. A sample consists of a user
 * stack and user registers. The max_entries value applies to both the sample map
 * and the user stack map.
 *
 * @skel: BPF skeleton structure for the BPF object (e.g., memleak_obj in bcc/libbpf-tools)
 * @user_stack_size: Maximum size for storing each user stack
 * @max_entries: Maximum number of entries for both the sample map and user stack map
 * @return: Integer indicating success (0) or failure (non-zero)
 */
#define UW_MAP_SET(skel, user_stack_size, max_entries)	\
({							\
    int	__ret;					\
    do {						\
        skel->rodata->dwarf_unwind = true;	\
        skel->rodata->targ_user_stack_size = user_stack_size;	\
        skel->rodata->targ_max_entries = max_entries;		\
        __ret = uw_map__set(skel->obj, user_stack_size, max_entries);	\
    } while (0);					\
    __ret;						\
})

/*
 * uw_map__set(obj, user_stack_size, max_entries)
 *
 * Sets up the user stack and sample maps in the BPF object. A sample includes both
 * a user stack and user registers. The max_entries parameter applies to both maps.
 *
 * @obj: Pointer to the BPF object
 * @user_stack_size: Maximum size for each user stack
 * @max_entries: Maximum number of entries for both the sample map and user stack map
 * @return: Integer indicating success (0) or failure (non-zero)
 */
int uw_map__set(const struct bpf_object *obj, size_t user_stack_size, size_t max_entries);

//eslee: not thread-safe
/*
 * uw_map_lookup_elem(pid, stack_id, ip, ip_count)
 *
 * Looks up the BPF map value corresponding to the provided stack_id and unwinds it.
 * Stores the unwound instruction pointers (IPs) in the provided buffer.
 *
 * @pid: Process ID associated with the stack_id
 * @stack_id: User stack ID to look up and unwind
 * @ip: Pointer to a buffer where unwound instruction pointers will be stored
 * @ip_count: Number of IP entries the buffer can hold
 * @return: Integer indicating success (0) or failure (non-zero)
 */
int uw_map_lookup_elem(pid_t pid, const int *stack_id,
		       unsigned long *ip, size_t ip_count);

#endif /* __UNWIND_HELPERS_H */
