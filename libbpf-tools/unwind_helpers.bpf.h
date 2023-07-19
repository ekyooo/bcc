// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2023 LG Electronics Inc.
#ifndef __UNWIND_HELPERS_BPF_H
#define __UNWIND_HELPERS_BPF_H

#include <asm-generic/errno.h>
#include "unwind_helpers_types.h"

/*
 * The usage is documented in unwind_helpers.h
 *
 * Defines two maps to store user register dumps and stack dumps for unwinding.
 */
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define DEFAULT_MAX_ENTRIES 1
#define DEFAULT_USTACK_SIZE 256

const volatile bool dwarf_unwind = false;
const volatile size_t targ_max_entries = DEFAULT_MAX_ENTRIES;
const volatile size_t targ_user_stack_size = DEFAULT_USTACK_SIZE;

/*
 * Map to store sample data (registers and stack metadata)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct sample_data);
	__uint(max_entries, DEFAULT_MAX_ENTRIES);
} UW_SAMPLES_MAP SEC(".maps");

/*
 * Map to store user stack dumps. Value size is adjustable at load time via targ_user_stack_size
 * (default: DEFAULT_USTACK_SIZE bytes)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64[DEFAULT_USTACK_SIZE / sizeof(u64)]);
	__uint(max_entries, DEFAULT_MAX_ENTRIES);
} UW_STACKS_MAP SEC(".maps");

/*
 * Returns the ID of the user sample dumped for the current context.
 * Stores register and stack dumps in UW_SAMPLES_MAP and UW_STACKS_MAP.
 * Returns: Stack ID (>= 0) on success, negative error code (e.g., -EINVAL, -ENOMEM) on failure.
 */
static long uw_get_stackid()
{
	struct sample_data *sample;
	struct task_struct *task;
	struct mm_struct *mm;
	struct pt_regs *ctx;
	__u64* ustack;
	static __u32 id = 0;
	u64 sp;
	u32 stack_len;
	u32 dump_len;

	task = bpf_get_current_task_btf();
	ctx = (struct pt_regs *)bpf_task_pt_regs(task);

	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return -EINVAL;

	if (id >= targ_max_entries)
		return -ENOMEM;

	__sync_fetch_and_add(&id, 1);

	sample = bpf_map_lookup_elem(&UW_SAMPLES_MAP, &id);
	if (!sample)
		return -ENOENT;

	ustack = bpf_map_lookup_elem(&UW_STACKS_MAP, &id);
	if (!ustack)
		return -ENOENT;

	/* dump user regs */
	bpf_probe_read(&sample->user_regs, sizeof(struct pt_regs), ctx);

	/* dump user stack */
	sp = PT_REGS_SP_CORE(ctx);
	stack_len = BPF_CORE_READ(mm, start_stack) - sp;
	dump_len = MIN(stack_len, targ_user_stack_size);

	if (bpf_probe_read_user(ustack, dump_len, (void*)sp) == 0)
		sample->user_stack.size = dump_len;

	return id;
}

#endif /* __UNWIND_HELPERS_BPF_H */
