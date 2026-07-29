// SPDX-License-Identifier: GPL-2.0
/*
 * functrace.bpf.c  Trace userspace function calls (BPF program).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "functrace.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer: events flow from kernel to userspace */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, DEFAULT_RINGBUF_SIZE);
} rb SEC(".maps");

/* Per-thread tracing context (shadow stack + traceId) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_THREAD_CONTEXTS);
	__type(key, __u32);                /* tid */
	__type(value, struct thread_context);
} thread_ctx SEC(".maps");

/* Root cookies; a map keeps the lookup extensible to multiple roots. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ROOT_FUNCTIONS);
	__type(key, __u64);                /* bpf_cookie (func index) */
	__type(value, __u8);               /* 1 = root-func */
} root_funcs SEC(".maps");

/* Per-CPU scratch space for thread_context initialisation (avoids stack) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct thread_context);
} empty_ctx SEC(".maps");

/* Rodata: set once from userspace before load */
const volatile __u32 target_pid     = 0;   /* 0 = trace all PIDs */
const volatile __u32 max_depth      = MAX_CALL_DEPTH;

__u64 depth_overflows = 0;
__u64 dropped_events = 0;
__u64 thread_ctx_failures = 0;

SEC("tracepoint/sched/sched_process_exit")
int cleanup_thread_context(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	(void)ctx;
	if (target_pid && pid != target_pid)
		return 0;

	/* A thread can exit while still inside the root function. */
	bpf_map_delete_elem(&thread_ctx, &tid);
	return 0;
}

static __always_inline __u64 gen_span_id(void)
{
	__u64 id = ((__u64)bpf_get_prandom_u32() << 32) |
		   (__u64)bpf_get_prandom_u32();

	/* OTLP requires span IDs to be non-zero. */
	return id ? id : 1;
}

SEC("uprobe")
int trace_func_entry(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct thread_context *empty, *tc;
	__u64 cookie, span_id, ts;
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u32 zero = 0;
	__u8 *is_root;
	__u8 depth;
	int root_entry;

	if (target_pid && pid != target_pid)
		return 0;

	cookie = bpf_get_attach_cookie(ctx);
	is_root = bpf_map_lookup_elem(&root_funcs, &cookie);
	root_entry = is_root && *is_root;

	tc = bpf_map_lookup_elem(&thread_ctx, &tid);
	if (!tc) {
		/* Do not consume map entries for child functions called outside the
		 * configured root boundary. */
		if (!is_root || !*is_root)
			return 0;

		/* First time seeing this thread — use per-CPU scratch to init.
		 * Per-CPU array values are zero-initialised by kernel at map
		 * creation, and we reset key fields below, so no memset needed.
		 */
		empty = bpf_map_lookup_elem(&empty_ctx, &zero);
		if (!empty) {
			__sync_fetch_and_add(&thread_ctx_failures, 1);
			return 0;
		}
		empty->depth = 0;
		empty->skipped_exits = 0;
		empty->root_depth = 0;
		empty->trace_id_hi = 0;
		empty->trace_id_lo = 0;
		if (bpf_map_update_elem(&thread_ctx, &tid, empty,
					BPF_NOEXIST) < 0) {
			__sync_fetch_and_add(&thread_ctx_failures, 1);
			return 0;
		}
		tc = bpf_map_lookup_elem(&thread_ctx, &tid);
		if (!tc) {
			__sync_fetch_and_add(&thread_ctx_failures, 1);
			return 0;
		}
	}

	if (root_entry) {
		if (tc->root_depth == 0) {
			/* Start a new trace at the outermost transaction boundary. */
			tc->root_depth = 1;
			tc->depth = 0;
			tc->skipped_exits = 0;
			tc->trace_id_hi = ((__u64)bpf_get_prandom_u32() << 32) |
					  bpf_get_prandom_u32();
			tc->trace_id_lo = ((__u64)bpf_get_prandom_u32() << 32) |
					  bpf_get_prandom_u32();
			if (tc->trace_id_hi == 0 && tc->trace_id_lo == 0)
				tc->trace_id_lo = 1;
		} else {
			/* Preserve the outer frame and trace ID for recursive roots. */
			tc->root_depth++;
		}
	}

	/* Existing contexts only represent calls inside a root boundary. */
	if (tc->root_depth == 0)
		return 0;

	depth = tc->depth;
	if (tc->skipped_exits > 0 || depth >= max_depth ||
	    depth >= MAX_CALL_DEPTH) {
		tc->skipped_exits++;
		__sync_fetch_and_add(&depth_overflows, 1);
		return 0;
	}

	span_id = gen_span_id();
	ts = bpf_ktime_get_ns();

	/* Push frame onto shadow stack */
	tc->stack[depth].span_id = span_id;
	tc->stack[depth].start_ns = ts;
	tc->depth = depth + 1;

	return 0;
}

SEC("uretprobe")
int trace_func_exit(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct shadow_stack_frame *frame;
	struct functrace_event *e;
	struct thread_context *tc;
	__u64 cookie, end_ts, parent_span_id = 0;
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u8 *is_root;
	__u8 depth;
	int root_exit, outermost_root;

	if (target_pid && pid != target_pid)
		return 0;

	tc = bpf_map_lookup_elem(&thread_ctx, &tid);
	if (!tc || tc->root_depth == 0)
		return 0;

	cookie = bpf_get_attach_cookie(ctx);
	is_root = bpf_map_lookup_elem(&root_funcs, &cookie);
	root_exit = is_root && *is_root;
	outermost_root = root_exit && tc->root_depth <= 1;

	/* Match root nesting even if an entry was skipped due to overflow. */
	if (root_exit && tc->root_depth > 0)
		tc->root_depth--;

	/* Pair every overflowed entry with its uretprobe without popping a
	 * valid shadow-stack frame. Nested overflow is tracked as a count so
	 * normal LIFO handling resumes after all skipped calls return. */
	if (tc->skipped_exits > 0) {
		tc->skipped_exits--;
		if (outermost_root)
			bpf_map_delete_elem(&thread_ctx, &tid);
		return 0;
	}

	depth = tc->depth;
	if (depth == 0)
		goto check_root_exit;  /* underflow protection — shouldn't happen */

	depth--;
	/* Bounds check for verifier */
	if (depth >= MAX_CALL_DEPTH)
		goto check_root_exit;

	/* Pop frame */
	frame = &tc->stack[depth];
	end_ts = bpf_ktime_get_ns();

	/* parent = next frame down in stack, or 0 for the outermost root */
	if (depth > 0 && (depth - 1) < MAX_CALL_DEPTH)
		parent_span_id = tc->stack[depth - 1].span_id;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped_events, 1);
		tc->depth = depth;
		goto check_root_exit;
	}

	e->pid           = pid;
	e->tid           = tid;
	e->func_idx      = (__u32)cookie;
	e->is_root       = outermost_root ? 1 : 0;
	e->call_depth    = depth;
	e->_pad[0]       = 0;
	e->_pad[1]       = 0;
	e->trace_id_hi   = tc->trace_id_hi;
	e->trace_id_lo   = tc->trace_id_lo;
	e->span_id       = frame->span_id;
	e->parent_span_id = parent_span_id;
	e->start_ns      = frame->start_ns;
	e->end_ns        = end_ts;

	bpf_ringbuf_submit(e, 0);
	tc->depth = depth;

check_root_exit:
	/* Only the outermost root exit ends the trace. */
	if (outermost_root)
		bpf_map_delete_elem(&thread_ctx, &tid);

	return 0;
}
