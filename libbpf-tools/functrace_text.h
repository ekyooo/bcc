/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * functrace_text.h — top-down block text output
 *
 * Internal to functrace; do NOT include from trace_helpers.h/c.
 */

#ifndef __FUNCTRACE_TEXT_H
#define __FUNCTRACE_TEXT_H

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "functrace.h"

/* ── Safety limits ──────────────────────────────────────────────────── */

#define TEXT_BUF_MAX_SPANS   512   /* max spans per trace buffer */
#define TEXT_BUF_MAX_TRACES  256   /* max concurrent incomplete traces */

/* ── Data structures ─────────────────────────────────────────────────── */

/**
 * struct text_span_entry - One span stored while buffering a trace.
 */
struct text_span_entry {
	char     name[FUNC_NAME_LEN];
	uint64_t start_ns;   /* bpf_ktime_get_ns() at entry (CLOCK_MONOTONIC) */
	uint64_t end_ns;
	int      depth;      /* shadow stack depth (0 = root) */
};

/**
 * struct text_trace_buf - Per-(tid,trace_id_lo) accumulator for top-down mode.
 */
struct text_trace_buf {
	bool     active;
	uint32_t pid;
	uint32_t tid;
	uint64_t trace_id_lo;
	uint64_t root_start_ns;
	uint64_t root_end_ns;
	int      span_count;
	struct text_span_entry *spans;
};

/* ── Lifecycle ───────────────────────────────────────────────────────── */

/**
 * text_output_init - Initialise the text output subsystem.
 *
 * Must be called once before any events are processed.
 * Captures g_text_prog_start_ns; the static buffer pool starts zeroed.
 */
void text_output_init(void);

/* ── Output functions ────────────────────────────────────────────────── */

/**
 * text_output_flush_all - Flush incomplete traces and release their buffers.
 */
void text_output_flush_all(FILE *fp);

/**
 * text_handle_span - Main entry point called from handle_event().
 */
void text_handle_span(const struct functrace_event *e,
		      const char *func_name,
		      FILE *fp);

#endif /* __FUNCTRACE_TEXT_H */
