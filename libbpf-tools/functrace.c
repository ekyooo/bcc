// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * functrace  Trace userspace function calls with call tree visualisation.
 *
 * Based on funclatency from BCC by Brendan Gregg.
 */
#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "functrace.h"
#include "functrace.skel.h"
#include "trace_helpers.h"
#include "functrace_text.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define MAX_FUNCTIONS   32
#define MAX_BINARIES    16
#define OUTPUT_FILE_MAX 256
#define BINARY_PATH_MAX 256

static struct env {
	bool              verbose;
	int               duration;
	pid_t             pid;
	char              functions[MAX_FUNCTIONS][FUNC_NAME_LEN];
	int               func_binary[MAX_FUNCTIONS]; /* index into binaries[]; -1 until first -b */
	int               func_count;
	char              output_file[OUTPUT_FILE_MAX];
	char              binaries[MAX_BINARIES][BINARY_PATH_MAX];
	int               binary_count;
	bool              otel;       /* true = -F otel (OTLP JSONL), false = text */
	char              roots[MAX_FUNCTIONS][FUNC_NAME_LEN];
	int               root_binary[MAX_FUNCTIONS]; /* like func_binary[] */
	int               root_count;
	bool              is_root[MAX_FUNCTIONS]; /* functions[i] given by -R */
	int               max_depth;
	size_t            ringbuf_sz; /* ring buffer size in bytes */
} env = {
	.duration       = 0,
	.pid            = 0,
	.func_count     = 0,
	.otel           = false,
	.max_depth      = MAX_CALL_DEPTH,
	.ringbuf_sz     = DEFAULT_RINGBUF_SIZE,
};

static volatile sig_atomic_t exiting = 0;
static FILE          *output_fp = NULL;
static struct time_sync tsync;
static volatile __u64 depth_overflows = 0;
static volatile __u64 dropped_events = 0;
static volatile __u64 thread_ctx_failures = 0;

const char *argp_program_version     = "functrace 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] =
	"-b BINARY -R ROOT [-f FUNC ...] [-b BINARY2 [-R ROOT2] [-f FUNC2 ...]]";
static const char program_doc[] =
"Trace userspace function calls with call tree visualisation.\n"
"\n"
"USAGE: functrace [OPTIONS] -b BINARY -R ROOT [-f FUNC ...]\n"
"                 [-b BINARY2 [-R ROOT2] [-f FUNC2 ...]]\n"
"\n"
"Each -R and -f belongs to the most recent -b; options given before the\n"
"first -b belong to the first -b. -R also traces the function. A root\n"
"called inside another root's trace becomes a child span of that trace.\n"
"\v"
"Examples:\n"
"    functrace -b ./app -R my_func -f my_func           # text diagram\n"
"    functrace -b ./app -R main -f main -f foo          # call tree\n"
"    functrace -b ./app -R f1 -f f1 -F otel             # OTLP JSON\n"
"    functrace -b ./app -R main -f main -d 10           # trace for 10s\n"
"    functrace -b ./app -R main \\\n"
"              -b /usr/lib/libfoo.so -f foo_init        # app + shared lib\n"
"    functrace -b ./app -R main \\\n"
"              -b /usr/lib/libfoo.so -R foo_run         # root per binary\n"
;

static const struct argp_option opts[] = {
	{ "function",  'f', "FUNC",    0,
	  "Function to trace in the current -b (repeatable)", 0 },
	{ "binary",    'b', "PATH",    0,
	  "Binary or shared library with uprobes (repeatable)", 0 },
	{ "root-func", 'R', "FUNC",    0,
	  "Root function in the current -b (repeatable, required)", 0 },
	{ 0, 0, 0, 0, "", 0 },
	{ "pid",       'p', "PID",     0, "Trace only this PID (0 = all)",  0 },
	{ "output",    'o', "FILE",    0, "Output file (default: stdout)",  0 },
	{ "format",    'F', "FMT",     0, "Output format: otel (OTLP JSONL)", 0 },
	{ "duration",  'd', "SECONDS", 0, "Trace duration (0 = until Ctrl-C)", 0 },
	{ "max-depth", 'D', "N",       0, "Max call depth (default: 64)",   0 },
	{ "ringbuf-size", 'B', "BYTES", 0, "Ring buffer size (default: 1048576)", 0 },
	{ 0, 0, 0, 0, "", 0 },
	{ "verbose",   'v', NULL,      0, "Verbose debug output",           0 },
	{ NULL,        'h', NULL, OPTION_HIDDEN, "Show help",               0 },
	{},
};

static bool parse_long_arg(const char *arg, long min, long max, long *value)
{
	char *end;
	long parsed;

	errno = 0;
	parsed = strtol(arg, &end, 10);
	if (errno || end == arg || *end != '\0' || parsed < min || parsed > max)
		return false;
	*value = parsed;
	return true;
}

static bool parse_size_arg(const char *arg, size_t *value)
{
	char *end;
	long page_size;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(arg, &end, 10);
	page_size = sysconf(_SC_PAGESIZE);
	if (errno || end == arg || *end != '\0' || parsed == 0 ||
	    parsed > UINT32_MAX || page_size <= 0 ||
	    parsed < (unsigned long long)page_size ||
	    (parsed & (parsed - 1)) != 0)
		return false;
	*value = (size_t)parsed;
	return true;
}

static bool copy_arg(char *dst, size_t dst_sz, const char *src)
{
	size_t len = strlen(src);

	if (len >= dst_sz)
		return false;
	memcpy(dst, src, len + 1);
	return true;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long num;

	switch (key) {
	case 'f': {
		int bin = env.binary_count - 1;

		if (env.func_count >= MAX_FUNCTIONS) {
			warn("Too many functions (max %d)\n", MAX_FUNCTIONS);
			argp_usage(state);
		}
		if (!copy_arg(env.functions[env.func_count], FUNC_NAME_LEN, arg)) {
			warn("Function name too long (max %d bytes): %s\n",
				FUNC_NAME_LEN - 1, arg);
			argp_usage(state);
		}
		env.func_binary[env.func_count] = bin;
		env.func_count++;
		break;
	}
	case 'b':
		if (env.binary_count >= MAX_BINARIES) {
			warn("Too many binaries (max %d)\n", MAX_BINARIES);
			argp_usage(state);
		}
		for (int i = 0; i < env.binary_count; i++) {
			if (strcmp(env.binaries[i], arg) == 0) {
				warn("Binary specified more than once: %s\n", arg);
				argp_usage(state);
			}
		}
		if (!copy_arg(env.binaries[env.binary_count],
			      BINARY_PATH_MAX, arg)) {
			warn("Binary path too long (max %d bytes)\n",
				BINARY_PATH_MAX - 1);
			argp_usage(state);
		}
		env.binary_count++;
		break;
	case 'p':
		if (!parse_long_arg(arg, 0, INT_MAX, &num)) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = num;
		break;
	case 'o':
		if (!copy_arg(env.output_file, sizeof(env.output_file), arg)) {
			warn("Output path too long (max %d bytes)\n",
				OUTPUT_FILE_MAX - 1);
			argp_usage(state);
		}
		break;
	case 'F':
		if (strcmp(arg, "otel") == 0)
			env.otel = true;
		else {
			warn("Unknown format '%s' (use 'otel')\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		if (!parse_long_arg(arg, 0, INT_MAX, &num)) {
			warn("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env.duration = num;
		break;
	case 'R':
		if (env.root_count >= MAX_FUNCTIONS) {
			warn("Too many root functions (max %d)\n", MAX_FUNCTIONS);
			argp_usage(state);
		}
		if (!copy_arg(env.roots[env.root_count], FUNC_NAME_LEN, arg)) {
			warn("Root function name too long (max %d bytes): %s\n",
				FUNC_NAME_LEN - 1, arg);
			argp_usage(state);
		}
		env.root_binary[env.root_count] = env.binary_count - 1;
		env.root_count++;
		break;
	case 'D':
		if (!parse_long_arg(arg, 1, MAX_CALL_DEPTH, &num)) {
			warn("Invalid max-depth (1-%d): %s\n",
				MAX_CALL_DEPTH, arg);
			argp_usage(state);
		}
		env.max_depth = num;
		break;
	case 'B':
		if (!parse_size_arg(arg, &env.ringbuf_sz)) {
			warn("Invalid ringbuf-size (must be a power of two, at "
			     "least one page, and no larger than %u): %s\n",
			     UINT32_MAX, arg);
			argp_usage(state);
		}
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options  = opts,
	.parser   = parse_arg,
	.args_doc = args_doc,
	.doc      = program_doc,
};

static void sig_handler(int sig)
{
	exiting = true;
}

static int flush_output(void)
{
	if (!output_fp)
		return 0;
	if (fflush(output_fp) == EOF || ferror(output_fp)) {
		warn("Failed to flush output: %s\n", strerror(errno));
		return -EIO;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void check_dropped_events(struct functrace_bpf *skel)
{
	__u64 cur = skel->bss->dropped_events;

	if (cur > dropped_events) {
		warn("Ring buffer full: dropped %llu event(s)\n",
			(unsigned long long)(cur - dropped_events));
		dropped_events = cur;
	}
}

static void check_thread_ctx_failures(struct functrace_bpf *skel)
{
	__u64 cur = skel->bss->thread_ctx_failures;

	if (cur > thread_ctx_failures) {
		warn("Thread context unavailable: dropped %llu function call(s)\n",
			(unsigned long long)(cur - thread_ctx_failures));
		thread_ctx_failures = cur;
	}
}

/**
 * check_depth_overflows - Report calls skipped at the configured depth.
 *
 * BPF tracks skipped entry/exit pairs so valid shadow-stack frames remain
 * intact. Surface the aggregate count here and tell the user how to rerun
 * with a larger depth rather than emitting another ring-buffer event.
 */
static void check_depth_overflows(struct functrace_bpf *skel)
{
	__u64 cur = skel->bss->depth_overflows;

	if (cur > depth_overflows) {
		if (env.max_depth < MAX_CALL_DEPTH)
			warn("Shadow stack overflow: %llu function call(s) exceeded "
				"--max-depth=%d and were skipped; increase --max-depth "
				"and rerun (maximum: %d)\n",
				(unsigned long long)(cur - depth_overflows),
				env.max_depth, MAX_CALL_DEPTH);
		else
			warn("Shadow stack overflow: %llu function call(s) exceeded "
				"the maximum supported depth (%d) and were skipped\n",
				(unsigned long long)(cur - depth_overflows),
				MAX_CALL_DEPTH);
		depth_overflows = cur;
	}
}

/* Ring-buffer callback. */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct functrace_event *e = data;
	const char *func_name = "unknown";

	if (data_sz < sizeof(*e)) {
		warn("Short ring buffer event: got %zu bytes, expected %zu\n",
			data_sz, sizeof(*e));
		return -EINVAL;
	}

	/* Resolve function name from BPF cookie index */
	if (e->func_idx < (uint32_t)env.func_count)
		func_name = env.functions[e->func_idx];

	if (env.otel) {
		struct span s = {0};

		s.trace_id_hi          = e->trace_id_hi;
		s.trace_id_lo          = e->trace_id_lo;
		s.span_id              = e->span_id;
		s.parent_span_id       = e->parent_span_id;

		snprintf(s.name, SPAN_NAME_LEN, "%s", func_name);
		s.kind                = SPAN_KIND_INTERNAL;
		s.start_time_unix_nano = convert_to_realtime_ns(e->start_ns,
								&tsync);
		s.end_time_unix_nano   = convert_to_realtime_ns(e->end_ns,
								&tsync);
		/* The probe observes completion, not the function's return value. */
		s.status_code         = SPAN_STATUS_UNSET;
		s.pid                 = e->pid;
		s.tid                 = e->tid;

		return print_span(&s, TRACE_FORMAT_OTEL_SPAN_JSON, output_fp);
	} else {
		text_handle_span(e, func_name, output_fp);
		if (ferror(output_fp))
			return -EIO;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer     *rb   = NULL;
	struct functrace_bpf   *skel = NULL;
	struct bpf_link        *links[MAX_FUNCTIONS * 2 + 1] = {};
	uint64_t                start_ns;
	int                     link_count = 0;
	int                     err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.binary_count == 0) {
		warn("Error: specify the binary path with -b\n");
		return 1;
	}

	/* --root-func is mandatory for trace boundary */
	if (env.root_count == 0) {
		warn("Error: -R/--root-func is required\n");
		return 1;
	}

	/* -R and -f options given before the first -b belong to the first -b */
	for (int i = 0; i < env.func_count; i++) {
		if (env.func_binary[i] < 0)
			env.func_binary[i] = 0;
	}
	for (int r = 0; r < env.root_count; r++) {
		if (env.root_binary[r] < 0)
			env.root_binary[r] = 0;
	}
	for (int i = 0; i < env.func_count; i++) {
		for (int j = 0; j < i; j++) {
			if (env.func_binary[i] == env.func_binary[j] &&
			    strcmp(env.functions[i], env.functions[j]) == 0) {
				warn("Function specified more than once for "
				     "'%s': %s\n",
				     env.binaries[env.func_binary[i]],
				     env.functions[i]);
				return argp_err_exit_status;
			}
		}
	}
	for (int r = 0; r < env.root_count; r++) {
		for (int s = 0; s < r; s++) {
			if (env.root_binary[r] == env.root_binary[s] &&
			    strcmp(env.roots[r], env.roots[s]) == 0) {
				warn("Root function specified more than once for "
				     "'%s': %s\n",
				     env.binaries[env.root_binary[r]],
				     env.roots[r]);
				return argp_err_exit_status;
			}
		}
	}

	/* A root is also traced; reuse a matching -f in the same binary only */
	for (int r = 0; r < env.root_count; r++) {
		int i;

		for (i = 0; i < env.func_count; i++) {
			if (env.func_binary[i] == env.root_binary[r] &&
			    strcmp(env.functions[i], env.roots[r]) == 0)
				break;
		}
		if (i == env.func_count) {
			if (env.func_count >= MAX_FUNCTIONS) {
				warn("Too many functions (max %d)\n",
				     MAX_FUNCTIONS);
				return argp_err_exit_status;
			}
			snprintf(env.functions[i], FUNC_NAME_LEN, "%s",
				 env.roots[r]);
			env.func_binary[i] = env.root_binary[r];
			env.func_count++;
		}
		env.is_root[i] = true;
	}

	for (int b = 0; b < env.binary_count; b++) {
		bool used = false;

		for (int i = 0; i < env.func_count && !used; i++)
			used = env.func_binary[i] == b;
		if (!used) {
			warn("Error: no -R or -f function given for binary '%s'\n",
			     env.binaries[b]);
			return argp_err_exit_status;
		}
	}

	/* Snapshot clock reference before any events arrive */
	sync_time(&tsync);

	/* Initialise text output subsystem */
	text_output_init();

	/* Open output stream */
	if (env.output_file[0]) {
		output_fp = fopen(env.output_file, "a");
		if (!output_fp) {
			warn("Cannot open output file '%s': %s\n",
				env.output_file, strerror(errno));
			return 1;
		}
	} else {
		output_fp = stdout;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	skel = functrace_bpf__open();
	if (!skel) {
		warn("Failed to open BPF skeleton\n");
		err = -ENOMEM;
		goto cleanup;
	}
	skel->rodata->target_pid    = env.pid;
	skel->rodata->max_depth     = env.max_depth;

	/* Set ring buffer size from CLI option */
	err = bpf_map__set_max_entries(skel->maps.rb, env.ringbuf_sz);
	if (err) {
		warn("Failed to set ring buffer size to %zu: %s\n",
			env.ringbuf_sz, strerror(-err));
		goto cleanup;
	}

	err = functrace_bpf__load(skel);
	if (err) {
		warn("Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Remove contexts for threads that die inside a root function. */
	{
		struct bpf_link *thread_exit_link =
			bpf_program__attach_tracepoint(
				skel->progs.cleanup_thread_context,
				"sched", "sched_process_exit");
		err = libbpf_get_error(thread_exit_link);
		if (err) {
			warn("Failed to attach sched_process_exit cleanup: %s\n",
				strerror(-err));
			goto cleanup;
		}
		links[link_count++] = thread_exit_link;
	}

	/* Populate root_funcs map with every -R function */
	for (int i = 0; i < env.func_count; i++) {
		uint64_t cookie = (uint64_t)i;
		uint8_t  one    = 1;
		int rf_fd = bpf_map__fd(skel->maps.root_funcs);

		if (!env.is_root[i])
			continue;
		err = bpf_map_update_elem(rf_fd, &cookie, &one, BPF_ANY);
		if (err) {
			warn("Failed to set root_funcs map: %s\n",
				strerror(errno));
			goto cleanup;
		}
		if (env.verbose)
			warn("Root function: %s in %s (cookie=%llu)\n",
				env.functions[i],
				env.binaries[env.func_binary[i]],
				(unsigned long long)cookie);
	}

	/* Attach uprobes for each function in its own binary */
	for (int i = 0; i < env.func_count; i++) {
		const char *binary = env.binaries[env.func_binary[i]];
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
			.func_name = env.functions[i],
			.retprobe  = false,
			.bpf_cookie = (uint64_t)i,
		);
		struct bpf_link *entry_link =
			bpf_program__attach_uprobe_opts(
				skel->progs.trace_func_entry,
				env.pid ? env.pid : -1,
				binary, 0, &uprobe_opts);
		err = libbpf_get_error(entry_link);
		if (err) {
			warn("Failed to attach uprobe for '%s' in '%s': %s\n",
				env.functions[i], binary, strerror(-err));
			goto cleanup;
		}
		links[link_count++] = entry_link;

		LIBBPF_OPTS(bpf_uprobe_opts, uretprobe_opts,
			.func_name = env.functions[i],
			.retprobe  = true,
			.bpf_cookie = (uint64_t)i,
		);
		struct bpf_link *exit_link =
			bpf_program__attach_uprobe_opts(
				skel->progs.trace_func_exit,
				env.pid ? env.pid : -1,
				binary, 0, &uretprobe_opts);
		err = libbpf_get_error(exit_link);
		if (err) {
			warn("Failed to attach uretprobe for '%s' in '%s': %s\n",
				env.functions[i], binary, strerror(-err));
			goto cleanup;
		}
		links[link_count++] = exit_link;
	}

	if (env.verbose) {
		warn("Format     : %s\n", env.otel ? "otel" : "text");
		warn("Max depth  : %d\n", env.max_depth);
		warn("Ringbuf    : %zu bytes\n", env.ringbuf_sz);
		for (int b = 0; b < env.binary_count; b++) {
			bool has_root = false;

			warn("Binary     : %s\n", env.binaries[b]);
			warn("Root funcs :");
			for (int i = 0; i < env.func_count; i++) {
				if (env.func_binary[i] == b && env.is_root[i]) {
					warn(" %s", env.functions[i]);
					has_root = true;
				}
			}
			warn("%s\n", has_root ? "" : " (none)");
			warn("Functions  :");
			for (int i = 0; i < env.func_count; i++) {
				if (env.func_binary[i] == b)
					warn(" %s", env.functions[i]);
			}
			warn("\n");
		}
		if (env.pid)
			warn("PID        : %u\n", env.pid);
		else
			warn("PID        : all\n");
	}

	/* BPF ring buffers have no perf-buffer lost-event callback. Drop
	 * accounting is maintained in the BSS counter and checked while polling. */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
			      handle_event, NULL, NULL);
	if (!rb) {
		warn("Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	warn("Tracing... Hit Ctrl-C to stop.\n");
	start_ns = get_ktime_ns();

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			warn("Ring buffer poll error: %d\n", err);
			break;
		}
		if (flush_output()) {
			err = -EIO;
			break;
		}

		check_depth_overflows(skel);
		check_dropped_events(skel);
		check_thread_ctx_failures(skel);

		if (env.duration > 0) {
			if (get_ktime_ns() - start_ns >=
			    (uint64_t)env.duration * NSEC_PER_SEC) {
				/* ring_buffer__poll() returns the number of
				 * records consumed (>= 0) on success, not a
				 * pure error indicator. Reset err to 0 here
				 * so a normal duration-based exit is not
				 * mistaken for failure by `return err != 0`
				 * below just because the last poll cycle
				 * happened to process events.
				 */
				err = 0;
				break;
			}
		}
	}

	check_depth_overflows(skel);
	check_dropped_events(skel);
	check_thread_ctx_failures(skel);
	if (err > 0)
		err = 0;

cleanup:
	ring_buffer__free(rb);
	for (int i = 0; i < link_count; i++)
		bpf_link__destroy(links[i]);
	functrace_bpf__destroy(skel);
	if (output_fp) {
		if (!env.otel)
			text_output_flush_all(output_fp);
		if (flush_output() && err == 0)
			err = -EIO;
	}
	if (output_fp && output_fp != stdout)
		fclose(output_fp);

	if (dropped_events)
		warn("Dropped %llu event(s) total because the ring buffer was full\n",
			(unsigned long long)dropped_events);
	if (thread_ctx_failures)
		warn("Dropped %llu function call(s) total because thread context "
		     "was unavailable\n",
			(unsigned long long)thread_ctx_failures);
	if (depth_overflows)
		warn("Skipped %llu function call(s) total because --max-depth=%d "
			"was exceeded\n",
			(unsigned long long)depth_overflows, env.max_depth);

	return err != 0;
}
