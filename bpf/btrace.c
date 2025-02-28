// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

__u32 ready SEC(".data.ready") = 0;

struct btrace_fn_arg_flags {
    bool is_number_ptr;
    bool is_str;
};

#define MAX_FN_ARGS 6
struct btrace_fn_args {
    struct btrace_fn_arg_flags args[MAX_FN_ARGS];
    __u32 nr_fn_args;
} __attribute__((packed));

struct btrace_config {
    __u32 output_lbr:1;
    __u32 output_stack:1;
    __u32 is_ret_str:1;
    __u32 pad:29;
    __u32 pid;

    struct btrace_fn_args fn_args;
} __attribute__((packed));

volatile const struct btrace_config btrace_config = {};
#define cfg (&btrace_config)

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} func_stacks SEC(".maps");

struct btrace_fn_arg_data {
    __u64 raw_data;
    __u64 ptr_data;
};

struct btrace_fn_data {
    struct btrace_fn_arg_data args[MAX_FN_ARGS];
    __u8 arg[32];
    __u8 ret[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} events SEC(".maps");

#define MAX_LBR_ENTRIES 32
struct event {
    struct perf_branch_entry lbr[MAX_LBR_ENTRIES];
    __s64 nr_bytes;
    __s64 func_ret;
    __u64 func_ip;
    __u32 cpu;
    __u32 pid;
    __u8 comm[16];
    __s64 func_stack_id;
    struct btrace_fn_data fn_data;
} __attribute__((packed));

struct event btrace_events[1] SEC(".data.events");

static __always_inline void
output_fn_args(struct event *event, void *ctx)
{
    __u64 arg;
    __u32 i;

    for (i = 0; i < MAX_FN_ARGS; i++) {
        if (i >= cfg->fn_args.nr_fn_args)
            break;

        (void) bpf_get_func_arg(ctx, i, &arg); /* required 5.17 kernel. */
        event->fn_data.args[i].raw_data = arg;

        if (!arg)
            continue;

        if (cfg->fn_args.args[i].is_str)
            bpf_probe_read_kernel_str(&event->fn_data.arg, sizeof(event->fn_data.arg), (void *) arg);
        else if (cfg->fn_args.args[i].is_number_ptr)
            bpf_probe_read_kernel(&event->fn_data.args[i].ptr_data, sizeof(event->fn_data.args[i].ptr_data), (void *) arg);
    }
}

static __noinline bool
filter_fnarg(void *ctx)
{
    return ctx != NULL;
}

static __always_inline int
emit_btrace_event(void *ctx)
{
    struct event *event;
    __u64 retval;
    __u32 cpu;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id();
    event = &btrace_events[cpu];

    if (cfg->output_lbr)
        event->nr_bytes = bpf_get_branch_snapshot(event->lbr, sizeof(event->lbr), 0); /* required 5.16 kernel. */

    /* Other filters must be after bpf_get_branch_snapshot() to avoid polluting
     * LBR entries.
     */

    event->pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid && event->pid != cfg->pid)
        return BPF_OK;
    if (!filter_fnarg(ctx))
        return BPF_OK;

    bpf_get_func_ret(ctx, (void *) &retval); /* required 5.17 kernel. */
    event->func_ret = retval;
    event->func_ip = bpf_get_func_ip(ctx); /* required 5.17 kernel. */
    event->cpu = cpu;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->func_stack_id = -1;
    if (cfg->output_stack)
        event->func_stack_id = bpf_get_stackid(ctx, &func_stacks, BPF_F_FAST_STACK_CMP);
    output_fn_args(event, ctx);
    if (cfg->is_ret_str && retval)
        bpf_probe_read_kernel_str(&event->fn_data.ret, sizeof(event->fn_data.ret), (void *) retval);

    bpf_ringbuf_output(&events, event, sizeof(*event), 0);

    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(fexit_fn)
{
    return emit_btrace_event(ctx);
}

SEC("fentry")
int BPF_PROG(fentry_fn)
{
    return emit_btrace_event(ctx);
}

char __license[] SEC("license") = "GPL";
