#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in the project examples directory with:
# sudo ./hello_world_write.py
# This script traces the write syscall and prints "Hello, World!"

from bcc import BPF

# Create a BPF program that traces the write syscall
bpf_text = """
#include <linux/ptrace.h>

int syscall__ret_execve(struct pt_regs *ctx) {
    struct comm_event event = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .type = TYPE_RETURN,
    };
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    comm_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""
# bpf_trace_printk("Hello, World!\\n");

# Load the BPF program
b = BPF(text=bpf_text)

# Start tracing the write syscall
b.trace_print()
