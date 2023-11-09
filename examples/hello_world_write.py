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

int kprobe__sys_write(struct pt_regs *ctx, int fd, const char *buf, size_t count) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_text)

# Start tracing the write syscall
b.trace_print()

