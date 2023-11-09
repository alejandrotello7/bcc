#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in the project examples directory with:
# sudo ./hello_world_open.py
# This script traces the open syscall and prints "Hello, World!"

from bcc import BPF

# Create a BPF program that traces the open syscall
bpf_text = """
#include <linux/ptrace.h>

int kprobe__sys_open(struct pt_regs *ctx, const char *filename, int flags, int mode) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_text)

# Start tracing the open syscall
b.trace_print()
# print('TEst')