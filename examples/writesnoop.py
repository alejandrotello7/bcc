#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# writesnoop: Trace write() and open() syscalls for a specific process without actually executing the syscalls.
#            For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: writesnoop -p PID
#
# Copyright 2023 Alejandro Tello
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import os
import socket
import threading
import time

# Server configuration
HOST = '127.0.0.1'
PORT = 12345

# arguments
examples = """examples:
    ./writesnoop -p 181          # only trace writes for PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace write() and open() syscalls for a specific process without actually executing the syscalls.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", required=True,
                    help="trace syscalls for this PID only")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>

struct data_t {
    u64 id;
    u64 test;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char name[NAME_MAX];
};

BPF_PERF_OUTPUT(events);
"""

bpf_text_kprobe_header_write = """
int syscall__trace_entry_write(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count)
{
"""

bpf_text_kprobe_body_write = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    if (pid != %s) {
        return 0;
    }

    struct data_t data = {};
    data.id    = id;
    data.ts    = bpf_ktime_get_ns() / 1000;
    data.uid   = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Read the data from user space buffer to BPF program memory
    bpf_probe_read_user(&data.name, sizeof(data.name), (void *)buf);
    data.ret = count;

    events.perf_submit(ctx, &data, sizeof(data));

    // Don't actually execute the syscall from user
    //bpf_override_return(ctx, -EPERM);
    return 0;
}
""" % args.pid

bpf_text_kprobe_header_open = """
int syscall__trace_entry_open(struct pt_regs *ctx, const char __user *filename, int flags, umode_t mode)
{
"""

bpf_text_kprobe_body_open = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    if (pid != %s) {
        return 0;
    }

    struct data_t data = {};
    data.id    = id;
    data.ts    = bpf_ktime_get_ns() / 1000;
    data.uid   = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Read the data from user space buffer to BPF program memory
    bpf_probe_read_user(&data.name, sizeof(data.name), (void *)filename);
    //bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)filename);
    data.ret = 0;  // For open(), set ret to 0
    int client_fd;
    if (data.ret == 0) {
    }
    events.perf_submit(ctx, &data, sizeof(data));

    // Don't actually execute the syscall from user
    //bpf_override_return(ctx, -EPERM);
    return 0;
}
""" % args.pid

# initialize BPF
b = BPF(
    text=bpf_text + bpf_text_kprobe_header_write + bpf_text_kprobe_body_write + bpf_text_kprobe_header_open + bpf_text_kprobe_body_open)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__trace_entry_open")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__trace_entry_write")

# header
print("%-14s %-6s %-16s %-4s %-3s %s" %
      ("TIME(s)", "PID", "COMM", "FD", "ERR", "WRITE_DATA/OPEN_FILE"))


# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    # Send the event.name to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    client_socket.sendall(event.name)
    client_socket.close()

    # print event data
    printb(b"%-14.9f %-6d %-16s %-4d %-3d %s" %
           ((float(event.ts) / 1000000), event.id >> 32, event.comm,
            event.id & 0xffffffff, event.ret, event.name))


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
