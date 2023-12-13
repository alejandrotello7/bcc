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

import json

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
from ctypes import *
import struct
from ptrace_example.debugger import PtraceDebugger
from ptrace_example.debugger.process import PtraceProcess
import signal

# Server configuration
HOST = '127.0.0.1'
PORT = 12345
file_descriptor = 0

# arguments
examples = """examples:
    ./interceptor -p 181          # only trace writes for PID 181
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
#include <linux/bpf.h>

struct data_t {
    u64 id;
    u64 test;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char name[NAME_MAX];
    u64 ipc_value;
    //int stack_value;
};
struct ipc {
    int value;
};

struct map_elem {
    int counter;
    struct bpf_timer timer;
};

BPF_RINGBUF_OUTPUT(open_events, 16);
BPF_RINGBUF_OUTPUT(write_events, 16);
BPF_RINGBUF_OUTPUT(tester_events, 16);
BPF_HASH(ipc_comm, struct ipc);
BPF_HASH(completion_map, u32);
BPF_HASH(hmap, int, struct map_elem);

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
    bpf_probe_read_user(&data.name, sizeof(data.name), (void *)buf);
    //data.ret = PT_REGS_RC(ctx);
    data.ret = fd;
    write_events.ringbuf_output(&data, sizeof(data),0);
    u64 return_value = 0;
    //bpf_override_return(ctx, return_value);
    return 0;

}
""" % args.pid

bpf_text_kprobe_header_open = """
int syscall__trace_entry_open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode)
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
    data.ipc_value = 42;
    data.ret = PT_REGS_RC(ctx);

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.name, sizeof(data.name), (void *)filename);
    open_events.ringbuf_output(&data, sizeof(data),0);

    return 0;
}
""" % args.pid

bpf_text_kretprobe_header_open = """
int syscall__trace_return_open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode)
{
"""

bpf_text_kretprobe_body_open = """
    struct bpf_timer timer;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    if (pid != %s) {
        return 0;
    } 
    
    struct ipc key = {};
    key.value = 1;
    u64 *val;
    u64 ts;
    val = ipc_comm.lookup(&key);
    if(val){
        bpf_override_return(ctx, (unsigned long)*val);
        return 0;
    }else{
       return 0;
    }
    
    struct map_elem *map_val;
    int key_val = 0;
    map_val = hmap.lookup(&key_val);
    if(map_val) {
        bpf_timer_init(&map_val->timer, &hmap, CLOCK_REALTIME);
        bpf_timer_start(&map_val->timer, 1000 /* call timer_cb2 in 1 usec */, 0);
    }
    
    /* while (val == 0 || ts < 5) {
        val = ipc_comm.lookup(&key); 
        ts = bpf_ktime_get_ns() / 1000;
    }  */
    
    struct data_t data = {};
    bpf_probe_read_user(&data.name, sizeof(data.name), (void *)filename);
    data.ret = PT_REGS_RC(ctx);
    u64 return_value = 0;
    bpf_override_return(ctx, return_value);
    return 0;
}
""" % args.pid

# initialize BPF
b = BPF(
    text=bpf_text + bpf_text_kprobe_header_open + bpf_text_kprobe_body_open +
         bpf_text_kretprobe_header_open + bpf_text_kretprobe_body_open +
         bpf_text_kprobe_header_write + bpf_text_kprobe_body_write)

b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__trace_entry_open")
b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__trace_return_open")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__trace_entry_write")

# header
print("%-14s %-6s %-16s %-4s %-3s %s" %
      ("TIME(s)", "PID", "COMM", "FD", "ERR", "WRITE_DATA/OPEN_FILE"))


# process event
def print_open_ring(ctx, data, size):
    global file_descriptor
    open_events = b["open_events"].event(data)
    ipc = b["ipc_comm"]
    completion_map = b["completion_map"]

    event_name = open_events.name.decode('utf-8')
    print(event_name)
    event_data = {"operation": 1, "filename": event_name}
    serialized_data = json.dumps(event_data).encode('utf-8')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    client_socket.sendall(serialized_data)
    response = client_socket.recv(4)
    response_int = struct.unpack('I', response)[0]
    completion_map[c_int(open_events.id & 0xffffffff)] = c_ulonglong(1)
    ipc[c_int(0)] = c_ulonglong(response_int)


    file_descriptor = response_int
    client_socket.close()
    print(response_int)


def print_write_ring(ctx, data, size):
    write_events = b["write_events"].event(data)
    event_name = write_events.name.decode('utf-8')
    event_data = {"operation": 2, "file_descriptor": file_descriptor, "data": event_name}
    serialized_data = json.dumps(event_data).encode('utf-8')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    client_socket.sendall(serialized_data)
    response = client_socket.recv(4)
    response_int = struct.unpack('I', response)[0]
    client_socket.close()
    print(response_int)

def print_tester_ring(ctx,data,size):
    tester_events = b["tester_events"].event(data)
    print("TEST")

b["open_events"].open_ring_buffer(print_open_ring)
b["write_events"].open_ring_buffer(print_write_ring)
b["tester_events"].open_ring_buffer(print_tester_ring)

start_time = datetime.now()
while True:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
