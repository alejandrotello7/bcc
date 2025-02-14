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
from ctypes import *
import struct



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
struct call_arguments{
    char path[NAME_MAX];
    char data[NAME_MAX];
};

BPF_RINGBUF_OUTPUT(events, 16);
BPF_HASH(ipc_comm, struct ipc);
//BPF_STACK(stack, int, 10240);
BPF_HASH(call_data, struct ipc, struct call_arguments);

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
    u64 *val;
    struct ipc key = {};
    key.value = 1;
    val = ipc_comm.lookup(&key);
    if(val){
         data.ipc_value = *val;
         //fd = *val;
    }
    data.id    = id;
    data.ts    = bpf_ktime_get_ns() / 1000;
    data.uid   = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Read the data from user space buffer to BPF program memory
    bpf_probe_read_user(&data.name, sizeof(data.name), (void *)buf);
    data.ret = count;
    

    //int stack_value;
    //stack.peek(&stack_value);
    //data.stack_value = stack_value;
    
    events.ringbuf_output(&data, sizeof(data),0);

   val = ipc_comm.lookup(&key);
    if(val){
        data.ipc_value = *val;
    }
    // Don't actually execute the syscall from user
    //bpf_override_return(ctx, -EPERM);
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
    
    //int stack_init_value = 10;
    //stack.push(&stack_init_value, 0);


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
    //bpf_probe_read_user_str(data.name, sizeof(data.name), filename);
    
    data.ret = 0;  // For open(), set ret to 0
    int client_fd;
    if (data.ret == 0) {
    }
    
    struct ipc key = {};
    key.value = 1;
    u64 zero = 0, *val;
    val = ipc_comm.lookup_or_try_init(&key, &zero);
    if(val){
        (*val) = 0;
        data.ipc_value = *val;
    } else{
        data.ipc_value = 42;
    }
    //int stack_value;
    //stack.peek(&stack_value);
    //data.stack_value = stack_value;
    
    //data.ipc_value = *val;
    events.ringbuf_output(&data, sizeof(data),0);
    val = ipc_comm.lookup(&key);
    if(val){
        //bpf_override_return(ctx, (unsigned long)*val);
        return 0;
    }else{
       return 0;
    }
}
""" % args.pid

bpf_text_kretprobe_header_open = """
int syscall__trace_return_open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode)
{
"""

bpf_text_kretprobe_body_open = """
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    if (pid != %s) {
        return 0;
    }    
    // key.value = 1;
    // u64 zero = 0, *val;
    // val = ipc_comm.lookup(&key);
    // if (val) {
    //    int timeout = 1000;
    //    while ((int)*val == 7 && timeout > 0) {
    //        val = ipc_comm.lookup(&key);
    //        if (val) {
    //            timeout--;
    //       } else {
    //            return 0;
    //        }
    //    }
    //    //bpf_override_return(ctx, (unsigned long)*val);
    //    return 0;     
    //}
    struct ipc key = {};
    struct call_arguments call_args = {};
    call_args.path[0] = 0;
    call_args.data[0] = 0;

    struct call_arguments *val;
    key.value = PT_REGS_RC(ctx);
    //val = call_data.lookup_or_try_init(&key, &call_args);
    return 0;
}
""" % args.pid

# initialize BPF
b = BPF(
    text=bpf_text + bpf_text_kprobe_header_write + bpf_text_kprobe_body_write + bpf_text_kprobe_header_open + bpf_text_kprobe_body_open + bpf_text_kretprobe_header_open + bpf_text_kretprobe_body_open)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__trace_entry_open")
b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__trace_entry_write")
b.attach_kretprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__trace_return_open")


# header
print("%-14s %-6s %-16s %-4s %-3s %s" %
      ("TIME(s)", "PID", "COMM", "FD", "ERR", "WRITE_DATA/OPEN_FILE"))


# process event
def print_event(ctx, data, size):
    event = b["events"].event(data)
    ipc = b["ipc_comm"]
    # stack = b["stack"]
    # stack.push(c_int(42))
    #
    # for key,value in ipc.items_lookup_batch():
    #     print(key.value, value.value)
    if(ipc[c_int(1)].value != 0):
        print(f'FD value: {ipc[c_int(1)].value}')
        print(f'Event name: {event.name}')

    if c_int(2) in ipc:
        print(f'Return value: {ipc[c_int(2)].value}')

    # Send the event.name to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    client_socket.sendall(event.name)
    response = client_socket.recv(4)
    response_int = struct.unpack('I', response)[0]
    client_socket.close()
    if response:
        ipc[c_int(1)] = c_ulonglong(response_int)
    else:
        ipc[c_int(1)] = c_ulonglong(13)

    print("%-14.9f %-6d %-16s %-4d %-3d %s %d" %
           ((float(event.ts) / 1000000), event.id >> 32, event.comm,
            event.id & 0xffffffff, event.ret, event.name, event.ipc_value))



# loop with callback to print_event
b["events"].open_ring_buffer(print_event)
start_time = datetime.now()
while True:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
