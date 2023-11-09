#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# This is an example of tracing an event and printing custom fields.
# run in project examples directory with:
# sudo ./trace_fields.py"

from __future__ import print_function
from bcc import BPF

prog = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char name[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};


BPF_HASH(infotmp, u64, struct val_t);
int trace_return(struct pt_regs *regs)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = infotmp.lookup(&id);

    struct data_t data = {};
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_user_str(&data.name, sizeof(data.name), (void *)valp->fname);
    data.id = valp->id;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(regs);
    bpf_trace_printk("Value: %s",data.name);
  return 0;
}

"""
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="trace_return")
print("PID MESSAGE")
try:
    b.trace_print(fmt="{1} {5}")
except KeyboardInterrupt:
    exit()
