from bcc import BPF

# Load the eBPF program
bpf_program = """
#include <linux/sched.h>

int kprobe__sys_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode) {
    const char __user *filen = (char *)PT_REGS_PARM2(ctx);
    char fname[256];
    bpf_probe_read_user_str(&fname, sizeof(fname),(void*)filename);
    bpf_trace_printk("Entered sys_openat: dfd=%d, filename=%s\\n", dfd, filen);

    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_program)

# Attach the eBPF program
b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="kprobe__sys_openat")

# Print trace output
print("Tracing sys_openat... Hit Ctrl+C to end.")

try:
    b.trace_print()
except KeyboardInterrupt:
    exit()
