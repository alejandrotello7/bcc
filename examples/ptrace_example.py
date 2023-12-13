import errno
import os
import signal
import subprocess
import time

import ptrace.debugger
from ptrace import *

def run_ptrace(pid):
    # Parent process (ptrace)
    print("Ptrace process (PID=%d) started" % os.getpid())
    # Attach to the target process
    debugger = ptrace.debugger.PtraceDebugger()
    process = debugger.addProcess(pid, False)

    # Modify the return value of the openat syscall
    regs = process.getregs()
    print("Original registers:", regs)

    # Change the return value to a different file descriptor
    new_fd = 10  # You can replace this with the desired FD
    regs.rax = -new_fd # Set the return value (negative for error code)

    # Set the modified registers
    process.setregs(regs)


    # Detach from the target process
    process.detach()


if __name__ == "__main__":
    # Run the target process in the background
    target_pid = subprocess.Popen(["python3", "target_process.py"]).pid
    # Allow some time for the target process to start
    time.sleep(1)

    # Run the ptrace process
    run_ptrace(target_pid)

    # Wait for the target process to finish (or interrupt it with Ctrl+C)
    try:
        os.waitpid(target_pid, 0)
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting...")
        os.kill(target_pid, signal.SIGTERM)
