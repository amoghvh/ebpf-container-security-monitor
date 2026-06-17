#!/usr/bin/env python3
"""
Ultra-simple Container Monitor - Just PID and Command
"""

from bcc import BPF
import ctypes as ct
import time
import signal
import sys
import os
from datetime import datetime

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]

running = True

def signal_handler(sig, frame):
    global running
    print("\n👋 Shutting down...")
    running = False

def is_container(pid):
    try:
        with open(f"/proc/{pid}/cgroup", 'r') as f:
            return any(x in f.read() for x in ['docker', 'kubepods', 'containerd'])
    except:
        return False

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    comm = event.comm.decode('utf-8', 'ignore').strip('\x00')
    icon = "🐳" if is_container(event.pid) else "💻"
    print(f"{icon} PID: {event.pid:6d} | COMMAND: {comm}")

def main():
    print("=" * 50)
    print("🐳 Container Monitor (Ultra-Simple)")
    print("=" * 50)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        b = BPF(text=bpf_text)
        b.attach_tracepoint(tp="syscalls:sys_enter_execve", 
                           fn_name="tracepoint__syscalls__sys_enter_execve")
        b["events"].open_perf_buffer(print_event)
        
        print("✅ Ready! Listening for events...")
        print("Press Ctrl+C to stop\n")
        
        while running:
            b.perf_buffer_poll()
            time.sleep(0.1)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
