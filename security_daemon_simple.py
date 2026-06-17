#!/usr/bin/env python3
"""
eBPF Container Security Daemon - Minimal Working Version
"""

from bcc import BPF
import ctypes as ct
import time
import signal
import sys
import os

bpf_program = """
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
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
    print("\n🛑 Shutting down...")
    running = False

def is_container(pid):
    try:
        with open(f"/proc/{pid}/cgroup", 'r') as f:
            return 'docker' in f.read() or 'kubepods' in f.read()
    except:
        return False

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    comm = event.comm.decode('utf-8', 'ignore').strip('\x00')
    icon = "🐳" if is_container(event.pid) else "💻"
    print(f"{icon} PID: {event.pid:6d} | CMD: {comm}")

def main():
    print("=" * 50)
    print("🐳 eBPF Security Daemon (Minimal)")
    print("=" * 50)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        print("📁 Loading eBPF...")
        b = BPF(text=bpf_program)
        print("✅ Loaded")
        
        b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="tracepoint__syscalls__sys_enter_execve")
        print("✅ Attached")
        
        b["events"].open_perf_buffer(print_event)
        print("\n📊 Listening for events...")
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
