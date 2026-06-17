#!/usr/bin/env python3
"""
eBPF Container Security Daemon - Python Version
Detects container process executions in real-time
"""

from bcc import BPF
import ctypes as ct
import time
import signal
import sys
import os

# eBPF program in C - FIXED VERSION
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // BCC provides args as a pointer to the tracepoint arguments
    // The execve syscall has: filename, argv, envp
    // We can access the filename directly
    char filename[256];
    bpf_probe_read_str(&filename, sizeof(filename), (void *)args->args[0]);
    __builtin_memcpy(event.filename, filename, sizeof(filename));
    
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

# Define event structure for Python
class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
    ]

running = True
event_count = 0
container_count = 0

def signal_handler(sig, frame):
    global running
    print(f"\n\n📊 Statistics:")
    print(f"   Total events: {event_count}")
    print(f"   Container events: {container_count}")
    print("\n🛑 Shutting down...")
    running = False

def is_container_process(pid):
    """Check if a process is running in a container"""
    try:
        cgroup_path = f"/proc/{pid}/cgroup"
        if os.path.exists(cgroup_path):
            with open(cgroup_path, 'r') as f:
                content = f.read()
                if 'docker' in content or 'kubepods' in content or 'containerd' in content:
                    return True
    except:
        pass
    return False

def print_event(cpu, data, size):
    global event_count, container_count
    event = ct.cast(data, ct.POINTER(Event)).contents
    event_count += 1
    
    comm = event.comm.decode('utf-8', 'ignore').strip('\x00')
    filename = event.filename.decode('utf-8', 'ignore').strip('\x00')
    
    # Check if this is a container process
    is_container = is_container_process(event.pid)
    if is_container:
        container_count += 1
    
    # Format output
    pid_str = f"{event.pid:6d}"
    comm_str = comm[:15]
    file_str = filename[:50]
    icon = "🐳" if is_container else "💻"
    
    print(f"{icon} [{event_count:4d}] PID: {pid_str} | CMD: {comm_str:15s} | FILE: {file_str}")

def main():
    global running
    
    print("=" * 70)
    print("🐳 eBPF Container Security Daemon")
    print("=" * 70)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("📁 Loading eBPF program...")
    
    try:
        b = BPF(text=bpf_program)
        print("✅ eBPF program loaded")
        
        b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="tracepoint__syscalls__sys_enter_execve")
        print("✅ Tracepoint attached to sys_enter_execve")
        
        b["events"].open_perf_buffer(print_event)
        
        print("\n📊 Listening for container process events...")
        print("🔍 Running containers will be marked with 🐳")
        print("Press Ctrl+C to stop")
        print("-" * 70)
        
        while running:
            b.perf_buffer_poll(timeout=100)
            time.sleep(0.1)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    print("\n✅ Shutdown complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
