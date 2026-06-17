#!/usr/bin/env python3
"""
Container Security Monitor - Using execsnoop pattern
This works because it matches the BCC execsnoop implementation
"""

from bcc import BPF
import ctypes as ct
import time
import signal
import sys
import os
from datetime import datetime

# eBPF program - EXACT pattern from execsnoop
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event.pid = pid_tgid >> 32;
    event.ppid = bpf_get_current_pid_tgid() >> 32;  // This is actually tgid
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    
    // BCC's execsnoop uses this pattern to get filename
    char filename[ARGSIZE];
    bpf_probe_read_str(filename, sizeof(filename), (void *)args[0]);
    __builtin_memcpy(event.filename, filename, sizeof(event.filename));
    
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 128),
    ]

running = True
event_count = 0
container_count = 0

def signal_handler(sig, frame):
    global running
    print(f"\n\n📊 Summary:")
    print(f"   Total processes: {event_count}")
    print(f"   Container processes: {container_count}")
    print("\n👋 Shutting down...")
    running = False

def is_container_process(pid):
    """Check if process is in a container"""
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

def get_container_id(pid):
    """Get container ID if exists"""
    try:
        cgroup_path = f"/proc/{pid}/cgroup"
        if os.path.exists(cgroup_path):
            with open(cgroup_path, 'r') as f:
                for line in f:
                    if 'docker-' in line:
                        import re
                        match = re.search(r'docker-([a-f0-9]+)\.scope', line)
                        if match:
                            return match.group(1)[:12]
                    elif 'kubepods' in line:
                        match = re.search(r'pod([a-f0-9-]+)', line)
                        if match:
                            return match.group(1)[:12]
    except:
        pass
    return None

def print_event(cpu, data, size):
    global event_count, container_count
    
    event = ct.cast(data, ct.POINTER(Event)).contents
    event_count += 1
    
    pid = event.pid
    comm = event.comm.decode('utf-8', 'ignore').strip('\x00')
    filename = event.filename.decode('utf-8', 'ignore').strip('\x00')
    
    # Check if container
    in_container = is_container_process(pid)
    if in_container:
        container_count += 1
    
    container_id = get_container_id(pid) if in_container else None
    
    # Format output
    timestamp = datetime.now().strftime("%H:%M:%S")
    icon = "🐳" if in_container else "💻"
    container_label = f"[{container_id[:8]}]" if container_id else "[host]"
    
    print(f"{timestamp} {icon} {container_label:12} PID:{pid:6d} CMD:{comm:15s} FILE:{filename[:50]}")

def main():
    global running
    
    print("=" * 80)
    print("🐳 Container Security Monitor (execsnoop pattern)")
    print("=" * 80)
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Load eBPF
        b = BPF(text=bpf_text)
        b.attach_tracepoint(tp="syscalls:sys_enter_execve", 
                           fn_name="tracepoint__syscalls__sys_enter_execve")
        
        # Open perf buffer
        b["events"].open_perf_buffer(print_event)
        
        print("✅ eBPF loaded and attached")
        print("🔍 Monitoring... (Press Ctrl+C to stop)")
        print("-" * 80)
        
        # Event loop
        while running:
            try:
                b.perf_buffer_poll()
                time.sleep(0.1)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"⚠️ Warning: {e}")
                continue
                
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
