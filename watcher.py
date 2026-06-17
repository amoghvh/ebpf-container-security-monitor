#!/usr/bin/env python3
"""
Container Monitor - Wrapper around execsnoop
Detects if processes are running in containers
"""

import subprocess
import sys
import os
import time
from datetime import datetime

def is_container(pid):
    """Check if process is in a container"""
    try:
        with open(f"/proc/{pid}/cgroup", 'r') as f:
            content = f.read()
            return 'docker' in content or 'kubepods' in content or 'containerd' in content
    except:
        return False

print("=" * 70)
print("🐳 Container Monitor (using execsnoop)")
print("=" * 70)
print("📡 Monitoring... Press Ctrl+C to stop\n")

# Start execsnoop
process = subprocess.Popen(
    ['sudo', 'execsnoop-bpfcc', '-T'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

try:
    for line in process.stdout:
        line = line.strip()
        if line and not line.startswith('TIME') and not line.startswith('COMM'):
            parts = line.split()
            if len(parts) >= 5:
                timestamp = parts[0] if len(parts) > 0 else ""
                comm = parts[1] if len(parts) > 1 else ""
                pid = parts[2] if len(parts) > 2 else "0"
                
                try:
                    pid_int = int(pid)
                    in_container = is_container(pid_int)
                    icon = "🐳" if in_container else "💻"
                    container_label = "[CONTAINER]" if in_container else "[HOST]"
                    
                    print(f"{icon} {timestamp} {container_label:12} PID:{pid:6s} CMD:{comm}")
                except:
                    print(f"   {line}")
except KeyboardInterrupt:
    print("\n👋 Shutting down...")
    process.terminate()
    process.wait()
