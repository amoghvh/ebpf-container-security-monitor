#!/usr/bin/env python3
"""
Final Container Security Monitor
Detects all process executions and identifies container processes
"""

import subprocess
import os
import sys
import re
from datetime import datetime

# Suspicious patterns to alert on
SUSPICIOUS = ['chroot', 'unshare', 'nsenter', 'docker exec', 'kubectl exec']

def is_container(pid):
    """Check if process is in a container"""
    try:
        with open(f"/proc/{pid}/cgroup", 'r') as f:
            content = f.read()
            return any(x in content for x in ['docker', 'kubepods', 'containerd'])
    except:
        return False

def get_container_id(pid):
    """Get container ID if available"""
    try:
        with open(f"/proc/{pid}/cgroup", 'r') as f:
            for line in f:
                if 'docker-' in line:
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

def is_suspicious(comm):
    """Check for suspicious commands"""
    return any(s in comm.lower() for s in SUSPICIOUS)

print("=" * 80)
print("🔒 Container Security Monitor")
print("=" * 80)
print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("📡 Monitoring container process executions...")
print("⚠️  Alerts for:", ', '.join(SUSPICIOUS))
print("-" * 80)

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
        if line and not line.startswith('TIME') and not line.startswith('COMM'):
            parts = line.strip().split()
            if len(parts) >= 5:
                timestamp = parts[0]
                comm = parts[1]
                pid = parts[2]
                
                try:
                    pid_int = int(pid)
                    container = is_container(pid_int)
                    
                    if container:
                        container_id = get_container_id(pid_int) or "unknown"
                        suspicious = is_suspicious(comm)
                        icon = "🚨" if suspicious else "🐳"
                        alert = " ⚠️ ALERT!" if suspicious else ""
                        
                        print(f"{icon} {timestamp} [CONTAINER:{container_id[:8]}] PID:{pid:6s} CMD:{comm}{alert}")
                    else:
                        # Only show host commands if they're interesting
                        if comm in ['docker', 'kubectl', 'containerd']:
                            print(f"💻 {timestamp} [HOST] PID:{pid:6s} CMD:{comm}")
                            
                except Exception as e:
                    pass
                    
except KeyboardInterrupt:
    print("\n👋 Shutting down...")
    process.terminate()
    process.wait()
    print("✅ Shutdown complete")
