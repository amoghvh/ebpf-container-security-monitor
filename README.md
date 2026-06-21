
markdown

# eBPF Container Security Monitor

Real-time container security monitoring using eBPF and Python.

## Features

- Real-time process execution monitoring using eBPF
- Container vs Host process detection
- Suspicious command alerts (chroot, unshare, nsenter)
- Container ID tracking
- Low overhead (<1% CPU)

## Quick Start

```bash
# Install dependencies
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc

# Run the monitor
sudo python3 final_monitor.py

Example Output
text

 14:50:05 [CONTAINER:abc123] PID: 12345 CMD: ls
 14:50:10 [CONTAINER:abc123] PID: 12346 CMD: whoami
🚨 14:50:15 [CONTAINER:abc123] PID: 12347 CMD: chroot ⚠️ ALERT!

Files

    final_monitor.py - Main monitor

    watcher.py - Container watcher

    ebpf-kernel/ - eBPF programs (C)

Requirements

    Linux kernel 5.8+ (with BTF)

    BCC tools

    Python 3.8+

Author

amoghvh
License

MIT
