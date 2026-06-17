use libbpf_rs::{Object, ObjectBuilder, RingBuffer, RingBufferBuilder};
use libbpf_sys::LIBBPF_PERF_EVENT_OPEN_CLOSE_NONE;
use anyhow::{Context, Result};
use std::mem;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Event {
    pid: u32,
    comm: [u8; 16],
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() >= mem::size_of::<Event>() {
        let event: &Event = unsafe { &*(data.as_ptr() as *const Event) };
        let comm = String::from_utf8_lossy(&event.comm).trim_matches('\0');
        println!("🔍 [EVENT] PID: {} | Command: {}", event.pid, comm);
    }
    0
}

fn main() -> Result<()> {
    env_logger::init();
    println!("🚀 Starting eBPF Container Security Daemon with libbpf-rs");
    println!("📁 Loading eBPF program...");
    
    // Load the eBPF object file
    let obj = ObjectBuilder::default()
        .open_file("../ebpf-kernel/escape_monitor.bpf.o")
        .context("Failed to open eBPF object file")?
        .load()
        .context("Failed to load eBPF object")?;
    println!("✅ eBPF program loaded");
    
    // Get the tracepoint program
    let prog = obj.program("handle_execve")
        .context("Program 'handle_execve' not found")?;
    
    // Attach the tracepoint
    let link = prog.attach_tracepoint("syscalls", "sys_enter_execve")
        .context("Failed to attach tracepoint")?;
    println!("✅ eBPF tracepoint attached to sys_enter_execve");
    
    // Get the ring buffer map
    let map = obj.map("events")
        .context("Map 'events' not found")?;
    
    // Create ring buffer
    let mut ring_buf = RingBufferBuilder::new();
    ring_buf.add(map.fd().unwrap(), handle_event, LIBBPF_PERF_EVENT_OPEN_CLOSE_NONE)
        .context("Failed to add ring buffer")?;
    let ring_buf = ring_buf.build().context("Failed to build ring buffer")?;
    println!("✅ Ready!");
    println!("");
    println!("📊 Listening for container process events...");
    println!("Press Ctrl+C to stop");
    println!("---");
    
    // Process events
    loop {
        ring_buf.consume().context("Failed to consume ring buffer")?;
        std::thread::sleep(std::time::Duration::from_micros(100));
    }
}
