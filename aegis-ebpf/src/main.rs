use std::convert::TryFrom as _;

use aegis_ebpf_common::{MemoryEvent, MemorySyscall, TASK_COMM_LEN};
use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap, RingBuf},
    programs::TracePoint,
};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aegis-ebpf"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    attach_syscall_tracepoint(&mut ebpf, "sys_enter_mmap", "sys_enter_mmap")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_enter_mprotect", "sys_enter_mprotect")?;
    attach_syscall_tracepoint(
        &mut ebpf,
        "sys_enter_memfd_create",
        "sys_enter_memfd_create",
    )?;
    attach_syscall_tracepoint(&mut ebpf, "sys_enter_ptrace", "sys_enter_ptrace")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_mmap", "sys_exit_mmap")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_mprotect", "sys_exit_mprotect")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_memfd_create", "sys_exit_memfd_create")?;
    attach_syscall_tracepoint(&mut ebpf, "sys_exit_ptrace", "sys_exit_ptrace")?;

    populate_blocklist(&mut ebpf)?;

    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("eBPF map EVENTS not found")?,
    )?;
    let mut ring_buf =
        tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    println!("Listening for memory syscall tracepoints. Press Ctrl-C to stop.");
    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            readiness = ring_buf.readable_mut() => {
                let mut guard = readiness?;
                while let Some(item) = guard.get_inner_mut().next() {
                    if let Some(event) = MemoryEvent::from_bytes(item.as_ref()) {
                        print_memory_event(event);
                    } else {
                        warn!("received malformed ring buffer sample with {} bytes", item.len());
                    }
                }
                guard.clear_ready();
            }
        }
    }

    println!("Exiting...");

    Ok(())
}

fn populate_blocklist(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut blocklist = HashMap::<_, u32, u32>::try_from(
        ebpf.map_mut("BLOCKLIST")
            .context("eBPF map BLOCKLIST not found")?,
    )?;

    // Block common system processes that generate noise.
    // NOTE: Keep this minimal and deterministic for now; dynamic /proc discovery can be added later.
    let blocked_tgids = [1_u32, 2_u32];
    for tgid in blocked_tgids {
        blocklist.insert(tgid, 1, 0)?;
    }

    let rate_limited_count = Array::<_, u64>::try_from(
        ebpf.map("RATE_LIMITED_COUNT")
            .context("eBPF map RATE_LIMITED_COUNT not found")?,
    )?;
    let dropped = rate_limited_count.get(&0, 0).unwrap_or(0);
    println!(
        "Kernel filter blocklist initialized ({} TGIDs). rate_limited_drops={}",
        blocked_tgids.len(),
        dropped
    );

    Ok(())
}

fn attach_syscall_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    tracepoint_name: &str,
) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF program {program_name} not found"))?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", tracepoint_name)?;
    Ok(())
}

fn print_memory_event(event: MemoryEvent) {
    let syscall = event
        .syscall_kind()
        .map(|kind| kind.as_str())
        .unwrap_or("unknown");
    let comm = parse_comm(&event.comm);

    match event.syscall_kind() {
        Some(MemorySyscall::Mmap) => {
            println!(
                "[{}] tgid={} pid={} comm={} mmap(addr=0x{:x}, len={}, prot=0x{:x}, flags=0x{:x}, fd={}, offset={})",
                event.timestamp_ns,
                event.tgid,
                event.pid,
                comm,
                event.args[0],
                event.args[1],
                event.args[2],
                event.args[3],
                event.args[4] as i64,
                event.args[5]
            );
        }
        Some(MemorySyscall::Mprotect) => {
            println!(
                "[{}] tgid={} pid={} comm={} mprotect(addr=0x{:x}, len={}, prot=0x{:x})",
                event.timestamp_ns,
                event.tgid,
                event.pid,
                comm,
                event.args[0],
                event.args[1],
                event.args[2]
            );
        }
        Some(MemorySyscall::MemfdCreate) => {
            println!(
                "[{}] tgid={} pid={} comm={} memfd_create(name_ptr=0x{:x}, flags=0x{:x})",
                event.timestamp_ns, event.tgid, event.pid, comm, event.args[0], event.args[1]
            );
        }
        Some(MemorySyscall::Ptrace) => {
            println!(
                "[{}] tgid={} pid={} comm={} ptrace(request=0x{:x}, target_pid={}, addr=0x{:x}, data=0x{:x})",
                event.timestamp_ns,
                event.tgid,
                event.pid,
                comm,
                event.args[0],
                event.args[1],
                event.args[2],
                event.args[3]
            );
        }
        None => {
            println!(
                "[{}] tgid={} pid={} comm={} syscall={} args={:?}",
                event.timestamp_ns, event.tgid, event.pid, comm, syscall, event.args
            );
        }
    }
}

fn parse_comm(comm: &[u8; TASK_COMM_LEN]) -> String {
    let len = comm.iter().position(|&b| b == 0).unwrap_or(TASK_COMM_LEN);
    String::from_utf8_lossy(&comm[..len]).into_owned()
}
