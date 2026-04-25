//! Loads the pre-built `aegis-ebpf` ELF and attaches all syscall tracepoints.
//! Used by Vagrant / CI matrix jobs to validate CO-RE + verifier on many kernels without rebuilding BPF.

use std::{env, path::PathBuf};

use anyhow::{Context, Result};
use aya::{
    EbpfLoader, VerifierLogLevel,
    maps::RingBuf,
    programs::{Program, trace_point::TracePointLinkId},
};

/// Same pairing as `aegis_ebpf::start_sensor`.
const SYSCALL_TRACEPOINTS: &[(&str, &str)] = &[
    ("sys_enter_mmap", "sys_enter_mmap"),
    ("sys_enter_mprotect", "sys_enter_mprotect"),
    ("sys_enter_memfd_create", "sys_enter_memfd_create"),
    ("sys_enter_ptrace", "sys_enter_ptrace"),
    ("sys_exit_mmap", "sys_exit_mmap"),
    ("sys_exit_mprotect", "sys_exit_mprotect"),
    ("sys_exit_memfd_create", "sys_exit_memfd_create"),
    ("sys_exit_ptrace", "sys_exit_ptrace"),
];

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

fn resolve_object_path() -> Result<PathBuf> {
    if let Ok(p) = env::var("AEGIS_EBPF_OBJECT") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
        anyhow::bail!("AEGIS_EBPF_OBJECT={} is not a file", pb.display());
    }
    if let Some(arg) = env::args().nth(1) {
        let pb = PathBuf::from(arg);
        if pb.is_file() {
            return Ok(pb);
        }
        anyhow::bail!("argument {} is not a file", pb.display());
    }
    anyhow::bail!(
        "usage: aegis-ebpf-loader [PATH_TO_AEGIS_EBPF]\n\
         or set AEGIS_EBPF_OBJECT to the pre-built ELF (bpfel-unknown-none output)."
    )
}

fn main() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        euid == 0,
        "must run as root (CAP_BPF required for BPF_PROG_LOAD)"
    );

    bump_memlock_rlimit();

    let path = resolve_object_path()?;
    eprintln!("aegis-ebpf-loader: loading {}", path.display());

    let mut ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load_file(&path)
        .with_context(|| format!("EbpfLoader::load_file({})", path.display()))?;

    let mut _links: Vec<TracePointLinkId> = Vec::new();

    for &(program_name, tracepoint_name) in SYSCALL_TRACEPOINTS {
        let program = ebpf
            .program_mut(program_name)
            .with_context(|| format!("missing program `{program_name}`"))?;
        let Program::TracePoint(tp) = program else {
            anyhow::bail!("`{program_name}` is not a TracePoint");
        };
        tp.load()
            .with_context(|| format!("BPF_PROG_LOAD failed for `{program_name}`"))?;
        let link = tp
            .attach("syscalls", tracepoint_name)
            .with_context(|| format!("attach `{program_name}` -> syscalls/{tracepoint_name}"))?;
        _links.push(link);
    }

    // Touch the ring buffer map so relocation / map creation errors surface early.
    let _ring = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map missing")?)
        .context("EVENTS is not a BPF_MAP_TYPE_RINGBUF")?;

    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    eprintln!(
        "aegis-ebpf-loader: OK — loaded object and attached {} tracepoints (kernel {}).",
        SYSCALL_TRACEPOINTS.len(),
        release
    );

    Ok(())
}
