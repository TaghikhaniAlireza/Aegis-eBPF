//! Measures extra wall-clock time for `mprotect` RWX→RW cycles with Aegis tracepoints attached
//! vs a clean baseline (no eBPF programs on those tracepoints).
//!
//! Each **cycle** is two syscalls: `mprotect(PROT_RWX)` then `mprotect(PROT_RW)`. **Average latency
//! per syscall** is `elapsed / (successful_cycles * 2)`.
//!
//! Requires **root** and full BPF / tracepoint support. Marked `#[ignore]` so default `cargo test`
//! passes on restricted kernels. On a capable host:
//!
//! ```text
//! sudo env PATH="$PATH" RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" \
//!   cargo test --test ebpf_overhead_bench -p aegis-ebpf -- --ignored --nocapture
//! ```
//!
//! Override the maximum allowed **extra** nanoseconds per syscall (default `1000`) if your
//! machine is noisy or slower:
//!
//! ```text
//! AEGIS_MPROTECT_OVERHEAD_NS_MAX=2000 sudo ... cargo test ...
//! ```

mod common;

use std::time::Instant;

use aya::{
    EbpfLoader, VerifierLogLevel,
    programs::{Program, trace_point::TracePointLinkId},
};

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

const TIMED_CYCLES: u64 = 100_000;
const WARMUP_CYCLES: u64 = 2_000;
/// Default ceiling for `(ebpf_ns_per_syscall - baseline_ns_per_syscall)`; override with
/// `AEGIS_MPROTECT_OVERHEAD_NS_MAX`.
const DEFAULT_OVERHEAD_MAX_NS_PER_SYSCALL: u64 = 1000;

fn mmap_page() -> *mut libc::c_void {
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            prot_rw,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(
        page,
        libc::MAP_FAILED,
        "mmap(MAP_ANONYMOUS) failed: {}",
        std::io::Error::last_os_error()
    );
    page
}

fn mprotect_rwx_rw_cycles(page: *mut libc::c_void, cycles: u64) -> u64 {
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;
    let prot_rwx = prot_rw | libc::PROT_EXEC;
    let mut ok = 0u64;
    for _ in 0..cycles {
        unsafe {
            if libc::mprotect(page, 4096, prot_rwx) == 0 && libc::mprotect(page, 4096, prot_rw) == 0
            {
                ok += 1;
            }
        }
    }
    ok
}

fn ns_per_syscall(elapsed_ns: u128, successful_cycles: u64) -> f64 {
    let syscalls = successful_cycles as u128 * 2;
    assert!(syscalls > 0, "no successful syscalls to average");
    elapsed_ns as f64 / syscalls as f64
}

#[test]
#[ignore = "needs root + full BPF tracepoint support; run with --ignored on a capable kernel"]
fn test_mprotect_latency_overhead_with_ebpf() {
    common::assert_running_as_root();
    common::bump_memlock_rlimit();

    let max_overhead_ns: u64 = std::env::var("AEGIS_MPROTECT_OVERHEAD_NS_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_OVERHEAD_MAX_NS_PER_SYSCALL);

    let page = mmap_page();

    mprotect_rwx_rw_cycles(page, WARMUP_CYCLES);

    let baseline_start = Instant::now();
    let baseline_ok = mprotect_rwx_rw_cycles(page, TIMED_CYCLES);
    let baseline_elapsed = baseline_start.elapsed();

    assert_eq!(
        baseline_ok, TIMED_CYCLES,
        "baseline: expected {TIMED_CYCLES} successful mprotect cycles"
    );

    let baseline_ns = baseline_elapsed.as_nanos();
    let baseline_per_syscall = ns_per_syscall(baseline_ns, baseline_ok);

    let path = common::resolve_ebpf_object_path();
    let mut ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load_file(&path)
        .unwrap_or_else(|e| panic!("failed to load eBPF object from {}: {e}", path.display()));

    let mut _links: Vec<TracePointLinkId> = Vec::new();
    for &(program_name, tracepoint_name) in SYSCALL_TRACEPOINTS {
        let program = ebpf
            .program_mut(program_name)
            .unwrap_or_else(|| panic!("missing program `{program_name}`"));
        let Program::TracePoint(tp) = program else {
            panic!("`{program_name}` is not a TracePoint");
        };
        tp.load()
            .unwrap_or_else(|e| panic!("load `{program_name}`: {e}"));
        let link = tp.attach("syscalls", tracepoint_name).unwrap_or_else(|e| {
            panic!("attach `{program_name}` -> syscalls/{tracepoint_name}: {e}")
        });
        _links.push(link);
    }

    mprotect_rwx_rw_cycles(page, WARMUP_CYCLES);

    let ebpf_start = Instant::now();
    let ebpf_ok = mprotect_rwx_rw_cycles(page, TIMED_CYCLES);
    let ebpf_elapsed = ebpf_start.elapsed();

    unsafe {
        libc::munmap(page, 4096);
    }

    assert_eq!(
        ebpf_ok, TIMED_CYCLES,
        "eBPF: expected {TIMED_CYCLES} successful mprotect cycles"
    );

    let ebpf_ns = ebpf_elapsed.as_nanos();
    let ebpf_per_syscall = ns_per_syscall(ebpf_ns, ebpf_ok);

    let overhead_per_syscall = ebpf_per_syscall - baseline_per_syscall;

    eprintln!(
        "[ebpf_overhead_bench] cycles={TIMED_CYCLES} ({} syscalls each run)",
        TIMED_CYCLES * 2
    );
    eprintln!(
        "[ebpf_overhead_bench] baseline: total={baseline_elapsed:?} avg_ns_per_syscall={baseline_per_syscall:.2}"
    );
    eprintln!(
        "[ebpf_overhead_bench] ebpf:    total={ebpf_elapsed:?} avg_ns_per_syscall={ebpf_per_syscall:.2}"
    );
    eprintln!(
        "[ebpf_overhead_bench] overhead_ns_per_syscall={overhead_per_syscall:.2} (max allowed {max_overhead_ns})"
    );

    assert!(
        overhead_per_syscall <= max_overhead_ns as f64,
        "eBPF mprotect overhead too high: {overhead_per_syscall:.2} ns/syscall > {max_overhead_ns} ns/syscall; \
         raise AEGIS_MPROTECT_OVERHEAD_NS_MAX if this host is legitimately slower"
    );
}
