//! Loads the compiled eBPF object and runs `BPF_PROG_LOAD` for each **tracepoint** program so the
//! kernel verifier must accept them. (The linked object may also contain non-tracepoint symbols
//! such as `aegis_ebpf`; those are skipped because they are not valid `BPF_PROG_TYPE_TRACEPOINT`
//! loads.)
//!
//! Requires **root** (or CAP_BPF) and a prior **eBPF build**.
//!
//! The test is marked `#[ignore]` because many CI / microVM kernels (for example Firecracker)
//! reject `BPF_PROG_LOAD` for tracepoints with `EINVAL` before the verifier runs. On a normal
//! Linux workstation or server with BPF enabled, run:
//!
//! `sudo env PATH="$PATH" RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" cargo test --test verifier_load_test -p aegis-ebpf -- --ignored`

use std::path::PathBuf;

use aya::{EbpfLoader, VerifierLogLevel, programs::Program};

/// Must match `#[tracepoint]` entry points in `aegis-ebpf-ebpf`.
const EXPECTED_TRACEPOINTS: &[&str] = &[
    "sys_enter_mmap",
    "sys_enter_mprotect",
    "sys_enter_memfd_create",
    "sys_enter_ptrace",
    "sys_exit_mmap",
    "sys_exit_mprotect",
    "sys_exit_memfd_create",
    "sys_exit_ptrace",
];

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

fn assert_running_as_root() {
    let euid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))?
                .split_whitespace()
                .nth(1)?
                .parse::<u32>()
                .ok()
        });
    assert_eq!(
        euid,
        Some(0),
        "verifier_load_test must run as root (eBPF load requires CAP_BPF). \
         When using sudo, pass through PATH, RUSTUP_HOME, and CARGO_HOME so cargo/rustup resolve, \
         then: cargo test --test verifier_load_test -p aegis-ebpf"
    );
}

fn collect_ebpf_object_paths() -> Vec<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();

    let workspace_root = manifest_dir.parent().map(PathBuf::from);
    let target_roots = {
        let mut roots = Vec::new();
        if let Some(ref ws) = workspace_root {
            roots.push(ws.join("target"));
        }
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            roots.push(PathBuf::from(td));
        }
        roots
    };

    for target in &target_roots {
        paths.push(target.join("bpfel-unknown-none/release/aegis-ebpf"));
        paths.push(target.join("bpfel-unknown-none/debug/aegis-ebpf"));
    }

    // `aya_build` output (used by this workspace's `build.rs`): nested under each `OUT_DIR`.
    for target in &target_roots {
        for profile in ["debug", "release"] {
            let build_dir = target.join(profile).join("build");
            if let Ok(entries) = std::fs::read_dir(&build_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if !name.starts_with("aegis-ebpf-") {
                        continue;
                    }
                    let out = entry.path().join("out");
                    paths.push(out.join("aegis-ebpf"));
                    paths.push(out.join(
                        "aya-build/target/aegis-ebpf-ebpf/bpfel-unknown-none/release/aegis-ebpf",
                    ));
                }
            }
        }
    }

    paths
}

fn resolve_ebpf_object_path() -> PathBuf {
    let mut candidates: Vec<PathBuf> = collect_ebpf_object_paths()
        .into_iter()
        .filter(|p| p.is_file())
        .collect();

    if candidates.is_empty() {
        let tried = collect_ebpf_object_paths()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n  ");

        panic!(
            "compiled eBPF object `aegis-ebpf` not found. Checked:\n  {tried}\n\n\
             Build the BPF target first, for example from the workspace root:\n\
               cargo build -p aegis-ebpf\n\n\
             (The `aegis-ebpf` crate's build.rs compiles `aegis-ebpf-ebpf` for `bpfel-unknown-none`.)"
        );
    }

    candidates.sort_by_key(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    candidates.pop().expect("non-empty after is_file filter")
}

#[test]
#[ignore = "needs root + full BPF tracepoint support; run with --ignored on a capable kernel"]
fn test_load_ebpf_program() {
    assert_running_as_root();
    bump_memlock_rlimit();

    let path = resolve_ebpf_object_path();
    let mut ebpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load_file(&path)
        .unwrap_or_else(|e| {
            panic!(
                "failed to parse/load eBPF object from {}: {e}",
                path.display()
            )
        });

    let mut tracepoint_names: Vec<&str> = ebpf
        .programs()
        .filter_map(|(name, p)| matches!(p, Program::TracePoint(_)).then_some(name))
        .collect();
    tracepoint_names.sort();

    assert!(
        !tracepoint_names.is_empty(),
        "no tracepoint programs found in {}; check aegis-ebpf-ebpf exports #[tracepoint] progs",
        path.display()
    );

    for expected in EXPECTED_TRACEPOINTS {
        assert!(
            tracepoint_names.contains(expected),
            "expected tracepoint `{expected}` missing from object; found: {tracepoint_names:?}"
        );
    }

    assert_eq!(
        tracepoint_names.len(),
        EXPECTED_TRACEPOINTS.len(),
        "tracepoint set mismatch: expected exactly {:?}, found {:?}",
        EXPECTED_TRACEPOINTS,
        tracepoint_names
    );

    for name in EXPECTED_TRACEPOINTS {
        let program = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("program `{name}` missing after enumeration"));
        let Program::TracePoint(tp) = program else {
            panic!("program `{name}` is not a TracePoint");
        };
        if let Err(e) = tp.load() {
            panic!("kernel verifier rejected tracepoint `{name}`: {e}");
        }
    }
}
