//! Read `/proc/<pid>/cmdline` as a single space-joined string (NUL-separated argv in procfs).

use std::fs;

/// Join `/proc/<pid>/cmdline` NUL-separated segments with ASCII spaces.
///
/// Prefer **TGID** (thread group leader) when attributing a process image to match `ps` / rule
/// haystack semantics for threaded workloads.
pub fn read_proc_cmdline_joined(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cmdline");
    let raw = fs::read(&path).ok()?;
    let s = String::from_utf8_lossy(&raw);
    Some(
        s.split('\0')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    )
    .filter(|s| !s.is_empty())
}
