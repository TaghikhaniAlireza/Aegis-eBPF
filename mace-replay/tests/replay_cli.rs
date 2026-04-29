//! Integration test for `mace-replay replay` (requires `cargo test` so `CARGO_BIN_EXE_*` is set).

use std::{fs, process::Command};

#[test]
fn replay_runs_against_json_array() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_path = dir.path().join("rules.yaml");
    fs::write(
        &rules_path,
        r#"
rules:
  - id: "R-MMAP"
    name: "mmap"
    severity: "low"
    description: "d"
    conditions:
      syscall: "mmap"
"#,
    )
    .expect("write rules");

    let data_path = dir.path().join("ev.json");
    fs::write(
        &data_path,
        r#"[
  {"timestamp_ns":1,"tgid":10,"pid":10,"uid":0,"comm":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"event_type":"Mmap","addr":4096,"len":4096,"flags":0,"ret":0,"execve_cmdline":"","openat_path":""}
]"#,
    )
    .expect("write events");

    let bin = env!("CARGO_BIN_EXE_mace-replay");
    let out = Command::new(bin)
        .args([
            "replay",
            "--data",
            data_path.to_str().unwrap(),
            "--rules",
            rules_path.to_str().unwrap(),
            "--state-window-ms",
            "60000",
        ])
        .output()
        .expect("spawn mace-replay");

    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("R-MMAP"), "stdout={s}");
}
