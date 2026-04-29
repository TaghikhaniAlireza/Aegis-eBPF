//! Append-only JSON audit log for configuration and high-level SDK/engine actions (Phase 4.1).
//!
//! Set `MACE_AUDIT_LOG_PATH` to a file path to enable. Each line is one JSON object with
//! `ts_unix_ms`, `action`, `detail`, and optional `caller` / `success` fields. Opens with
//! `O_APPEND` so normal writes are append-only at the filesystem level.

use std::{
    fs::OpenOptions,
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static AUDIT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Call once at process start (e.g. from `mace_engine_init`) to enable audit if env is set.
pub fn init_from_env() {
    let Ok(path) = std::env::var("MACE_AUDIT_LOG_PATH") else {
        AUDIT_ENABLED.store(false, Ordering::Relaxed);
        return;
    };
    if path.trim().is_empty() {
        AUDIT_ENABLED.store(false, Ordering::Relaxed);
        return;
    }
    // Touch open to fail fast if path is invalid (optional).
    if let Err(e) = OpenOptions::new().create(true).append(true).open(&path) {
        tracing::warn!("MACE_AUDIT_LOG_PATH={path} could not be opened for audit logging: {e}");
        AUDIT_ENABLED.store(false, Ordering::Relaxed);
        return;
    }
    AUDIT_ENABLED.store(true, Ordering::Relaxed);
    tracing::info!("Mace audit log enabled: {path}");
}

pub fn is_enabled() -> bool {
    AUDIT_ENABLED.load(Ordering::Relaxed)
}

fn ts_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Append one audit record (no secrets: avoid full YAML bodies).
pub fn record(action: &str, detail: &str, success: bool) {
    if !is_enabled() {
        return;
    }
    let Ok(path) = std::env::var("MACE_AUDIT_LOG_PATH") else {
        return;
    };
    let line = format!(
        "{{\"ts_unix_ms\":{},\"action\":{},\"detail\":{},\"success\":{}}}\n",
        ts_ms(),
        serde_json::to_string(action).unwrap_or_else(|_| "\"\"".into()),
        serde_json::to_string(detail).unwrap_or_else(|_| "\"\"".into()),
        success
    );
    let _ = append_line(&path, &line);
}

fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn audit_skips_when_env_unset() {
        unsafe {
            std::env::remove_var("MACE_AUDIT_LOG_PATH");
        }
        init_from_env();
        assert!(!is_enabled());
    }

    #[test]
    fn audit_writes_json_line() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "mace-audit-test-{}.log",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let p = path.to_string_lossy().to_string();
        unsafe {
            std::env::set_var("MACE_AUDIT_LOG_PATH", &p);
        }
        init_from_env();
        assert!(is_enabled());
        record("test_action", "detail=value", true);
        let s = fs::read_to_string(&p).expect("read audit");
        assert!(s.contains("test_action"), "unexpected audit line: {s:?}");
        assert!(
            s.contains("true") || s.contains("success"),
            "unexpected audit line: {s:?}"
        );
        let _ = fs::remove_file(&p);
        unsafe {
            std::env::remove_var("MACE_AUDIT_LOG_PATH");
        }
        AUDIT_ENABLED.store(false, Ordering::Relaxed);
    }
}
