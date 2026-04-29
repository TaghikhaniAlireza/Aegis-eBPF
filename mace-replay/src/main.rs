//! Replay serialized [`mace_ebpf_common::MemoryEvent`] values against a YAML rule set (no eBPF).

use std::{fs, path::PathBuf};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use mace_ebpf::{EnrichedEvent, rules::loader::RuleSet, state::StateTracker};

#[derive(Parser)]
#[command(
    name = "mace-replay",
    version,
    about = "Offline rule engine replay (sandbox)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate recorded events from a JSON file against `--rules`.
    Replay {
        /// Path to JSON: either `[{...MemoryEvent...}, ...]` or `{"events":[...]}`.
        #[arg(long)]
        data: PathBuf,
        /// Rule YAML file or directory (same semantics as `mace_load_rules_file`).
        #[arg(long)]
        rules: PathBuf,
        /// State tracker window in milliseconds (default 300_000).
        #[arg(long, default_value_t = 300_000u64)]
        state_window_ms: u64,
    },
}

fn load_events_json(path: &PathBuf) -> anyhow::Result<Vec<mace_ebpf_common::MemoryEvent>> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if let Ok(ev) = serde_json::from_str::<mace_ebpf_common::MemoryEvent>(&raw) {
        return Ok(vec![ev]);
    }
    if let Ok(arr) = serde_json::from_str::<Vec<mace_ebpf_common::MemoryEvent>>(&raw) {
        return Ok(arr);
    }
    #[derive(serde::Deserialize)]
    struct Wrap {
        events: Vec<mace_ebpf_common::MemoryEvent>,
    }
    let w: Wrap = serde_json::from_str(&raw)
        .context("expected JSON array of MemoryEvent or {\"events\":[...]}")?;
    Ok(w.events)
}

fn load_rules(path: &PathBuf) -> anyhow::Result<RuleSet> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.is_dir() {
        RuleSet::from_dir(path).map_err(Into::into)
    } else {
        RuleSet::from_file(path).map_err(Into::into)
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Replay {
            data,
            rules,
            state_window_ms,
        } => {
            let rule_set = load_rules(&rules)?;
            let events = load_events_json(&data)?;
            if events.is_empty() {
                bail!("no events in {}", data.display());
            }

            let mut tracker = StateTracker::new(state_window_ms);

            println!(
                "replay: {} events, {} rules loaded from {}",
                events.len(),
                rule_set.rules().len(),
                rules.display()
            );

            for (idx, inner) in events.into_iter().enumerate() {
                let event = EnrichedEvent {
                    inner,
                    metadata: None,
                    cmdline_context: None,
                    username: None,
                };
                tracker.update(&event);
                tracker.expire_old(event.inner.timestamp_ns);
                let tgid = event.inner.tgid;
                if let Some(st_mut) = tracker.get_mut(tgid) {
                    for rule in rule_set.rules() {
                        rule.advance_sequence(&event, st_mut);
                    }
                }
                let state = tracker.get(tgid);
                let (enforce, shadow, suppressed, timings) =
                    rule_set.evaluate_with_suppressions_profiled(&event, state);

                println!(
                    "event[{idx}] tgid={} syscall={:?} enforce={:?} shadow={:?} suppressed_by={:?}",
                    event.inner.tgid,
                    event.inner.event_type,
                    enforce.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                    shadow.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                    suppressed
                );
                for (rid, ns) in &timings {
                    println!("  rule {rid}: eval {ns} ns");
                }

                if let Some(st_mut) = tracker.get_mut(tgid) {
                    for rule in enforce.iter().chain(shadow.iter()) {
                        rule.reset_sequence_progress(st_mut);
                    }
                }
            }
            println!("replay: done");
        }
    }
    Ok(())
}
