//! Summarize kernel-side eBPF counters exposed via the `KERNEL_STATS` per-CPU array map.

use std::sync::atomic::{AtomicU64, Ordering};

use aya::{Ebpf, maps::Array};

use crate::observability::metrics::{
    record_kernel_lru_insert_fail, record_ringbuf_reserve_fail_kernel,
};

/// Ring buffer reserve/output failures (index 0 of `KERNEL_STATS`).
static LAST_RINGBUF_FAILS: AtomicU64 = AtomicU64::new(0);
/// Pending-map insert failures (index 1).
static LAST_LRU_FAILS: AtomicU64 = AtomicU64::new(0);

/// Read `KERNEL_STATS` BPF array (4 × u64) and export Prometheus deltas.
pub fn refresh_kernel_stats_from_ebpf(ebpf: &mut Ebpf) {
    let Ok(arr) =
        Array::<_, u64>::try_from(ebpf.map_mut("KERNEL_STATS").expect("KERNEL_STATS map"))
    else {
        return;
    };
    let mut ring = 0u64;
    let mut lru = 0u64;
    for i in 0u32..4 {
        if let Ok(v) = arr.get(&i, 0) {
            match i {
                0 => ring = v,
                1 => lru = v,
                _ => {}
            }
        }
    }
    let prev_r = LAST_RINGBUF_FAILS.swap(ring, Ordering::Relaxed);
    if ring > prev_r {
        record_ringbuf_reserve_fail_kernel(ring - prev_r);
    }
    let prev_l = LAST_LRU_FAILS.swap(lru, Ordering::Relaxed);
    if lru > prev_l {
        record_kernel_lru_insert_fail(lru - prev_l);
    }
}
