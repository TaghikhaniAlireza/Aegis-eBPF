//! Metric definitions using the `metrics` facade (no-op unless a recorder is installed).

#[cfg(any(feature = "prometheus", feature = "otel"))]
macro_rules! record_metric {
    (counter: $name:expr) => {
        ::metrics::counter!($name).increment(1);
    };
    (counter: $name:expr, $($labels:tt)+) => {
        ::metrics::counter!($name, $($labels)+).increment(1);
    };
    (gauge: $name:expr, $value:expr) => {
        ::metrics::gauge!($name).set($value as f64);
    };
    (gauge: $name:expr, $value:expr, $($labels:tt)+) => {
        ::metrics::gauge!($name, $($labels)+).set($value as f64);
    };
    (histogram: $name:expr, $value:expr) => {
        ::metrics::histogram!($name).record($value as f64);
    };
    (histogram: $name:expr, $value:expr, $($labels:tt)+) => {
        ::metrics::histogram!($name, $($labels)+).record($value as f64);
    };
}

#[cfg(not(any(feature = "prometheus", feature = "otel")))]
macro_rules! record_metric {
    ($($_tt:tt)*) => {};
}

#[allow(unused_imports)]
pub(crate) use record_metric;

pub const EVENTS_INGESTED_TOTAL: &str = "mace_events_ingested_total";
pub const EVENTS_DROPPED_TOTAL: &str = "mace_events_dropped_total";
/// Kernel eBPF: ring buffer `reserve` / `output` failures (summed from per-CPU `KERNEL_STATS` map).
pub const EVENTS_DROPPED_RINGBUF_FULL_TOTAL: &str = "mace_events_dropped_ringbuf_full_total";
/// Kernel eBPF: pending syscall / payload LRU map insert failures (correlates with LRU eviction pressure).
pub const EVENTS_FILTERED_BY_KERNEL_LRU_TOTAL: &str = "mace_events_filtered_by_kernel_lru_total";
/// Userspace: events emitted from reorder heap when the reorder window deadline fires (timeout path).
pub const EVENTS_DROPPED_REORDER_TIMEOUT_TOTAL: &str = "mace_events_dropped_reorder_timeout_total";
/// Userspace: enriched → reorder channel full / closed (event not queued for reorder).
pub const EVENTS_DROPPED_CHANNEL_ENRICHED_TOTAL: &str =
    "mace_events_dropped_channel_enriched_total";
/// Userspace: reorder → partition router channel full / closed.
pub const EVENTS_DROPPED_CHANNEL_ORDERED_TOTAL: &str = "mace_events_dropped_channel_ordered_total";
pub const ALERTS_FIRED_TOTAL: &str = "mace_alerts_fired_total";
pub const PIPELINE_LATENCY_NS: &str = "mace_pipeline_latency_ns";
pub const REORDER_BUFFER_SIZE: &str = "mace_reorder_buffer_size";
pub const WORKER_QUEUE_DEPTH: &str = "mace_worker_queue_depth";
/// Histogram: per-rule `matches_with_state` evaluation time (nanoseconds), labeled by `rule_id`.
pub const RULE_EVAL_NS: &str = "mace_rule_eval_ns";

#[inline]
pub fn record_event_ingested() {
    record_metric!(counter: EVENTS_INGESTED_TOTAL);
}

#[inline]
pub fn record_event_dropped() {
    record_metric!(counter: EVENTS_DROPPED_TOTAL);
}

#[inline]
pub fn record_ringbuf_reserve_fail_kernel(n: u64) {
    for _ in 0..n {
        record_metric!(counter: EVENTS_DROPPED_RINGBUF_FULL_TOTAL);
    }
}

#[inline]
pub fn record_kernel_lru_insert_fail(n: u64) {
    for _ in 0..n {
        record_metric!(counter: EVENTS_FILTERED_BY_KERNEL_LRU_TOTAL);
    }
}

#[inline]
pub fn record_reorder_deadline_flush_events(n: usize) {
    for _ in 0..n {
        record_metric!(counter: EVENTS_DROPPED_REORDER_TIMEOUT_TOTAL);
    }
}

#[inline]
pub fn record_channel_drop_enriched() {
    record_metric!(counter: EVENTS_DROPPED_CHANNEL_ENRICHED_TOTAL);
}

#[inline]
pub fn record_channel_drop_ordered() {
    record_metric!(counter: EVENTS_DROPPED_CHANNEL_ORDERED_TOTAL);
}

#[inline]
#[cfg_attr(
    not(any(feature = "prometheus", feature = "otel")),
    allow(unused_variables)
)]
pub fn record_alert_fired(rule_id: &str) {
    record_metric!(counter: ALERTS_FIRED_TOTAL, "rule_id" => rule_id.to_string());
}

#[inline]
#[cfg_attr(
    not(any(feature = "prometheus", feature = "otel")),
    allow(unused_variables)
)]
pub fn record_pipeline_latency(latency_ns: u64) {
    record_metric!(histogram: PIPELINE_LATENCY_NS, latency_ns);
}

#[inline]
#[cfg_attr(
    not(any(feature = "prometheus", feature = "otel")),
    allow(unused_variables)
)]
pub fn update_reorder_buffer_size(size: usize) {
    record_metric!(gauge: REORDER_BUFFER_SIZE, size);
}

#[inline]
#[cfg_attr(
    not(any(feature = "prometheus", feature = "otel")),
    allow(unused_variables)
)]
pub fn update_worker_queue_depth(worker_id: usize, depth: usize) {
    record_metric!(
        gauge: WORKER_QUEUE_DEPTH,
        depth,
        "worker_id" => worker_id.to_string()
    );
}

#[inline]
#[cfg_attr(
    not(any(feature = "prometheus", feature = "otel")),
    allow(unused_variables)
)]
pub fn record_rule_eval_ns(rule_id: &str, ns: u64) {
    record_metric!(histogram: RULE_EVAL_NS, ns, "rule_id" => rule_id.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_helpers_compile() {
        record_event_ingested();
        record_event_dropped();
        record_alert_fired("test_rule");
        record_pipeline_latency(1000);
        update_reorder_buffer_size(42);
        update_worker_queue_depth(0, 10);
        record_channel_drop_ordered();
        record_rule_eval_ns("r1", 123);
    }
}
