use std::sync::Arc;

use aegis_ebpf_common::MemoryEvent;
use log::warn;
use tokio::sync::{mpsc, oneshot};

use crate::{ContextEnricher, PodMetadata, SensorConfig, start_sensor};

pub mod config;

#[derive(Clone, Debug)]
pub struct EnrichedEvent {
    pub inner: MemoryEvent,
    pub metadata: Option<PodMetadata>,
}

pub struct PipelineHandle {
    rx: mpsc::Receiver<EnrichedEvent>,
    shutdown_tx: oneshot::Sender<()>,
}

pub async fn start_pipeline(
    sensor_config: SensorConfig,
    pipeline_config: config::PipelineConfig,
    enricher: Arc<dyn ContextEnricher>,
) -> anyhow::Result<PipelineHandle> {
    let raw_rx = start_sensor(sensor_config).await?;
    Ok(spawn_pipeline_from_raw(
        raw_rx,
        pipeline_config.channel_buffer_size,
        enricher,
    ))
}

fn spawn_pipeline_from_raw(
    raw_rx: mpsc::Receiver<MemoryEvent>,
    channel_buffer_size: usize,
    enricher: Arc<dyn ContextEnricher>,
) -> PipelineHandle {
    let (enriched_tx, enriched_rx) = mpsc::channel(channel_buffer_size.max(1));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(run_enrichment_worker(raw_rx, enriched_tx, enricher, shutdown_rx));

    PipelineHandle {
        rx: enriched_rx,
        shutdown_tx,
    }
}

async fn run_enrichment_worker(
    mut raw_rx: mpsc::Receiver<MemoryEvent>,
    enriched_tx: mpsc::Sender<EnrichedEvent>,
    enricher: Arc<dyn ContextEnricher>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let mut shutdown_requested = false;
    loop {
        if shutdown_requested {
            match raw_rx.try_recv() {
                Ok(event) => {
                    if send_enriched_event(event, &enriched_tx, enricher.as_ref())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
            }
            continue;
        }

        tokio::select! {
            maybe_event = raw_rx.recv() => {
                let Some(event) = maybe_event else { return };
                if send_enriched_event(event, &enriched_tx, enricher.as_ref()).await.is_err() {
                    return;
                }
            }
            _ = &mut shutdown_rx => {
                shutdown_requested = true;
            }
        }
    }
}

async fn send_enriched_event(
    event: MemoryEvent,
    enriched_tx: &mpsc::Sender<EnrichedEvent>,
    enricher: &dyn ContextEnricher,
) -> Result<(), ()> {
    // cgroup_id is not yet present in MemoryEvent in this workspace,
    // so use tgid as the current enrichment key placeholder.
    let cgroup_id = u64::from(event.tgid);
    let metadata = match enricher.enrich(cgroup_id).await {
        Some(metadata) => Some(metadata),
        None => {
            warn!("context enrichment returned no metadata for cgroup_id={cgroup_id}");
            None
        }
    };

    let enriched = EnrichedEvent {
        inner: event,
        metadata,
    };
    enriched_tx.send(enriched).await.map_err(|_| ())
}

impl PipelineHandle {
    pub async fn next_event(&mut self) -> Option<EnrichedEvent> {
        self.rx.recv().await
    }

    pub async fn shutdown(self) {
        drop(self.shutdown_tx);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::sync::mpsc;

    use super::{EnrichedEvent, PipelineHandle, config, spawn_pipeline_from_raw};
    use crate::{ContextEnricher, NoopEnricher, PodMetadata};
    use aegis_ebpf_common::{EventType, MemoryEvent};

    fn fake_event(timestamp_ns: u64, tgid: u32, pid: u32) -> MemoryEvent {
        MemoryEvent {
            timestamp_ns,
            tgid,
            pid,
            comm: [0; 16],
            event_type: EventType::Mmap,
            addr: 0x1000,
            len: 4096,
            flags: 0,
            ret: 0,
        }
    }

    fn spawn_test_pipeline(
        enricher: Arc<dyn ContextEnricher>,
    ) -> (mpsc::Sender<MemoryEvent>, PipelineHandle) {
        let (raw_tx, raw_rx) = mpsc::channel(128);
        let handle =
            spawn_pipeline_from_raw(raw_rx, config::PipelineConfig::default().channel_buffer_size, enricher);
        (raw_tx, handle)
    }

    #[tokio::test]
    async fn happy_path_noop_enricher_preserves_fields() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        let input = fake_event(123, 456, 789);
        raw_tx.send(input).await.expect("send should succeed");

        let output = handle.next_event().await.expect("event should arrive");
        assert!(output.metadata.is_none());
        assert_eq!(output.inner.timestamp_ns, 123);
        assert_eq!(output.inner.tgid, 456);
    }

    struct AlwaysMetadataEnricher;

    #[async_trait]
    impl ContextEnricher for AlwaysMetadataEnricher {
        async fn enrich(&self, _cgroup_id: u64) -> Option<PodMetadata> {
            Some(PodMetadata {
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                node_name: "node-1".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn enrichment_populates_metadata() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(AlwaysMetadataEnricher));
        raw_tx
            .send(fake_event(1, 2, 3))
            .await
            .expect("send should succeed");

        let output = handle.next_event().await.expect("event should arrive");
        let metadata = output.metadata.expect("metadata should be present");
        assert_eq!(metadata.pod_name, "test-pod");
        assert_eq!(metadata.namespace, "default");
        assert_eq!(metadata.node_name, "node-1");
    }

    struct AlwaysNoneEnricher;

    #[async_trait]
    impl ContextEnricher for AlwaysNoneEnricher {
        async fn enrich(&self, _cgroup_id: u64) -> Option<PodMetadata> {
            None
        }
    }

    #[tokio::test]
    async fn enrichment_failure_is_non_fatal() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(AlwaysNoneEnricher));
        for idx in 0..3 {
            raw_tx
                .send(fake_event(100 + idx, 200 + idx as u32, 300 + idx as u32))
                .await
                .expect("send should succeed");
        }

        let mut received = Vec::<EnrichedEvent>::new();
        for _ in 0..3 {
            received.push(handle.next_event().await.expect("event should arrive"));
        }
        assert_eq!(received.len(), 3);
        assert!(received.iter().all(|event| event.metadata.is_none()));

        let pending = tokio::time::timeout(Duration::from_millis(50), handle.next_event()).await;
        assert!(pending.is_err(), "channel should stay open without immediate close");
    }

    #[tokio::test]
    async fn shutdown_drains_inflight_events() {
        let (raw_tx, mut handle) = spawn_test_pipeline(Arc::new(NoopEnricher));
        for idx in 0..50u64 {
            raw_tx
                .send(fake_event(1_000 + idx, 42, 42))
                .await
                .expect("send should succeed");
        }

        // Extract the receiver so we can continue draining after shutdown consumes the handle.
        let (_dummy_tx, dummy_rx) = mpsc::channel(1);
        let mut rx = std::mem::replace(&mut handle.rx, dummy_rx);
        handle.shutdown().await;

        let mut count = 0usize;
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            count += 1;
        }

        assert_eq!(count, 50);
    }
}
