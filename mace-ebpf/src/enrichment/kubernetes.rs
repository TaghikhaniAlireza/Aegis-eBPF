#![cfg(feature = "kubernetes")]

/*
Manual testing in a real Kubernetes environment:
1) Configure Kubernetes auth:
   - Use local kubeconfig: export KUBECONFIG=/path/to/kubeconfig
   - Or run in-cluster where ServiceAccount credentials are mounted.
2) Build and run the sensor with Kubernetes support:
   - cargo run --features kubernetes --release
3) Trigger a memory event in a pod and verify enrichment output includes pod metadata:
   - Expected enrichment contains pod name, namespace, and node name.
   - Example expected shape: Some(PodMetadata { pod_name: "...", namespace: "...", node_name: "..." })
*/

use std::{future::Future, time::Duration};

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, api::ListParams};
use moka::sync::Cache;
use tracing::warn;

use crate::{ContextEnricher, PodMetadata};

const CACHE_MAX_CAPACITY: u64 = 10_000;
const CACHE_TTL_SECONDS: u64 = 60;
/// Hard cap on how long a single Kubernetes list+scan may block enrichment (slow API / large clusters).
const K8S_LOOKUP_TIMEOUT: Duration = Duration::from_secs(12);
/// Upper bound on Pod objects examined per cache miss (limits CPU when API returns huge lists).
const K8S_MAX_PODS_PER_LOOKUP: u32 = 5_000;

pub struct KubernetesEnricher {
    client: Client,
    cache: Cache<u64, PodMetadata>,
}

async fn enrich_with_cache<F, Fut>(
    cache: &Cache<u64, PodMetadata>,
    cgroup_id: u64,
    lookup: F,
) -> Option<PodMetadata>
where
    F: FnOnce(u64) -> Fut,
    Fut: Future<Output = Option<PodMetadata>>,
{
    if let Some(metadata) = cache.get(&cgroup_id) {
        return Some(metadata);
    }

    let metadata = lookup(cgroup_id).await?;
    cache.insert(cgroup_id, metadata.clone());
    Some(metadata)
}

impl KubernetesEnricher {
    pub async fn new() -> Option<Self> {
        let client = Client::try_default().await.ok()?;
        let cache = Cache::builder()
            .max_capacity(CACHE_MAX_CAPACITY)
            .time_to_live(Duration::from_secs(CACHE_TTL_SECONDS))
            .build();
        Some(Self { client, cache })
    }

    async fn lookup_pod_metadata(&self, cgroup_id: u64) -> Option<PodMetadata> {
        let pods: Api<Pod> = Api::all(self.client.clone());
        let list_params = ListParams::default().limit(K8S_MAX_PODS_PER_LOOKUP);
        let list_future = pods.list(&list_params);
        let pod_list = match tokio::time::timeout(K8S_LOOKUP_TIMEOUT, list_future).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => {
                warn!(error = %e, "kubernetes: list pods failed");
                return None;
            }
            Err(_) => {
                warn!(
                    timeout_secs = K8S_LOOKUP_TIMEOUT.as_secs(),
                    "kubernetes: list pods timed out — skipping enrichment for this cgroup_id"
                );
                return None;
            }
        };

        let cgroup_hex = format!("{cgroup_id:x}");

        for pod in pod_list.items {
            let matches = pod
                .status
                .as_ref()
                .and_then(|status| status.container_statuses.as_ref())
                .into_iter()
                .flatten()
                .filter_map(|container| container.container_id.as_deref())
                .any(|container_id| container_id.contains(&cgroup_hex));

            if !matches {
                continue;
            }

            return Some(PodMetadata {
                pod_name: pod.metadata.name.unwrap_or_default(),
                namespace: pod.metadata.namespace.unwrap_or_default(),
                node_name: pod
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.node_name.clone())
                    .unwrap_or_default(),
            });
        }

        None
    }
}

#[async_trait]
impl ContextEnricher for KubernetesEnricher {
    async fn enrich(&self, cgroup_id: u64) -> Option<PodMetadata> {
        enrich_with_cache(&self.cache, cgroup_id, |id| self.lookup_pod_metadata(id)).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use moka::sync::Cache;

    use super::{KubernetesEnricher, enrich_with_cache};
    use crate::{ContextEnricher, PodMetadata};

    fn assert_context_enricher<T: ContextEnricher>() {}

    #[test]
    fn kubernetes_enricher_implements_context_enricher() {
        assert_context_enricher::<KubernetesEnricher>();
    }

    #[derive(Clone)]
    struct CountingEnricher {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ContextEnricher for CountingEnricher {
        async fn enrich(&self, _cgroup_id: u64) -> Option<PodMetadata> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Some(PodMetadata {
                pod_name: "p".into(),
                namespace: "ns".into(),
                node_name: "n".into(),
            })
        }
    }

    #[tokio::test]
    async fn enrich_with_cache_hits_second_time() {
        let cache: Cache<u64, PodMetadata> = Cache::builder()
            .max_capacity(10)
            .time_to_live(Duration::from_secs(60))
            .build();
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingEnricher {
            calls: Arc::clone(&calls),
        };

        let first = enrich_with_cache(&cache, 42, |_| async { inner.enrich(42).await }).await;
        assert!(first.is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let second = enrich_with_cache(&cache, 42, |_| async { inner.enrich(42).await }).await;
        assert!(second.is_some());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "lookup must not run again on cache hit"
        );
    }
}
