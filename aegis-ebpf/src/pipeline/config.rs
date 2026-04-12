#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub channel_buffer_size: usize,
    pub reorder_window_ms: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            channel_buffer_size: 4096,
            reorder_window_ms: 50,
        }
    }
}
