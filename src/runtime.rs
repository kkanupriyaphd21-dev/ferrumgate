use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct RuntimeConfig {
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    #[serde(default = "default_max_blocking_threads")]
    pub max_blocking_threads: usize,
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
    #[serde(default = "default_io_poll_threads")]
    pub io_poll_threads: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: default_worker_threads(),
            max_blocking_threads: default_max_blocking_threads(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            io_poll_threads: default_io_poll_threads(),
        }
    }
}

fn default_worker_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}

fn default_max_blocking_threads() -> usize {
    512
}

fn default_shutdown_timeout_secs() -> u64 {
    30
}

fn default_io_poll_threads() -> usize {
    1
}

pub struct RuntimeStats {
    pub num_workers: usize,
    pub blocking_threads: usize,
    pub active_tasks: u64,
    pub total_tasks_spawned: u64,
}

impl RuntimeStats {
    pub fn new(worker_threads: usize, blocking_threads: usize) -> Self {
        Self {
            num_workers: worker_threads,
            blocking_threads,
            active_tasks: 0,
            total_tasks_spawned: 0,
        }
    }
}
