//! Sampling strategies for distributed tracing.
//!
//! Provides configurable sampling decisions to control trace volume
//! while maintaining representative data for observability.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::tracing_ctx::{TraceContext, TraceId, record_trace_start};

/// Sampling decision result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingDecision {
    /// Record and export the trace.
    RecordAndSample,
    /// Record locally but don't export (for metrics only).
    RecordOnly,
    /// Don't record or export.
    Drop,
}

/// Trait for sampling strategies.
pub trait Sampler: Send + Sync {
    /// Decide whether to sample a trace.
    fn should_sample(&self, trace_id: &TraceId) -> SamplingDecision;

    /// Human-readable name of the sampler.
    fn name(&self) -> &str;

    /// Get sampling rate (0.0 to 1.0).
    fn rate(&self) -> f64;
}

/// Always sample all traces.
pub struct AlwaysOnSampler;

impl Sampler for AlwaysOnSampler {
    fn should_sample(&self, _trace_id: &TraceId) -> SamplingDecision {
        SamplingDecision::RecordAndSample
    }

    fn name(&self) -> &str { "always_on" }

    fn rate(&self) -> f64 { 1.0 }
}

/// Never sample any traces.
pub struct AlwaysOffSampler;

impl Sampler for AlwaysOffSampler {
    fn should_sample(&self, _trace_id: &TraceId) -> SamplingDecision {
        SamplingDecision::Drop
    }

    fn name(&self) -> &str { "always_off" }

    fn rate(&self) -> f64 { 0.0 }
}

/// Sample a fixed percentage of traces.
pub struct ProbabilitySampler {
    probability: f64,
    threshold: u64,
    total_evaluated: AtomicU64,
    sampled_count: AtomicU64,
}

impl ProbabilitySampler {
    pub fn new(probability: f64) -> Self {
        let probability = probability.clamp(0.0, 1.0);
        let threshold = (probability * u64::MAX as f64) as u64;
        Self {
            probability,
            threshold,
            total_evaluated: AtomicU64::new(0),
            sampled_count: AtomicU64::new(0),
        }
    }

    fn hash_trace_id(trace_id: &TraceId) -> u64 {
        let mut hash: u64 = 0;
        for &byte in &trace_id.0 {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }
}

impl Sampler for ProbabilitySampler {
    fn should_sample(&self, trace_id: &TraceId) -> SamplingDecision {
        self.total_evaluated.fetch_add(1, Ordering::Relaxed);

        let hash = Self::hash_trace_id(trace_id);
        if hash <= self.threshold {
            self.sampled_count.fetch_add(1, Ordering::Relaxed);
            SamplingDecision::RecordAndSample
        } else {
            SamplingDecision::Drop
        }
    }

    fn name(&self) -> &str { "probability" }

    fn rate(&self) -> f64 { self.probability }

    fn sampled_ratio(&self) -> f64 {
        let total = self.total_evaluated.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            self.sampled_count.load(Ordering::Relaxed) as f64 / total as f64
        }
    }
}

/// Rate-limited sampler that caps traces per second.
pub struct RateLimitedSampler {
    max_per_second: u64,
    current_second: AtomicU64,
    current_count: AtomicU64,
    total_evaluated: AtomicU64,
    sampled_count: AtomicU64,
}

impl RateLimitedSampler {
    pub fn new(max_per_second: u64) -> Self {
        Self {
            max_per_second,
            current_second: AtomicU64::new(0),
            current_count: AtomicU64::new(0),
            total_evaluated: AtomicU64::new(0),
            sampled_count: AtomicU64::new(0),
        }
    }

    fn current_unix_second() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Sampler for RateLimitedSampler {
    fn should_sample(&self, _trace_id: &TraceId) -> SamplingDecision {
        self.total_evaluated.fetch_add(1, Ordering::Relaxed);
        let now = Self::current_unix_second();
        let current_second = self.current_second.load(Ordering::Relaxed);

        if now != current_second {
            self.current_second.store(now, Ordering::Relaxed);
            self.current_count.store(1, Ordering::Relaxed);
            self.sampled_count.fetch_add(1, Ordering::Relaxed);
            SamplingDecision::RecordAndSample
        } else {
            let count = self.current_count.fetch_add(1, Ordering::Relaxed);
            if count < self.max_per_second {
                self.sampled_count.fetch_add(1, Ordering::Relaxed);
                SamplingDecision::RecordAndSample
            } else {
                SamplingDecision::Drop
            }
        }
    }

    fn name(&self) -> &str { "rate_limited" }

    fn rate(&self) -> f64 {
        let total = self.total_evaluated.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            self.sampled_count.load(Ordering::Relaxed) as f64 / total as f64
        }
    }
}

/// Parent-based sampler that respects parent sampling decision.
pub struct ParentBasedSampler {
    root_sampler: Box<dyn Sampler>,
}

impl ParentBasedSampler {
    pub fn new(root_sampler: Box<dyn Sampler>) -> Self {
        Self { root_sampler }
    }
}

impl Sampler for ParentBasedSampler {
    fn should_sample(&self, trace_id: &TraceId) -> SamplingDecision {
        self.root_sampler.should_sample(trace_id)
    }

    fn name(&self) -> &str { "parent_based" }

    fn rate(&self) -> f64 { self.root_sampler.rate() }
}

/// Apply sampling decision to a trace context.
pub fn apply_sampling(ctx: &mut TraceContext, sampler: &dyn Sampler) {
    let decision = sampler.should_sample(&ctx.trace_id);
    match decision {
        SamplingDecision::RecordAndSample => {
            ctx.set_sampled(true);
        }
        SamplingDecision::RecordOnly => {
            ctx.set_sampled(false);
        }
        SamplingDecision::Drop => {
            ctx.set_sampled(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_always_on_sampler() {
        let sampler = AlwaysOnSampler;
        let trace_id = TraceId::generate();
        assert_eq!(sampler.should_sample(&trace_id), SamplingDecision::RecordAndSample);
        assert_eq!(sampler.rate(), 1.0);
    }

    #[test]
    fn test_always_off_sampler() {
        let sampler = AlwaysOffSampler;
        let trace_id = TraceId::generate();
        assert_eq!(sampler.should_sample(&trace_id), SamplingDecision::Drop);
        assert_eq!(sampler.rate(), 0.0);
    }

    #[test]
    fn test_probability_sampler_bounds() {
        let sampler = ProbabilitySampler::new(0.5);
        assert_eq!(sampler.name(), "probability");
        assert_eq!(sampler.rate(), 0.5);
    }

    #[test]
    fn test_probability_sampler_clamps() {
        let sampler = ProbabilitySampler::new(1.5);
        assert_eq!(sampler.rate(), 1.0);

        let sampler = ProbabilitySampler::new(-0.5);
        assert_eq!(sampler.rate(), 0.0);
    }

    #[test]
    fn test_rate_limited_sampler() {
        let sampler = RateLimitedSampler::new(100);
        assert_eq!(sampler.name(), "rate_limited");

        let trace_id = TraceId::generate();
        let decision = sampler.should_sample(&trace_id);
        assert_eq!(decision, SamplingDecision::RecordAndSample);
    }

    #[test]
    fn test_parent_based_sampler() {
        let root = Box::new(AlwaysOnSampler);
        let sampler = ParentBasedSampler::new(root);
        assert_eq!(sampler.name(), "parent_based");
        assert_eq!(sampler.rate(), 1.0);
    }

    #[test]
    fn test_apply_sampling() {
        let mut ctx = TraceContext::new_root();
        let sampler = AlwaysOffSampler;
        apply_sampling(&mut ctx, &sampler);
        assert!(!ctx.is_sampled());
    }
}
