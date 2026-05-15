use crate::errors::{GatewayError, GatewayResult};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
    pub retryable_status: Vec<u16>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
            retryable_status: vec![429, 500, 502, 503, 504],
        }
    }
}

impl RetryPolicy {
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    pub fn with_retryable_status(mut self, status: Vec<u16>) -> Self {
        self.retryable_status = status;
        self
    }

    pub fn is_retryable(&self, error: &GatewayError) -> bool {
        error.is_recoverable()
    }

    pub fn is_retryable_status(&self, status: u16) -> bool {
        self.retryable_status.contains(&status)
    }

    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let mut backoff = self.initial_backoff.mul_f64(self.backoff_multiplier.powi(attempt as i32));
        if backoff > self.max_backoff {
            backoff = self.max_backoff;
        }

        if self.jitter {
            let jitter_range = backoff.as_millis() as u64;
            let jitter_amount = rand_range(0, jitter_range);
            backoff - Duration::from_millis(jitter_amount / 2)
        } else {
            backoff
        }
    }
}

fn rand_range(min: u64, max: u64) -> u64 {
    if max <= min {
        return min;
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    min + (seed % (max - min))
}

pub struct RetryAttempt {
    pub attempt: u32,
    pub backoff: Duration,
    pub reason: String,
}

pub async fn execute_with_retry<F, Fut, T>(
    policy: &RetryPolicy,
    mut operation: F,
) -> GatewayResult<T>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = GatewayResult<T>>,
{
    let mut last_error = None;

    for attempt in 0..=policy.max_retries {
        match operation(attempt).await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if !policy.is_retryable(&err) || attempt == policy.max_retries {
                    return Err(err);
                }

                let backoff = policy.backoff_for_attempt(attempt);
                tracing::warn!(
                    attempt = attempt + 1,
                    max_retries = policy.max_retries,
                    backoff_ms = backoff.as_millis(),
                    error = %err,
                    "retryable error encountered, waiting before retry"
                );

                last_error = Some(err);
                tokio::time::sleep(backoff).await;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| GatewayError::Internal("retry exhausted without error".to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ConnectionError;

    #[test]
    fn test_default_policy() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.initial_backoff, Duration::from_millis(100));
        assert_eq!(policy.max_backoff, Duration::from_secs(10));
        assert!(policy.jitter);
    }

    #[test]
    fn test_backoff_increases_exponentially() {
        let policy = RetryPolicy::default();
        let b0 = policy.backoff_for_attempt(0);
        let b1 = policy.backoff_for_attempt(1);
        let b2 = policy.backoff_for_attempt(2);
        assert!(b1 > b0);
        assert!(b2 > b1);
    }

    #[test]
    fn test_backoff_respects_max() {
        let policy = RetryPolicy::default()
            .with_max_backoff(Duration::from_millis(500))
            .with_initial_backoff(Duration::from_millis(100))
            .with_multiplier(10.0);
        let b5 = policy.backoff_for_attempt(5);
        assert!(b5 <= Duration::from_millis(500));
    }

    #[test]
    fn test_is_retryable() {
        let policy = RetryPolicy::default();
        let err = GatewayError::Connection(ConnectionError::ConnectionTimeout {
            addr: "127.0.0.1:8080".to_string(),
        });
        assert!(policy.is_retryable(&err));

        let crypto_err = GatewayError::Crypto(crate::errors::CryptoError::EncryptionFailed("test".to_string()));
        assert!(!policy.is_retryable(&crypto_err));
    }

    #[test]
    fn test_is_retryable_status() {
        let policy = RetryPolicy::default();
        assert!(policy.is_retryable_status(502));
        assert!(policy.is_retryable_status(503));
        assert!(policy.is_retryable_status(429));
        assert!(!policy.is_retryable_status(400));
        assert!(!policy.is_retryable_status(404));
    }

    #[test]
    fn test_builder_pattern() {
        let policy = RetryPolicy::default()
            .with_max_retries(5)
            .with_initial_backoff(Duration::from_millis(50))
            .with_max_backoff(Duration::from_secs(30))
            .with_multiplier(3.0)
            .with_jitter(false)
            .with_retryable_status(vec![500, 502, 503]);

        assert_eq!(policy.max_retries, 5);
        assert_eq!(policy.initial_backoff, Duration::from_millis(50));
        assert_eq!(policy.max_backoff, Duration::from_secs(30));
        assert!(!policy.jitter);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let policy = RetryPolicy::default()
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));

        let mut call_count = 0;
        let result = execute_with_retry(&policy, |_| async {
            call_count += 1;
            if call_count < 3 {
                Err(GatewayError::Connection(ConnectionError::ConnectionTimeout {
                    addr: "127.0.0.1:8080".to_string(),
                }))
            } else {
                Ok("success")
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(call_count, 3);
    }

    #[tokio::test]
    async fn test_retry_exhausts_on_non_retryable() {
        let policy = RetryPolicy::default()
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));

        let result = execute_with_retry(&policy, |_| async {
            Err(GatewayError::Crypto(crate::errors::CryptoError::EncryptionFailed("test".to_string())))
        })
        .await;

        assert!(result.is_err());
    }
}
