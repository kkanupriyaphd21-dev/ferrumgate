//! Token blacklist for revocation.
//!
//! Maintains a set of revoked tokens with automatic expiration.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Token blacklist with TTL-based expiration.
pub struct TokenBlacklist {
    revoked: RwLock<HashMap<String, Instant>>,
    default_ttl: Duration,
}

impl TokenBlacklist {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            revoked: RwLock::new(HashMap::new()),
            default_ttl,
        }
    }

    pub fn revoke(&self, token_id: &str) {
        self.revoked.write().unwrap().insert(
            token_id.to_string(),
            Instant::now() + self.default_ttl,
        );
    }

    pub fn revoke_with_ttl(&self, token_id: &str, ttl: Duration) {
        self.revoked.write().unwrap().insert(
            token_id.to_string(),
            Instant::now() + ttl,
        );
    }

    pub fn is_revoked(&self, token_id: &str) -> bool {
        let mut revoked = self.revoked.write().unwrap();

        // Clean up expired entries
        let now = Instant::now();
        revoked.retain(|_, expiry| *expiry > now);

        revoked.contains_key(token_id)
    }

    pub fn size(&self) -> usize {
        self.revoked.read().unwrap().len()
    }

    pub fn clear(&self) {
        self.revoked.write().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_revoke_and_check() {
        let blacklist = TokenBlacklist::new(Duration::from_secs(60));
        blacklist.revoke("token-123");
        assert!(blacklist.is_revoked("token-123"));
        assert!(!blacklist.is_revoked("token-456"));
    }

    #[test]
    fn test_blacklist_size() {
        let blacklist = TokenBlacklist::new(Duration::from_secs(60));
        blacklist.revoke("token-1");
        blacklist.revoke("token-2");
        assert_eq!(blacklist.size(), 2);
    }

    #[test]
    fn test_blacklist_clear() {
        let blacklist = TokenBlacklist::new(Duration::from_secs(60));
        blacklist.revoke("token-1");
        blacklist.clear();
        assert_eq!(blacklist.size(), 0);
    }
}
