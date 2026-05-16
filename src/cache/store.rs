//! Cache storage backends.
//!
//! Provides in-memory and LRU cache store implementations
//! with thread-safe access and automatic eviction.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use crate::cache::{CacheableResponse, CacheConfig, CacheError, CacheLookup, record_cache_eviction};

/// A cached entry with metadata.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub response: CacheableResponse,
    pub created_at: Instant,
    pub ttl: Duration,
    pub access_count: u64,
    pub last_accessed: Instant,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl CacheEntry {
    pub fn is_fresh(&self) -> bool {
        self.created_at.elapsed() < self.ttl
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.age())
    }
}

/// Trait for cache storage backends.
pub trait CacheStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError>;
    fn put(&self, key: &str, entry: CacheEntry) -> Result<(), CacheError>;
    fn remove(&self, key: &str) -> Result<(), CacheError>;
    fn clear(&self) -> Result<(), CacheError>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
}

/// Simple in-memory cache store.
pub struct MemoryCacheStore {
    entries: RwLock<HashMap<String, CacheEntry>>,
    config: CacheConfig,
}

impl MemoryCacheStore {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
        }
    }

    fn evict_if_needed(&self) {
        let mut entries = self.entries.write().unwrap();
        while entries.len() >= self.config.max_entries {
            if let Some(oldest_key) = entries.iter()
                .min_by_key(|(_, e)| e.last_accessed)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
                record_cache_eviction();
            } else {
                break;
            }
        }
    }
}

impl CacheStore for MemoryCacheStore {
    fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(key) {
            entry.access_count += 1;
            entry.last_accessed = Instant::now();
            Ok(Some(entry.clone()))
        } else {
            Ok(None)
        }
    }

    fn put(&self, key: &str, entry: CacheEntry) -> Result<(), CacheError> {
        if key.len() > 4096 {
            return Err(CacheError::KeyTooLong { length: key.len(), max: 4096 });
        }
        if entry.response.content_length() > self.config.max_entry_size {
            return Err(CacheError::ValueTooLarge {
                size: entry.response.content_length(),
                max: self.config.max_entry_size,
            });
        }

        self.evict_if_needed();
        self.entries.write().unwrap().insert(key.to_string(), entry);
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), CacheError> {
        self.entries.write().unwrap().remove(key);
        Ok(())
    }

    fn clear(&self) -> Result<(), CacheError> {
        self.entries.write().unwrap().clear();
        Ok(())
    }

    fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }
}

/// LRU cache store with automatic eviction of least recently used entries.
pub struct LruCacheStore {
    entries: RwLock<HashMap<String, CacheEntry>>,
    access_order: RwLock<Vec<String>>,
    config: CacheConfig,
}

impl LruCacheStore {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            access_order: RwLock::new(Vec::new()),
            config,
        }
    }

    fn touch_key(&self, key: &str) {
        let mut order = self.access_order.write().unwrap();
        if let Some(pos) = order.iter().position(|k| k == key) {
            order.remove(pos);
        }
        order.push(key.to_string());
    }

    fn evict_lru(&self) {
        let mut order = self.access_order.write().unwrap();
        let mut entries = self.entries.write().unwrap();

        while entries.len() >= self.config.max_entries {
            if let Some(lru_key) = order.first().cloned() {
                order.remove(0);
                entries.remove(&lru_key);
                record_cache_eviction();
            } else {
                break;
            }
        }
    }
}

impl CacheStore for LruCacheStore {
    fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get_mut(key) {
            entry.access_count += 1;
            drop(entries);
            self.touch_key(key);
            let entries = self.entries.write().unwrap();
            Ok(entries.get(key).cloned())
        } else {
            Ok(None)
        }
    }

    fn put(&self, key: &str, entry: CacheEntry) -> Result<(), CacheError> {
        if key.len() > 4096 {
            return Err(CacheError::KeyTooLong { length: key.len(), max: 4096 });
        }
        if entry.response.content_length() > self.config.max_entry_size {
            return Err(CacheError::ValueTooLarge {
                size: entry.response.content_length(),
                max: self.config.max_entry_size,
            });
        }

        self.evict_lru();
        self.entries.write().unwrap().insert(key.to_string(), entry);
        self.touch_key(key);
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), CacheError> {
        self.entries.write().unwrap().remove(key);
        let mut order = self.access_order.write().unwrap();
        if let Some(pos) = order.iter().position(|k| k == key) {
            order.remove(pos);
        }
        Ok(())
    }

    fn clear(&self) -> Result<(), CacheError> {
        self.entries.write().unwrap().clear();
        self.access_order.write().unwrap().clear();
        Ok(())
    }

    fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_entry() -> CacheEntry {
        CacheEntry {
            response: CacheableResponse::new(200, HashMap::new(), vec![1, 2, 3], "key".to_string()),
            created_at: Instant::now(),
            ttl: Duration::from_secs(60),
            access_count: 0,
            last_accessed: Instant::now(),
            etag: None,
            last_modified: None,
        }
    }

    #[test]
    fn test_memory_cache_store_put_and_get() {
        let config = CacheConfig::default();
        let store = MemoryCacheStore::new(config);
        let entry = create_test_entry();
        store.put("test-key", entry).unwrap();

        let retrieved = store.get("test-key").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_memory_cache_store_miss() {
        let config = CacheConfig::default();
        let store = MemoryCacheStore::new(config);
        let retrieved = store.get("nonexistent").unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_memory_cache_store_remove() {
        let config = CacheConfig::default();
        let store = MemoryCacheStore::new(config);
        store.put("test-key", create_test_entry()).unwrap();
        store.remove("test-key").unwrap();
        assert!(store.get("test-key").unwrap().is_none());
    }

    #[test]
    fn test_memory_cache_store_clear() {
        let config = CacheConfig::default();
        let store = MemoryCacheStore::new(config);
        store.put("key1", create_test_entry()).unwrap();
        store.put("key2", create_test_entry()).unwrap();
        store.clear().unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn test_memory_cache_store_eviction() {
        let config = CacheConfig {
            max_entries: 3,
            ..Default::default()
        };
        let store = MemoryCacheStore::new(config);

        for i in 0..5 {
            store.put(&format!("key-{}", i), create_test_entry()).unwrap();
        }

        assert!(store.len() <= 3);
    }

    #[test]
    fn test_lru_cache_store_ordering() {
        let config = CacheConfig {
            max_entries: 3,
            ..Default::default()
        };
        let store = LruCacheStore::new(config);

        store.put("a", create_test_entry()).unwrap();
        store.put("b", create_test_entry()).unwrap();
        store.put("c", create_test_entry()).unwrap();

        // Access "a" to make it recently used
        store.get("a").unwrap();

        // Add "d" - should evict "b" (least recently used)
        store.put("d", create_test_entry()).unwrap();

        assert!(store.get("a").unwrap().is_some());
        assert!(store.get("b").unwrap().is_none());
    }

    #[test]
    fn test_cache_entry_freshness() {
        let entry = CacheEntry {
            response: CacheableResponse::new(200, HashMap::new(), vec![], "key".to_string()),
            created_at: Instant::now(),
            ttl: Duration::from_secs(1),
            access_count: 0,
            last_accessed: Instant::now(),
            etag: None,
            last_modified: None,
        };
        assert!(entry.is_fresh());
    }

    #[test]
    fn test_cache_entry_expired() {
        let entry = CacheEntry {
            response: CacheableResponse::new(200, HashMap::new(), vec![], "key".to_string()),
            created_at: Instant::now() - Duration::from_secs(10),
            ttl: Duration::from_secs(1),
            access_count: 0,
            last_accessed: Instant::now(),
            etag: None,
            last_modified: None,
        };
        assert!(!entry.is_fresh());
    }
}
