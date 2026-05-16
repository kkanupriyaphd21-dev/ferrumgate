//! Log rotation configuration and management.
//!
//! This module provides log rotation capabilities for file-based logging,
//! supporting:
//!
//! - Size-based rotation (rotate when file exceeds a threshold)
//! - Time-based rotation (rotate on a schedule: daily, hourly, minutely)
//! - Retention policies (keep N most recent rotated files)
//! - Compressed archive storage (gzip)
//! - Atomic rotation to prevent log loss
//!
//! # Rotation Strategies
//!
//! ## Size-Based Rotation
//!
//! Files are rotated when they exceed the configured maximum size. The
//! rotation is atomic: the current file is renamed to a timestamped
//! archive, and a new file is created for continued logging.
//!
//! ## Time-Based Rotation
//!
//! Files are rotated on a fixed schedule regardless of size. This is
//! useful for compliance requirements or predictable log management.
//!
//! # File Naming Convention
//!
//! Rotated files follow the pattern:
//! ```
//! {prefix}.{timestamp}.log.gz
//! ```
//!
//! Where:
//! - `prefix` is the configured file prefix (e.g., "ferrumgate")
//! - `timestamp` is the rotation time in ISO 8601 format
//! - `.gz` indicates gzip compression
//!
//! # Retention Policy
//!
//! The retention policy controls how many rotated files are kept. When
//! the limit is exceeded, the oldest files are deleted automatically.
//! This prevents unbounded disk usage.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::logging::{LoggingError, RotationSchedule};

/// Configuration for log rotation behavior.
#[derive(Debug, Clone)]
pub struct LogRotationConfig {
    /// Maximum size of a single log file in bytes before rotation.
    pub max_file_size_bytes: u64,

    /// Time-based rotation schedule.
    pub schedule: RotationSchedule,

    /// Maximum number of rotated files to retain.
    pub max_retained_files: usize,

    /// Whether to compress rotated files using gzip.
    pub compress_rotated: bool,

    /// Directory where rotated files are stored.
    pub rotation_directory: Option<PathBuf>,

    /// Prefix for rotated file names.
    pub file_prefix: String,

    /// Whether to delete rotated files immediately (testing only).
    pub immediate_cleanup: bool,
}

impl LogRotationConfig {
    /// Create a new rotation config with default values.
    pub fn default_for_production() -> Self {
        Self {
            max_file_size_bytes: 100 * 1024 * 1024, // 100 MB
            schedule: RotationSchedule::Daily,
            max_retained_files: 10,
            compress_rotated: true,
            rotation_directory: None,
            file_prefix: "ferrumgate".to_string(),
            immediate_cleanup: false,
        }
    }

    /// Create a new rotation config optimized for testing.
    pub fn default_for_testing() -> Self {
        Self {
            max_file_size_bytes: 1024 * 1024, // 1 MB
            schedule: RotationSchedule::Minutely,
            max_retained_files: 3,
            compress_rotated: false,
            rotation_directory: None,
            file_prefix: "test".to_string(),
            immediate_cleanup: true,
        }
    }

    /// Get the rotation directory, falling back to the log file's parent.
    pub fn get_rotation_directory(&self, log_file: &Path) -> PathBuf {
        self.rotation_directory
            .clone()
            .unwrap_or_else(|| log_file.parent().unwrap_or(Path::new(".")).to_path_buf())
    }
}

/// Log rotation policy that determines when rotation should occur.
#[derive(Debug, Clone)]
pub struct LogRotationPolicy {
    config: LogRotationConfig,
    last_rotation_time: SystemTime,
    current_file_size: u64,
    rotation_count: u64,
}

impl LogRotationPolicy {
    /// Create a new rotation policy with the given configuration.
    pub fn new(config: LogRotationConfig) -> Self {
        Self {
            config,
            last_rotation_time: SystemTime::now(),
            current_file_size: 0,
            rotation_count: 0,
        }
    }

    /// Check if rotation should occur based on current file size.
    pub fn should_rotate_by_size(&self) -> bool {
        self.current_file_size >= self.config.max_file_size_bytes
    }

    /// Check if rotation should occur based on time schedule.
    pub fn should_rotate_by_time(&self) -> bool {
        let elapsed = SystemTime::now()
            .duration_since(self.last_rotation_time)
            .unwrap_or(Duration::ZERO);

        match self.config.schedule {
            RotationSchedule::Daily => elapsed >= Duration::from_secs(86400),
            RotationSchedule::Hourly => elapsed >= Duration::from_secs(3600),
            RotationSchedule::Minutely => elapsed >= Duration::from_secs(60),
            RotationSchedule::Never => false,
        }
    }

    /// Check if rotation should occur (either size or time based).
    pub fn should_rotate(&self) -> bool {
        self.should_rotate_by_size() || self.should_rotate_by_time()
    }

    /// Record that a rotation has occurred.
    pub fn record_rotation(&mut self) {
        self.last_rotation_time = SystemTime::now();
        self.current_file_size = 0;
        self.rotation_count += 1;
    }

    /// Update the current file size.
    pub fn update_file_size(&mut self, size: u64) {
        self.current_file_size = size;
    }

    /// Get the number of rotations performed.
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count
    }

    /// Get the time of the last rotation.
    pub fn last_rotation_time(&self) -> SystemTime {
        self.last_rotation_time
    }
}

/// Perform log rotation: rename current file, compress, and cleanup old files.
///
/// # Arguments
///
/// * `current_file` - Path to the current active log file
/// * `config` - Rotation configuration
///
/// # Returns
///
/// The path to the newly rotated file, or an error if rotation fails.
pub fn rotate_log_file(
    current_file: &Path,
    config: &LogRotationConfig,
) -> Result<PathBuf, LoggingError> {
    if !current_file.exists() {
        return Err(LoggingError::RotationConfig(
            "current log file does not exist".into(),
        ));
    }

    let rotation_dir = config.get_rotation_directory(current_file);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    // Build the rotated file name
    let rotated_name = if config.compress_rotated {
        format!("{}.{}.{}.gz", config.file_prefix, timestamp, "log")
    } else {
        format!("{}.{}.{}", config.file_prefix, timestamp, "log")
    };

    let rotated_path = rotation_dir.join(&rotated_name);

    // Rename the current file to the rotated name
    fs::rename(current_file, &rotated_path).map_err(|e| {
        LoggingError::RotationConfig(format!("failed to rename log file: {}", e))
    })?;

    // Compress the rotated file if configured
    if config.compress_rotated {
        compress_file(&rotated_path).map_err(|e| {
            LoggingError::RotationConfig(format!("failed to compress rotated file: {}", e))
        })?;
    }

    // Create a new empty log file
    let new_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(current_file)
        .map_err(|e| {
            LoggingError::RotationConfig(format!("failed to create new log file: {}", e))
        })?;

    drop(new_file);

    // Clean up old rotated files
    cleanup_old_rotated_files(&rotation_dir, &config.file_prefix, config.max_retained_files)
        .map_err(|e| {
            LoggingError::RotationConfig(format!("failed to cleanup old files: {}", e))
        })?;

    Ok(rotated_path)
}

/// Compress a file using gzip compression.
///
/// The original file is replaced with a .gz version.
fn compress_file(file_path: &Path) -> io::Result<()> {
    // Read the original file
    let mut input_file = File::open(file_path)?;
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)?;

    // Remove the original file
    fs::remove_file(file_path)?;

    // Create the compressed file
    let compressed_path = file_path.with_extension("log.gz");
    let compressed_file = File::create(&compressed_path)?;
    let mut encoder = GzEncoder::new(compressed_file, Compression::default());
    encoder.write_all(&buffer)?;
    encoder.finish()?;

    Ok(())
}

/// Clean up old rotated files, keeping only the most recent N files.
fn cleanup_old_rotated_files(
    directory: &Path,
    prefix: &str,
    max_files: usize,
) -> io::Result<()> {
    // List all rotated files matching the prefix pattern
    let mut rotated_files: Vec<(PathBuf, SystemTime)> = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with(prefix) && (name.ends_with(".log.gz") || name.ends_with(".log")) {
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        rotated_files.push((path, modified));
                    }
                }
            }
        }
    }

    // Sort by modification time (oldest first)
    rotated_files.sort_by_key(|(_, time)| *time);

    // Delete oldest files if we exceed the limit
    while rotated_files.len() > max_files {
        if let Some((oldest, _)) = rotated_files.first() {
            fs::remove_file(oldest)?;
            rotated_files.remove(0);
        } else {
            break;
        }
    }

    Ok(())
}

/// Check the current size of a log file.
pub fn get_file_size(path: &Path) -> io::Result<u64> {
    fs::metadata(path).map(|m| m.len())
}

/// Check if a log file needs rotation based on size.
pub fn needs_rotation_by_size(path: &Path, max_size_bytes: u64) -> io::Result<bool> {
    let size = get_file_size(path)?;
    Ok(size >= max_size_bytes)
}

/// Get a list of all rotated log files in a directory.
pub fn list_rotated_files(
    directory: &Path,
    prefix: &str,
) -> io::Result<Vec<(PathBuf, SystemTime)>> {
    let mut files = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with(prefix) && (name.ends_with(".log.gz") || name.ends_with(".log")) {
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        files.push((path, modified));
                    }
                }
            }
        }
    }

    // Sort by modification time (newest first)
    files.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(files)
}

/// Decompress a gzip file and return the contents.
pub fn decompress_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut decoder = GzDecoder::new(BufReader::new(file));
    let mut buffer = Vec::new();
    decoder.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Calculate total disk usage of rotated log files.
pub fn calculate_rotated_disk_usage(directory: &Path, prefix: &str) -> io::Result<u64> {
    let files = list_rotated_files(directory, prefix)?;
    let mut total = 0u64;

    for (path, _) in files {
        if let Ok(metadata) = fs::metadata(&path) {
            total += metadata.len();
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_config_production_defaults() {
        let config = LogRotationConfig::default_for_production();
        assert_eq!(config.max_file_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.schedule, RotationSchedule::Daily);
        assert_eq!(config.max_retained_files, 10);
        assert!(config.compress_rotated);
        assert!(!config.immediate_cleanup);
        assert_eq!(config.file_prefix, "ferrumgate");
    }

    #[test]
    fn test_rotation_config_testing_defaults() {
        let config = LogRotationConfig::default_for_testing();
        assert_eq!(config.max_file_size_bytes, 1024 * 1024);
        assert_eq!(config.schedule, RotationSchedule::Minutely);
        assert_eq!(config.max_retained_files, 3);
        assert!(!config.compress_rotated);
        assert!(config.immediate_cleanup);
        assert_eq!(config.file_prefix, "test");
    }

    #[test]
    fn test_rotation_policy_size_based() {
        let config = LogRotationConfig::default_for_production();
        let mut policy = LogRotationPolicy::new(config);

        assert!(!policy.should_rotate_by_size());

        policy.update_file_size(50 * 1024 * 1024);
        assert!(!policy.should_rotate_by_size());

        policy.update_file_size(100 * 1024 * 1024);
        assert!(policy.should_rotate_by_size());

        policy.update_file_size(150 * 1024 * 1024);
        assert!(policy.should_rotate_by_size());
    }

    #[test]
    fn test_rotation_policy_time_based() {
        let config = LogRotationConfig::default_for_testing();
        let policy = LogRotationPolicy::new(config);

        // Should not rotate immediately
        assert!(!policy.should_rotate_by_time());

        // Minutely schedule should trigger after 60 seconds
        // We can't easily test this without mocking time
    }

    #[test]
    fn test_rotation_policy_never_schedule() {
        let mut config = LogRotationConfig::default_for_production();
        config.schedule = RotationSchedule::Never;
        config.max_file_size_bytes = u64::MAX; // Never rotate by size either

        let policy = LogRotationPolicy::new(config);
        assert!(!policy.should_rotate());
    }

    #[test]
    fn test_rotation_policy_record_rotation() {
        let config = LogRotationConfig::default_for_production();
        let mut policy = LogRotationPolicy::new(config);

        assert_eq!(policy.rotation_count(), 0);

        policy.update_file_size(200 * 1024 * 1024);
        policy.record_rotation();

        assert_eq!(policy.rotation_count(), 1);
        assert_eq!(policy.current_file_size, 0);
    }

    #[test]
    fn test_get_file_size() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_rotation_size.tmp");

        // Create a test file
        let mut file = File::create(&test_file).unwrap();
        file.write_all(b"hello world").unwrap();
        drop(file);

        let size = get_file_size(&test_file).unwrap();
        assert_eq!(size, 11);

        // Cleanup
        fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn test_needs_rotation_by_size() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_rotation_check.tmp");

        let mut file = File::create(&test_file).unwrap();
        file.write_all(b"0123456789").unwrap();
        drop(file);

        assert!(!needs_rotation_by_size(&test_file, 100).unwrap());
        assert!(needs_rotation_by_size(&test_file, 5).unwrap());
        assert!(needs_rotation_by_size(&test_file, 10).unwrap());

        fs::remove_file(&test_file).unwrap();
    }

    #[test]
    fn test_rotation_config_get_directory() {
        let config = LogRotationConfig::default_for_production();
        let log_file = Path::new("/var/log/ferrumgate/server.log");

        let dir = config.get_rotation_directory(log_file);
        assert_eq!(dir, Path::new("/var/log/ferrumgate"));
    }

    #[test]
    fn test_rotation_config_custom_directory() {
        let mut config = LogRotationConfig::default_for_production();
        config.rotation_directory = Some(PathBuf::from("/tmp/rotated"));

        let log_file = Path::new("/var/log/ferrumgate/server.log");
        let dir = config.get_rotation_directory(log_file);
        assert_eq!(dir, Path::new("/tmp/rotated"));
    }
}
