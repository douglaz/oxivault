//! Anti-tampering and integrity verification
//!
//! This module provides mechanisms to detect and prevent tampering
//! with the wallet firmware and data.

use crate::{Error, Result};
use core::mem;
use sha2::{Digest, Sha256};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

/// Firmware integrity checker
pub struct IntegrityChecker {
    /// Expected firmware hash
    expected_hash: [u8; 32],
    /// Canary values for stack protection
    canaries: Vec<u32>,
}

impl IntegrityChecker {
    /// Create a new integrity checker
    pub fn new(expected_hash: [u8; 32]) -> Self {
        // Initialize with random-looking canary values
        let canaries = vec![0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE];

        Self {
            expected_hash,
            canaries,
        }
    }

    /// Verify firmware integrity
    pub fn verify_firmware(&self, firmware: &[u8]) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(firmware);
        let hash = hasher.finalize();

        // Use constant-time comparison
        use subtle::ConstantTimeEq;
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);
        let valid: bool = self.expected_hash.ct_eq(&hash_array).into();

        if !valid {
            return Err(Error::InvalidParameter(
                "Firmware integrity check failed".into(),
            ));
        }

        Ok(())
    }

    /// Check stack canaries for buffer overflow detection
    pub fn check_canaries(&self) -> bool {
        self.canaries[0] == 0xDEADBEEF
            && self.canaries[1] == 0xCAFEBABE
            && self.canaries[2] == 0x8BADF00D
            && self.canaries[3] == 0xFEEDFACE
    }

    /// Place canary on stack
    pub fn place_canary(&self) -> StackCanary {
        StackCanary::new()
    }
}

/// Stack canary for detecting buffer overflows
pub struct StackCanary {
    value: u32,
}

impl Default for StackCanary {
    fn default() -> Self {
        Self::new()
    }
}

impl StackCanary {
    /// Create a new stack canary
    pub fn new() -> Self {
        Self { value: 0xDEADC0DE }
    }

    /// Check if canary is intact
    pub fn is_valid(&self) -> bool {
        self.value == 0xDEADC0DE
    }
}

impl Drop for StackCanary {
    fn drop(&mut self) {
        if !self.is_valid() {
            // Canary was corrupted - possible buffer overflow
            // In production, this should trigger a system reset
            #[cfg(feature = "std")]
            panic!("Stack canary corruption detected!");
        }
    }
}

/// Memory region guard for detecting unauthorized access
pub struct MemoryGuard {
    region_start: usize,
    region_end: usize,
    checksum: u32,
}

impl MemoryGuard {
    /// Create a guard for a memory region
    pub fn new(data: &[u8]) -> Self {
        let region_start = data.as_ptr() as usize;
        let region_end = region_start + data.len();
        let checksum = Self::calculate_checksum(data);

        Self {
            region_start,
            region_end,
            checksum,
        }
    }

    /// Calculate checksum for data
    fn calculate_checksum(data: &[u8]) -> u32 {
        data.iter()
            .fold(0u32, |acc, &b| acc.wrapping_add(b as u32).rotate_left(1))
    }

    /// Verify the guarded memory region
    pub fn verify(&self, data: &[u8]) -> bool {
        let current_start = data.as_ptr() as usize;
        let current_end = current_start + data.len();

        // Check if memory region matches
        if current_start != self.region_start || current_end != self.region_end {
            return false;
        }

        // Verify checksum
        Self::calculate_checksum(data) == self.checksum
    }
}

/// Anti-debugging detection
pub struct AntiDebug;

impl AntiDebug {
    /// Check for debugger presence (platform-specific)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn is_debugger_present() -> bool {
        use std::fs;

        // Check /proc/self/status for TracerPid
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split_whitespace().nth(1) {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            return pid != 0;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check for debugger presence (fallback for other platforms)
    #[cfg(not(all(feature = "std", target_os = "linux")))]
    pub fn is_debugger_present() -> bool {
        // Platform doesn't support debugger detection
        false
    }

    /// Timing-based debugger detection
    pub fn timing_check() -> bool {
        use sha2::{Digest, Sha256};

        // Measure time for a known operation
        let start = Self::get_timestamp();

        // Perform a known operation
        let mut hasher = Sha256::new();
        for i in 0..1000 {
            hasher.update([i as u8]);
        }
        let _ = hasher.finalize();

        let elapsed = Self::get_timestamp().wrapping_sub(start);

        // If execution is too slow, might be debugging
        // This threshold needs calibration for the target platform
        elapsed > 1000000 // nanoseconds
    }

    #[cfg(feature = "std")]
    fn get_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[cfg(not(feature = "std"))]
    fn get_timestamp() -> u64 {
        // In embedded, would use hardware timer
        0
    }
}

/// Function pointer validation to prevent ROP attacks
pub struct FunctionValidator {
    valid_functions: Vec<usize>,
}

impl Default for FunctionValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionValidator {
    /// Create a new function validator
    pub fn new() -> Self {
        Self {
            valid_functions: Vec::new(),
        }
    }

    /// Register a valid function pointer
    pub fn register_function<T>(&mut self, func: fn() -> T) {
        let addr = func as *const () as usize;
        self.valid_functions.push(addr);
    }

    /// Validate a function pointer
    pub fn is_valid_function<T>(&self, func: fn() -> T) -> bool {
        let addr = func as *const () as usize;
        self.valid_functions.contains(&addr)
    }
}

/// Runtime assertion with anti-tampering
pub fn secure_assert(condition: bool, message: &str) -> Result<()> {
    if !condition {
        // Clear sensitive data before panicking
        unsafe {
            // In production, would clear all sensitive memory regions
            core::ptr::write_volatile(&mut mem::zeroed::<[u8; 1024]>(), mem::zeroed());
        }

        return Err(Error::InvalidParameter(message.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_checker() {
        let firmware = b"fake_firmware_data";

        let mut hasher = Sha256::new();
        hasher.update(firmware);
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

        let checker = IntegrityChecker::new(hash);
        assert!(checker.verify_firmware(firmware).is_ok());

        let tampered = b"tampered_firmware";
        assert!(checker.verify_firmware(tampered).is_err());
    }

    #[test]
    fn test_stack_canary() {
        let canary = StackCanary::new();
        assert!(canary.is_valid());
        // Drop will check canary automatically
    }

    #[test]
    fn test_memory_guard() {
        let data = vec![1, 2, 3, 4, 5];
        let guard = MemoryGuard::new(&data);

        assert!(guard.verify(&data));

        let different_data = vec![1, 2, 3, 4, 6];
        assert!(!guard.verify(&different_data));
    }

    #[test]
    fn test_function_validator() {
        fn test_func1() -> i32 {
            42
        }
        fn test_func2() -> i32 {
            99
        }

        let mut validator = FunctionValidator::new();
        validator.register_function(test_func1);

        assert!(validator.is_valid_function(test_func1));
        assert!(!validator.is_valid_function(test_func2));
    }

    #[test]
    fn test_secure_assert() {
        assert!(secure_assert(true, "Should pass").is_ok());
        assert!(secure_assert(false, "Should fail").is_err());
    }
}
