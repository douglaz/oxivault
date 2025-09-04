//! PIN Protection Module
//! 
//! Provides secure PIN/password protection with:
//! - Attempt counting and lockout
//! - Secure PIN storage
//! - Time-based lockout
//! - Anti-bruteforce measures

use crate::{Result, Error};
use zeroize::Zeroize;
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format};

/// PIN manager for device protection
pub struct PinManager {
    /// Hashed PIN (never store plaintext)
    pin_hash: [u8; 32],
    /// Salt for PIN hashing
    salt: [u8; 32],
    /// Failed attempt counter
    failed_attempts: u32,
    /// Maximum allowed attempts
    max_attempts: u32,
    /// Lockout duration in seconds
    lockout_duration: u64,
    /// Timestamp of last failed attempt
    last_failed_timestamp: Option<u64>,
    /// Device locked flag
    is_locked: bool,
}

impl PinManager {
    /// Create new PIN manager
    pub fn new(max_attempts: u32, lockout_duration: u64) -> Self {
        Self {
            pin_hash: [0; 32],
            salt: [0; 32],
            failed_attempts: 0,
            max_attempts,
            lockout_duration,
            last_failed_timestamp: None,
            is_locked: false,
        }
    }

    /// Initialize with a new PIN
    pub fn set_pin(&mut self, pin: &str, entropy: &[u8]) -> Result<()> {
        if pin.len() < 4 {
            return Err(Error::InvalidParameter("PIN too short".to_string()));
        }
        
        if pin.len() > 32 {
            return Err(Error::InvalidParameter("PIN too long".to_string()));
        }
        
        // Generate salt from entropy
        let mut salt_engine = sha256::HashEngine::default();
        salt_engine.input(entropy);
        salt_engine.input(b"oxivault-pin-salt");
        let salt_hash = sha256::Hash::from_engine(salt_engine);
        self.salt.copy_from_slice(&salt_hash[..]);
        
        // Hash PIN with salt
        self.pin_hash = Self::hash_pin(pin, &self.salt);
        
        // Reset counters
        self.failed_attempts = 0;
        self.is_locked = false;
        self.last_failed_timestamp = None;
        
        Ok(())
    }

    /// Verify PIN
    pub fn verify_pin(&mut self, pin: &str, current_time: u64) -> Result<bool> {
        // Check if locked
        if self.is_locked {
            if let Some(last_failed) = self.last_failed_timestamp {
                let elapsed = current_time.saturating_sub(last_failed);
                if elapsed < self.lockout_duration {
                    return Err(Error::InvalidParameter(
                        format!("Device locked. Wait {} seconds", self.lockout_duration - elapsed)
                    ));
                } else {
                    // Unlock after timeout
                    self.is_locked = false;
                    self.failed_attempts = 0;
                }
            }
        }
        
        // Hash provided PIN
        let provided_hash = Self::hash_pin(pin, &self.salt);
        
        // Constant-time comparison
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.pin_hash[i] ^ provided_hash[i];
        }
        
        if diff == 0 {
            // Success - reset counter
            self.failed_attempts = 0;
            self.last_failed_timestamp = None;
            Ok(true)
        } else {
            // Failed attempt
            self.failed_attempts += 1;
            self.last_failed_timestamp = Some(current_time);
            
            if self.failed_attempts >= self.max_attempts {
                self.is_locked = true;
                Err(Error::InvalidParameter(
                    format!("Too many attempts. Device locked for {} seconds", self.lockout_duration)
                ))
            } else {
                Ok(false)
            }
        }
    }

    /// Hash PIN with salt
    fn hash_pin(pin: &str, salt: &[u8]) -> [u8; 32] {
        let mut engine = HmacEngine::<sha256::Hash>::new(salt);
        engine.input(pin.as_bytes());
        engine.input(b"oxivault-pin-v1");
        
        // Additional iterations for slowdown
        let mut hash = Hmac::<sha256::Hash>::from_engine(engine).to_byte_array();
        for _ in 0..1000 {
            let mut engine = HmacEngine::<sha256::Hash>::new(salt);
            engine.input(&hash);
            hash = Hmac::<sha256::Hash>::from_engine(engine).to_byte_array();
        }
        
        hash
    }

    /// Get remaining attempts
    pub fn remaining_attempts(&self) -> u32 {
        self.max_attempts.saturating_sub(self.failed_attempts)
    }

    /// Check if device is locked
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Get lockout status
    pub fn lockout_status(&self, current_time: u64) -> LockoutStatus {
        if !self.is_locked {
            return LockoutStatus::Unlocked;
        }
        
        if let Some(last_failed) = self.last_failed_timestamp {
            let elapsed = current_time.saturating_sub(last_failed);
            if elapsed < self.lockout_duration {
                LockoutStatus::Locked {
                    remaining_seconds: self.lockout_duration - elapsed,
                }
            } else {
                LockoutStatus::Unlocked
            }
        } else {
            LockoutStatus::Unlocked
        }
    }

    /// Change PIN (requires old PIN verification)
    pub fn change_pin(&mut self, old_pin: &str, new_pin: &str, current_time: u64, entropy: &[u8]) -> Result<()> {
        // Verify old PIN first
        if !self.verify_pin(old_pin, current_time)? {
            return Err(Error::InvalidParameter("Invalid old PIN".to_string()));
        }
        
        // Set new PIN
        self.set_pin(new_pin, entropy)
    }
}

/// Lockout status
#[derive(Debug, Clone, PartialEq)]
pub enum LockoutStatus {
    /// Device is unlocked
    Unlocked,
    /// Device is locked
    Locked {
        /// Remaining lockout time in seconds
        remaining_seconds: u64,
    },
}

/// Secure PIN entry buffer
pub struct SecurePinEntry {
    /// PIN buffer (will be zeroized on drop)
    buffer: Vec<u8>,
    /// Maximum PIN length
    max_length: usize,
}

impl SecurePinEntry {
    /// Create new secure PIN entry
    pub fn new(max_length: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(max_length),
            max_length,
        }
    }

    /// Add digit to PIN
    pub fn add_digit(&mut self, digit: u8) -> Result<()> {
        if digit > 9 {
            return Err(Error::InvalidParameter("Invalid digit".to_string()));
        }
        
        if self.buffer.len() >= self.max_length {
            return Err(Error::InvalidParameter("PIN too long".to_string()));
        }
        
        self.buffer.push(b'0' + digit);
        Ok(())
    }

    /// Remove last digit
    pub fn backspace(&mut self) {
        self.buffer.pop();
    }

    /// Clear PIN
    pub fn clear(&mut self) {
        self.buffer.zeroize();
        self.buffer.clear();
    }

    /// Get PIN as string (temporary - will be zeroized)
    pub fn as_str(&self) -> &str {
        // Safe because we only add ASCII digits
        unsafe { core::str::from_utf8_unchecked(&self.buffer) }
    }

    /// Get masked display (*****)
    pub fn masked_display(&self) -> String {
        "*".repeat(self.buffer.len())
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Drop for SecurePinEntry {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl Zeroize for SecurePinEntry {
    fn zeroize(&mut self) {
        self.buffer.zeroize();
    }
}

/// Anti-bruteforce delay calculator
pub struct AntibruteforceDelay {
    /// Base delay in milliseconds
    base_delay_ms: u64,
    /// Exponential factor
    exponential_factor: f32,
}

impl AntibruteforceDelay {
    /// Create new delay calculator
    pub fn new(base_delay_ms: u64, exponential_factor: f32) -> Self {
        Self {
            base_delay_ms,
            exponential_factor,
        }
    }

    /// Calculate delay for given attempt number
    pub fn calculate_delay(&self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }
        
        // Exponential backoff with cap
        // Manual power calculation for no_std compatibility
        let mut factor = 1.0_f32;
        for _ in 0..attempt {
            factor *= self.exponential_factor;
        }
        let delay = self.base_delay_ms * (factor as u64);
        delay.min(60_000) // Cap at 60 seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_manager() {
        let mut manager = PinManager::new(3, 300);
        let entropy = [0x42; 32];
        
        // Set PIN
        manager.set_pin("1234", &entropy).unwrap();
        
        // Verify correct PIN
        assert!(manager.verify_pin("1234", 1000).unwrap());
        
        // Verify wrong PIN
        assert!(!manager.verify_pin("5678", 2000).unwrap());
        assert_eq!(manager.remaining_attempts(), 2);
        
        // More wrong attempts
        assert!(!manager.verify_pin("9999", 3000).unwrap());
        assert_eq!(manager.remaining_attempts(), 1);
        
        // Last wrong attempt - should lock
        let result = manager.verify_pin("0000", 4000);
        assert!(result.is_err());
        assert!(manager.is_locked());
        
        // Try while locked
        let result = manager.verify_pin("1234", 4100);
        assert!(result.is_err());
        
        // Try after lockout expired
        assert!(manager.verify_pin("1234", 4301).unwrap());
        assert!(!manager.is_locked());
    }

    #[test]
    fn test_secure_pin_entry() {
        let mut entry = SecurePinEntry::new(6);
        
        // Add digits
        entry.add_digit(1).unwrap();
        entry.add_digit(2).unwrap();
        entry.add_digit(3).unwrap();
        entry.add_digit(4).unwrap();
        
        assert_eq!(entry.as_str(), "1234");
        assert_eq!(entry.masked_display(), "****");
        assert_eq!(entry.len(), 4);
        
        // Backspace
        entry.backspace();
        assert_eq!(entry.as_str(), "123");
        
        // Clear
        entry.clear();
        assert!(entry.is_empty());
    }

    #[test]
    fn test_antibruteforce_delay() {
        let delay_calc = AntibruteforceDelay::new(100, 2.0);
        
        assert_eq!(delay_calc.calculate_delay(0), 0);
        assert_eq!(delay_calc.calculate_delay(1), 200);
        assert_eq!(delay_calc.calculate_delay(2), 400);
        assert_eq!(delay_calc.calculate_delay(3), 800);
        assert_eq!(delay_calc.calculate_delay(4), 1600);
    }

    #[test]
    fn test_pin_change() {
        let mut manager = PinManager::new(3, 300);
        let entropy = [0x42; 32];
        
        // Set initial PIN
        manager.set_pin("1234", &entropy).unwrap();
        
        // Change with wrong old PIN
        let result = manager.change_pin("5678", "9999", 1000, &entropy);
        assert!(result.is_err());
        
        // Change with correct old PIN
        manager.change_pin("1234", "5678", 2000, &entropy).unwrap();
        
        // Verify new PIN
        assert!(manager.verify_pin("5678", 3000).unwrap());
        assert!(!manager.verify_pin("1234", 4000).unwrap());
    }
}