//! Secure memory handling for sensitive data
//!
//! This module provides types that ensure sensitive data is properly
//! zeroed when dropped, preventing secrets from lingering in memory.

use core::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// A secure container for sensitive byte arrays that zeros memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes {
    #[zeroize(skip)]
    len: usize,
    data: Vec<u8>,
}

impl SecureBytes {
    /// Create a new SecureBytes from a slice
    pub fn new(data: &[u8]) -> Self {
        Self {
            len: data.len(),
            data: data.to_vec(),
        }
    }

    /// Create a new SecureBytes with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            len: 0,
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get a reference to the data
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get a mutable reference to the data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Extend from a slice
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other);
        self.len += other.len();
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/// A secure string that zeros memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    /// Create a new SecureString
    pub fn new(s: &str) -> Self {
        Self {
            inner: s.to_string(),
        }
    }

    /// Create an empty SecureString
    pub fn empty() -> Self {
        Self {
            inner: String::new(),
        }
    }

    /// Get string slice
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Push a string slice
    pub fn push_str(&mut self, s: &str) {
        self.inner.push_str(s);
    }

    /// Clear the string
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl Deref for SecureString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

/// A secure 32-byte seed that zeros memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureSeed {
    seed: [u8; 32],
}

impl SecureSeed {
    /// Create a new SecureSeed
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Create a SecureSeed from a slice
    pub fn from_slice(data: &[u8]) -> crate::Result<Self> {
        if data.len() != 32 {
            return Err(crate::Error::InvalidParameter(
                "Seed must be 32 bytes".into(),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(data);
        Ok(Self { seed })
    }

    /// Get the seed bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.seed
    }

    /// Get a mutable reference to the seed
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.seed
    }
}

impl AsRef<[u8]> for SecureSeed {
    fn as_ref(&self) -> &[u8] {
        &self.seed
    }
}

impl AsRef<[u8; 32]> for SecureSeed {
    fn as_ref(&self) -> &[u8; 32] {
        &self.seed
    }
}

/// A secure private key that zeros memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    key: [u8; 32],
}

impl SecureKey {
    /// Create a new SecureKey
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Create from slice
    pub fn from_slice(data: &[u8]) -> crate::Result<Self> {
        if data.len() != 32 {
            return Err(crate::Error::InvalidParameter(
                "Key must be 32 bytes".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(data);
        Ok(Self { key })
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Constant-time comparison
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.key.ct_eq(&other.key).into()
    }
}

/// A secure mnemonic phrase that zeros memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureMnemonic {
    phrase: String,
}

impl SecureMnemonic {
    /// Create a new SecureMnemonic
    pub fn new(phrase: &str) -> Self {
        Self {
            phrase: phrase.to_string(),
        }
    }

    /// Get the phrase
    pub fn as_str(&self) -> &str {
        &self.phrase
    }

    /// Get word count
    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }

    /// Validate the mnemonic has correct word count
    pub fn validate_word_count(&self) -> bool {
        let count = self.word_count();
        matches!(count, 12 | 15 | 18 | 21 | 24)
    }
}

impl AsRef<str> for SecureMnemonic {
    fn as_ref(&self) -> &str {
        &self.phrase
    }
}

/// Memory locking support for sensitive data (platform-specific)
#[cfg(all(feature = "std", target_family = "unix"))]
pub mod mlock {
    use std::io;

    /// Lock memory pages to prevent swapping
    pub fn lock_memory(addr: *const u8, len: usize) -> io::Result<()> {
        unsafe {
            let result = libc::mlock(addr as *const libc::c_void, len);
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    /// Unlock memory pages
    pub fn unlock_memory(addr: *const u8, len: usize) -> io::Result<()> {
        unsafe {
            let result = libc::munlock(addr as *const libc::c_void, len);
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes() {
        let data = b"secret data";
        let mut secure = SecureBytes::new(data);
        assert_eq!(secure.as_slice(), data);

        secure.extend_from_slice(b" more");
        assert_eq!(secure.as_slice(), b"secret data more");
    }

    #[test]
    fn test_secure_string() {
        let mut secure = SecureString::new("secret");
        assert_eq!(secure.as_str(), "secret");

        secure.push_str(" data");
        assert_eq!(secure.as_str(), "secret data");

        secure.clear();
        assert_eq!(secure.as_str(), "");
    }

    #[test]
    fn test_secure_seed() {
        let seed_data = [42u8; 32];
        let secure = SecureSeed::new(seed_data);
        assert_eq!(secure.as_bytes(), seed_data);
    }

    #[test]
    fn test_secure_key() {
        let key1 = SecureKey::new([1u8; 32]);
        let key2 = SecureKey::new([1u8; 32]);
        let key3 = SecureKey::new([2u8; 32]);

        assert!(key1.ct_eq(&key2));
        assert!(!key1.ct_eq(&key3));
    }

    #[test]
    fn test_secure_mnemonic() {
        let mnemonic = SecureMnemonic::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        assert_eq!(mnemonic.word_count(), 12);
        assert!(mnemonic.validate_word_count());

        let invalid = SecureMnemonic::new("word1 word2 word3");
        assert!(!invalid.validate_word_count());
    }
}
