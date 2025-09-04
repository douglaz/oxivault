//! Timing attack resistance and constant-time operations
//!
//! This module provides functions that execute in constant time
//! to prevent timing-based side-channel attacks.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Constant-time comparison of two byte slices
pub fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time byte selection based on a condition
pub fn ct_select_bytes(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    let mut result = Vec::with_capacity(a.len());
    let choice = Choice::from(condition as u8);

    for i in 0..a.len() {
        let selected = u8::conditional_select(&b[i], &a[i], choice);
        result.push(selected);
    }

    result
}

/// Constant-time u32 selection
pub fn ct_select_u32(condition: bool, a: u32, b: u32) -> u32 {
    let choice = Choice::from(condition as u8);
    u32::conditional_select(&b, &a, choice)
}

/// Constant-time array copy with selection
pub fn ct_copy_32(condition: bool, src: &[u8; 32], dst: &mut [u8; 32]) {
    let choice = Choice::from(condition as u8);
    for i in 0..32 {
        dst[i] = u8::conditional_select(&dst[i], &src[i], choice);
    }
}

/// Constant-time PIN/password verification with timing attack resistance
pub struct ConstantTimeVerifier {
    expected_hash: [u8; 32],
}

impl ConstantTimeVerifier {
    /// Create a new verifier with the expected hash
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self { expected_hash }
    }

    /// Verify a PIN/password hash in constant time
    pub fn verify(&self, provided_hash: &[u8; 32]) -> bool {
        self.expected_hash.ct_eq(provided_hash).into()
    }

    /// Verify with additional dummy operations to mask timing
    pub fn verify_with_dummy_ops(&self, provided_hash: &[u8; 32]) -> bool {
        use sha2::{Digest, Sha256};

        // Perform dummy operations regardless of result
        let mut dummy = Sha256::new();
        dummy.update(provided_hash);
        let _dummy_result = dummy.finalize();

        // Constant-time comparison
        let result = self.expected_hash.ct_eq(provided_hash);

        // More dummy operations
        let mut dummy2 = Sha256::new();
        dummy2.update(&self.expected_hash);
        let _dummy_result2 = dummy2.finalize();

        result.into()
    }
}

/// Constant-time modular exponentiation for RSA-like operations
pub fn ct_mod_exp(base: u32, exp: u32, modulus: u32) -> u32 {
    if modulus == 1 {
        return 0;
    }

    let mut result = 1u64;
    let mut base = base as u64;
    let mut exp = exp;
    let modulus = modulus as u64;

    base %= modulus;

    // Always perform the same number of iterations
    for _ in 0..32 {
        let bit = exp & 1;
        let temp = (result * base) % modulus;
        result = u64::conditional_select(&result, &temp, Choice::from(bit as u8));

        base = (base * base) % modulus;
        exp >>= 1;
    }

    result as u32
}

/// Dummy operations to add noise to timing measurements
pub fn add_timing_noise() {
    use sha2::{Digest, Sha256};

    // Perform some dummy crypto operations
    let mut hasher = Sha256::new();
    hasher.update(b"timing noise");
    let _ = hasher.finalize();

    // Some dummy arithmetic
    let mut acc = 1u32;
    for i in 1..10 {
        acc = acc.wrapping_mul(i);
    }

    // Prevent optimization
    core::hint::black_box(acc);
}

/// Constant-time memory comparison with early exit protection
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still perform dummy operations
        add_timing_noise();
        return false;
    }

    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }

    // Add noise
    add_timing_noise();

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_compare() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(ct_compare(&a, &b));
        assert!(!ct_compare(&a, &c));
        assert!(!ct_compare(&a[..3], &b));
    }

    #[test]
    fn test_ct_select_bytes() {
        let a = vec![1u8, 2, 3];
        let b = vec![4u8, 5, 6];

        let result_true = ct_select_bytes(true, &a, &b);
        assert_eq!(result_true, a);

        let result_false = ct_select_bytes(false, &a, &b);
        assert_eq!(result_false, b);
    }

    #[test]
    fn test_ct_select_u32() {
        assert_eq!(ct_select_u32(true, 42, 99), 42);
        assert_eq!(ct_select_u32(false, 42, 99), 99);
    }

    #[test]
    fn test_constant_time_verifier() {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"correct_password");
        let correct_hash = hasher.finalize().into();

        let verifier = ConstantTimeVerifier::new(correct_hash);

        // Test correct password
        assert!(verifier.verify(&correct_hash));

        // Test incorrect password
        let mut hasher = Sha256::new();
        hasher.update(b"wrong_password");
        let wrong_hash = hasher.finalize().into();
        assert!(!verifier.verify(&wrong_hash));

        // Test with dummy ops
        assert!(verifier.verify_with_dummy_ops(&correct_hash));
        assert!(!verifier.verify_with_dummy_ops(&wrong_hash));
    }

    #[test]
    fn test_ct_mod_exp() {
        // 2^3 mod 5 = 8 mod 5 = 3
        assert_eq!(ct_mod_exp(2, 3, 5), 3);

        // 3^4 mod 7 = 81 mod 7 = 4
        assert_eq!(ct_mod_exp(3, 4, 7), 4);
    }

    #[test]
    fn test_secure_compare() {
        let a = b"secret_key";
        let b = b"secret_key";
        let c = b"wrong_key!";

        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
        assert!(!secure_compare(&a[..5], b));
    }
}
