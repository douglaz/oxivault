//! Secure random number generation for OxiVault
//!
//! Provides cryptographically secure random number generation with
//! support for both std and no_std environments.

use crate::Result;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Trait for random number generation
pub trait RandomSource {
    /// Generate random bytes
    fn random_bytes(&mut self, dest: &mut [u8]) -> Result<()>;

    /// Generate a random u32
    fn random_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.random_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Generate a random byte
    fn random_u8(&mut self) -> Result<u8> {
        let mut byte = [0u8; 1];
        self.random_bytes(&mut byte)?;
        Ok(byte[0])
    }
}

#[cfg(feature = "std")]
/// Secure RNG using OS entropy (std environments)
pub struct SecureRng {
    rng: rand::rngs::OsRng,
}

#[cfg(feature = "std")]
impl SecureRng {
    /// Create a new secure RNG
    pub fn new() -> Self {
        use rand::rngs::OsRng;
        Self { rng: OsRng }
    }
}

#[cfg(feature = "std")]
impl RandomSource for SecureRng {
    fn random_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        use rand::RngCore;
        self.rng.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
/// Hardware RNG for embedded environments
pub struct HardwareRng {
    // In embedded, this would interface with hardware TRNG
    // For now, we'll require injection from the hardware layer
    entropy_source: fn(&mut [u8]) -> Result<()>,
}

#[cfg(not(feature = "std"))]
impl HardwareRng {
    /// Create a new hardware RNG with the given entropy source
    pub fn new(entropy_source: fn(&mut [u8]) -> Result<()>) -> Self {
        Self { entropy_source }
    }
}

#[cfg(not(feature = "std"))]
impl RandomSource for HardwareRng {
    fn random_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        (self.entropy_source)(dest)
    }
}

/// Entropy mixer for combining multiple entropy sources
pub struct EntropyMixer {
    pool: Vec<u8>,
    pool_pos: usize,
}

impl EntropyMixer {
    /// Create a new entropy mixer
    pub fn new() -> Self {
        Self {
            pool: Vec::with_capacity(64),
            pool_pos: 0,
        }
    }

    /// Add entropy to the pool
    pub fn add_entropy(&mut self, data: &[u8]) {
        use sha2::{Digest, Sha256};

        // Mix new entropy with existing pool using SHA256
        let mut hasher = Sha256::new();
        hasher.update(&self.pool);
        hasher.update(data);
        let mixed = hasher.finalize();

        // Replace pool with mixed entropy
        self.pool.clear();
        self.pool.extend_from_slice(&mixed);
        self.pool_pos = 0;
    }

    /// Extract random bytes from the pool
    pub fn extract_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        use sha2::{Digest, Sha256};

        if self.pool.is_empty() {
            return Err(crate::Error::InsufficientEntropy);
        }

        for byte in dest.iter_mut() {
            if self.pool_pos >= self.pool.len() {
                // Regenerate pool using hash of current pool
                let mut hasher = Sha256::new();
                hasher.update(&self.pool);
                hasher.update(b"regenerate");
                let new_pool = hasher.finalize();
                self.pool.clear();
                self.pool.extend_from_slice(&new_pool);
                self.pool_pos = 0;
            }

            *byte = self.pool[self.pool_pos];
            self.pool_pos += 1;
        }

        Ok(())
    }

    /// Combine hardware RNG with user entropy
    pub fn mix_sources<R: RandomSource>(
        &mut self,
        rng: &mut R,
        user_entropy: Option<&[u8]>,
    ) -> Result<()> {
        // Get hardware randomness
        let mut hw_entropy = [0u8; 32];
        rng.random_bytes(&mut hw_entropy)?;
        self.add_entropy(&hw_entropy);

        // Mix in user entropy if provided
        if let Some(user_data) = user_entropy {
            self.add_entropy(user_data);
        }

        // Add timestamp or counter for additional uniqueness
        #[cfg(feature = "std")]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let timestamp = duration.as_nanos() as u64;
                self.add_entropy(&timestamp.to_le_bytes());
            }
        }

        Ok(())
    }
}

impl RandomSource for EntropyMixer {
    fn random_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        self.extract_bytes(dest)
    }
}

/// Global RNG instance for convenience (std only)
#[cfg(feature = "std")]
pub fn random_bytes(dest: &mut [u8]) -> Result<()> {
    let mut rng = SecureRng::new();
    rng.random_bytes(dest)
}

/// Generate a random 32-byte seed (std only)
#[cfg(feature = "std")]
pub fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    random_bytes(&mut seed)?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rng() -> Result<()> {
        #[cfg(feature = "std")]
        {
            let mut rng = SecureRng::new();

            // Test byte generation
            let mut bytes1 = [0u8; 32];
            let mut bytes2 = [0u8; 32];
            rng.random_bytes(&mut bytes1)?;
            rng.random_bytes(&mut bytes2)?;

            // Should generate different values
            assert_ne!(bytes1, bytes2);

            // Should not be all zeros
            assert_ne!(bytes1, [0u8; 32]);

            // Test u32 generation
            let val1 = rng.random_u32()?;
            let val2 = rng.random_u32()?;
            assert_ne!(val1, val2);
        }

        Ok(())
    }

    #[test]
    fn test_entropy_mixer() -> Result<()> {
        let mut mixer = EntropyMixer::new();

        // Add some entropy
        mixer.add_entropy(b"test entropy 1");
        mixer.add_entropy(b"test entropy 2");

        // Extract bytes
        let mut bytes = [0u8; 64];
        mixer.extract_bytes(&mut bytes)?;

        // Should not be zeros
        assert_ne!(bytes, [0u8; 64]);

        // Extract more bytes (should regenerate pool)
        let mut more_bytes = [0u8; 64];
        mixer.extract_bytes(&mut more_bytes)?;

        // Should be different from first extraction
        assert_ne!(bytes, more_bytes);

        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_mixed_sources() -> Result<()> {
        let mut mixer = EntropyMixer::new();
        let mut rng = SecureRng::new();

        // Mix hardware and user entropy
        mixer.mix_sources(&mut rng, Some(b"user provided entropy"))?;

        // Should be able to extract bytes
        let mut output = [0u8; 32];
        mixer.random_bytes(&mut output)?;
        assert_ne!(output, [0u8; 32]);

        Ok(())
    }
}
