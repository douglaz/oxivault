//! BIP-39 Mnemonic generation and management

use crate::{Error, Result};
use bip39::{Language, Mnemonic};
use sha2::{Sha256, Digest};

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::String, format};

/// Mnemonic phrase manager
pub struct MnemonicManager {
    mnemonic: Mnemonic,
}

impl MnemonicManager {
    /// Generate a new mnemonic from entropy
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        // Validate entropy length (128, 160, 192, 224, or 256 bits)
        match entropy.len() {
            16 | 20 | 24 | 28 | 32 => {},
            _ => return Err(Error::InvalidEntropy(
                format!("Invalid entropy length: {} bytes (need 16, 20, 24, 28, or 32)", entropy.len())
            )),
        }

        let mnemonic = Mnemonic::from_entropy(entropy)
            .map_err(|_| Error::InvalidMnemonic)?;
        
        Ok(Self { mnemonic })
    }

    /// Create from existing mnemonic phrase (requires std)
    #[cfg(feature = "std")]
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| Error::InvalidMnemonic)?;
        
        Ok(Self { mnemonic })
    }

    /// Generate a new random mnemonic (requires std feature for RNG)
    #[cfg(feature = "std")]
    pub fn generate(word_count: usize) -> Result<Self> {
        use rand::RngCore;
        
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(Error::InvalidMnemonic),
        };

        let mut entropy = vec![0u8; entropy_bytes];
        rand::thread_rng().fill_bytes(&mut entropy);
        
        Self::from_entropy(&entropy)
    }
    
    /// Generate a new random mnemonic using no_std compatible RNG
    /// Requires an entropy source to be provided
    #[cfg(not(feature = "std"))]
    pub fn generate_with_rng<R: crate::rng::RandomSource>(
        word_count: usize,
        rng: &mut R,
    ) -> Result<Self> {
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(Error::InvalidMnemonic),
        };
        
        let mut entropy = [0u8; 32]; // Max size needed
        rng.random_bytes(&mut entropy[..entropy_bytes])?;
        
        Self::from_entropy(&entropy[..entropy_bytes])
    }

    /// Get the mnemonic phrase as a string (requires std)
    #[cfg(feature = "std")]
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Get individual words (requires std)
    #[cfg(feature = "std")]
    pub fn words(&self) -> Vec<&'static str> {
        self.mnemonic.words().collect()
    }

    /// Generate seed bytes from mnemonic with optional passphrase (requires std)
    #[cfg(feature = "std")]
    pub fn to_seed_bytes(&self, passphrase: &str) -> [u8; 64] {
        self.mnemonic.to_seed(passphrase)
    }

    /// Validate a mnemonic phrase (requires std)
    #[cfg(feature = "std")]
    pub fn validate(phrase: &str) -> bool {
        Mnemonic::parse_in(Language::English, phrase).is_ok()
    }

    /// Generate entropy using double SHA256 (similar to Krux/Tapsigner)
    pub fn generate_entropy_from_bytes(input: &[u8]) -> [u8; 32] {
        let hash1 = Sha256::digest(input);
        let hash2 = Sha256::digest(&hash1);
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&hash2);
        entropy
    }
    
    /// Generate mnemonic from user-provided entropy (no_std compatible)
    #[cfg(not(feature = "std"))]
    pub fn generate_from_user_entropy(
        word_count: usize,
        user_entropy: &[u8],
    ) -> Result<Self> {
        use crate::rng::EntropyMixer;
        
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(Error::InvalidMnemonic),
        };
        
        // Mix user entropy using SHA256
        let mixed_entropy = Self::generate_entropy_from_bytes(user_entropy);
        
        // Use only the required number of bytes
        Self::from_entropy(&mixed_entropy[..entropy_bytes])
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let manager = MnemonicManager::from_phrase(phrase).unwrap();
        assert_eq!(manager.phrase(), phrase);
    }

    #[test]
    fn test_validate_mnemonic() {
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(MnemonicManager::validate(valid));
        
        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(!MnemonicManager::validate(invalid));
    }

    #[test]
    fn test_entropy_generation() {
        let input = b"test input for entropy generation";
        let entropy = MnemonicManager::generate_entropy_from_bytes(input);
        assert_eq!(entropy.len(), 32);
    }
}

#[cfg(all(test, not(feature = "std")))]
mod no_std_tests {
    use super::*;
    
    #[test]
    fn test_no_std_mnemonic_generation() {
        // Test generating mnemonic from user entropy
        let user_entropy = b"some random user input for entropy";
        let result = MnemonicManager::generate_from_user_entropy(12, user_entropy);
        assert!(result.is_ok());
        
        // Test with hardware RNG mock
        fn mock_entropy(dest: &mut [u8]) -> Result<()> {
            // In real hardware, this would read from TRNG
            for (i, byte) in dest.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(17).wrapping_add(42);
            }
            Ok(())
        }
        
        let mut rng = crate::rng::HardwareRng::new(mock_entropy);
        let result = MnemonicManager::generate_with_rng(24, &mut rng);
        assert!(result.is_ok());
    }
}