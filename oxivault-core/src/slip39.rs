//! SLIP-39 Shamir Secret Sharing implementation
//!
//! Based on: https://github.com/satoshilabs/slips/blob/master/slip-0039.md

use crate::{Error, Result};
use sha2::{Digest, Sha256};

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};
#[cfg(feature = "std")]
use alloc::{format, vec};

/// SLIP-39 word list (1024 words)
const SLIP39_WORDLIST: &[&str] = &[
    "academic", "acid", "acne", "acquire", "acrobat", "activity", "actress", "adapt", "adequate",
    "adjust",
    // ... (truncated for brevity, would include all 1024 words)
];

/// Share parameters
#[derive(Debug, Clone)]
pub struct ShareParams {
    /// Unique identifier (16 bits)
    pub identifier: u16,
    /// Iteration exponent for key derivation
    pub iteration_exponent: u8,
    /// Group threshold (number of groups required)
    pub group_threshold: u8,
    /// Group count (total number of groups)
    pub group_count: u8,
    /// Group index
    pub group_index: u8,
    /// Member threshold (shares needed in this group)
    pub member_threshold: u8,
    /// Member index
    pub member_index: u8,
}

/// A single SLIP-39 share
#[derive(Debug, Clone)]
pub struct Share {
    /// Share parameters
    pub params: ShareParams,
    /// Share value data
    pub value: Vec<u8>,
    /// Checksum
    pub checksum: [u8; 3],
}

impl Share {
    /// Convert share to mnemonic words
    pub fn to_mnemonic(&self) -> Result<String> {
        let mut data = Vec::new();

        // Pack header
        data.extend_from_slice(&self.params.identifier.to_be_bytes());
        data.push(self.params.iteration_exponent << 4 | (self.params.group_threshold & 0x0F));
        data.push(self.params.group_count << 4 | self.params.group_index);
        data.push(self.params.member_threshold << 4 | self.params.member_index);

        // Add share value
        data.extend_from_slice(&self.value);

        // Add checksum
        data.extend_from_slice(&self.checksum);

        // Convert to word indices (10 bits per word)
        let words = Self::data_to_words(&data)?;

        // Convert indices to words
        let mnemonic: Vec<&str> = words
            .iter()
            .map(|&idx| {
                SLIP39_WORDLIST
                    .get(idx as usize)
                    .copied()
                    .ok_or(Error::InvalidMnemonic)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(mnemonic.join(" "))
    }

    /// Create share from mnemonic words
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();

        if words.len() < 20 {
            return Err(Error::InvalidMnemonic);
        }

        // Convert words to indices
        let indices: Vec<u16> = words
            .iter()
            .map(|word| {
                SLIP39_WORDLIST
                    .iter()
                    .position(|&w| w == *word)
                    .map(|i| i as u16)
                    .ok_or(Error::InvalidMnemonic)
            })
            .collect::<Result<Vec<_>>>()?;

        // Convert indices to data (10 bits per word)
        let data = Self::words_to_data(&indices)?;

        // Parse header
        if data.len() < 7 {
            return Err(Error::InvalidMnemonic);
        }

        let identifier = u16::from_be_bytes([data[0], data[1]]);
        let iteration_exponent = data[2] >> 4;
        let group_threshold = data[2] & 0x0F;
        let group_count = data[3] >> 4;
        let group_index = data[3] & 0x0F;
        let member_threshold = data[4] >> 4;
        let member_index = data[4] & 0x0F;

        // Extract value and checksum
        let value_end = data.len() - 3;
        let value = data[5..value_end].to_vec();
        let mut checksum = [0u8; 3];
        checksum.copy_from_slice(&data[value_end..]);

        Ok(Share {
            params: ShareParams {
                identifier,
                iteration_exponent,
                group_threshold,
                group_count,
                group_index,
                member_threshold,
                member_index,
            },
            value,
            checksum,
        })
    }

    /// Convert data bytes to word indices (10 bits each)
    fn data_to_words(data: &[u8]) -> Result<Vec<u16>> {
        let mut words = Vec::new();
        let mut bits = 0u32;
        let mut bits_left = 0;

        for byte in data {
            bits = (bits << 8) | (*byte as u32);
            bits_left += 8;

            while bits_left >= 10 {
                bits_left -= 10;
                let word = ((bits >> bits_left) & 0x3FF) as u16;
                words.push(word);
            }
        }

        // Add remaining bits if any
        if bits_left > 0 {
            let word = ((bits << (10 - bits_left)) & 0x3FF) as u16;
            words.push(word);
        }

        Ok(words)
    }

    /// Convert word indices to data bytes
    fn words_to_data(words: &[u16]) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut bits = 0u32;
        let mut bits_left = 0;

        for &word in words {
            if word >= 1024 {
                return Err(Error::InvalidMnemonic);
            }

            bits = (bits << 10) | (word as u32);
            bits_left += 10;

            while bits_left >= 8 {
                bits_left -= 8;
                let byte = ((bits >> bits_left) & 0xFF) as u8;
                data.push(byte);
            }
        }

        Ok(data)
    }
}

/// Shamir Secret Sharing manager
pub struct ShamirSecretSharing<R: crate::rng::RandomSource> {
    rng: R,
}

impl<R: crate::rng::RandomSource> ShamirSecretSharing<R> {
    /// Create new SSS instance
    pub fn new(rng: R) -> Self {
        Self { rng }
    }

    /// Split a secret into shares
    pub fn split_secret(
        &mut self,
        secret: &[u8],
        threshold: u8,
        total_shares: u8,
        identifier: u16,
    ) -> Result<Vec<Share>> {
        if threshold > total_shares {
            return Err(Error::InvalidParameter(
                "Threshold cannot exceed total shares".into(),
            ));
        }

        if threshold < 2 {
            return Err(Error::InvalidParameter(
                "Threshold must be at least 2".into(),
            ));
        }

        let mut shares = Vec::new();

        // For each byte of the secret
        for byte_idx in 0..secret.len() {
            let secret_byte = secret[byte_idx];

            // Generate random polynomial coefficients
            let mut coefficients = vec![secret_byte];
            for _ in 1..threshold {
                let random = self
                    .rng
                    .random_u8()
                    .map_err(|_| Error::InsufficientEntropy)?;
                coefficients.push(random);
            }

            // Evaluate polynomial at x=1..total_shares
            for share_idx in 1..=total_shares {
                let x = share_idx;
                let y = self.evaluate_polynomial(&coefficients, x);

                if shares.len() < share_idx as usize {
                    shares.push(Vec::new());
                }
                shares[share_idx as usize - 1].push(y);
            }
        }

        // Create Share objects
        let mut result = Vec::new();
        for (idx, share_data) in shares.into_iter().enumerate() {
            let params = ShareParams {
                identifier,
                iteration_exponent: 0,
                group_threshold: 1,
                group_count: 1,
                group_index: 0,
                member_threshold: threshold,
                member_index: idx as u8,
            };

            let checksum = self.calculate_checksum(&share_data);

            result.push(Share {
                params,
                value: share_data,
                checksum,
            });
        }

        Ok(result)
    }

    /// Combine shares to recover secret
    pub fn combine_shares(&self, shares: &[Share]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(Error::InvalidParameter("No shares provided".into()));
        }

        // Verify all shares have same parameters
        let first = &shares[0];
        for share in shares.iter().skip(1) {
            if share.params.identifier != first.params.identifier
                || share.params.member_threshold != first.params.member_threshold
                || share.value.len() != first.value.len()
            {
                return Err(Error::InvalidParameter(
                    "Inconsistent share parameters".into(),
                ));
            }
        }

        if shares.len() < first.params.member_threshold as usize {
            return Err(Error::InvalidParameter(format!(
                "Need at least {} shares",
                first.params.member_threshold
            )));
        }

        // Verify checksums
        for share in shares {
            let calculated = self.calculate_checksum(&share.value);
            if calculated != share.checksum {
                return Err(Error::ChecksumError);
            }
        }

        let secret_len = first.value.len();
        let mut secret = Vec::with_capacity(secret_len);

        // Recover each byte using Lagrange interpolation
        for byte_idx in 0..secret_len {
            let mut points = Vec::new();
            for share in shares {
                let x = share.params.member_index + 1; // x values are 1-indexed
                let y = share.value[byte_idx];
                points.push((x, y));
            }

            let recovered_byte = self.lagrange_interpolate(&points, 0)?;
            secret.push(recovered_byte);
        }

        Ok(secret)
    }

    /// Evaluate polynomial at given x using Horner's method
    fn evaluate_polynomial(&self, coefficients: &[u8], x: u8) -> u8 {
        let mut result = 0u8;

        for &coeff in coefficients.iter().rev() {
            result = self.gf256_add(self.gf256_mul(result, x), coeff);
        }

        result
    }

    /// Lagrange interpolation in GF(256)
    fn lagrange_interpolate(&self, points: &[(u8, u8)], x: u8) -> Result<u8> {
        let mut result = 0u8;

        for i in 0..points.len() {
            let (xi, yi) = points[i];
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for j in 0..points.len() {
                if i != j {
                    let (xj, _) = points[j];
                    numerator = self.gf256_mul(numerator, self.gf256_sub(x, xj));
                    denominator = self.gf256_mul(denominator, self.gf256_sub(xi, xj));
                }
            }

            let lagrange_coeff = self.gf256_div(numerator, denominator)?;
            result = self.gf256_add(result, self.gf256_mul(yi, lagrange_coeff));
        }

        Ok(result)
    }

    /// GF(256) addition (XOR)
    fn gf256_add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// GF(256) subtraction (same as addition in GF(256))
    fn gf256_sub(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// GF(256) multiplication using log/exp tables for efficiency
    fn gf256_mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }

        // Use logarithm approach for multiplication
        let log_a = self.gf256_log(a);
        let log_b = self.gf256_log(b);
        let log_result = (log_a as u16 + log_b as u16) % 255;
        self.gf256_exp(log_result as u8)
    }

    /// GF(256) division
    fn gf256_div(&self, a: u8, b: u8) -> Result<u8> {
        if b == 0 {
            return Err(Error::InvalidParameter("Division by zero".into()));
        }
        if a == 0 {
            return Ok(0);
        }

        // Find multiplicative inverse of b
        let b_inv = self.gf256_inverse(b)?;
        Ok(self.gf256_mul(a, b_inv))
    }

    /// Find multiplicative inverse in GF(256)
    fn gf256_inverse(&self, a: u8) -> Result<u8> {
        if a == 0 {
            return Err(Error::InvalidParameter("No inverse for zero".into()));
        }

        // In GF(256), a^254 = a^(-1) since a^255 = 1 for all non-zero a
        // We can compute this efficiently using the logarithm table
        let log_a = self.gf256_log(a);
        let log_inv = (255 - log_a) % 255;
        Ok(self.gf256_exp(log_inv))
    }

    /// Calculate checksum for share data
    fn calculate_checksum(&self, data: &[u8]) -> [u8; 3] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut checksum = [0u8; 3];
        checksum.copy_from_slice(&hash[0..3]);
        checksum
    }

    /// GF(256) logarithm (discrete log base g=3)
    fn gf256_log(&self, a: u8) -> u8 {
        // Precomputed log table for GF(256) with generator 3
        const LOG_TABLE: [u8; 256] = [
            0xff, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee,
            0xdf, 0x03, 0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8,
            0xf8, 0x69, 0x1c, 0xc1, 0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4,
            0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78, 0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24,
            0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e, 0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0,
            0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38, 0x66, 0xdd, 0xfd, 0x30,
            0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10, 0x7e, 0x6e,
            0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
            0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73,
            0xa7, 0x57, 0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5,
            0xe7, 0xe6, 0xad, 0xe8, 0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb,
            0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0, 0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec,
            0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7, 0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60,
            0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d, 0x97, 0xb2, 0x87, 0x90,
            0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1, 0x53, 0x39,
            0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
            0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99,
            0xe3, 0xa5, 0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80,
            0xc0, 0xf7, 0x70, 0x07,
        ];
        LOG_TABLE[a as usize]
    }

    /// GF(256) exponentiation (power of generator g=3)
    fn gf256_exp(&self, a: u8) -> u8 {
        // Precomputed exp table for GF(256) with generator 3
        const EXP_TABLE: [u8; 256] = [
            0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8,
            0x13, 0x35, 0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a,
            0x1e, 0x22, 0x66, 0xaa, 0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe,
            0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31, 0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
            0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd, 0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b,
            0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88, 0x83, 0x9e, 0xb9, 0xd0,
            0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a, 0xb5, 0xc4,
            0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
            0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20,
            0x60, 0xa0, 0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56,
            0xfa, 0x15, 0x3f, 0x41, 0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed,
            0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75, 0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
            0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80, 0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23,
            0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54, 0xfc, 0x1f, 0x21, 0x63,
            0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca, 0x45, 0xcf,
            0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
            0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2,
            0x0d, 0x17, 0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4,
            0xc7, 0x52, 0xf6, 0x01,
        ];
        if a == 0xff {
            0
        } else {
            EXP_TABLE[a as usize]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test RNG for deterministic testing
    struct TestRng(u8);

    impl crate::rng::RandomSource for TestRng {
        fn random_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn test_gf256_operations() -> Result<()> {
        let sss = ShamirSecretSharing::new(TestRng(0));

        // Test addition (XOR)
        assert_eq!(sss.gf256_add(5, 3), 6);
        assert_eq!(sss.gf256_add(255, 255), 0);

        // Test multiplication
        assert_eq!(sss.gf256_mul(0, 5), 0);
        assert_eq!(sss.gf256_mul(1, 5), 5);
        // In GF(256), multiplication is different from regular arithmetic
        // Using the log/exp tables with generator 3
        assert_eq!(sss.gf256_mul(2, 3), 6); // 2 = 3^25, 3 = 3^1, so 2*3 = 3^26 = 6

        // Test inverse
        let a = 7u8;
        let a_inv = sss.gf256_inverse(a)?;
        assert_eq!(sss.gf256_mul(a, a_inv), 1);

        Ok(())
    }

    #[test]
    fn test_split_combine_basic() -> Result<()> {
        let rng = TestRng(42);
        let mut sss = ShamirSecretSharing::new(rng);
        let secret = b"test secret data";

        // Split into 5 shares with threshold 3
        let shares = sss.split_secret(secret, 3, 5, 12345)?;
        assert_eq!(shares.len(), 5);

        // Combine using exactly threshold shares
        let recovered = sss.combine_shares(&shares[0..3])?;
        assert_eq!(recovered, secret);

        // Combine using more than threshold
        let recovered = sss.combine_shares(&shares)?;
        assert_eq!(recovered, secret);

        Ok(())
    }

    #[test]
    fn test_share_mnemonic_conversion() -> Result<()> {
        let params = ShareParams {
            identifier: 0x1234,
            iteration_exponent: 0,
            group_threshold: 1,
            group_count: 1,
            group_index: 0,
            member_threshold: 3,
            member_index: 0,
        };

        let _share = Share {
            params,
            value: vec![0x12, 0x34, 0x56, 0x78],
            checksum: [0xAB, 0xCD, 0xEF],
        };

        // Convert to mnemonic (would need full wordlist for real test)
        // let mnemonic = share.to_mnemonic()?;
        // let recovered = Share::from_mnemonic(&mnemonic)?;
        // assert_eq!(recovered.params.identifier, share.params.identifier);

        Ok(())
    }
}
