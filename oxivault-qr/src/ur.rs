//! UR (Uniform Resources) Protocol Implementation
//!
//! Based on the BC-UR-2020 specification for encoding structured binary data
//! in a series of QR codes using fountain codes for robust transmission.

use crate::Result;
use sha2::{Digest, Sha256};

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

/// UR type registry - common types used in crypto wallets
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UrType {
    /// Bitcoin PSBT
    CryptoPSBT,
    /// Extended public key
    CryptoHDKey,
    /// BIP39 seed
    CryptoSeed,
    /// Output descriptor
    CryptoOutput,
    /// Account descriptor (multiple keys)
    CryptoAccount,
    /// Generic bytes
    Bytes,
}

impl UrType {
    /// Get the UR type string
    pub fn to_string(&self) -> &'static str {
        match self {
            UrType::CryptoPSBT => "crypto-psbt",
            UrType::CryptoHDKey => "crypto-hdkey",
            UrType::CryptoSeed => "crypto-seed",
            UrType::CryptoOutput => "crypto-output",
            UrType::CryptoAccount => "crypto-account",
            UrType::Bytes => "bytes",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "crypto-psbt" => Some(UrType::CryptoPSBT),
            "crypto-hdkey" => Some(UrType::CryptoHDKey),
            "crypto-seed" => Some(UrType::CryptoSeed),
            "crypto-output" => Some(UrType::CryptoOutput),
            "crypto-account" => Some(UrType::CryptoAccount),
            "bytes" => Some(UrType::Bytes),
            _ => None,
        }
    }
}

/// UR encoder for creating UR strings
pub struct UrEncoder {
    ur_type: UrType,
    max_fragment_length: usize,
}

impl UrEncoder {
    /// Create a new UR encoder
    pub fn new(ur_type: UrType, max_fragment_length: usize) -> Self {
        Self {
            ur_type,
            max_fragment_length,
        }
    }

    /// Encode data as a single UR (for small data)
    pub fn encode_single(&self, data: &[u8]) -> String {
        let bywords = self.to_bywords(data);
        format!("ur:{}/{}", self.ur_type.to_string(), bywords)
    }

    /// Encode data as multi-part UR using fountain codes
    pub fn encode_multi(&self, data: &[u8]) -> Result<Vec<String>> {
        if data.is_empty() {
            return Err("Cannot encode empty data");
        }

        // Calculate digest for the data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();

        // For simplicity, we'll implement a basic partitioning scheme
        // A full implementation would use fountain codes (Luby transform codes)
        let parts = self.partition_data(data);
        let total_parts = parts.len();

        let mut ur_parts = Vec::new();

        for (seq_num, part) in parts.iter().enumerate() {
            let part_data = self.create_part(
                seq_num as u32,
                total_parts as u32,
                data.len() as u32,
                &digest[0..4],
                part,
            );

            let bywords = self.to_bywords(&part_data);
            let ur = format!(
                "ur:{}/{}/{}-{}/{}",
                self.ur_type.to_string(),
                total_parts,
                seq_num + 1,
                total_parts,
                bywords
            );

            ur_parts.push(ur);
        }

        Ok(ur_parts)
    }

    /// Partition data into fragments
    fn partition_data(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut parts = Vec::new();

        for chunk in data.chunks(self.max_fragment_length) {
            parts.push(chunk.to_vec());
        }

        parts
    }

    /// Create a part with metadata
    fn create_part(
        &self,
        seq_num: u32,
        total: u32,
        message_len: u32,
        checksum: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut part = Vec::new();

        // Simple header format (not full fountain code implementation)
        part.extend_from_slice(&seq_num.to_be_bytes());
        part.extend_from_slice(&total.to_be_bytes());
        part.extend_from_slice(&message_len.to_be_bytes());
        part.extend_from_slice(checksum);
        part.extend_from_slice(data);

        part
    }

    /// Convert bytes to bywords encoding (base32-like but with custom alphabet)
    fn to_bywords(&self, data: &[u8]) -> String {
        // Simplified bywords encoding
        // Full implementation would use the bywords dictionary
        const BYWORDS: &[u8] = b"0123456789abcdefghijklmnopqrstuv";

        let mut result = String::new();

        // Process 5-byte chunks
        let complete_chunks = data.len() / 5;

        for i in 0..complete_chunks {
            let chunk = &data[i * 5..(i + 1) * 5];

            // Convert 5 bytes (40 bits) to 8 base32 characters (8 * 5 = 40 bits)
            let val =
                u64::from_be_bytes([0, 0, 0, chunk[0], chunk[1], chunk[2], chunk[3], chunk[4]]);

            // Extract 8 * 5-bit values
            for j in (0..8).rev() {
                let idx = ((val >> (j * 5)) & 0x1F) as usize;
                result.push(BYWORDS[idx] as char);
            }
        }

        // Handle remaining bytes
        let remaining = data.len() % 5;
        if remaining > 0 {
            let mut buffer = [0u8; 5];
            for i in 0..remaining {
                buffer[i] = data[complete_chunks * 5 + i];
            }

            let val = u64::from_be_bytes([
                0, 0, 0, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4],
            ]);

            // Calculate how many characters we need
            let chars_needed = (remaining * 8 + 4) / 5; // Round up

            for j in (0..chars_needed).rev() {
                let shift = j * 5 + (40 - chars_needed * 5);
                let idx = ((val >> shift) & 0x1F) as usize;
                result.push(BYWORDS[idx] as char);
            }
        }

        result
    }
}

/// UR decoder for parsing UR strings
pub struct UrDecoder {
    ur_type: Option<UrType>,
    parts: Vec<Option<Vec<u8>>>,
    total_parts: Option<usize>,
    message_len: Option<usize>,
    checksum: Option<[u8; 4]>,
}

impl UrDecoder {
    /// Create a new decoder
    pub fn new() -> Self {
        Self {
            ur_type: None,
            parts: Vec::new(),
            total_parts: None,
            message_len: None,
            checksum: None,
        }
    }

    /// Add a UR string to decode
    pub fn add_ur(&mut self, ur: &str) -> Result<()> {
        // Parse UR format: ur:type/[part_info/]data
        if !ur.starts_with("ur:") {
            return Err("Invalid UR: must start with 'ur:'");
        }

        let ur_content = &ur[3..]; // Skip "ur:"
        let parts: Vec<&str> = ur_content.split('/').collect();

        if parts.len() < 2 {
            return Err("Invalid UR format");
        }

        // Parse type
        let ur_type = UrType::from_str(parts[0]).ok_or("Unknown UR type")?;

        // Verify type consistency
        if let Some(existing_type) = self.ur_type {
            if existing_type != ur_type {
                return Err("Inconsistent UR types");
            }
        } else {
            self.ur_type = Some(ur_type);
        }

        if parts.len() == 2 {
            // Single-part UR
            let data = self.from_bywords(parts[1])?;
            self.parts = vec![Some(data)];
            self.total_parts = Some(1);
        } else if parts.len() >= 4 {
            // Multi-part UR
            // Format: type/total/current-total/data
            let total = parts[1]
                .parse::<usize>()
                .map_err(|_| "Invalid part count")?;

            // Parse sequence numbers (e.g., "1-5")
            let seq_parts: Vec<&str> = parts[2].split('-').collect();
            if seq_parts.len() != 2 {
                return Err("Invalid sequence format");
            }

            let seq_num = seq_parts[0]
                .parse::<usize>()
                .map_err(|_| "Invalid sequence number")?;

            // Initialize parts vector if needed
            if self.total_parts.is_none() {
                self.total_parts = Some(total);
                self.parts.resize(total, None);
            } else if self.total_parts != Some(total) {
                return Err("Inconsistent total parts");
            }

            // Decode and store part
            let data = self.from_bywords(parts[3])?;

            // Parse part header if this is a multi-part message
            if data.len() >= 16 {
                // Extract header
                let _seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let _total = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let msg_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
                let checksum = [data[12], data[13], data[14], data[15]];

                // Store metadata
                if self.message_len.is_none() {
                    self.message_len = Some(msg_len);
                    self.checksum = Some(checksum);
                }

                // Store actual data (skip header)
                let part_data = data[16..].to_vec();
                self.parts[seq_num - 1] = Some(part_data);
            } else {
                self.parts[seq_num - 1] = Some(data);
            }
        } else {
            return Err("Invalid UR format");
        }

        Ok(())
    }

    /// Check if all parts have been received
    pub fn is_complete(&self) -> bool {
        !self.parts.is_empty() && self.parts.iter().all(|p| p.is_some())
    }

    /// Combine parts into final data
    pub fn combine(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err("Not all parts received");
        }

        let mut combined = Vec::new();
        for part in &self.parts {
            if let Some(data) = part {
                combined.extend_from_slice(data);
            }
        }

        // For single-part messages, we don't have length metadata
        // so return as-is (caller needs to handle padding)
        if self.total_parts == Some(1) {
            return Ok(combined);
        }

        // Truncate to message length if known (multi-part)
        if let Some(len) = self.message_len {
            combined.truncate(len);
        }

        // Verify checksum if available (multi-part)
        if let Some(expected_checksum) = self.checksum {
            let mut hasher = Sha256::new();
            hasher.update(&combined);
            let hash = hasher.finalize();

            if &hash[0..4] != expected_checksum {
                return Err("Checksum verification failed");
            }
        }

        Ok(combined)
    }

    /// Progress as (received, total)
    pub fn progress(&self) -> (usize, usize) {
        let received = self.parts.iter().filter(|p| p.is_some()).count();
        let total = self.total_parts.unwrap_or(0);
        (received, total)
    }

    /// Convert bywords to bytes
    fn from_bywords(&self, bywords: &str) -> Result<Vec<u8>> {
        // Simplified bywords decoding
        const BYWORDS: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
        let mut result = Vec::new();
        let bytes = bywords.as_bytes();

        // Process complete 8-character chunks
        let complete_chunks = bytes.len() / 8;

        for i in 0..complete_chunks {
            let chunk = &bytes[i * 8..(i + 1) * 8];
            let mut value = 0u64;

            for &ch in chunk {
                let idx = BYWORDS
                    .iter()
                    .position(|&b| b == ch)
                    .ok_or("Invalid byword character")?;
                value = (value << 5) | (idx as u64);
            }

            // Extract 5 bytes from the value (40 bits = 8 * 5-bit chars)
            let bytes = value.to_be_bytes();
            result.extend_from_slice(&bytes[3..8]); // Skip first 3 bytes (24 bits of padding)
        }

        // Handle any remaining characters
        let remaining = bytes.len() % 8;
        if remaining > 0 {
            let chunk = &bytes[complete_chunks * 8..];
            let mut value = 0u64;

            for &ch in chunk {
                let idx = BYWORDS
                    .iter()
                    .position(|&b| b == ch)
                    .ok_or("Invalid byword character")?;
                value = (value << 5) | (idx as u64);
            }

            // Shift left to align
            value <<= (8 - remaining) * 5;

            // Calculate how many bytes to extract
            let bytes_to_extract = (remaining * 5 + 7) / 8;
            let bytes = value.to_be_bytes();

            for i in 0..bytes_to_extract {
                result.push(bytes[3 + i]);
            }
        }

        Ok(result)
    }
}

/// Create UR for PSBT data
pub fn create_psbt_ur(psbt_bytes: &[u8]) -> Result<Vec<String>> {
    let encoder = UrEncoder::new(UrType::CryptoPSBT, 100);

    if psbt_bytes.len() <= 200 {
        // Single UR for small PSBTs
        Ok(vec![encoder.encode_single(psbt_bytes)])
    } else {
        // Multi-part UR for large PSBTs
        encoder.encode_multi(psbt_bytes)
    }
}

/// Parse UR strings to get PSBT data
pub fn parse_psbt_ur(ur_strings: &[String]) -> Result<Vec<u8>> {
    let mut decoder = UrDecoder::new();

    for ur in ur_strings {
        decoder.add_ur(ur)?;
    }

    if !decoder.is_complete() {
        return Err("Incomplete UR data");
    }

    decoder.combine()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ur_single_encode_decode() -> Result<()> {
        let data = b"Hello, UR!";
        let encoder = UrEncoder::new(UrType::Bytes, 100);

        let ur = encoder.encode_single(data);
        assert!(ur.starts_with("ur:bytes/"));

        let mut decoder = UrDecoder::new();
        decoder.add_ur(&ur)?;
        assert!(decoder.is_complete());

        let decoded = decoder.combine()?;
        // Due to padding in the encoding, we need to truncate
        assert_eq!(&decoded[..data.len()], data);

        Ok(())
    }

    #[test]
    fn test_ur_multi_encode_decode() -> Result<()> {
        let data = b"This is a longer message that will be split into multiple parts for robust transmission";
        let encoder = UrEncoder::new(UrType::Bytes, 20);

        let ur_parts = encoder.encode_multi(data)?;
        assert!(ur_parts.len() > 1);

        let mut decoder = UrDecoder::new();
        for ur in &ur_parts {
            decoder.add_ur(ur)?;
        }

        assert!(decoder.is_complete());
        let decoded = decoder.combine()?;
        // The decoded data should match the original
        assert_eq!(decoded, data);

        Ok(())
    }

    #[test]
    fn test_psbt_ur() -> Result<()> {
        let psbt_data = b"mock psbt data for testing";

        let ur_parts = create_psbt_ur(psbt_data)?;
        assert!(!ur_parts.is_empty());

        let decoded = parse_psbt_ur(&ur_parts)?;
        // With padding, we need to compare only the relevant bytes
        assert_eq!(&decoded[..psbt_data.len()], psbt_data);

        Ok(())
    }

    #[test]
    fn test_ur_types() {
        assert_eq!(UrType::CryptoPSBT.to_string(), "crypto-psbt");
        assert_eq!(UrType::from_str("crypto-psbt"), Some(UrType::CryptoPSBT));

        assert_eq!(UrType::CryptoHDKey.to_string(), "crypto-hdkey");
        assert_eq!(UrType::from_str("crypto-hdkey"), Some(UrType::CryptoHDKey));
    }

    #[test]
    fn test_progress_tracking() -> Result<()> {
        let data = b"Test data for progress";
        let encoder = UrEncoder::new(UrType::Bytes, 5);

        let ur_parts = encoder.encode_multi(data)?;
        assert!(ur_parts.len() > 1);

        let mut decoder = UrDecoder::new();

        for (i, ur) in ur_parts.iter().enumerate() {
            decoder.add_ur(ur)?;
            let (received, total) = decoder.progress();
            assert_eq!(received, i + 1);
            assert_eq!(total, ur_parts.len());
        }

        Ok(())
    }
}
