//! BBQr - Better Bitcoin QR Code Format
//! 
//! BBQr is a protocol for encoding large amounts of data across multiple
//! QR codes with error recovery and sequencing support.

use crate::Result;
use sha2::{Sha256, Digest};

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::String, format};

/// BBQr file types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    /// PSBT (Partially Signed Bitcoin Transaction)
    Psbt,
    /// Plain text message
    Text,
    /// Binary data
    Binary,
    /// JSON data
    Json,
    /// Transaction (hex encoded)
    Transaction,
    /// Bitcoin address
    Address,
    /// Extended public key
    Xpub,
    /// Output descriptor
    Descriptor,
}

impl FileType {
    /// Get the file type code for encoding
    pub fn code(&self) -> char {
        match self {
            FileType::Psbt => 'P',
            FileType::Text => 'T',
            FileType::Binary => 'B',
            FileType::Json => 'J',
            FileType::Transaction => 'X',
            FileType::Address => 'A',
            FileType::Xpub => 'U',
            FileType::Descriptor => 'D',
        }
    }
    
    /// Parse file type from code
    pub fn from_code(code: char) -> Result<Self> {
        match code {
            'P' => Ok(FileType::Psbt),
            'T' => Ok(FileType::Text),
            'B' => Ok(FileType::Binary),
            'J' => Ok(FileType::Json),
            'X' => Ok(FileType::Transaction),
            'A' => Ok(FileType::Address),
            'U' => Ok(FileType::Xpub),
            'D' => Ok(FileType::Descriptor),
            _ => Err("Invalid file type code"),
        }
    }
}

/// BBQr encoding type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncodingType {
    /// Raw binary encoding
    Raw,
    /// Base32 encoding
    Base32,
    /// Z85 encoding (more efficient than Base32)
    Z85,
}

impl EncodingType {
    /// Get the encoding type code
    pub fn code(&self) -> char {
        match self {
            EncodingType::Raw => 'R',
            EncodingType::Base32 => '3',
            EncodingType::Z85 => 'Z',
        }
    }
    
    /// Parse encoding type from code
    pub fn from_code(code: char) -> Result<Self> {
        match code {
            'R' => Ok(EncodingType::Raw),
            '3' => Ok(EncodingType::Base32),
            'Z' => Ok(EncodingType::Z85),
            _ => Err("Invalid encoding type code"),
        }
    }
}

/// BBQr header information
#[derive(Debug, Clone)]
pub struct BBQrHeader {
    /// File type being encoded
    pub file_type: FileType,
    /// Encoding type used
    pub encoding_type: EncodingType,
    /// Total number of parts
    pub total_parts: u16,
    /// Current part number (1-indexed)
    pub part_number: u16,
    /// Total data length
    pub data_length: u32,
    /// Checksum of the complete data
    pub checksum: [u8; 4],
}

impl BBQrHeader {
    /// Create header string for QR code
    pub fn to_string(&self) -> String {
        format!(
            "B${}{}${:04X}{:04X}{:08X}{:08X}",
            self.file_type.code(),
            self.encoding_type.code(),
            self.total_parts,
            self.part_number,
            self.data_length,
            u32::from_be_bytes(self.checksum)
        )
    }
    
    /// Parse header from string
    pub fn from_string(s: &str) -> Result<Self> {
        if !s.starts_with("B$") || s.len() < 29 {
            return Err("Invalid BBQr header format");
        }
        
        let chars: Vec<char> = s.chars().collect();
        
        let file_type = FileType::from_code(chars[2])?;
        let encoding_type = EncodingType::from_code(chars[3])?;
        
        // Skip the second '$' at position 4
        if chars[4] != '$' {
            return Err("Invalid BBQr header separator");
        }
        
        // Parse hex values
        let total_parts = u16::from_str_radix(&s[5..9], 16)
            .map_err(|_| "Invalid total parts")?;
        let part_number = u16::from_str_radix(&s[9..13], 16)
            .map_err(|_| "Invalid part number")?;
        let data_length = u32::from_str_radix(&s[13..21], 16)
            .map_err(|_| "Invalid data length")?;
        let checksum_val = u32::from_str_radix(&s[21..29], 16)
            .map_err(|_| "Invalid checksum")?;
        
        Ok(BBQrHeader {
            file_type,
            encoding_type,
            total_parts,
            part_number,
            data_length,
            checksum: checksum_val.to_be_bytes(),
        })
    }
}

/// BBQr encoder for splitting data into multiple QR codes
pub struct BBQrEncoder {
    /// File type to encode
    file_type: FileType,
    /// Encoding type to use
    encoding_type: EncodingType,
    /// Maximum bytes per QR code (excluding header)
    max_fragment_size: usize,
}

impl BBQrEncoder {
    /// Create a new BBQr encoder
    pub fn new(file_type: FileType, encoding_type: EncodingType, max_fragment_size: usize) -> Self {
        Self {
            file_type,
            encoding_type,
            max_fragment_size,
        }
    }
    
    /// Split data into BBQr formatted parts
    pub fn split(&self, data: &[u8]) -> Result<Vec<String>> {
        // Calculate checksum
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&hash[0..4]);
        
        // Encode data based on encoding type
        let encoded_data = self.encode_data(data)?;
        
        // Calculate number of parts needed
        let total_parts = ((encoded_data.len() + self.max_fragment_size - 1) / self.max_fragment_size) as u16;
        
        if total_parts > 9999 {
            return Err("Data too large for BBQr encoding");
        }
        
        let mut parts = Vec::new();
        
        for (i, chunk) in encoded_data.chunks(self.max_fragment_size).enumerate() {
            let header = BBQrHeader {
                file_type: self.file_type,
                encoding_type: self.encoding_type,
                total_parts,
                part_number: (i + 1) as u16,
                data_length: data.len() as u32,
                checksum,
            };
            
            let mut part = header.to_string();
            part.push('$'); // Separator between header and data
            
            // Add the encoded chunk
            match self.encoding_type {
                EncodingType::Raw => {
                    // For raw, convert to hex
                    for byte in chunk {
                        part.push_str(&format!("{:02X}", byte));
                    }
                },
                EncodingType::Base32 => {
                    part.push_str(&String::from_utf8_lossy(chunk));
                },
                EncodingType::Z85 => {
                    part.push_str(&String::from_utf8_lossy(chunk));
                },
            }
            
            parts.push(part);
        }
        
        Ok(parts)
    }
    
    /// Encode data based on encoding type
    fn encode_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.encoding_type {
            EncodingType::Raw => Ok(data.to_vec()),
            EncodingType::Base32 => {
                // Simple base32 encoding (could use data-encoding crate)
                Ok(self.base32_encode(data))
            },
            EncodingType::Z85 => {
                // Z85 encoding (could use z85 crate)
                Ok(self.z85_encode(data))
            },
        }
    }
    
    /// Simple base32 encoding implementation
    fn base32_encode(&self, data: &[u8]) -> Vec<u8> {
        const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut result = Vec::new();
        
        for chunk in data.chunks(5) {
            let mut buffer = [0u8; 5];
            for (i, &b) in chunk.iter().enumerate() {
                buffer[i] = b;
            }
            
            // Convert 5 bytes to 8 base32 characters
            let val = u64::from_be_bytes([0, 0, 0, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]]);
            
            for i in (0..8).rev() {
                let idx = ((val >> (i * 5)) & 0x1F) as usize;
                result.push(BASE32_ALPHABET[idx]);
            }
        }
        
        result
    }
    
    /// Z85 encoding implementation
    fn z85_encode(&self, data: &[u8]) -> Vec<u8> {
        const Z85_CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
        
        let mut result = Vec::new();
        let mut i = 0;
        
        // Process 4-byte chunks
        while i + 3 < data.len() {
            // Convert 4 bytes to a 32-bit value
            let value = u32::from_be_bytes([
                data[i], data[i + 1], data[i + 2], data[i + 3]
            ]);
            
            // Encode as 5 Z85 characters
            let mut encoded = [0u8; 5];
            let mut val = value;
            for j in (0..5).rev() {
                encoded[j] = Z85_CHARS[(val % 85) as usize];
                val /= 85;
            }
            result.extend_from_slice(&encoded);
            
            i += 4;
        }
        
        // Handle remaining bytes with padding
        if i < data.len() {
            let remaining = data.len() - i;
            let mut padded = [0u8; 4];
            for j in 0..remaining {
                padded[j] = data[i + j];
            }
            
            let value = u32::from_be_bytes(padded);
            let mut encoded = [0u8; 5];
            let mut val = value;
            for j in (0..5).rev() {
                encoded[j] = Z85_CHARS[(val % 85) as usize];
                val /= 85;
            }
            
            // For Z85, we always encode full 5-char groups, even with padding
            // The decoder will need to know the original length
            result.extend_from_slice(&encoded);
        }
        
        result
    }
}

/// BBQr decoder for combining QR code parts
pub struct BBQrDecoder {
    /// Collected parts
    parts: Vec<Option<Vec<u8>>>,
    /// Expected header info
    header: Option<BBQrHeader>,
}

impl BBQrDecoder {
    /// Create a new decoder
    pub fn new() -> Self {
        Self {
            parts: Vec::new(),
            header: None,
        }
    }
    
    /// Add a QR code part
    pub fn add_part(&mut self, qr_data: &str) -> Result<()> {
        // BBQr format is: header(29 chars) + $ + data
        // Header format: B$FE$TTTTPPPPDDDDDDDDCCCCCCCC
        if qr_data.len() < 30 {
            return Err("QR data too short for BBQr format");
        }
        
        // Extract the fixed-length header
        let header_str = &qr_data[..29];
        let header = BBQrHeader::from_string(header_str)?;
        
        // Verify separator after header
        if !qr_data[29..].starts_with('$') {
            return Err("Missing data separator after header");
        }
        
        // Extract data after the separator
        let data_str = &qr_data[30..];
        
        // Initialize or verify header
        if let Some(ref expected) = self.header {
            if expected.file_type != header.file_type ||
               expected.encoding_type != header.encoding_type ||
               expected.total_parts != header.total_parts ||
               expected.data_length != header.data_length ||
               expected.checksum != header.checksum {
                return Err("Inconsistent BBQr headers");
            }
        } else {
            self.header = Some(header.clone());
            self.parts.resize(header.total_parts as usize, None);
        }
        
        // Decode and store data
        let data = self.decode_data(data_str, header.encoding_type)?;
        
        let idx = (header.part_number - 1) as usize;
        if idx >= self.parts.len() {
            return Err("Invalid part number");
        }
        
        self.parts[idx] = Some(data);
        
        Ok(())
    }
    
    /// Check if all parts have been received
    pub fn is_complete(&self) -> bool {
        !self.parts.is_empty() && self.parts.iter().all(|p| p.is_some())
    }
    
    /// Get progress as (received, total)
    pub fn progress(&self) -> (usize, usize) {
        let received = self.parts.iter().filter(|p| p.is_some()).count();
        (received, self.parts.len())
    }
    
    /// Combine all parts into final data
    pub fn combine(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err("Not all parts received");
        }
        
        let header = self.header.as_ref().ok_or("No header set")?;
        
        // Combine parts
        let mut combined = Vec::new();
        for part in &self.parts {
            if let Some(data) = part {
                combined.extend_from_slice(data);
            }
        }
        
        // Truncate to exact data length (important for Z85 which pads to 4-byte boundaries)
        combined.truncate(header.data_length as usize);
        
        // Verify checksum
        let mut hasher = Sha256::new();
        hasher.update(&combined);
        let hash = hasher.finalize();
        
        if &hash[0..4] != header.checksum {
            return Err("Checksum verification failed");
        }
        
        Ok(combined)
    }
    
    /// Decode data based on encoding type
    fn decode_data(&self, data: &str, encoding_type: EncodingType) -> Result<Vec<u8>> {
        match encoding_type {
            EncodingType::Raw => {
                // Decode from hex
                let mut result = Vec::new();
                for chunk in data.as_bytes().chunks(2) {
                    if chunk.len() == 2 {
                        let byte = u8::from_str_radix(
                            &String::from_utf8_lossy(chunk), 16
                        ).map_err(|_| "Invalid hex data")?;
                        result.push(byte);
                    }
                }
                Ok(result)
            },
            EncodingType::Base32 => {
                // Decode base32
                Ok(self.base32_decode(data.as_bytes())?)
            },
            EncodingType::Z85 => {
                // Decode Z85
                self.z85_decode(data.as_bytes())
            },
        }
    }
    
    /// Simple base32 decoding
    fn base32_decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        for chunk in data.chunks(8) {
            let mut value = 0u64;
            for &c in chunk {
                let digit = match c {
                    b'A'..=b'Z' => c - b'A',
                    b'2'..=b'7' => c - b'2' + 26,
                    _ => return Err("Invalid base32 character"),
                };
                value = (value << 5) | (digit as u64);
            }
            
            // Extract 5 bytes from the value
            for i in (0..5).rev() {
                result.push((value >> (i * 8)) as u8);
            }
        }
        
        Ok(result)
    }
    
    /// Z85 decoding
    fn z85_decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Create reverse lookup table
        let mut decode_table = [0xff_u8; 256];
        let z85_chars = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
        for (i, &ch) in z85_chars.iter().enumerate() {
            decode_table[ch as usize] = i as u8;
        }
        
        let mut result = Vec::new();
        let mut i = 0;
        
        // Process 5-character chunks
        while i + 4 < data.len() {
            let mut value = 0u32;
            for j in 0..5 {
                let ch = data[i + j];
                let decoded = decode_table[ch as usize];
                if decoded == 0xff {
                    return Err("Invalid Z85 character");
                }
                value = value * 85 + decoded as u32;
            }
            
            // Convert to 4 bytes
            result.extend_from_slice(&value.to_be_bytes());
            i += 5;
        }
        
        // Z85 should always have complete 5-char groups when properly encoded
        // Any remaining characters indicate an encoding error
        if i < data.len() {
            return Err("Invalid Z85 data: incomplete group");
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bbqr_header() -> Result<()> {
        let header = BBQrHeader {
            file_type: FileType::Psbt,
            encoding_type: EncodingType::Raw,
            total_parts: 3,
            part_number: 1,
            data_length: 1024,
            checksum: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        
        let header_str = header.to_string();
        assert!(header_str.starts_with("B$PR$"));
        
        let parsed = BBQrHeader::from_string(&header_str)?;
        assert_eq!(parsed.file_type, FileType::Psbt);
        assert_eq!(parsed.total_parts, 3);
        assert_eq!(parsed.part_number, 1);
        
        Ok(())
    }
    
    #[test]
    fn test_bbqr_split_combine() -> Result<()> {
        let data = b"This is test data for BBQr encoding that spans multiple QR codes";
        
        let encoder = BBQrEncoder::new(FileType::Text, EncodingType::Raw, 20);
        let parts = encoder.split(data)?;
        
        assert!(parts.len() > 1);
        
        let mut decoder = BBQrDecoder::new();
        for part in parts {
            decoder.add_part(&part)?;
        }
        
        assert!(decoder.is_complete());
        
        let combined = decoder.combine()?;
        assert_eq!(combined, data);
        
        Ok(())
    }
    
    #[test]
    fn test_file_types() -> Result<()> {
        assert_eq!(FileType::Psbt.code(), 'P');
        assert_eq!(FileType::from_code('P')?, FileType::Psbt);
        
        assert_eq!(FileType::Transaction.code(), 'X');
        assert_eq!(FileType::from_code('X')?, FileType::Transaction);
        
        Ok(())
    }
    
    #[test]
    fn test_progress_tracking() -> Result<()> {
        let data = b"Test data";
        let encoder = BBQrEncoder::new(FileType::Binary, EncodingType::Raw, 3);
        let parts = encoder.split(data)?;
        
        let mut decoder = BBQrDecoder::new();
        
        assert_eq!(decoder.progress(), (0, 0));
        
        decoder.add_part(&parts[0])?;
        assert_eq!(decoder.progress(), (1, parts.len()));
        
        for part in &parts[1..] {
            decoder.add_part(part)?;
        }
        
        assert_eq!(decoder.progress(), (parts.len(), parts.len()));
        assert!(decoder.is_complete());
        
        Ok(())
    }
    
    #[test]
    fn test_z85_encoding() -> Result<()> {
        let encoder = BBQrEncoder::new(FileType::Binary, EncodingType::Z85, 100);
        
        // Test exact 4-byte multiple
        let data1 = b"Test";
        let encoded = encoder.z85_encode(data1);
        let decoder = BBQrDecoder::new();
        let decoded = decoder.z85_decode(&encoded)?;
        assert_eq!(decoded, data1);
        
        // Test another 4-byte multiple
        let data2 = b"ABCD1234";
        let encoded = encoder.z85_encode(data2);
        let decoded = decoder.z85_decode(&encoded)?;
        assert_eq!(decoded, data2);
        
        // Note: Z85 requires 4-byte aligned data
        // In BBQr, the data length is tracked in the header
        // So padding is handled at the protocol level
        
        Ok(())
    }
    
    #[test]
    fn test_bbqr_with_z85() -> Result<()> {
        let data = b"Test data for Z85 BBQr encoding";
        
        let encoder = BBQrEncoder::new(FileType::Text, EncodingType::Z85, 10);
        let parts = encoder.split(data)?;
        
        assert!(parts.len() > 1);
        
        let mut decoder = BBQrDecoder::new();
        for part in parts {
            decoder.add_part(&part)?;
        }
        
        assert!(decoder.is_complete());
        
        let combined = decoder.combine()?;
        assert_eq!(combined, data);
        
        Ok(())
    }
}