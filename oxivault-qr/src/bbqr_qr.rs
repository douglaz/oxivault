//! BBQr QR Code Integration
//!
//! Provides QR code generation for BBQr parts with animation support

use crate::{
    bbqr::{BBQrDecoder, BBQrEncoder, EncodingType, FileType},
    Result,
};
use qrcode::{EcLevel, QrCode, Version};

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "std")]
use std::string::ToString;

/// BBQr QR code generator with multi-part support
pub struct BBQrQrGenerator {
    /// Maximum data per QR code (affects QR density)
    max_fragment_size: usize,
    /// Error correction level for QR codes
    ec_level: EcLevel,
    /// Preferred QR version (size)
    preferred_version: Option<Version>,
}

impl BBQrQrGenerator {
    /// Create a new BBQr QR generator with defaults
    pub fn new() -> Self {
        Self {
            max_fragment_size: 200, // Good balance for QR version 15-20
            ec_level: EcLevel::M,   // Medium error correction
            preferred_version: None,
        }
    }

    /// Create with custom settings
    pub fn with_settings(max_fragment_size: usize, ec_level: EcLevel) -> Self {
        Self {
            max_fragment_size,
            ec_level,
            preferred_version: None,
        }
    }

    /// Set preferred QR version
    pub fn set_version(&mut self, version: Version) {
        self.preferred_version = Some(version);
    }

    /// Generate QR codes for data using BBQr protocol
    pub fn generate_parts(&self, data: &[u8], file_type: FileType) -> Result<Vec<QrCode>> {
        // Determine best encoding type based on data
        let encoding_type = self.select_encoding_type(data);

        // Create BBQr encoder
        let encoder = BBQrEncoder::new(file_type, encoding_type, self.max_fragment_size);

        // Split data into BBQr parts
        let parts = encoder.split(data)?;

        // Generate QR code for each part
        let mut qr_codes = Vec::new();
        for part in parts {
            let qr = self.generate_qr_for_part(&part)?;
            qr_codes.push(qr);
        }

        Ok(qr_codes)
    }

    /// Generate QR codes for PSBT data
    pub fn generate_psbt_qrs(&self, psbt_bytes: &[u8]) -> Result<Vec<QrCode>> {
        self.generate_parts(psbt_bytes, FileType::Psbt)
    }

    /// Generate QR codes for an extended public key
    pub fn generate_xpub_qrs(&self, xpub: &str) -> Result<Vec<QrCode>> {
        self.generate_parts(xpub.as_bytes(), FileType::Xpub)
    }

    /// Generate QR codes for an output descriptor
    pub fn generate_descriptor_qrs(&self, descriptor: &str) -> Result<Vec<QrCode>> {
        self.generate_parts(descriptor.as_bytes(), FileType::Descriptor)
    }

    /// Select optimal encoding type based on data characteristics
    fn select_encoding_type(&self, data: &[u8]) -> EncodingType {
        // Check if data is mostly ASCII printable
        let ascii_count = data.iter().filter(|&&b| b >= 32 && b <= 126).count();
        let ascii_ratio = ascii_count as f32 / data.len() as f32;

        if ascii_ratio > 0.9 {
            // Mostly text, use Base32 for better QR efficiency
            EncodingType::Base32
        } else if data.len() > 500 {
            // Large binary data, use Z85 for compression
            EncodingType::Z85
        } else {
            // Small binary data, use raw encoding
            EncodingType::Raw
        }
    }

    /// Generate a single QR code for a BBQr part
    fn generate_qr_for_part(&self, part_data: &str) -> Result<QrCode> {
        if let Some(version) = self.preferred_version {
            // Use specified version
            QrCode::with_version(part_data, version, self.ec_level)
                .map_err(|_| "Failed to generate QR with specified version")
        } else {
            // Auto-select version based on data size
            let min_version = self.estimate_min_version(part_data.len());
            QrCode::with_version(part_data, min_version, self.ec_level).or_else(|_| {
                // Fallback to automatic version selection
                QrCode::with_error_correction_level(part_data, self.ec_level)
                    .map_err(|_| "Failed to generate QR code")
            })
        }
    }

    /// Estimate minimum QR version needed for data
    fn estimate_min_version(&self, data_len: usize) -> Version {
        // Rough capacity estimates for EcLevel::M
        match data_len {
            0..=72 => Version::Normal(5),
            73..=128 => Version::Normal(8),
            129..=208 => Version::Normal(12),
            209..=288 => Version::Normal(15),
            289..=480 => Version::Normal(20),
            481..=688 => Version::Normal(25),
            689..=992 => Version::Normal(30),
            _ => Version::Normal(40), // Maximum version
        }
    }
}

/// Animated QR display for multi-part BBQr sequences
pub struct BBQrAnimator {
    /// QR codes to display
    qr_codes: Vec<QrCode>,
    /// Current frame index
    current_frame: usize,
    /// Frame duration in milliseconds
    frame_duration_ms: u32,
}

impl BBQrAnimator {
    /// Create new animator from QR codes
    pub fn new(qr_codes: Vec<QrCode>) -> Self {
        Self {
            qr_codes,
            current_frame: 0,
            frame_duration_ms: 500, // 500ms per frame default
        }
    }

    /// Set frame duration
    pub fn set_duration(&mut self, ms: u32) {
        self.frame_duration_ms = ms;
    }

    /// Get current frame
    pub fn current(&self) -> Option<&QrCode> {
        self.qr_codes.get(self.current_frame)
    }

    /// Advance to next frame
    pub fn next(&mut self) -> Option<&QrCode> {
        self.current_frame = (self.current_frame + 1) % self.qr_codes.len();
        self.current()
    }

    /// Get progress as (current, total)
    pub fn progress(&self) -> (usize, usize) {
        (self.current_frame + 1, self.qr_codes.len())
    }

    /// Reset to first frame
    pub fn reset(&mut self) {
        self.current_frame = 0;
    }

    /// Get all QR codes
    pub fn all_codes(&self) -> &[QrCode] {
        &self.qr_codes
    }
}

/// QR scanner state machine for BBQr assembly
pub struct BBQrScanner {
    decoder: BBQrDecoder,
    scanned_parts: Vec<String>,
}

impl BBQrScanner {
    /// Create new scanner
    pub fn new() -> Self {
        Self {
            decoder: BBQrDecoder::new(),
            scanned_parts: Vec::new(),
        }
    }

    /// Process a scanned QR code
    pub fn scan(&mut self, qr_data: &str) -> Result<ScanResult> {
        // Check if we've already scanned this part
        if self.scanned_parts.contains(&qr_data.to_string()) {
            return Ok(ScanResult::Duplicate);
        }

        // Try to add to decoder
        self.decoder.add_part(qr_data)?;
        self.scanned_parts.push(qr_data.to_string());

        // Check if complete
        if self.decoder.is_complete() {
            let data = self.decoder.combine()?;
            Ok(ScanResult::Complete(data))
        } else {
            let (received, total) = self.decoder.progress();
            Ok(ScanResult::Progress { received, total })
        }
    }

    /// Get current progress
    pub fn progress(&self) -> (usize, usize) {
        self.decoder.progress()
    }

    /// Reset scanner state
    pub fn reset(&mut self) {
        self.decoder = BBQrDecoder::new();
        self.scanned_parts.clear();
    }
}

/// Result of scanning a QR code
#[derive(Debug)]
pub enum ScanResult {
    /// Need more parts
    Progress { received: usize, total: usize },
    /// Already scanned this part
    Duplicate,
    /// All parts received, data assembled
    Complete(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbqr_qr_generation() -> Result<()> {
        let generator = BBQrQrGenerator::new();
        let data = b"Test PSBT data that will be split into multiple QR codes";

        let qr_codes = generator.generate_psbt_qrs(data)?;
        assert!(qr_codes.len() >= 1);

        // Each QR should be valid
        for qr in &qr_codes {
            assert!(qr.width() > 0);
        }

        Ok(())
    }

    #[test]
    fn test_encoding_selection() {
        let generator = BBQrQrGenerator::new();

        // ASCII text should use Base32
        let text_data = b"This is mostly text data with spaces and punctuation!";
        assert_eq!(
            generator.select_encoding_type(text_data),
            EncodingType::Base32
        );

        // Binary data should use Raw or Z85
        let binary_data = &[0u8, 1, 2, 3, 255, 254, 253, 252];
        let encoding = generator.select_encoding_type(binary_data);
        assert!(encoding == EncodingType::Raw || encoding == EncodingType::Z85);
    }

    #[test]
    fn test_animator() -> Result<()> {
        let generator = BBQrQrGenerator::new();
        let data = b"Animation test data";
        let qr_codes = generator.generate_parts(data, FileType::Text)?;

        let mut animator = BBQrAnimator::new(qr_codes.clone());

        // Check initial state
        assert_eq!(animator.progress(), (1, qr_codes.len()));

        // Advance frames
        animator.next();
        if qr_codes.len() > 1 {
            assert_eq!(animator.progress(), (2, qr_codes.len()));
        } else {
            assert_eq!(animator.progress(), (1, 1));
        }

        // Reset
        animator.reset();
        assert_eq!(animator.progress(), (1, qr_codes.len()));

        Ok(())
    }

    #[test]
    fn test_scanner_workflow() -> Result<()> {
        // Generate multi-part QR data
        let data = b"This is test data that will be split and then reassembled by the scanner";
        let encoder = BBQrEncoder::new(FileType::Binary, EncodingType::Raw, 20);
        let parts = encoder.split(data)?;

        assert!(parts.len() > 1, "Need multiple parts for this test");

        let mut scanner = BBQrScanner::new();

        // Scan all parts except the last one
        for (i, part) in parts.iter().enumerate().take(parts.len() - 1) {
            match scanner.scan(part)? {
                ScanResult::Progress { received, total } => {
                    assert_eq!(received, i + 1);
                    assert_eq!(total, parts.len());
                }
                _ => panic!("Expected Progress result"),
            }
        }

        // Scan the last part
        match scanner.scan(&parts[parts.len() - 1])? {
            ScanResult::Complete(assembled) => {
                assert_eq!(assembled, data);
            }
            _ => panic!("Expected Complete result"),
        }

        Ok(())
    }

    #[test]
    fn test_duplicate_detection() -> Result<()> {
        let data = b"Test";
        let encoder = BBQrEncoder::new(FileType::Binary, EncodingType::Raw, 100);
        let parts = encoder.split(data)?;

        let mut scanner = BBQrScanner::new();

        // First scan should work
        scanner.scan(&parts[0])?;

        // Second scan of same part should be detected as duplicate
        match scanner.scan(&parts[0])? {
            ScanResult::Duplicate => (),
            _ => panic!("Expected Duplicate result"),
        }

        Ok(())
    }
}
