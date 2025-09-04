#![cfg_attr(not(feature = "std"), no_std)]

//! QR code generation and parsing for IronVault

use qrcode::{QrCode, Version, EcLevel};
use heapless::Vec as HeaplessVec;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;

// Public exports
pub mod bbqr;
pub mod bbqr_qr;
pub mod ur;

pub use bbqr::{BBQrEncoder, BBQrDecoder, BBQrHeader, FileType, EncodingType};
pub use bbqr_qr::{BBQrQrGenerator, BBQrAnimator, BBQrScanner, ScanResult};
pub use ur::{UrEncoder, UrDecoder, UrType, create_psbt_ur, parse_psbt_ur};

// Re-export Result type for consistency
pub type Result<T> = core::result::Result<T, &'static str>;

/// Maximum QR code size we support
pub const MAX_QR_SIZE: usize = 1024;

/// QR code generator for embedded displays
pub struct QrGenerator;

impl QrGenerator {
    /// Generate a QR code from data
    pub fn generate(data: &str) -> Result<QrCode> {
        QrCode::new(data).map_err(|_| "Failed to generate QR code")
    }

    /// Generate QR code with specific version and error correction
    pub fn generate_with_options(
        data: &str,
        version: Version,
        ec_level: EcLevel,
    ) -> Result<QrCode> {
        QrCode::with_version(data, version, ec_level)
            .map_err(|_| "Failed to generate QR code with options")
    }

    /// Convert QR code to bitmap for display (no_std compatible)
    pub fn to_bitmap<const SIZE: usize>(qr: &QrCode) -> HeaplessVec<u8, SIZE> {
        let mut bitmap = HeaplessVec::new();
        let width = qr.width();
        
        for y in 0..width {
            for x in 0..width {
                if matches!(qr[(x, y)], qrcode::Color::Dark) {
                    let _ = bitmap.push(1);
                } else {
                    let _ = bitmap.push(0);
                }
            }
        }
        
        bitmap
    }
}

/// ASCII art QR code renderer for terminal display
pub struct AsciiQrRenderer;

impl AsciiQrRenderer {
    /// Render QR code as ASCII art for terminal display
    pub fn render(qr: &QrCode) -> String {
        let width = qr.width();
        let mut output = String::new();
        
        // Top border
        for _ in 0..width + 2 {
            output.push_str("██");
        }
        output.push('\n');
        
        // QR code content with side borders
        for y in 0..width {
            output.push_str("██"); // Left border
            for x in 0..width {
                if matches!(qr[(x, y)], qrcode::Color::Dark) {
                    output.push_str("  "); // Dark module (inverted for terminal)
                } else {
                    output.push_str("██"); // Light module
                }
            }
            output.push_str("██\n"); // Right border
        }
        
        // Bottom border
        for _ in 0..width + 2 {
            output.push_str("██");
        }
        output.push('\n');
        
        output
    }
    
    /// Render QR code with compact unicode blocks
    pub fn render_compact(qr: &QrCode) -> String {
        let width = qr.width();
        let mut output = String::new();
        
        // Process pairs of rows for half-block characters
        for y in (0..width).step_by(2) {
            for x in 0..width {
                let top = matches!(qr[(x, y)], qrcode::Color::Dark);
                let bottom = if y + 1 < width {
                    matches!(qr[(x, y + 1)], qrcode::Color::Dark)
                } else {
                    false
                };
                
                let ch = match (top, bottom) {
                    (false, false) => ' ',  // Both white
                    (true, false) => '▀',    // Top black, bottom white
                    (false, true) => '▄',    // Top white, bottom black
                    (true, true) => '█',     // Both black
                };
                output.push(ch);
            }
            output.push('\n');
        }
        
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbqr::{BBQrEncoder, BBQrDecoder, FileType, EncodingType};

    #[test]
    fn test_qr_generation() -> Result<()> {
        let qr = QrGenerator::generate("bitcoin:bc1qtest")?;
        assert!(qr.width() > 0);
        Ok(())
    }

    #[test]
    fn test_bbqr_integration() -> Result<()> {
        let data = b"test data for BBQr splitting";
        
        // Test encoding
        let encoder = BBQrEncoder::new(FileType::Binary, EncodingType::Raw, 10);
        let parts = encoder.split(data)?;
        assert!(parts.len() > 1);
        
        // Test decoding
        let mut decoder = BBQrDecoder::new();
        for part in &parts {
            decoder.add_part(part)?;
        }
        
        assert!(decoder.is_complete());
        let combined = decoder.combine()?;
        assert_eq!(combined, data);
        
        Ok(())
    }
    
    #[test]
    fn test_ascii_renderer() -> Result<()> {
        let qr = QrGenerator::generate("test")?;
        let ascii = AsciiQrRenderer::render(&qr);
        assert!(ascii.contains("██"));
        assert!(ascii.contains('\n'));
        
        let compact = AsciiQrRenderer::render_compact(&qr);
        assert!(compact.len() < ascii.len());
        
        Ok(())
    }
}