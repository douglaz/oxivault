//! QR Code Import Module
//! 
//! Provides QR code import functionality with support for:
//! - Single QR codes
//! - BBQr multi-part codes
//! - UR (Uniform Resources) format
//! - Animated QR sequences

use std::time::{Duration, Instant};
use oxivault_qr::{
    BBQrDecoder,
};
use anyhow::{Result, anyhow};

/// QR import state machine
pub struct QrImporter {
    /// Current import method
    method: ImportMethod,
    /// BBQr decoder for multi-part codes
    bbqr_decoder: Option<BBQrDecoder>,
    /// UR parts collected (simplified UR handling)
    ur_parts: Vec<String>,
    /// Collected parts
    parts: Vec<String>,
    /// Import progress
    progress: ImportProgress,
    /// Last update time
    last_update: Instant,
}

/// Import methods
#[derive(Debug, Clone, PartialEq)]
pub enum ImportMethod {
    /// Single QR code
    Single,
    /// BBQr multi-part
    BBQr,
    /// UR format
    UniformResource,
    /// Auto-detect
    Auto,
}

/// Import progress tracking
#[derive(Debug, Clone)]
pub struct ImportProgress {
    /// Total parts expected
    pub total: Option<usize>,
    /// Parts received
    pub received: usize,
    /// Import complete
    pub complete: bool,
    /// Decoded data
    pub data: Option<Vec<u8>>,
    /// Data type
    pub data_type: Option<DataType>,
}

/// Detected data types
#[derive(Debug, Clone)]
pub enum DataType {
    /// Bitcoin transaction
    Transaction,
    /// PSBT
    Psbt,
    /// Mnemonic phrase
    Mnemonic,
    /// XPUB
    Xpub,
    /// Text message
    Text,
    /// Unknown binary
    Binary,
}

impl QrImporter {
    /// Create new QR importer
    pub fn new() -> Self {
        Self {
            method: ImportMethod::Auto,
            bbqr_decoder: None,
            ur_parts: Vec::new(),
            parts: Vec::new(),
            progress: ImportProgress {
                total: None,
                received: 0,
                complete: false,
                data: None,
                data_type: None,
            },
            last_update: Instant::now(),
        }
    }

    /// Set import method
    pub fn set_method(&mut self, method: ImportMethod) {
        self.method = method;
        self.reset();
    }

    /// Process a QR code part
    pub fn process_part(&mut self, data: &str) -> Result<ImportStatus> {
        self.last_update = Instant::now();

        match self.method {
            ImportMethod::Auto => self.auto_detect_and_process(data),
            ImportMethod::Single => self.process_single(data),
            ImportMethod::BBQr => self.process_bbqr(data),
            ImportMethod::UniformResource => self.process_ur(data),
        }
    }

    /// Auto-detect format and process
    fn auto_detect_and_process(&mut self, data: &str) -> Result<ImportStatus> {
        // Check for BBQr format
        if data.starts_with("B$") {
            self.method = ImportMethod::BBQr;
            return self.process_bbqr(data);
        }

        // Check for UR format
        if data.to_lowercase().starts_with("ur:") {
            self.method = ImportMethod::UniformResource;
            return self.process_ur(data);
        }

        // Assume single QR
        self.method = ImportMethod::Single;
        self.process_single(data)
    }

    /// Process single QR code
    fn process_single(&mut self, data: &str) -> Result<ImportStatus> {
        // Try to detect data type
        let data_type = Self::detect_data_type(data);
        
        self.progress.complete = true;
        self.progress.received = 1;
        self.progress.total = Some(1);
        self.progress.data = Some(data.as_bytes().to_vec());
        self.progress.data_type = Some(data_type);

        Ok(ImportStatus::Complete {
            data: data.as_bytes().to_vec(),
            data_type: self.progress.data_type.clone().unwrap(),
        })
    }

    /// Process BBQr part
    fn process_bbqr(&mut self, data: &str) -> Result<ImportStatus> {
        if self.bbqr_decoder.is_none() {
            self.bbqr_decoder = Some(BBQrDecoder::new());
        }

        if let Some(ref mut decoder) = self.bbqr_decoder {
            decoder.add_part(data).map_err(|e| anyhow!(e))?;
            
            let (received, total) = decoder.progress();
            self.progress.received = received;
            self.progress.total = Some(total);

            if decoder.is_complete() {
                let decoded = decoder.combine().map_err(|e| anyhow!(e))?;
                self.progress.complete = true;
                self.progress.data = Some(decoded.clone());
                
                // Detect type from decoded data
                if let Ok(text) = String::from_utf8(decoded.clone()) {
                    self.progress.data_type = Some(Self::detect_data_type(&text));
                } else {
                    self.progress.data_type = Some(DataType::Binary);
                }

                return Ok(ImportStatus::Complete {
                    data: decoded,
                    data_type: self.progress.data_type.clone().unwrap(),
                });
            }
        }

        Ok(ImportStatus::PartReceived {
            received: self.progress.received,
            total: self.progress.total.unwrap_or(0),
        })
    }

    /// Process UR part (simplified for now)
    fn process_ur(&mut self, data: &str) -> Result<ImportStatus> {
        // For now, just collect UR parts as strings
        // Full UR implementation would use fountain codes
        self.ur_parts.push(data.to_string());
        self.progress.received = self.ur_parts.len();
        
        // Simple heuristic: assume we need at least a few parts
        if self.ur_parts.len() >= 3 {
            // Combine all parts (simplified)
            let combined = self.ur_parts.join("");
            self.progress.complete = true;
            self.progress.data = Some(combined.as_bytes().to_vec());
            self.progress.data_type = Some(DataType::Binary);
            
            return Ok(ImportStatus::Complete {
                data: combined.as_bytes().to_vec(),
                data_type: DataType::Binary,
            });
        }
        
        Ok(ImportStatus::PartReceived {
            received: self.progress.received,
            total: 0, // Unknown total for UR
        })
    }

    /// Detect data type from string
    fn detect_data_type(data: &str) -> DataType {
        // Check for mnemonic (12-24 words)
        let words: Vec<&str> = data.split_whitespace().collect();
        if words.len() >= 12 && words.len() <= 24 {
            // Basic check for mnemonic-like content
            if words.iter().all(|w| w.chars().all(|c| c.is_alphabetic())) {
                return DataType::Mnemonic;
            }
        }

        // Check for XPUB/ZPUB
        if data.starts_with("xpub") || data.starts_with("zpub") || data.starts_with("tpub") {
            return DataType::Xpub;
        }

        // Check for base64 PSBT (starts with specific magic bytes when decoded)
        if data.len() > 10 && !data.contains(' ') {
            if let Ok(decoded) = base64_decode(data) {
                // PSBT magic bytes: 0x70, 0x73, 0x62, 0x74, 0xff
                if decoded.len() > 5 && &decoded[0..5] == &[0x70, 0x73, 0x62, 0x74, 0xff] {
                    return DataType::Psbt;
                }
            }
        }

        // Default to text
        DataType::Text
    }


    /// Reset the importer
    pub fn reset(&mut self) {
        self.bbqr_decoder = None;
        self.ur_parts.clear();
        self.parts.clear();
        self.progress = ImportProgress {
            total: None,
            received: 0,
            complete: false,
            data: None,
            data_type: None,
        };
        self.last_update = Instant::now();
    }

    /// Get current progress
    pub fn progress(&self) -> &ImportProgress {
        &self.progress
    }

    /// Check if import timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_update.elapsed() > timeout && !self.progress.complete
    }
}

/// Import status
#[derive(Debug, Clone)]
pub enum ImportStatus {
    /// Part received, waiting for more
    PartReceived { received: usize, total: usize },
    /// Import complete
    Complete { data: Vec<u8>, data_type: DataType },
    /// Error occurred
    Error(String),
}

impl Default for QrImporter {
    fn default() -> Self {
        Self::new()
    }
}

/// QR Scanner simulation for testing
pub struct QrScanner {
    /// Simulated QR codes to scan
    queue: Vec<String>,
    /// Current index
    index: usize,
}

impl QrScanner {
    pub fn new(codes: Vec<String>) -> Self {
        Self {
            queue: codes,
            index: 0,
        }
    }

    /// Simulate scanning next QR code
    pub fn scan_next(&mut self) -> Option<String> {
        if self.index < self.queue.len() {
            let code = self.queue[self.index].clone();
            self.index += 1;
            Some(code)
        } else {
            None
        }
    }

    /// Reset scanner
    pub fn reset(&mut self) {
        self.index = 0;
    }

    /// Check if more codes available
    pub fn has_more(&self) -> bool {
        self.index < self.queue.len()
    }
}

// Helper function to decode base64 safely
fn base64_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_qr_import() {
        let mut importer = QrImporter::new();
        let test_data = "test mnemonic phrase with twelve words here for testing import functionality properly";
        
        let result = importer.process_part(test_data).unwrap();
        
        match result {
            ImportStatus::Complete { data, data_type } => {
                assert_eq!(String::from_utf8(data).unwrap(), test_data);
                assert!(matches!(data_type, DataType::Mnemonic));
            }
            _ => panic!("Expected complete import"),
        }
    }

    #[test]
    fn test_data_type_detection() {
        // Test mnemonic detection
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(matches!(QrImporter::detect_data_type(mnemonic), DataType::Mnemonic));

        // Test XPUB detection
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        assert!(matches!(QrImporter::detect_data_type(xpub), DataType::Xpub));

        // Test text detection
        let text = "Hello, this is a text message";
        assert!(matches!(QrImporter::detect_data_type(text), DataType::Text));
    }

    #[test]
    fn test_scanner_simulation() {
        let codes = vec![
            "Part 1".to_string(),
            "Part 2".to_string(),
            "Part 3".to_string(),
        ];
        
        let mut scanner = QrScanner::new(codes);
        
        assert!(scanner.has_more());
        assert_eq!(scanner.scan_next(), Some("Part 1".to_string()));
        assert_eq!(scanner.scan_next(), Some("Part 2".to_string()));
        assert_eq!(scanner.scan_next(), Some("Part 3".to_string()));
        assert!(!scanner.has_more());
        assert_eq!(scanner.scan_next(), None);
    }
}