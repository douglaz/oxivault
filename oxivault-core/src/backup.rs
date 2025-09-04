//! Secure Backup and Recovery Module
//! 
//! Provides encrypted backup functionality for hardware wallets
//! Supporting both SD card and QR code backup methods

use bitcoin::bip32::{Xpriv, Fingerprint};
use bitcoin::secp256k1::Secp256k1;
use crate::{Result, Error, entropy::get_hardware_entropy};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format};
#[cfg(feature = "std")]
use std::format;

/// AES-256-GCM for encryption (simplified for demo)
type HmacSha256 = Hmac<Sha256>;

/// Backup format version
const BACKUP_VERSION: u8 = 1;

/// Magic bytes for backup file identification
const MAGIC_BYTES: [u8; 4] = [0x49, 0x52, 0x4F, 0x4E]; // "IRON"

/// Backup container structure
#[derive(Debug, Clone)]
pub struct BackupContainer {
    /// Version of the backup format
    pub version: u8,
    /// Master fingerprint for identification
    pub fingerprint: Fingerprint,
    /// Encrypted seed data
    pub encrypted_seed: Vec<u8>,
    /// Authentication tag
    pub auth_tag: [u8; 32],
    /// Salt for key derivation
    pub salt: [u8; 32],
    /// Iteration count for PBKDF2
    pub iterations: u32,
    /// Timestamp of backup creation
    pub timestamp: u64,
    /// Optional metadata
    pub metadata: BackupMetadata,
}

/// Backup metadata
#[derive(Debug, Clone)]
pub struct BackupMetadata {
    /// Wallet name
    pub name: String,
    /// BIP32 derivation paths used
    pub derivation_paths: Vec<String>,
    /// Network (Bitcoin, Testnet)
    pub network: String,
    /// Backup sequence number
    pub sequence: u32,
}

/// Backup manager for creating and restoring backups
pub struct BackupManager {
    /// Current backup sequence
    sequence: u32,
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new() -> Self {
        Self { sequence: 0 }
    }
    
    /// Create an encrypted backup of the wallet
    pub fn create_backup(
        &mut self,
        xpriv: &Xpriv,
        passphrase: &str,
        metadata: BackupMetadata,
    ) -> Result<BackupContainer> {
        // Generate random salt
        let mut salt = [0u8; 32];
        get_hardware_entropy(&mut salt)?;
        
        // Derive encryption key from passphrase using PBKDF2
        let iterations = 100_000;
        let key = Self::derive_key(passphrase.as_bytes(), &salt, iterations);
        
        // Serialize the private key
        let seed_data = xpriv.encode();
        
        // Encrypt seed data (simplified - real implementation needs AES-GCM)
        let encrypted_seed = Self::encrypt_data(&seed_data, &key)?;
        
        // Generate authentication tag
        let auth_tag = Self::generate_auth_tag(&encrypted_seed, &key);
        
        self.sequence += 1;
        
        let secp = Secp256k1::new();
        
        Ok(BackupContainer {
            version: BACKUP_VERSION,
            fingerprint: xpriv.fingerprint(&secp),
            encrypted_seed,
            auth_tag,
            salt,
            iterations,
            timestamp: Self::current_timestamp(),
            metadata,
        })
    }
    
    /// Restore wallet from backup
    pub fn restore_backup(
        &self,
        container: &BackupContainer,
        passphrase: &str,
    ) -> Result<Xpriv> {
        // Check version compatibility
        if container.version != BACKUP_VERSION {
            return Err(Error::BackupError(format!(
                "Unsupported backup version: {}",
                container.version
            )));
        }
        
        // Derive decryption key
        let key = Self::derive_key(
            passphrase.as_bytes(),
            &container.salt,
            container.iterations,
        );
        
        // Verify authentication tag
        let expected_tag = Self::generate_auth_tag(&container.encrypted_seed, &key);
        if expected_tag != container.auth_tag {
            return Err(Error::BackupError("Invalid passphrase or corrupted backup".to_string()));
        }
        
        // Decrypt seed data
        let seed_data = Self::decrypt_data(&container.encrypted_seed, &key)?;
        
        // Reconstruct extended private key
        let xpriv = Xpriv::decode(&seed_data)
            .map_err(|e| Error::BackupError(format!("Failed to restore key: {:?}", e)))?;
        
        // Verify fingerprint matches
        let secp = Secp256k1::new();
        if xpriv.fingerprint(&secp) != container.fingerprint {
            return Err(Error::BackupError("Fingerprint mismatch after restore".to_string()));
        }
        
        Ok(xpriv)
    }
    
    /// Derive encryption key using PBKDF2
    fn derive_key(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        // Simplified PBKDF2 - real implementation needs proper PBKDF2
        let mut hasher = Sha256::new();
        hasher.update(passphrase);
        hasher.update(salt);
        
        let mut result = hasher.finalize();
        for _ in 1..iterations {
            let mut hasher = Sha256::new();
            hasher.update(&result);
            result = hasher.finalize();
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }
    
    /// Encrypt data (simplified XOR for demo - use AES-GCM in production)
    fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        let mut encrypted = Vec::with_capacity(data.len());
        for (i, byte) in data.iter().enumerate() {
            encrypted.push(byte ^ key[i % 32]);
        }
        Ok(encrypted)
    }
    
    /// Decrypt data (simplified XOR for demo - use AES-GCM in production)
    fn decrypt_data(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        Self::encrypt_data(encrypted, key) // XOR is symmetric
    }
    
    /// Generate authentication tag using HMAC-SHA256
    fn generate_auth_tag(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result.into_bytes());
        tag
    }
    
    /// Get current timestamp (simplified)
    fn current_timestamp() -> u64 {
        // In embedded, this would come from RTC or be user-provided
        1700000000
    }
}

/// SD Card backup interface
pub struct SdCardBackup {
    /// Path to backup directory
    path: String,
}

impl SdCardBackup {
    /// Create new SD card backup interface
    pub fn new(path: String) -> Self {
        Self { path }
    }
    
    /// Write backup to SD card
    pub async fn write_backup(&self, container: &BackupContainer) -> Result<()> {
        let data = self.serialize_container(container)?;
        
        // In real implementation, write to SD card via HAL
        // For now, just validate the data
        if data.len() > 1024 * 1024 {
            return Err(Error::BackupError("Backup too large".to_string()));
        }
        
        Ok(())
    }
    
    /// Read backup from SD card
    pub async fn read_backup(&self, filename: &str) -> Result<BackupContainer> {
        // In real implementation, read from SD card via HAL
        // For now, return error
        Err(Error::BackupError("SD card read not implemented".to_string()))
    }
    
    /// List available backups
    pub async fn list_backups(&self) -> Result<Vec<String>> {
        // In real implementation, list files from SD card
        Ok(Vec::new())
    }
    
    /// Delete backup file
    pub async fn delete_backup(&self, filename: &str) -> Result<()> {
        // In real implementation, delete from SD card
        Ok(())
    }
    
    /// Serialize backup container
    fn serialize_container(&self, container: &BackupContainer) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        // Write magic bytes
        data.extend_from_slice(&MAGIC_BYTES);
        
        // Write version
        data.push(container.version);
        
        // Write fingerprint
        data.extend_from_slice(&container.fingerprint.to_bytes());
        
        // Write salt
        data.extend_from_slice(&container.salt);
        
        // Write iterations (big endian)
        data.extend_from_slice(&container.iterations.to_be_bytes());
        
        // Write timestamp (big endian)
        data.extend_from_slice(&container.timestamp.to_be_bytes());
        
        // Write encrypted seed length and data
        let seed_len = container.encrypted_seed.len() as u32;
        data.extend_from_slice(&seed_len.to_be_bytes());
        data.extend_from_slice(&container.encrypted_seed);
        
        // Write auth tag
        data.extend_from_slice(&container.auth_tag);
        
        // Write metadata (simplified - JSON in production)
        let metadata_bytes = container.metadata.name.as_bytes();
        data.extend_from_slice(&(metadata_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(metadata_bytes);
        
        Ok(data)
    }
    
    /// Deserialize backup container
    fn deserialize_container(&self, data: &[u8]) -> Result<BackupContainer> {
        if data.len() < 100 {
            return Err(Error::BackupError("Invalid backup data".to_string()));
        }
        
        // Check magic bytes
        if &data[0..4] != &MAGIC_BYTES {
            return Err(Error::BackupError("Invalid backup format".to_string()));
        }
        
        // Parse fields (simplified)
        // Real implementation needs proper parsing with bounds checking
        
        Err(Error::BackupError("Deserialization not fully implemented".to_string()))
    }
}

/// QR code backup for paper storage
pub struct QrBackup;

impl QrBackup {
    /// Generate QR codes for backup (using BBQr format)
    pub fn generate_qr_codes(container: &BackupContainer, max_qr_size: usize) -> Result<Vec<Vec<u8>>> {
        // Serialize container
        let sd_backup = SdCardBackup::new(String::new());
        let data = sd_backup.serialize_container(container)?;
        
        // Split into chunks for QR codes
        let chunks: Vec<&[u8]> = data.chunks(max_qr_size).collect();
        let total_chunks = chunks.len();
        let mut qr_codes = Vec::new();
        
        for (i, chunk) in chunks.into_iter().enumerate() {
            // Add header with sequence info
            let mut qr_data = Vec::new();
            qr_data.push((i as u8) | 0x80); // Set high bit for backup QR
            qr_data.push(total_chunks as u8);
            qr_data.extend_from_slice(chunk);
            qr_codes.push(qr_data);
        }
        
        Ok(qr_codes)
    }
    
    /// Restore from QR codes
    pub fn restore_from_qr(qr_codes: Vec<Vec<u8>>) -> Result<BackupContainer> {
        // Sort QR codes by sequence number
        let mut sorted_codes = qr_codes;
        sorted_codes.sort_by_key(|qr| qr[0] & 0x7F);
        
        // Reconstruct data
        let mut data = Vec::new();
        for qr in sorted_codes {
            if qr.len() < 3 {
                return Err(Error::BackupError("Invalid QR code data".to_string()));
            }
            data.extend_from_slice(&qr[2..]);
        }
        
        // Deserialize
        let sd_backup = SdCardBackup::new(String::new());
        sd_backup.deserialize_container(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::Network;
    use bitcoin::secp256k1::Secp256k1;
    
    #[test]
    fn test_backup_creation() {
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();
        let mut manager = BackupManager::new();
        
        let metadata = BackupMetadata {
            name: "Test Wallet".to_string(),
            derivation_paths: vec!["m/84'/0'/0'".to_string()],
            network: "bitcoin".to_string(),
            sequence: 1,
        };
        
        let backup = manager.create_backup(&xpriv, "test_password", metadata).unwrap();
        assert_eq!(backup.version, BACKUP_VERSION);
        let secp = Secp256k1::new();
        assert_eq!(backup.fingerprint, xpriv.fingerprint(&secp));
    }
    
    #[test]
    fn test_backup_restore() {
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();
        let mut manager = BackupManager::new();
        
        let metadata = BackupMetadata {
            name: "Test Wallet".to_string(),
            derivation_paths: vec!["m/84'/0'/0'".to_string()],
            network: "bitcoin".to_string(),
            sequence: 1,
        };
        
        let backup = manager.create_backup(&xpriv, "test_password", metadata).unwrap();
        let restored = manager.restore_backup(&backup, "test_password").unwrap();
        
        let secp = Secp256k1::new();
        assert_eq!(restored.fingerprint(&secp), xpriv.fingerprint(&secp));
        assert_eq!(restored.encode(), xpriv.encode());
    }
    
    #[test]
    fn test_wrong_passphrase() {
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();
        let mut manager = BackupManager::new();
        
        let metadata = BackupMetadata {
            name: "Test Wallet".to_string(),
            derivation_paths: vec![],
            network: "bitcoin".to_string(),
            sequence: 1,
        };
        
        let backup = manager.create_backup(&xpriv, "correct_password", metadata).unwrap();
        let result = manager.restore_backup(&backup, "wrong_password");
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid passphrase"));
    }
}