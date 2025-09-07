//! Secure Backup and Recovery Module
//!
//! Provides encrypted backup functionality for hardware wallets
//! Supporting both SD card and QR code backup methods

use crate::{entropy::get_hardware_entropy, Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use bitcoin::bip32::{Fingerprint, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
#[cfg(feature = "std")]
use std::{
    format,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

/// AES-256-GCM for encryption (simplified for demo)
#[allow(dead_code)]
type HmacSha256 = Hmac<Sha256>;

/// Backup format version
const BACKUP_VERSION: u8 = 1;

/// Magic bytes for backup file identification
const MAGIC_BYTES: [u8; 4] = [0x4F, 0x58, 0x49, 0x56]; // "OXIV"

/// Backup container structure
#[derive(Debug, Clone)]
pub struct BackupContainer {
    /// Version of the backup format
    pub version: u8,
    /// Master fingerprint for identification
    pub fingerprint: Fingerprint,
    /// Encrypted seed data
    pub encrypted_seed: Vec<u8>,
    /// Authentication tag (from AES-GCM)
    pub auth_tag: [u8; 16],
    /// Nonce for AES-GCM encryption
    pub nonce: [u8; 12],
    /// Salt for key derivation
    pub salt: [u8; 32],
    /// Iteration count for PBKDF2
    pub iterations: u32,
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

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
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

        // Generate random nonce for AES-GCM
        let mut nonce = [0u8; 12];
        get_hardware_entropy(&mut nonce)?;

        // Derive encryption key from passphrase using PBKDF2
        let iterations = 100_000;
        let key = Self::derive_key(passphrase.as_bytes(), &salt, iterations);

        // Serialize the private key
        let seed_data = xpriv.encode();

        // Encrypt seed data using AES-256-GCM
        let (encrypted_seed, auth_tag) = Self::encrypt_data(&seed_data, &key, &nonce)?;

        self.sequence += 1;

        let secp = Secp256k1::new();

        Ok(BackupContainer {
            version: BACKUP_VERSION,
            fingerprint: xpriv.fingerprint(&secp),
            encrypted_seed,
            auth_tag,
            nonce,
            salt,
            iterations,
            metadata,
        })
    }

    /// Restore wallet from backup
    pub fn restore_backup(&self, container: &BackupContainer, passphrase: &str) -> Result<Xpriv> {
        // Check version compatibility
        if container.version != BACKUP_VERSION {
            return Err(Error::BackupError(format!(
                "Unsupported backup version: {}",
                container.version
            )));
        }

        // Derive decryption key
        let key = Self::derive_key(passphrase.as_bytes(), &container.salt, container.iterations);

        // Decrypt seed data with authentication
        let seed_data = Self::decrypt_data(
            &container.encrypted_seed,
            &key,
            &container.nonce,
            &container.auth_tag,
        )?;

        // Reconstruct extended private key
        let xpriv = Xpriv::decode(&seed_data)
            .map_err(|e| Error::BackupError(format!("Failed to restore key: {:?}", e)))?;

        // Verify fingerprint matches
        let secp = Secp256k1::new();
        if xpriv.fingerprint(&secp) != container.fingerprint {
            return Err(Error::BackupError(
                "Fingerprint mismatch after restore".to_string(),
            ));
        }

        Ok(xpriv)
    }

    /// Derive encryption key using PBKDF2
    fn derive_key(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut key);
        key
    }

    /// Encrypt data using AES-256-GCM
    fn encrypt_data(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<(Vec<u8>, [u8; 16])> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| Error::BackupError(format!("Encryption failed: {e}")))?;

        // AES-GCM appends the auth tag to the ciphertext
        // We need to separate them
        let (encrypted, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(tag);

        Ok((encrypted.to_vec(), auth_tag))
    }

    /// Decrypt data using AES-256-GCM
    fn decrypt_data(
        encrypted: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
        auth_tag: &[u8; 16],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);

        // Reconstruct the ciphertext with auth tag
        let mut ciphertext = encrypted.to_vec();
        ciphertext.extend_from_slice(auth_tag);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| Error::BackupError(format!("Decryption failed: {e}")))?;

        Ok(plaintext)
    }

    /// Generate authentication tag using HMAC-SHA256
    #[allow(dead_code)]
    fn generate_auth_tag(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result.into_bytes());
        tag
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

        // Validate backup size
        if data.len() > 1024 * 1024 {
            return Err(Error::BackupError("Backup too large".to_string()));
        }

        #[cfg(feature = "std")]
        {
            // Create backup directory if it doesn't exist
            let backup_dir = Path::new(&self.path);
            fs::create_dir_all(backup_dir).map_err(|e| {
                Error::BackupError(format!("Failed to create backup directory: {e}"))
            })?;

            // Generate filename with fingerprint and counter
            // Use a simple counter suffix to allow multiple backups
            let base_name = format!(
                "backup_{:08x}",
                u32::from_be_bytes(container.fingerprint.to_bytes())
            );

            // Find a unique filename by adding a counter if needed
            let mut filename = format!("{}.ovb", base_name);
            let mut counter = 1;
            while backup_dir.join(&filename).exists() {
                filename = format!("{}_{}.ovb", base_name, counter);
                counter += 1;
            }

            let file_path = backup_dir.join(filename);

            // Write backup data to file
            let mut file = File::create(&file_path)
                .map_err(|e| Error::BackupError(format!("Failed to create backup file: {e}")))?;

            file.write_all(&data)
                .map_err(|e| Error::BackupError(format!("Failed to write backup data: {e}")))?;

            file.sync_all()
                .map_err(|e| Error::BackupError(format!("Failed to sync backup file: {e}")))?;
        }

        #[cfg(not(feature = "std"))]
        {
            // For embedded systems, this would use HAL layer for SD card access
            // For now, just validate the data
        }

        Ok(())
    }

    /// Read backup from SD card
    pub async fn read_backup(&self, filename: &str) -> Result<BackupContainer> {
        #[cfg(feature = "std")]
        {
            let backup_dir = Path::new(&self.path);
            let file_path = backup_dir.join(filename);

            // Check if file exists
            if !file_path.exists() {
                return Err(Error::BackupError(format!(
                    "Backup file not found: {filename}"
                )));
            }

            // Read backup data from file
            let mut file = File::open(&file_path)
                .map_err(|e| Error::BackupError(format!("Failed to open backup file: {e}")))?;

            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|e| Error::BackupError(format!("Failed to read backup data: {e}")))?;

            // Deserialize the container
            self.deserialize_container(&data)
        }

        #[cfg(not(feature = "std"))]
        {
            // For embedded systems, this would use HAL layer for SD card access
            Err(Error::BackupError(
                "SD card read not available in embedded mode".to_string(),
            ))
        }
    }

    /// List available backups
    pub async fn list_backups(&self) -> Result<Vec<String>> {
        #[cfg(feature = "std")]
        {
            let backup_dir = Path::new(&self.path);

            // Create directory if it doesn't exist
            if !backup_dir.exists() {
                fs::create_dir_all(backup_dir).map_err(|e| {
                    Error::BackupError(format!("Failed to create backup directory: {e}"))
                })?;
                return Ok(Vec::new());
            }

            // List all .ovb files in the backup directory
            let mut backups = Vec::new();
            let entries = fs::read_dir(backup_dir)
                .map_err(|e| Error::BackupError(format!("Failed to read backup directory: {e}")))?;

            for entry in entries {
                let entry = entry.map_err(|e| {
                    Error::BackupError(format!("Failed to read directory entry: {e}"))
                })?;
                let path = entry.path();

                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("ovb") {
                    if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
                        backups.push(filename.to_string());
                    }
                }
            }

            // Sort by filename (which includes timestamp)
            backups.sort();
            Ok(backups)
        }

        #[cfg(not(feature = "std"))]
        {
            // For embedded systems, this would use HAL layer for SD card access
            Ok(Vec::new())
        }
    }

    /// Delete backup file
    pub async fn delete_backup(&self, filename: &str) -> Result<()> {
        #[cfg(feature = "std")]
        {
            let backup_dir = Path::new(&self.path);
            let file_path = backup_dir.join(filename);

            // Check if file exists
            if !file_path.exists() {
                return Err(Error::BackupError(format!(
                    "Backup file not found: {filename}"
                )));
            }

            // Delete the file
            fs::remove_file(&file_path)
                .map_err(|e| Error::BackupError(format!("Failed to delete backup file: {e}")))?;
        }

        #[cfg(not(feature = "std"))]
        {
            // For embedded systems, this would use HAL layer for SD card access
        }

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

        // Write nonce
        data.extend_from_slice(&container.nonce);

        // Write iterations (big endian)
        data.extend_from_slice(&container.iterations.to_be_bytes());

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
        // Minimum size check: magic(4) + version(1) + fingerprint(4) + salt(32) + nonce(12) + iterations(4) + seed_len(4) + auth_tag(16) + metadata_len(2)
        const MIN_SIZE: usize = 4 + 1 + 4 + 32 + 12 + 4 + 4 + 16 + 2;
        if data.len() < MIN_SIZE {
            return Err(Error::BackupError(format!(
                "Invalid backup data: too small ({} bytes, minimum {})",
                data.len(),
                MIN_SIZE
            )));
        }

        let mut offset = 0;

        // Check magic bytes
        if data[offset..offset + 4] != MAGIC_BYTES {
            return Err(Error::BackupError(
                "Invalid backup format: wrong magic bytes".to_string(),
            ));
        }
        offset += 4;

        // Parse version
        let version = data[offset];
        offset += 1;

        // Parse fingerprint
        let mut fingerprint_bytes = [0u8; 4];
        fingerprint_bytes.copy_from_slice(&data[offset..offset + 4]);
        let fingerprint = Fingerprint::from(fingerprint_bytes);
        offset += 4;

        // Parse salt
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Parse nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[offset..offset + 12]);
        offset += 12;

        // Parse iterations
        let iterations = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        // Parse encrypted seed length and data
        if offset + 4 > data.len() {
            return Err(Error::BackupError(
                "Invalid backup data: truncated seed length".to_string(),
            ));
        }
        let seed_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + seed_len > data.len() {
            return Err(Error::BackupError(format!(
                "Invalid backup data: seed length {} exceeds available data",
                seed_len
            )));
        }
        let encrypted_seed = data[offset..offset + seed_len].to_vec();
        offset += seed_len;

        // Parse auth tag
        if offset + 16 > data.len() {
            return Err(Error::BackupError(
                "Invalid backup data: truncated auth tag".to_string(),
            ));
        }
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        // Parse metadata length and name
        if offset + 2 > data.len() {
            return Err(Error::BackupError(
                "Invalid backup data: truncated metadata length".to_string(),
            ));
        }
        let metadata_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + metadata_len > data.len() {
            return Err(Error::BackupError(format!(
                "Invalid backup data: metadata length {} exceeds available data",
                metadata_len
            )));
        }
        let name = String::from_utf8(data[offset..offset + metadata_len].to_vec())
            .map_err(|e| Error::BackupError(format!("Invalid metadata name: {e}")))?;

        // Create metadata with defaults for missing fields
        let metadata = BackupMetadata {
            name,
            derivation_paths: Vec::new(),
            network: "bitcoin".to_string(),
            sequence: 0,
        };

        Ok(BackupContainer {
            version,
            fingerprint,
            encrypted_seed,
            auth_tag,
            nonce,
            salt,
            iterations,
            metadata,
        })
    }
}

/// QR code backup for paper storage
pub struct QrBackup;

impl QrBackup {
    /// Generate QR codes for backup (using BBQr format)
    pub fn generate_qr_codes(
        container: &BackupContainer,
        max_qr_size: usize,
    ) -> Result<Vec<Vec<u8>>> {
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
    use bitcoin::bip32::Xpriv;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::Network;

    #[test]
    fn test_backup_creation() {
        let xpriv = Xpriv::new_master(Network::Bitcoin, &[0; 32]).unwrap();
        let mut manager = BackupManager::new();

        let metadata = BackupMetadata {
            name: "Test Wallet".to_string(),
            derivation_paths: vec!["m/84'/0'/0'".to_string()],
            network: "bitcoin".to_string(),
            sequence: 1,
        };

        let backup = manager
            .create_backup(&xpriv, "test_password", metadata)
            .unwrap();
        assert_eq!(backup.version, BACKUP_VERSION);
        let secp = Secp256k1::new();
        assert_eq!(backup.fingerprint, xpriv.fingerprint(&secp));
    }

    #[test]
    fn test_backup_restore() {
        let xpriv = Xpriv::new_master(Network::Bitcoin, &[0; 32]).unwrap();
        let mut manager = BackupManager::new();

        let metadata = BackupMetadata {
            name: "Test Wallet".to_string(),
            derivation_paths: vec!["m/84'/0'/0'".to_string()],
            network: "bitcoin".to_string(),
            sequence: 1,
        };

        let backup = manager
            .create_backup(&xpriv, "test_password", metadata)
            .unwrap();
        let restored = manager.restore_backup(&backup, "test_password").unwrap();

        let secp = Secp256k1::new();
        assert_eq!(restored.fingerprint(&secp), xpriv.fingerprint(&secp));
        assert_eq!(restored.encode(), xpriv.encode());
    }

    #[test]
    fn test_wrong_passphrase() {
        let xpriv = Xpriv::new_master(Network::Bitcoin, &[0; 32]).unwrap();
        let mut manager = BackupManager::new();

        let metadata = BackupMetadata {
            name: "Test Wallet".to_string(),
            derivation_paths: vec![],
            network: "bitcoin".to_string(),
            sequence: 1,
        };

        let backup = manager
            .create_backup(&xpriv, "correct_password", metadata)
            .unwrap();
        let result = manager.restore_backup(&backup, "wrong_password");

        assert!(result.is_err());
        // AES-GCM will fail decryption with wrong passphrase
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Decryption failed"));
    }
}
