//! Secure Backup and Recovery Module
//!
//! Provides encrypted backup functionality for hardware wallets
//! Supporting both SD card and QR code backup methods

use crate::{entropy::get_hardware_entropy, Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use bitcoin::bip32::{Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
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
use std::format;

/// AES-256-GCM for encryption
type Aes256GcmType = Aes256Gcm;

/// PBKDF2 iteration count (100,000 for strong security)
const PBKDF2_ITERATIONS: u32 = 100_000;

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

/// Backup metadata for identification
#[derive(Debug, Clone)]
pub struct BackupMetadata {
    /// User-defined name for the backup
    pub name: String,
    /// Derivation paths used (for reference)
    pub derivation_paths: Vec<String>,
    /// Network (bitcoin, testnet, etc.)
    pub network: String,
    /// Backup sequence number
    pub sequence: u32,
}

/// Backup manager for creating and restoring backups
pub struct BackupManager {
    /// Secp256k1 context
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Create encrypted backup from master key
    pub fn create_backup(
        &self,
        xpriv: &Xpriv,
        passphrase: &str,
        metadata: Option<BackupMetadata>,
    ) -> Result<BackupContainer> {
        // Get master fingerprint
        let xpub = Xpub::from_priv(&self.secp, xpriv);
        let fingerprint = xpub.fingerprint();

        // Generate salt for key derivation
        let mut salt = [0u8; 32];
        get_hardware_entropy(&mut salt)?;

        // Derive encryption key from passphrase
        let key = self.derive_key(passphrase, &salt, PBKDF2_ITERATIONS);

        // Generate nonce for AES-GCM
        let mut nonce = [0u8; 12];
        get_hardware_entropy(&mut nonce)?;

        // Encrypt the seed (includes private key and chain code)
        let seed_data = xpriv.encode();
        let cipher = Aes256GcmType::new(Key::<Aes256GcmType>::from_slice(&key));
        let nonce_obj = Nonce::from_slice(&nonce);

        let encrypted = cipher
            .encrypt(nonce_obj, seed_data.as_ref())
            .map_err(|_| Error::BackupError("Encryption failed".to_string()))?;

        // Split encrypted data and auth tag
        let (encrypted_seed, auth_tag_slice) = encrypted.split_at(encrypted.len() - 16);
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(auth_tag_slice);

        // Create metadata if not provided
        let metadata = metadata.unwrap_or_else(|| BackupMetadata {
            name: "Wallet Backup".to_string(),
            derivation_paths: vec!["m/84'/0'/0'".to_string()],
            network: "bitcoin".to_string(),
            sequence: 0,
        });

        Ok(BackupContainer {
            version: BACKUP_VERSION,
            fingerprint,
            encrypted_seed: encrypted_seed.to_vec(),
            auth_tag,
            nonce,
            salt,
            iterations: PBKDF2_ITERATIONS,
            metadata,
        })
    }

    /// Restore master key from encrypted backup
    pub fn restore_backup(&self, container: &BackupContainer, passphrase: &str) -> Result<Xpriv> {
        // Validate version
        if container.version != BACKUP_VERSION {
            return Err(Error::BackupError(format!(
                "Unsupported backup version: {}",
                container.version
            )));
        }

        // Derive encryption key from passphrase
        let key = self.derive_key(passphrase, &container.salt, container.iterations);

        // Reconstruct encrypted data with auth tag
        let mut encrypted = container.encrypted_seed.clone();
        encrypted.extend_from_slice(&container.auth_tag);

        // Decrypt the seed
        let cipher = Aes256GcmType::new(Key::<Aes256GcmType>::from_slice(&key));
        let nonce = Nonce::from_slice(&container.nonce);

        let decrypted = cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| Error::BackupError("Decryption failed - wrong passphrase?".to_string()))?;

        // Parse the seed into Xpriv (includes private key and chain code)
        let xpriv = Xpriv::decode(&decrypted)
            .map_err(|e| Error::BackupError(format!("Failed to decode master key: {e}")))?;

        // Verify fingerprint matches
        let xpub = Xpub::from_priv(&self.secp, &xpriv);
        let restored_fingerprint = xpub.fingerprint();

        if restored_fingerprint != container.fingerprint {
            return Err(Error::BackupError(
                "Fingerprint mismatch - corrupted backup?".to_string(),
            ));
        }

        Ok(xpriv)
    }

    /// Derive encryption key from passphrase using PBKDF2
    fn derive_key(&self, passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
        key
    }
}

/// Serialize backup container to bytes
pub fn serialize_container(container: &BackupContainer) -> Result<Vec<u8>> {
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

/// Deserialize backup container from bytes
pub fn deserialize_container(data: &[u8]) -> Result<BackupContainer> {
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

/// QR code backup for paper storage
pub struct QrBackup;

impl QrBackup {
    /// Generate QR codes for backup (using BBQr format)
    pub fn generate_qr_codes(
        container: &BackupContainer,
        max_qr_size: usize,
    ) -> Result<Vec<Vec<u8>>> {
        // Serialize container to bytes
        let data = serialize_container(container)?;

        // For now, just split into chunks (real implementation would use BBQr)
        let chunk_size = max_qr_size.min(512);
        let mut qr_codes = Vec::new();

        for chunk in data.chunks(chunk_size) {
            qr_codes.push(chunk.to_vec());
        }

        if qr_codes.is_empty() {
            return Err(Error::BackupError(
                "Failed to generate QR codes".to_string(),
            ));
        }

        Ok(qr_codes)
    }

    /// Restore backup from QR codes
    pub fn restore_from_qr(qr_codes: Vec<Vec<u8>>) -> Result<BackupContainer> {
        // Combine all QR code data
        let mut combined = Vec::new();
        for qr_data in qr_codes {
            combined.extend_from_slice(&qr_data);
        }

        // Deserialize the container
        deserialize_container(&combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_backup_restore_cycle() -> Result<()> {
        // Create a test master key
        let seed = [0x42u8; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;

        // Create backup manager
        let manager = BackupManager::new();

        // Create backup with passphrase
        let passphrase = "test_passphrase_123";
        let metadata = BackupMetadata {
            name: "Test Wallet".to_string(),
            derivation_paths: vec!["m/84'/0'/0'".to_string()],
            network: "bitcoin".to_string(),
            sequence: 1,
        };

        let container = manager.create_backup(&xpriv, passphrase, Some(metadata))?;

        // Restore from backup
        let restored_xpriv = manager.restore_backup(&container, passphrase)?;

        // Verify they match
        assert_eq!(
            xpriv.to_priv().to_bytes(),
            restored_xpriv.to_priv().to_bytes()
        );

        Ok(())
    }

    #[test]
    fn test_wrong_passphrase_fails() -> Result<()> {
        let seed = [0x42u8; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;

        let manager = BackupManager::new();
        let container = manager.create_backup(&xpriv, "correct_pass", None)?;

        // Try to restore with wrong passphrase
        let result = manager.restore_backup(&container, "wrong_pass");
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_serialization_roundtrip() -> Result<()> {
        let seed = [0x42u8; 32];
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;

        let manager = BackupManager::new();
        let container = manager.create_backup(&xpriv, "test", None)?;

        // Serialize and deserialize
        let serialized = serialize_container(&container)?;
        let deserialized = deserialize_container(&serialized)?;

        // Check key fields match
        assert_eq!(container.version, deserialized.version);
        assert_eq!(container.fingerprint, deserialized.fingerprint);
        assert_eq!(container.salt, deserialized.salt);
        assert_eq!(container.nonce, deserialized.nonce);
        assert_eq!(container.iterations, deserialized.iterations);
        assert_eq!(container.encrypted_seed, deserialized.encrypted_seed);
        assert_eq!(container.auth_tag, deserialized.auth_tag);

        Ok(())
    }
}
