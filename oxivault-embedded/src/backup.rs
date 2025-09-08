//! Embedded Backup Module
//!
//! Integrates oxivault-core backup functionality with SD card storage

use crate::drivers::sdcard::SdFileSystem;
use alloc::{format, string::ToString, vec::Vec};
use bitcoin::bip32::Xpriv;
use core::str;
use heapless;
use oxivault_core::{
    backup::{BackupContainer, BackupManager, BackupMetadata},
    Error, Result,
};

/// Embedded backup handler that integrates BackupManager with SD card storage
pub struct EmbeddedBackup<SPI, CS> {
    manager: BackupManager,
    sd: Option<SdFileSystem<SPI, CS>>,
}

impl<SPI, CS> EmbeddedBackup<SPI, CS>
where
    SPI: embedded_hal_async::spi::SpiDevice,
    CS: embedded_hal::digital::OutputPin,
{
    /// Create a new embedded backup handler
    pub fn new(sd: Option<SdFileSystem<SPI, CS>>) -> Self {
        Self {
            manager: BackupManager::new(),
            sd,
        }
    }

    /// Save a backup to SD card
    pub async fn save_backup(
        &mut self,
        xpriv: &Xpriv,
        passphrase: &str,
        slot: u8,
        name: &str,
    ) -> Result<()> {
        // Create backup container
        let metadata = BackupMetadata {
            name: name.to_string(),
            derivation_paths: Vec::new(),
            network: "bitcoin".to_string(),
            sequence: 0,
        };

        let container = self
            .manager
            .create_backup(xpriv, passphrase, Some(metadata))?;

        // Serialize container
        let data = serialize_container(&container)?;

        // Save to SD card if available
        if let Some(sd) = &mut self.sd {
            sd.save_backup(slot, &data)
                .await
                .map_err(|e| Error::BackupError(format!("SD card write failed: {:?}", e)))?;
        } else {
            return Err(Error::BackupError("No SD card available".to_string()));
        }

        Ok(())
    }

    /// Load a backup from SD card
    pub async fn load_backup(&mut self, slot: u8) -> Result<BackupContainer> {
        if let Some(sd) = &mut self.sd {
            let data = sd
                .load_backup(slot)
                .await
                .map_err(|e| Error::BackupError(format!("SD card read failed: {:?}", e)))?;

            deserialize_container(&data)
        } else {
            Err(Error::BackupError("No SD card available".to_string()))
        }
    }

    /// Restore wallet from backup
    pub async fn restore_backup(&mut self, slot: u8, passphrase: &str) -> Result<Xpriv> {
        let container = self.load_backup(slot).await?;
        self.manager.restore_backup(&container, passphrase)
    }

    /// List available backup slots (0-15)
    pub fn list_slots() -> heapless::Vec<u8, 16> {
        let mut slots = heapless::Vec::new();
        for i in 0..16 {
            let _ = slots.push(i);
        }
        slots
    }

    /// Delete a backup from SD card (just overwrites with zeros)
    pub async fn delete_backup(&mut self, slot: u8) -> Result<()> {
        if let Some(sd) = &mut self.sd {
            // Save empty data to slot to "delete" it
            let empty = [0u8; 32];
            sd.save_backup(slot, &empty)
                .await
                .map_err(|e| Error::BackupError(format!("SD card delete failed: {:?}", e)))?;
            Ok(())
        } else {
            Err(Error::BackupError("No SD card available".to_string()))
        }
    }
}

/// Serialize backup container to bytes
fn serialize_container(container: &BackupContainer) -> Result<heapless::Vec<u8, 2048>> {
    let mut data = heapless::Vec::new();

    // Magic bytes "OXIV"
    const MAGIC_BYTES: [u8; 4] = [0x4F, 0x58, 0x49, 0x56];
    data.extend_from_slice(&MAGIC_BYTES)
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Version
    data.push(container.version)
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Fingerprint
    data.extend_from_slice(&container.fingerprint.to_bytes())
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Salt
    data.extend_from_slice(&container.salt)
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Nonce
    data.extend_from_slice(&container.nonce)
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Iterations
    data.extend_from_slice(&container.iterations.to_be_bytes())
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Encrypted seed length and data
    let seed_len = container.encrypted_seed.len() as u32;
    data.extend_from_slice(&seed_len.to_be_bytes())
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;
    data.extend_from_slice(&container.encrypted_seed)
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Auth tag
    data.extend_from_slice(&container.auth_tag)
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    // Metadata name length and data
    let name_bytes = container.metadata.name.as_bytes();
    let name_len = name_bytes.len() as u16;
    data.extend_from_slice(&name_len.to_be_bytes())
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;
    data.extend_from_slice(name_bytes)
        .map_err(|_| Error::BackupError("Buffer overflow".to_string()))?;

    Ok(data)
}

/// Deserialize backup container from bytes
fn deserialize_container(data: &[u8]) -> Result<BackupContainer> {
    // Minimum size check
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
    const MAGIC_BYTES: [u8; 4] = [0x4F, 0x58, 0x49, 0x56];
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
    let fingerprint = bitcoin::bip32::Fingerprint::from(fingerprint_bytes);
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
    let seed_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + seed_len > data.len() {
        return Err(Error::BackupError(
            "Invalid backup data: truncated seed".to_string(),
        ));
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

    // Parse metadata
    if offset + 2 > data.len() {
        return Err(Error::BackupError(
            "Invalid backup data: truncated metadata".to_string(),
        ));
    }
    let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + name_len > data.len() {
        return Err(Error::BackupError(
            "Invalid backup data: truncated name".to_string(),
        ));
    }
    let name = str::from_utf8(&data[offset..offset + name_len])
        .map_err(|_| Error::BackupError("Invalid UTF-8 in name".to_string()))?
        .to_string();

    let metadata = BackupMetadata {
        name,
        derivation_paths: alloc::vec::Vec::new(),
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
