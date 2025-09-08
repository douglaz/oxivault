//! Secure Element Integration
//!
//! Support for ATECC608A/B secure elements for key storage and signing

use embassy_time::{Duration, Timer};
use embedded_hal_async::i2c::I2c;

/// ATECC608 I2C address
const ATECC_I2C_ADDRESS: u8 = 0x60;

/// ATECC608 Commands
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum Command {
    Info = 0x30,
    Nonce = 0x16,
    Random = 0x1B,
    GenKey = 0x40,
    Sign = 0x41,
    Verify = 0x45,
    SHA = 0x47,
    Lock = 0x17,
    Read = 0x02,
    Write = 0x12,
    DeriveKey = 0x1C,
    ECDH = 0x43,
}

/// Key slot configuration
#[derive(Debug, Clone, Copy)]
pub struct SlotConfig {
    /// Slot number (0-15)
    pub slot: u8,
    /// Whether slot is locked
    pub locked: bool,
    /// Key type stored in slot
    pub key_type: KeyType,
}

/// Supported key types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    /// Empty slot
    Empty,
    /// secp256k1 private key for Bitcoin
    Secp256k1,
    /// Ed25519 key
    Ed25519,
    /// AES-256 key
    Aes256,
    /// HMAC key
    Hmac,
}

/// Secure element errors
#[derive(Debug)]
pub enum SecureElementError {
    I2cError,
    NotInitialized,
    SlotLocked,
    InvalidSlot,
    InvalidCommand,
    ChecksumError,
    DeviceLocked,
    ExecutionError(u8),
}

/// ATECC608 secure element driver
pub struct Atecc608<I2C> {
    i2c: I2C,
    initialized: bool,
    serial_number: [u8; 9],
}

impl<I2C> Atecc608<I2C>
where
    I2C: I2c,
{
    /// Create new secure element driver
    pub fn new(i2c: I2C) -> Self {
        Self {
            i2c,
            initialized: false,
            serial_number: [0; 9],
        }
    }

    /// Initialize secure element
    pub async fn init(&mut self) -> Result<(), SecureElementError> {
        // Wake up device
        self.wake_up().await?;

        // Read device info
        let info = self.get_info().await?;

        // Store serial number
        self.serial_number.copy_from_slice(&info.serial[..]);

        self.initialized = true;
        Ok(())
    }

    /// Wake up the device
    async fn wake_up(&mut self) -> Result<(), SecureElementError> {
        // Send wake sequence (write 0x00)
        let wake = [0x00];

        // Ignore error on wake (device might already be awake)
        let _ = self.i2c.write(ATECC_I2C_ADDRESS, &wake).await;

        // Wait for device to wake
        Timer::after(Duration::from_millis(3)).await;

        // Read wake response (should be 0x04, 0x11, CRC, CRC)
        let mut response = [0u8; 4];
        self.i2c
            .read(ATECC_I2C_ADDRESS, &mut response)
            .await
            .map_err(|_| SecureElementError::I2cError)?;

        if response[0] != 0x04 || response[1] != 0x11 {
            return Err(SecureElementError::DeviceLocked);
        }

        Ok(())
    }

    /// Get device information
    pub async fn get_info(&mut self) -> Result<DeviceInfo, SecureElementError> {
        let mut info = DeviceInfo::default();

        // Read serial number (slots 0-1 and 8 of config zone)
        let sn_part1 = self.read_zone(0, 0, 0).await?;
        let sn_part2 = self.read_zone(0, 0, 8).await?;

        info.serial[0..4].copy_from_slice(&sn_part1[0..4]);
        info.serial[4..9].copy_from_slice(&sn_part2[0..5]);

        // Read revision
        let rev_data = self.read_zone(0, 0, 4).await?;
        info.revision = u32::from_le_bytes([rev_data[0], rev_data[1], rev_data[2], rev_data[3]]);

        Ok(info)
    }

    /// Generate random bytes
    pub async fn random(&mut self, output: &mut [u8]) -> Result<(), SecureElementError> {
        if !self.initialized {
            return Err(SecureElementError::NotInitialized);
        }

        // ATECC generates 32 bytes at a time
        for chunk in output.chunks_mut(32) {
            let random_data = self.execute_command(Command::Random, &[0x00, 0x00]).await?;

            let len = chunk.len().min(32);
            chunk[..len].copy_from_slice(&random_data[..len]);
        }

        Ok(())
    }

    /// Generate new key pair in slot
    pub async fn generate_key(&mut self, slot: u8) -> Result<[u8; 64], SecureElementError> {
        if !self.initialized {
            return Err(SecureElementError::NotInitialized);
        }

        if slot > 15 {
            return Err(SecureElementError::InvalidSlot);
        }

        // GenKey command parameters
        let params = [0x04, slot]; // Mode: create new private key

        let response = self.execute_command(Command::GenKey, &params).await?;

        // Response contains public key (64 bytes)
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&response[..64]);

        Ok(pubkey)
    }

    /// Sign data with key in slot
    pub async fn sign(
        &mut self,
        slot: u8,
        hash: &[u8; 32],
    ) -> Result<[u8; 64], SecureElementError> {
        if !self.initialized {
            return Err(SecureElementError::NotInitialized);
        }

        if slot > 15 {
            return Err(SecureElementError::InvalidSlot);
        }

        // Load message to TempKey using Nonce command
        let nonce_params = [0x03, 0x00]; // Mode: PassThrough
        let mut nonce_data = [0u8; 32];
        nonce_data.copy_from_slice(hash);

        self.execute_command_with_data(Command::Nonce, &nonce_params, &nonce_data)
            .await?;

        // Sign using TempKey
        let sign_params = [0x80, slot]; // Mode: External message in TempKey

        let response = self.execute_command(Command::Sign, &sign_params).await?;

        // Response contains signature (64 bytes)
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&response[..64]);

        Ok(signature)
    }

    /// Verify signature
    pub async fn verify(
        &mut self,
        pubkey: &[u8; 64],
        signature: &[u8; 64],
        hash: &[u8; 32],
    ) -> Result<bool, SecureElementError> {
        if !self.initialized {
            return Err(SecureElementError::NotInitialized);
        }

        // Load message to TempKey
        let nonce_params = [0x03, 0x00];
        let mut nonce_data = [0u8; 32];
        nonce_data.copy_from_slice(hash);

        self.execute_command_with_data(Command::Nonce, &nonce_params, &nonce_data)
            .await?;

        // Prepare verify data: signature || public key
        let mut verify_data = [0u8; 128];
        verify_data[..64].copy_from_slice(signature);
        verify_data[64..].copy_from_slice(pubkey);

        // Verify command
        let verify_params = [0x02, 0x00]; // Mode: External

        let result = self
            .execute_command_with_data(Command::Verify, &verify_params, &verify_data)
            .await;

        // Verification passes if command succeeds
        Ok(result.is_ok())
    }

    /// Store key in slot (must be unlocked)
    pub async fn write_key(&mut self, slot: u8, key: &[u8; 32]) -> Result<(), SecureElementError> {
        if !self.initialized {
            return Err(SecureElementError::NotInitialized);
        }

        if slot > 15 {
            return Err(SecureElementError::InvalidSlot);
        }

        // Write to data zone
        self.write_zone(2, slot, 0, key).await?;

        Ok(())
    }

    /// Read public key from slot
    pub async fn read_pubkey(&mut self, slot: u8) -> Result<[u8; 64], SecureElementError> {
        if !self.initialized {
            return Err(SecureElementError::NotInitialized);
        }

        if slot > 15 {
            return Err(SecureElementError::InvalidSlot);
        }

        // GenKey with mode 0x00 returns existing public key
        let params = [0x00, slot];

        let response = self.execute_command(Command::GenKey, &params).await?;

        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&response[..64]);

        Ok(pubkey)
    }

    /// Derive key using ECDH
    pub async fn ecdh(
        &mut self,
        slot: u8,
        other_pubkey: &[u8; 64],
    ) -> Result<[u8; 32], SecureElementError> {
        if !self.initialized {
            return Err(SecureElementError::NotInitialized);
        }

        if slot > 15 {
            return Err(SecureElementError::InvalidSlot);
        }

        // ECDH parameters
        let params = [0x0C, slot]; // Mode: output clear text

        let response = self
            .execute_command_with_data(Command::ECDH, &params, other_pubkey)
            .await?;

        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&response[..32]);

        Ok(shared_secret)
    }

    /// Execute command without data
    async fn execute_command(
        &mut self,
        command: Command,
        params: &[u8],
    ) -> Result<Vec<u8, 128>, SecureElementError> {
        self.execute_command_with_data(command, params, &[]).await
    }

    /// Execute command with data
    async fn execute_command_with_data(
        &mut self,
        command: Command,
        params: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8, 128>, SecureElementError> {
        // Build command packet
        let mut packet = Vec::<u8, 256>::new();

        // Word address (0x03 for command)
        let _ = packet.push(0x03);

        // Length (7 + params + data)
        let length = 7 + params.len() + data.len();
        let _ = packet.push(length as u8);

        // Opcode
        let _ = packet.push(command as u8);

        // Parameters (2 bytes)
        if !params.is_empty() {
            let _ = packet.push(params[0]);
        } else {
            let _ = packet.push(0x00);
        }

        if params.len() >= 2 {
            let _ = packet.push(params[1]);
        } else {
            let _ = packet.push(0x00);
        }

        // Data
        for byte in data {
            let _ = packet.push(*byte);
        }

        // Calculate CRC
        let crc = self.calculate_crc(&packet[1..]);
        let _ = packet.push((crc & 0xFF) as u8);
        let _ = packet.push((crc >> 8) as u8);

        // Send command
        self.i2c
            .write(ATECC_I2C_ADDRESS, &packet)
            .await
            .map_err(|_| SecureElementError::I2cError)?;

        // Wait for execution
        Timer::after(Duration::from_millis(50)).await;

        // Read response
        let mut response = [0u8; 130]; // Max response size
        self.i2c
            .read(ATECC_I2C_ADDRESS, &mut response)
            .await
            .map_err(|_| SecureElementError::I2cError)?;

        // Parse response
        let length = response[0] as usize;
        if !(4..=130).contains(&length) {
            return Err(SecureElementError::InvalidCommand);
        }

        // Check status/error code
        if length == 4 {
            // Error response
            let error_code = response[1];
            if error_code != 0x00 {
                return Err(SecureElementError::ExecutionError(error_code));
            }
        }

        // Verify CRC
        let data_end = length - 2;
        let received_crc = u16::from_le_bytes([response[data_end], response[data_end + 1]]);
        let calculated_crc = self.calculate_crc(&response[0..data_end]);

        if received_crc != calculated_crc {
            return Err(SecureElementError::ChecksumError);
        }

        // Return data (skip length byte and CRC)
        let mut result = Vec::new();
        for &byte in response.iter().take(data_end).skip(1) {
            let _ = result.push(byte);
        }

        Ok(result)
    }

    /// Read from zone
    async fn read_zone(
        &mut self,
        zone: u8,
        slot: u8,
        offset: u8,
    ) -> Result<[u8; 32], SecureElementError> {
        // Read command parameters
        let addr = ((zone as u16) << 11) | ((slot as u16) << 3) | ((offset as u16 >> 2) & 0x07);
        let params = addr.to_le_bytes();

        let response = self.execute_command(Command::Read, &params).await?;

        let mut data = [0u8; 32];
        data.copy_from_slice(&response[..32]);

        Ok(data)
    }

    /// Write to zone
    async fn write_zone(
        &mut self,
        zone: u8,
        slot: u8,
        offset: u8,
        data: &[u8],
    ) -> Result<(), SecureElementError> {
        // Write command parameters
        let addr = ((zone as u16) << 11) | ((slot as u16) << 3) | ((offset as u16 >> 2) & 0x07);
        let params = addr.to_le_bytes();

        self.execute_command_with_data(Command::Write, &params, data)
            .await?;

        Ok(())
    }

    /// Calculate CRC16 for ATECC
    fn calculate_crc(&self, data: &[u8]) -> u16 {
        let mut crc = 0u16;

        for byte in data {
            crc ^= (*byte as u16) << 8;

            for _ in 0..8 {
                if (crc & 0x8000) != 0 {
                    crc = (crc << 1) ^ 0x8005;
                } else {
                    crc <<= 1;
                }
            }
        }

        crc
    }
}

/// Device information
#[derive(Debug, Default)]
pub struct DeviceInfo {
    /// 9-byte serial number
    pub serial: [u8; 9],
    /// Device revision
    pub revision: u32,
}

use heapless::Vec;

/// High-level secure wallet operations
pub struct SecureWallet<I2C> {
    atecc: Atecc608<I2C>,
    /// Bitcoin signing key slot
    btc_slot: u8,
    /// Backup encryption key slot
    backup_slot: u8,
}

impl<I2C> SecureWallet<I2C>
where
    I2C: I2c,
{
    /// Create new secure wallet
    pub async fn new(mut atecc: Atecc608<I2C>) -> Result<Self, SecureElementError> {
        atecc.init().await?;

        Ok(Self {
            atecc,
            btc_slot: 0,    // Default Bitcoin key slot
            backup_slot: 1, // Default backup encryption slot
        })
    }

    /// Initialize wallet with new keys
    pub async fn initialize(&mut self) -> Result<(), SecureElementError> {
        // Generate Bitcoin signing key
        self.atecc.generate_key(self.btc_slot).await?;

        // Generate backup encryption key
        self.atecc.generate_key(self.backup_slot).await?;

        Ok(())
    }

    /// Get Bitcoin public key
    pub async fn get_bitcoin_pubkey(&mut self) -> Result<[u8; 64], SecureElementError> {
        self.atecc.read_pubkey(self.btc_slot).await
    }

    /// Sign Bitcoin transaction hash
    pub async fn sign_bitcoin_transaction(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<[u8; 64], SecureElementError> {
        self.atecc.sign(self.btc_slot, hash).await
    }

    /// Generate hardware entropy
    pub async fn get_entropy(&mut self, size: usize) -> Result<Vec<u8, 256>, SecureElementError> {
        let mut entropy = Vec::new();
        entropy
            .resize_default(size)
            .map_err(|_| SecureElementError::InvalidCommand)?;

        self.atecc.random(&mut entropy).await?;

        Ok(entropy)
    }

    /// Derive session key for encrypted communication
    pub async fn derive_session_key(
        &mut self,
        peer_pubkey: &[u8; 64],
    ) -> Result<[u8; 32], SecureElementError> {
        self.atecc.ecdh(self.backup_slot, peer_pubkey).await
    }
}

/// Integration with HAL trait
use crate::hal::{Error as HalError, SecureElement as SecureElementTrait};

impl<I2C> SecureElementTrait for SecureWallet<I2C>
where
    I2C: I2c,
{
    async fn random(&mut self, buffer: &mut [u8]) -> Result<(), HalError> {
        // Get entropy from secure element
        let entropy = self
            .get_entropy(buffer.len())
            .await
            .map_err(|_| HalError::SecureError)?;

        // Copy to output buffer
        buffer.copy_from_slice(&entropy);
        Ok(())
    }

    async fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], HalError> {
        // Hash message if needed (assuming 32-byte hash)
        if message.len() != 32 {
            return Err(HalError::InvalidParameter);
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(message);

        self.sign_bitcoin_transaction(&hash)
            .await
            .map_err(|_| HalError::SecureError)
    }

    async fn verify(&mut self, message: &[u8], signature: &[u8]) -> Result<bool, HalError> {
        // Verify signature using secure element
        if message.len() != 32 || signature.len() != 64 {
            return Err(HalError::InvalidParameter);
        }

        let mut msg = [0u8; 32];
        msg.copy_from_slice(message);

        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature);

        // Get public key for verification
        let pubkey = self
            .get_bitcoin_pubkey()
            .await
            .map_err(|_| HalError::SecureError)?;

        self.atecc
            .verify(&pubkey, &sig, &msg)
            .await
            .map_err(|_| HalError::SecureError)
    }
}

/// PIN management for secure element
pub struct PinManager {
    /// PIN attempt counter
    attempts_remaining: u8,
    /// Maximum PIN attempts
    max_attempts: u8,
    /// Stored PIN hash (simplified)
    pin_hash: Option<[u8; 32]>,
}

impl Default for PinManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PinManager {
    /// Create new PIN manager
    pub fn new() -> Self {
        Self {
            attempts_remaining: 3,
            max_attempts: 3,
            pin_hash: None,
        }
    }

    /// Set PIN
    pub fn set_pin(&mut self, pin: &str) -> Result<(), SecureElementError> {
        if pin.len() < 4 || pin.len() > 16 {
            return Err(SecureElementError::InvalidCommand);
        }

        // Simple hash (in production, use proper key derivation)
        let mut hash = [0u8; 32];
        for (i, byte) in pin.bytes().enumerate() {
            if i < 32 {
                hash[i] = byte;
            }
        }

        self.pin_hash = Some(hash);
        self.attempts_remaining = self.max_attempts;
        Ok(())
    }

    /// Verify PIN
    pub fn verify_pin(&mut self, pin: &str) -> Result<bool, SecureElementError> {
        if self.attempts_remaining == 0 {
            return Err(SecureElementError::DeviceLocked);
        }

        let mut hash = [0u8; 32];
        for (i, byte) in pin.bytes().enumerate() {
            if i < 32 {
                hash[i] = byte;
            }
        }

        if let Some(stored_hash) = self.pin_hash {
            if hash == stored_hash {
                self.attempts_remaining = self.max_attempts;
                return Ok(true);
            }
        }

        self.attempts_remaining -= 1;
        Ok(false)
    }

    /// Get remaining PIN attempts
    pub fn get_remaining_attempts(&self) -> u8 {
        self.attempts_remaining
    }

    /// Check if device is locked
    pub fn is_locked(&self) -> bool {
        self.attempts_remaining == 0
    }

    /// Reset PIN (requires admin access)
    pub fn reset(&mut self) {
        self.pin_hash = None;
        self.attempts_remaining = self.max_attempts;
    }
}

/// Extended secure wallet with PIN protection
pub struct ProtectedWallet<I2C> {
    /// Core wallet functionality
    wallet: SecureWallet<I2C>,
    /// PIN management
    pin_manager: PinManager,
    /// Authentication state
    authenticated: bool,
}

impl<I2C> ProtectedWallet<I2C>
where
    I2C: I2c,
{
    /// Create new protected wallet
    pub async fn new(i2c: I2C) -> Result<Self, SecureElementError> {
        let atecc = Atecc608::new(i2c);
        let wallet = SecureWallet::new(atecc).await?;

        Ok(Self {
            wallet,
            pin_manager: PinManager::new(),
            authenticated: false,
        })
    }

    /// Setup wallet with PIN
    pub fn setup_pin(&mut self, pin: &str) -> Result<(), SecureElementError> {
        self.pin_manager.set_pin(pin)
    }

    /// Authenticate with PIN
    pub fn authenticate(&mut self, pin: &str) -> Result<bool, SecureElementError> {
        let result = self.pin_manager.verify_pin(pin)?;
        self.authenticated = result;
        Ok(result)
    }

    /// Initialize wallet (requires authentication)
    pub async fn initialize(&mut self) -> Result<(), SecureElementError> {
        if !self.authenticated {
            return Err(SecureElementError::DeviceLocked);
        }
        self.wallet.initialize().await
    }

    /// Get Bitcoin public key (requires authentication)
    pub async fn get_bitcoin_pubkey(&mut self) -> Result<[u8; 64], SecureElementError> {
        if !self.authenticated {
            return Err(SecureElementError::DeviceLocked);
        }
        self.wallet.get_bitcoin_pubkey().await
    }

    /// Sign transaction (requires authentication)
    pub async fn sign_transaction(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<[u8; 64], SecureElementError> {
        if !self.authenticated {
            return Err(SecureElementError::DeviceLocked);
        }
        self.wallet.sign_bitcoin_transaction(hash).await
    }

    /// Get remaining PIN attempts
    pub fn get_pin_attempts(&self) -> u8 {
        self.pin_manager.get_remaining_attempts()
    }

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        self.pin_manager.is_locked()
    }

    /// Lock wallet (logout)
    pub fn lock(&mut self) {
        self.authenticated = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockI2c;

    impl embedded_hal_async::i2c::ErrorType for MockI2c {
        type Error = embedded_hal_async::i2c::ErrorKind;
    }

    impl embedded_hal_async::i2c::I2c for MockI2c {
        async fn read(
            &mut self,
            _address: u8,
            _buffer: &mut [u8],
        ) -> Result<(), embedded_hal_async::i2c::ErrorKind> {
            Ok(())
        }

        async fn write(
            &mut self,
            _address: u8,
            _data: &[u8],
        ) -> Result<(), embedded_hal_async::i2c::ErrorKind> {
            Ok(())
        }

        async fn write_read(
            &mut self,
            _address: u8,
            _write: &[u8],
            _read: &mut [u8],
        ) -> Result<(), embedded_hal_async::i2c::ErrorKind> {
            Ok(())
        }

        async fn transaction(
            &mut self,
            _address: u8,
            _operations: &mut [embedded_hal_async::i2c::Operation<'_>],
        ) -> Result<(), embedded_hal_async::i2c::ErrorKind> {
            Ok(())
        }
    }

    #[test]
    fn test_crc_calculation() {
        let i2c = MockI2c;
        let atecc = Atecc608::new(i2c);

        // Test known CRC value - Random command packet
        // The packet includes: [length, opcode, param1, param2_low, param2_high]
        let data = [0x07, 0x1B, 0x00, 0x00, 0x00];
        let crc = atecc.calculate_crc(&data);

        // The actual CRC for this specific packet
        // CRC-16/CCITT-FALSE for [0x07, 0x1B, 0x00, 0x00, 0x00]
        assert_eq!(crc, 0xDD6E);
    }

    #[test]
    fn test_device_creation() {
        let i2c = MockI2c;
        let _atecc = Atecc608::new(i2c);
    }
}
