//! SD Card Driver using embedded-sdmmc
//!
//! Provides async SD card access for backup storage

use embassy_time::{Duration, Timer};
use embedded_hal::digital::OutputPin;
use embedded_hal_async::spi::SpiDevice;

/// SD Card driver supporting SPI mode
pub struct SdCard<SPI, CS> {
    spi: SPI,
    cs: CS,
    initialized: bool,
}

/// SD Card commands
#[repr(u8)]
#[derive(Clone, Copy)]
enum Command {
    GoIdleState = 0,       // CMD0
    SendIfCond = 8,        // CMD8
    ReadOcr = 58,          // CMD58
    AppCmd = 55,           // CMD55
    AppSendOpCond = 41,    // ACMD41
    ReadSingleBlock = 17,  // CMD17
    WriteSingleBlock = 24, // CMD24
    SetBlockLen = 16,      // CMD16
}

/// SD Card response types
#[derive(Debug)]
pub enum SdError {
    InitFailed,
    TimeoutError,
    CrcError,
    WriteProtected,
    InvalidResponse,
    CardNotReady,
    SpiError,
}

impl<SPI, CS> SdCard<SPI, CS>
where
    SPI: SpiDevice,
    CS: OutputPin,
{
    /// Create a new SD card driver
    pub fn new(spi: SPI, cs: CS) -> Self {
        Self {
            spi,
            cs,
            initialized: false,
        }
    }

    /// Initialize the SD card
    pub async fn init(&mut self) -> Result<(), SdError> {
        // Start with CS high
        self.cs.set_high().map_err(|_| SdError::SpiError)?;

        // Send 80 clock pulses with CS high to initialize
        let dummy = [0xFF; 10];
        self.spi
            .write(&dummy)
            .await
            .map_err(|_| SdError::SpiError)?;

        // Send CMD0 (GO_IDLE_STATE) to reset card
        self.cs.set_low().map_err(|_| SdError::SpiError)?;

        let r1 = self.send_command(Command::GoIdleState, 0).await?;
        if r1 != 0x01 {
            self.cs.set_high().map_err(|_| SdError::SpiError)?;
            return Err(SdError::InitFailed);
        }

        // Send CMD8 (SEND_IF_COND) to check SD v2
        let r7 = self.send_command_r7(Command::SendIfCond, 0x1AA).await?;
        if r7.0 != 0x01 || r7.1 != 0x1AA {
            self.cs.set_high().map_err(|_| SdError::SpiError)?;
            return Err(SdError::InitFailed);
        }

        // Send ACMD41 (SD_SEND_OP_COND) until card is ready
        let mut retry = 100;
        loop {
            // Send CMD55 (APP_CMD) first
            let r1 = self.send_command(Command::AppCmd, 0).await?;
            if r1 & 0xFE != 0 {
                self.cs.set_high().map_err(|_| SdError::SpiError)?;
                return Err(SdError::InitFailed);
            }

            // Send ACMD41 with HCS bit set (support for SDHC)
            let r1 = self
                .send_command(Command::AppSendOpCond, 0x40000000)
                .await?;

            if r1 == 0x00 {
                break; // Card is ready
            }

            if retry == 0 {
                self.cs.set_high().map_err(|_| SdError::SpiError)?;
                return Err(SdError::TimeoutError);
            }
            retry -= 1;

            Timer::after(Duration::from_millis(10)).await;
        }

        // Send CMD58 (READ_OCR) to check CCS bit
        let ocr = self.send_command_r3(Command::ReadOcr, 0).await?;
        let ccs = (ocr.1 & 0x40000000) != 0; // Card Capacity Status

        // Set block size to 512 bytes for SDSC cards
        if !ccs {
            let r1 = self.send_command(Command::SetBlockLen, 512).await?;
            if r1 != 0x00 {
                self.cs.set_high().map_err(|_| SdError::SpiError)?;
                return Err(SdError::InitFailed);
            }
        }

        self.cs.set_high().map_err(|_| SdError::SpiError)?;
        self.initialized = true;

        Ok(())
    }

    /// Read a single 512-byte block
    pub async fn read_block(&mut self, block_num: u32) -> Result<[u8; 512], SdError> {
        if !self.initialized {
            return Err(SdError::CardNotReady);
        }

        self.cs.set_low().map_err(|_| SdError::SpiError)?;

        // Send CMD17 (READ_SINGLE_BLOCK)
        let r1 = self
            .send_command(Command::ReadSingleBlock, block_num)
            .await?;
        if r1 != 0x00 {
            self.cs.set_high().map_err(|_| SdError::SpiError)?;
            return Err(SdError::InvalidResponse);
        }

        // Wait for data token (0xFE)
        let mut retry = 100;
        loop {
            let mut buf = [0xFF];
            self.spi
                .transfer_in_place(&mut buf)
                .await
                .map_err(|_| SdError::SpiError)?;

            if buf[0] == 0xFE {
                break; // Data token received
            }

            if retry == 0 {
                self.cs.set_high().map_err(|_| SdError::SpiError)?;
                return Err(SdError::TimeoutError);
            }
            retry -= 1;

            Timer::after(Duration::from_micros(100)).await;
        }

        // Read 512 bytes of data
        let mut data = [0u8; 512];
        self.spi
            .read(&mut data)
            .await
            .map_err(|_| SdError::SpiError)?;

        // Read and discard 2-byte CRC
        let mut crc = [0xFF; 2];
        self.spi
            .read(&mut crc)
            .await
            .map_err(|_| SdError::SpiError)?;

        self.cs.set_high().map_err(|_| SdError::SpiError)?;

        Ok(data)
    }

    /// Write a single 512-byte block
    pub async fn write_block(&mut self, block_num: u32, data: &[u8; 512]) -> Result<(), SdError> {
        if !self.initialized {
            return Err(SdError::CardNotReady);
        }

        self.cs.set_low().map_err(|_| SdError::SpiError)?;

        // Send CMD24 (WRITE_SINGLE_BLOCK)
        let r1 = self
            .send_command(Command::WriteSingleBlock, block_num)
            .await?;
        if r1 != 0x00 {
            self.cs.set_high().map_err(|_| SdError::SpiError)?;
            return Err(SdError::InvalidResponse);
        }

        // Send data token (0xFE)
        let token = [0xFE];
        self.spi
            .write(&token)
            .await
            .map_err(|_| SdError::SpiError)?;

        // Send 512 bytes of data
        self.spi.write(data).await.map_err(|_| SdError::SpiError)?;

        // Send dummy CRC (2 bytes)
        let crc = [0xFF, 0xFF];
        self.spi.write(&crc).await.map_err(|_| SdError::SpiError)?;

        // Read data response token
        let mut response = [0xFF];
        self.spi
            .transfer_in_place(&mut response)
            .await
            .map_err(|_| SdError::SpiError)?;

        // Check if data was accepted (xxx00101)
        if (response[0] & 0x1F) != 0x05 {
            self.cs.set_high().map_err(|_| SdError::SpiError)?;
            return Err(SdError::InvalidResponse);
        }

        // Wait for card to finish writing
        let mut retry = 1000;
        loop {
            let mut buf = [0xFF];
            self.spi
                .transfer_in_place(&mut buf)
                .await
                .map_err(|_| SdError::SpiError)?;

            if buf[0] == 0xFF {
                break; // Card is ready
            }

            if retry == 0 {
                self.cs.set_high().map_err(|_| SdError::SpiError)?;
                return Err(SdError::TimeoutError);
            }
            retry -= 1;

            Timer::after(Duration::from_millis(1)).await;
        }

        self.cs.set_high().map_err(|_| SdError::SpiError)?;

        Ok(())
    }

    /// Send a command and receive R1 response
    async fn send_command(&mut self, cmd: Command, arg: u32) -> Result<u8, SdError> {
        // Command format: 01cccccc (0x40 | cmd)
        let cmd_byte = 0x40 | (cmd as u8);

        // Build command packet
        let mut packet = [0u8; 6];
        packet[0] = cmd_byte;
        packet[1] = (arg >> 24) as u8;
        packet[2] = (arg >> 16) as u8;
        packet[3] = (arg >> 8) as u8;
        packet[4] = arg as u8;

        // Calculate CRC (only needed for CMD0 and CMD8)
        packet[5] = match cmd {
            Command::GoIdleState => 0x95, // Pre-calculated CRC for CMD0
            Command::SendIfCond => 0x87,  // Pre-calculated CRC for CMD8 with arg 0x1AA
            _ => 0x01,                    // Dummy CRC
        };

        // Send command
        self.spi
            .write(&packet)
            .await
            .map_err(|_| SdError::SpiError)?;

        // Wait for response (up to 8 bytes)
        for _ in 0..8 {
            let mut response = [0xFF];
            self.spi
                .transfer_in_place(&mut response)
                .await
                .map_err(|_| SdError::SpiError)?;

            if (response[0] & 0x80) == 0 {
                return Ok(response[0]);
            }
        }

        Err(SdError::TimeoutError)
    }

    /// Send command and receive R3 response (R1 + 4 bytes)
    async fn send_command_r3(&mut self, cmd: Command, arg: u32) -> Result<(u8, u32), SdError> {
        let r1 = self.send_command(cmd, arg).await?;

        // Read 4 additional bytes
        let mut ocr = [0u8; 4];
        self.spi
            .read(&mut ocr)
            .await
            .map_err(|_| SdError::SpiError)?;

        let ocr_value = u32::from_be_bytes(ocr);
        Ok((r1, ocr_value))
    }

    /// Send command and receive R7 response (R1 + 4 bytes)
    async fn send_command_r7(&mut self, cmd: Command, arg: u32) -> Result<(u8, u32), SdError> {
        let r1 = self.send_command(cmd, arg).await?;

        // Read 4 additional bytes
        let mut data = [0u8; 4];
        self.spi
            .read(&mut data)
            .await
            .map_err(|_| SdError::SpiError)?;

        let value = u32::from_be_bytes(data);
        Ok((r1, value))
    }
}

/// High-level file operations for SD card
pub struct SdFileSystem<SPI, CS> {
    sd: SdCard<SPI, CS>,
}

impl<SPI, CS> SdFileSystem<SPI, CS>
where
    SPI: SpiDevice,
    CS: OutputPin,
{
    /// Create a new file system on SD card
    pub async fn new(mut sd: SdCard<SPI, CS>) -> Result<Self, SdError> {
        sd.init().await?;
        Ok(Self { sd })
    }

    /// Save wallet backup to SD card
    pub async fn save_backup(&mut self, slot: u8, data: &[u8]) -> Result<(), SdError> {
        // Simple allocation: slot 0-15, each gets 16 blocks (8KB)
        let base_block = (slot as u32) * 16;

        // Write size header in first block
        let mut header_block = [0u8; 512];
        let size = data.len() as u32;
        header_block[0..4].copy_from_slice(&size.to_le_bytes());
        header_block[4] = 0x42; // Magic byte 'B'
        header_block[5] = 0x55; // Magic byte 'U'
        self.sd.write_block(base_block, &header_block).await?;

        // Write data blocks
        for (i, chunk) in data.chunks(512).enumerate() {
            let mut block = [0u8; 512];
            block[..chunk.len()].copy_from_slice(chunk);
            self.sd
                .write_block(base_block + 1 + i as u32, &block)
                .await?;
        }

        Ok(())
    }

    /// Load wallet backup from SD card
    pub async fn load_backup(&mut self, slot: u8) -> Result<heapless::Vec<u8, 8192>, SdError> {
        let base_block = (slot as u32) * 16;

        // Read header block
        let header_block = self.sd.read_block(base_block).await?;

        // Check magic bytes
        if header_block[4] != 0x42 || header_block[5] != 0x55 {
            return Err(SdError::InvalidResponse);
        }

        // Get size
        let size = u32::from_le_bytes([
            header_block[0],
            header_block[1],
            header_block[2],
            header_block[3],
        ]) as usize;

        if size > 8192 {
            return Err(SdError::InvalidResponse);
        }

        // Read data blocks
        let mut result = heapless::Vec::new();
        let blocks_needed = size.div_ceil(512);

        for i in 0..blocks_needed {
            let block = self.sd.read_block(base_block + 1 + i as u32).await?;
            let bytes_to_copy = core::cmp::min(512, size - result.len());
            for &byte in block.iter().take(bytes_to_copy) {
                let _ = result.push(byte);
            }
        }

        Ok(result)
    }

    /// List available backup slots
    pub async fn list_backups(&mut self) -> Result<[bool; 16], SdError> {
        let mut slots = [false; 16];

        for (slot, slot_status) in slots.iter_mut().enumerate() {
            let base_block = (slot as u32) * 16;
            let header_block = self.sd.read_block(base_block).await?;

            // Check magic bytes
            if header_block[4] == 0x42 && header_block[5] == 0x55 {
                *slot_status = true;
            }
        }

        Ok(slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock types for testing
    struct MockSpi;
    struct MockPin;

    impl embedded_hal::spi::ErrorType for MockSpi {
        type Error = embedded_hal_async::spi::ErrorKind;
    }

    impl embedded_hal_async::spi::SpiDevice for MockSpi {
        async fn transaction(
            &mut self,
            _operations: &mut [embedded_hal_async::spi::Operation<'_, u8>],
        ) -> Result<(), embedded_hal_async::spi::ErrorKind> {
            // Mock implementation - process operations sequentially
            for _op in _operations.iter_mut() {
                // In a real implementation, would handle Read/Write operations
                // For testing, just return success
            }
            Ok(())
        }

        async fn read(
            &mut self,
            _buf: &mut [u8],
        ) -> Result<(), embedded_hal_async::spi::ErrorKind> {
            Ok(())
        }

        async fn write(&mut self, _buf: &[u8]) -> Result<(), embedded_hal_async::spi::ErrorKind> {
            Ok(())
        }

        async fn transfer(
            &mut self,
            _read: &mut [u8],
            _write: &[u8],
        ) -> Result<(), embedded_hal_async::spi::ErrorKind> {
            Ok(())
        }

        async fn transfer_in_place(
            &mut self,
            _buf: &mut [u8],
        ) -> Result<(), embedded_hal_async::spi::ErrorKind> {
            Ok(())
        }
    }

    impl embedded_hal::digital::ErrorType for MockPin {
        type Error = core::convert::Infallible;
    }

    impl embedded_hal::digital::OutputPin for MockPin {
        fn set_high(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn set_low(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_sd_card_creation() {
        let spi = MockSpi;
        let cs = MockPin;
        let _sd = SdCard::new(spi, cs);
    }
}
