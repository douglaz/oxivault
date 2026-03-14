//! SSD1306 OLED Display Driver
//!
//! Driver for SSD1306 128x64 OLED displays commonly used in hardware wallets
//! Supports both I2C and SPI interfaces

use embedded_graphics_core::{geometry::Size, pixelcolor::BinaryColor, prelude::*, Pixel};
use embedded_hal_async::i2c::I2c;
use heapless::Vec;

/// Display size
pub const DISPLAY_WIDTH: u32 = 128;
pub const DISPLAY_HEIGHT: u32 = 64;
pub const DISPLAY_PAGES: u8 = 8; // Height / 8

/// SSD1306 Commands
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Command {
    /// Set contrast (0x81 + value)
    SetContrast(u8),
    /// Display all on resume (0xA4)
    DisplayAllOnResume,
    /// Display all on (0xA5)
    DisplayAllOn,
    /// Normal display (0xA6)
    NormalDisplay,
    /// Inverted display (0xA7)
    InvertDisplay,
    /// Display off (0xAE)
    DisplayOff,
    /// Display on (0xAF)
    DisplayOn,
    /// Set display offset (0xD3 + value)
    SetDisplayOffset(u8),
    /// Set COM pins (0xDA + value)
    SetComPins(u8),
    /// Set VCOM deselect (0xDB + value)
    SetVcomDeselect(u8),
    /// Set display clock divide (0xD5 + value)
    SetDisplayClockDiv(u8),
    /// Set precharge (0xD9 + value)
    SetPrecharge(u8),
    /// Set multiplex (0xA8 + value)
    SetMultiplex(u8),
    /// Set column start and end address
    SetColumnAddress(u8, u8),
    /// Set page start and end address
    SetPageAddress(u8, u8),
    /// Set memory addressing mode
    SetMemoryMode(MemoryMode),
    /// Set charge pump (0x8D + value)
    SetChargePump(bool),
}

/// Memory addressing modes
#[derive(Debug, Clone, Copy)]
pub enum MemoryMode {
    Horizontal = 0x00,
    Vertical = 0x01,
    Page = 0x02,
}

/// Display rotation
#[derive(Debug, Clone, Copy)]
pub enum Rotation {
    Rotate0,
    Rotate180,
}

/// SSD1306 Display Interface
pub trait DisplayInterface {
    type Error;

    /// Send command to display
    async fn send_command(&mut self, cmd: u8) -> Result<(), Self::Error>;

    /// Send data to display
    async fn send_data(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

/// I2C interface for SSD1306
pub struct I2cInterface<I2C> {
    i2c: I2C,
    address: u8,
}

impl<I2C> I2cInterface<I2C> {
    pub fn new(i2c: I2C, address: u8) -> Self {
        Self { i2c, address }
    }
}

impl<I2C> DisplayInterface for I2cInterface<I2C>
where
    I2C: I2c,
{
    type Error = I2C::Error;

    async fn send_command(&mut self, cmd: u8) -> Result<(), Self::Error> {
        self.i2c.write(self.address, &[0x00, cmd]).await
    }

    async fn send_data(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        // Create buffer with control byte
        let mut buffer: Vec<u8, 129> = Vec::new();
        buffer.push(0x40).ok();
        buffer.extend_from_slice(data).ok();

        self.i2c.write(self.address, &buffer).await
    }
}

/// SSD1306 OLED Display Driver
pub struct Ssd1306<DI> {
    interface: DI,
    buffer: [u8; (DISPLAY_WIDTH as usize) * (DISPLAY_HEIGHT as usize) / 8],
    rotation: Rotation,
}

impl<DI> Ssd1306<DI>
where
    DI: DisplayInterface,
{
    /// Create new SSD1306 driver
    pub fn new(interface: DI, rotation: Rotation) -> Self {
        Self {
            interface,
            buffer: [0; (DISPLAY_WIDTH as usize) * (DISPLAY_HEIGHT as usize) / 8],
            rotation,
        }
    }

    /// Initialize the display
    pub async fn init(&mut self) -> Result<(), DI::Error> {
        // Display off
        self.send_command(Command::DisplayOff).await?;

        // Set display clock divide ratio
        self.send_command(Command::SetDisplayClockDiv(0x80)).await?;

        // Set multiplex ratio
        self.send_command(Command::SetMultiplex(63)).await?;

        // Set display offset
        self.send_command(Command::SetDisplayOffset(0)).await?;

        // Set start line
        self.interface.send_command(0x40).await?;

        // Set charge pump
        self.send_command(Command::SetChargePump(true)).await?;

        // Set memory mode
        self.send_command(Command::SetMemoryMode(MemoryMode::Horizontal))
            .await?;

        // Set segment remap and COM scan direction based on rotation
        match self.rotation {
            Rotation::Rotate0 => {
                self.interface.send_command(0xA1).await?; // Segment remap
                self.interface.send_command(0xC8).await?; // COM scan direction
            }
            Rotation::Rotate180 => {
                self.interface.send_command(0xA0).await?; // Segment remap
                self.interface.send_command(0xC0).await?; // COM scan direction
            }
        }

        // Set COM pins
        self.send_command(Command::SetComPins(0x12)).await?;

        // Set contrast
        self.send_command(Command::SetContrast(0x7F)).await?;

        // Set precharge period
        self.send_command(Command::SetPrecharge(0xF1)).await?;

        // Set VCOMH deselect level
        self.send_command(Command::SetVcomDeselect(0x40)).await?;

        // Display all on resume
        self.send_command(Command::DisplayAllOnResume).await?;

        // Normal display
        self.send_command(Command::NormalDisplay).await?;

        // Clear display
        self.clear().await?;

        // Display on
        self.send_command(Command::DisplayOn).await?;

        Ok(())
    }

    /// Send command to display
    async fn send_command(&mut self, cmd: Command) -> Result<(), DI::Error> {
        match cmd {
            Command::SetContrast(val) => {
                self.interface.send_command(0x81).await?;
                self.interface.send_command(val).await?;
            }
            Command::DisplayAllOnResume => self.interface.send_command(0xA4).await?,
            Command::DisplayAllOn => self.interface.send_command(0xA5).await?,
            Command::NormalDisplay => self.interface.send_command(0xA6).await?,
            Command::InvertDisplay => self.interface.send_command(0xA7).await?,
            Command::DisplayOff => self.interface.send_command(0xAE).await?,
            Command::DisplayOn => self.interface.send_command(0xAF).await?,
            Command::SetDisplayOffset(val) => {
                self.interface.send_command(0xD3).await?;
                self.interface.send_command(val).await?;
            }
            Command::SetComPins(val) => {
                self.interface.send_command(0xDA).await?;
                self.interface.send_command(val).await?;
            }
            Command::SetVcomDeselect(val) => {
                self.interface.send_command(0xDB).await?;
                self.interface.send_command(val).await?;
            }
            Command::SetDisplayClockDiv(val) => {
                self.interface.send_command(0xD5).await?;
                self.interface.send_command(val).await?;
            }
            Command::SetPrecharge(val) => {
                self.interface.send_command(0xD9).await?;
                self.interface.send_command(val).await?;
            }
            Command::SetMultiplex(val) => {
                self.interface.send_command(0xA8).await?;
                self.interface.send_command(val).await?;
            }
            Command::SetColumnAddress(start, end) => {
                self.interface.send_command(0x21).await?;
                self.interface.send_command(start).await?;
                self.interface.send_command(end).await?;
            }
            Command::SetPageAddress(start, end) => {
                self.interface.send_command(0x22).await?;
                self.interface.send_command(start).await?;
                self.interface.send_command(end).await?;
            }
            Command::SetMemoryMode(mode) => {
                self.interface.send_command(0x20).await?;
                self.interface.send_command(mode as u8).await?;
            }
            Command::SetChargePump(enable) => {
                self.interface.send_command(0x8D).await?;
                self.interface
                    .send_command(if enable { 0x14 } else { 0x10 })
                    .await?;
            }
        }
        Ok(())
    }

    /// Clear the display
    pub async fn clear(&mut self) -> Result<(), DI::Error> {
        self.buffer = [0; (DISPLAY_WIDTH as usize) * (DISPLAY_HEIGHT as usize) / 8];
        self.flush().await
    }

    /// Flush buffer to display
    pub async fn flush(&mut self) -> Result<(), DI::Error> {
        // Set column address
        self.send_command(Command::SetColumnAddress(0, 127)).await?;

        // Set page address
        self.send_command(Command::SetPageAddress(0, 7)).await?;

        // Send the buffer
        self.interface.send_data(&self.buffer).await?;

        Ok(())
    }

    /// Set pixel in buffer
    pub fn set_pixel(&mut self, x: u32, y: u32, color: bool) {
        if x >= DISPLAY_WIDTH || y >= DISPLAY_HEIGHT {
            return;
        }

        let page = y / 8;
        let bit = y % 8;
        let index = (page * DISPLAY_WIDTH + x) as usize;

        if color {
            self.buffer[index] |= 1 << bit;
        } else {
            self.buffer[index] &= !(1 << bit);
        }
    }

    /// Draw text (simplified without font support)
    pub fn draw_text(&mut self, text: &str, x: i32, y: i32, size: TextSize) {
        // Simplified text rendering - just draw pixels for demonstration
        // In production, use a proper font library
        let char_width = match size {
            TextSize::Small => 6,
            TextSize::Large => 9,
        };

        for i in 0..text.chars().count() {
            let px = x + (i as i32 * char_width);
            if px >= 0 && px < DISPLAY_WIDTH as i32 {
                self.set_pixel(px as u32, y as u32, true);
            }
        }
    }

    /// Display QR code (simplified - assumes pre-rendered)
    pub fn draw_qr(&mut self, qr_data: &[u8], x: u32, y: u32, scale: u32) {
        // This is a simplified QR renderer
        // In production, integrate with QR generation library
        let qr_size = 25; // Typical QR v1 size

        for row in 0..qr_size {
            for col in 0..qr_size {
                let byte_index = row * 4 + col / 8;
                if byte_index < qr_data.len() {
                    let bit = (qr_data[byte_index] >> (7 - (col % 8))) & 1;
                    if bit == 1 {
                        for sy in 0..scale {
                            for sx in 0..scale {
                                self.set_pixel(
                                    x + (col as u32) * scale + sx,
                                    y + (row as u32) * scale + sy,
                                    true,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Set display brightness
    pub async fn set_brightness(&mut self, brightness: u8) -> Result<(), DI::Error> {
        self.send_command(Command::SetContrast(brightness)).await
    }

    /// Turn display on
    pub async fn on(&mut self) -> Result<(), DI::Error> {
        self.send_command(Command::DisplayOn).await
    }

    /// Turn display off
    pub async fn off(&mut self) -> Result<(), DI::Error> {
        self.send_command(Command::DisplayOff).await
    }

    /// Invert display
    pub async fn invert(&mut self, invert: bool) -> Result<(), DI::Error> {
        if invert {
            self.send_command(Command::InvertDisplay).await
        } else {
            self.send_command(Command::NormalDisplay).await
        }
    }
}

/// Text size options
#[derive(Debug, Clone, Copy)]
pub enum TextSize {
    Small,
    Large,
}

// Implement embedded_graphics DrawTarget
impl<DI> DrawTarget for Ssd1306<DI>
where
    DI: DisplayInterface,
{
    type Color = BinaryColor;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(coord, color) in pixels.into_iter() {
            if coord.x >= 0
                && coord.x < DISPLAY_WIDTH as i32
                && coord.y >= 0
                && coord.y < DISPLAY_HEIGHT as i32
            {
                self.set_pixel(coord.x as u32, coord.y as u32, color == BinaryColor::On);
            }
        }
        Ok(())
    }
}

impl<DI> OriginDimensions for Ssd1306<DI>
where
    DI: DisplayInterface,
{
    fn size(&self) -> Size {
        Size::new(DISPLAY_WIDTH, DISPLAY_HEIGHT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pixel_indexing() {
        let mut display = Ssd1306::new(MockInterface, Rotation::Rotate0);

        // Test setting a pixel
        display.set_pixel(10, 20, true);
        let page = 20 / 8; // = 2
        let bit = 20 % 8; // = 4
        let index = (page * 128 + 10) as usize;
        core::assert_eq!(display.buffer[index] & (1 << bit), 1 << bit);
    }

    struct MockInterface;

    impl DisplayInterface for MockInterface {
        type Error = ();

        async fn send_command(&mut self, _cmd: u8) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn send_data(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
