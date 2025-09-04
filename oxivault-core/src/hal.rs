//! Hardware Abstraction Layer (HAL) for OxiVault
//!
//! Provides trait-based abstractions for hardware components to enable
//! portability across different embedded platforms.

pub mod mock;

use crate::Result;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Display capabilities
#[derive(Debug, Clone, Copy)]
pub struct DisplayCapabilities {
    /// Width in pixels
    pub width: u16,
    /// Height in pixels
    pub height: u16,
    /// Number of colors (1 for monochrome, 256 for grayscale, etc.)
    pub colors: u32,
    /// Supports partial refresh
    pub partial_refresh: bool,
}

/// Display abstraction trait
pub trait Display {
    /// Get display capabilities
    fn capabilities(&self) -> DisplayCapabilities;

    /// Clear the display
    fn clear(&mut self) -> Result<()>;

    /// Draw text at position
    fn draw_text(&mut self, x: u16, y: u16, text: &str, size: TextSize) -> Result<()>;

    /// Draw a pixel buffer (for QR codes, images, etc.)
    fn draw_bitmap(&mut self, x: u16, y: u16, width: u16, height: u16, data: &[u8]) -> Result<()>;

    /// Draw a rectangle
    fn draw_rect(&mut self, x: u16, y: u16, width: u16, height: u16, filled: bool) -> Result<()>;

    /// Update the display (flush buffer to screen)
    fn update(&mut self) -> Result<()>;

    /// Set contrast/brightness (0-255)
    fn set_brightness(&mut self, level: u8) -> Result<()>;
}

/// Text size options
#[derive(Debug, Clone, Copy)]
pub enum TextSize {
    Small,
    Normal,
    Large,
}

/// Input event types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputEvent {
    /// Button press
    ButtonPress(Button),
    /// Button release
    ButtonRelease(Button),
    /// Touch at position
    Touch(u16, u16),
    /// Rotary encoder rotation
    Rotation(i8),
}

/// Button types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Button {
    Up,
    Down,
    Left,
    Right,
    Select,
    Back,
    Button1,
    Button2,
    Button3,
}

/// Input abstraction trait
pub trait Input {
    /// Poll for input events (non-blocking)
    fn poll(&mut self) -> Option<InputEvent>;

    /// Wait for input event (blocking)
    fn wait(&mut self) -> InputEvent;

    /// Check if a button is currently pressed
    fn is_pressed(&self, button: Button) -> bool;
}

/// Storage capabilities
#[derive(Debug, Clone)]
pub struct StorageInfo {
    /// Total capacity in bytes
    pub capacity: usize,
    /// Available space in bytes
    pub available: usize,
    /// Supports encryption
    pub encrypted: bool,
    /// Wear leveling support
    pub wear_leveling: bool,
}

/// Storage abstraction trait
pub trait Storage {
    /// Get storage information
    fn info(&self) -> StorageInfo;

    /// Read data from storage
    fn read(&self, key: &str) -> Result<Vec<u8>>;

    /// Write data to storage
    fn write(&mut self, key: &str, data: &[u8]) -> Result<()>;

    /// Delete data from storage
    fn delete(&mut self, key: &str) -> Result<()>;

    /// List all keys
    fn list_keys(&self) -> Result<Vec<String>>;

    /// Check if key exists
    fn exists(&self, key: &str) -> bool;

    /// Wipe all data
    fn wipe_all(&mut self) -> Result<()>;
}

/// Camera/Scanner capabilities
#[derive(Debug, Clone)]
pub struct CameraInfo {
    /// Resolution width
    pub width: u16,
    /// Resolution height
    pub height: u16,
    /// Supports auto-focus
    pub auto_focus: bool,
    /// Has LED/flash
    pub has_flash: bool,
}

/// Camera/Scanner abstraction trait
pub trait Camera {
    /// Get camera information
    fn info(&self) -> CameraInfo;

    /// Capture an image
    fn capture(&mut self) -> Result<Vec<u8>>;

    /// Start continuous capture mode
    fn start_preview(&mut self) -> Result<()>;

    /// Stop continuous capture
    fn stop_preview(&mut self) -> Result<()>;

    /// Get latest frame from preview
    fn get_frame(&mut self) -> Result<Vec<u8>>;

    /// Enable/disable flash/LED
    fn set_flash(&mut self, enabled: bool) -> Result<()>;
}

/// Random number generator trait
pub trait RandomSource {
    /// Get random bytes
    fn get_random(&mut self, output: &mut [u8]) -> Result<()>;

    /// Get random u32
    fn get_random_u32(&mut self) -> Result<u32>;

    /// Reseed the RNG (if applicable)
    fn reseed(&mut self, seed: &[u8]) -> Result<()>;
}

/// Power management trait
pub trait Power {
    /// Get battery level (0-100%)
    fn battery_level(&self) -> u8;

    /// Check if charging
    fn is_charging(&self) -> bool;

    /// Enter low power mode
    fn sleep(&mut self) -> Result<()>;

    /// Wake from low power mode
    fn wake(&mut self) -> Result<()>;

    /// Set auto-sleep timeout in seconds (0 = disabled)
    fn set_auto_sleep(&mut self, seconds: u32) -> Result<()>;
}

/// Communication interface trait (USB, Bluetooth, etc.)
pub trait Communication {
    /// Check if connected
    fn is_connected(&self) -> bool;

    /// Send data
    fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receive data (non-blocking)
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize>;

    /// Wait for data (blocking)
    fn wait_receive(&mut self, buffer: &mut [u8]) -> Result<usize>;
}

/// Complete HAL interface combining all traits
pub trait HardwareAbstractionLayer {
    type Display: Display;
    type Input: Input;
    type Storage: Storage;
    type Camera: Camera;
    type Random: RandomSource;
    type Power: Power;
    type Comm: Communication;

    /// Get display interface
    fn display(&mut self) -> &mut Self::Display;

    /// Get input interface
    fn input(&mut self) -> &mut Self::Input;

    /// Get storage interface
    fn storage(&mut self) -> &mut Self::Storage;

    /// Get camera interface (if available)
    fn camera(&mut self) -> Option<&mut Self::Camera>;

    /// Get random source
    fn random(&mut self) -> &mut Self::Random;

    /// Get power management
    fn power(&mut self) -> &mut Self::Power;

    /// Get communication interface
    fn communication(&mut self) -> Option<&mut Self::Comm>;

    /// Initialize hardware
    fn init(&mut self) -> Result<()>;

    /// Shutdown hardware
    fn shutdown(&mut self) -> Result<()>;
}

/// Platform information
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    /// Platform name (e.g., "nRF52840", "STM32L4", "Simulator")
    pub name: String,
    /// Firmware version
    pub version: String,
    /// Unique device ID
    pub device_id: Vec<u8>,
    /// Total RAM in bytes
    pub ram_size: usize,
    /// Total flash storage in bytes
    pub flash_size: usize,
}

/// Platform-specific features trait
pub trait Platform {
    /// Get platform information
    fn info(&self) -> PlatformInfo;

    /// Perform platform-specific initialization
    fn platform_init(&mut self) -> Result<()>;

    /// Get CPU temperature (if available)
    fn cpu_temperature(&self) -> Option<f32>;

    /// Get uptime in milliseconds
    fn uptime_ms(&self) -> u64;

    /// Reboot the device
    fn reboot(&mut self) -> !;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_capabilities() {
        let caps = DisplayCapabilities {
            width: 128,
            height: 64,
            colors: 1,
            partial_refresh: false,
        };

        assert_eq!(caps.width, 128);
        assert_eq!(caps.height, 64);
        assert_eq!(caps.colors, 1);
    }

    #[test]
    fn test_input_events() {
        let event1 = InputEvent::ButtonPress(Button::Select);
        let event2 = InputEvent::ButtonPress(Button::Select);
        assert_eq!(event1, event2);

        let event3 = InputEvent::Touch(100, 50);
        if let InputEvent::Touch(x, y) = event3 {
            assert_eq!(x, 100);
            assert_eq!(y, 50);
        }
    }

    #[test]
    fn test_storage_info() {
        let info = StorageInfo {
            capacity: 1024 * 1024,
            available: 512 * 1024,
            encrypted: true,
            wear_leveling: true,
        };

        assert_eq!(info.capacity, 1024 * 1024);
        assert!(info.encrypted);
    }
}
