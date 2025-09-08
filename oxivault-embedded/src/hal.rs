//! Hardware Abstraction Layer
//!
//! Platform-independent hardware interface definitions

/// Hardware abstraction layer trait
pub trait HardwareAbstractionLayer {
    type Display: Display;
    type Button: Button;
    type Storage: StorageDevice;
    type SecureElement: SecureElement;

    /// Get display interface
    fn display(&mut self) -> Option<&mut Self::Display>;

    /// Get button interface
    fn button(&mut self) -> &mut Self::Button;

    /// Get storage device
    fn storage(&mut self) -> Option<&mut Self::Storage>;

    /// Get secure element
    fn secure_element(&mut self) -> Option<&mut Self::SecureElement>;
}

/// Display interface
pub trait Display {
    /// Clear the display
    async fn clear(&mut self) -> Result<(), Error>;

    /// Write text at position
    async fn write_text(&mut self, text: &str, x: u16, y: u16) -> Result<(), Error>;

    /// Display QR code (only available with "qr" feature)
    #[cfg(feature = "qr")]
    async fn show_qr(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Show menu with selection
    async fn show_menu(&mut self, items: &[&str], selected: usize) -> Result<(), Error>;
}

/// Button interface
pub trait Button {
    /// Wait for button press
    async fn wait_press(&mut self) -> ButtonPress;

    /// Check if button is pressed
    fn is_pressed(&self, button: ButtonPress) -> bool;
}

/// Button press types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ButtonPress {
    Confirm,
    Cancel,
    Up,
    Down,
}

/// Storage device interface
pub trait StorageDevice {
    /// Read data from storage
    async fn read(&mut self, offset: u32, buffer: &mut [u8]) -> Result<(), Error>;

    /// Write data to storage
    async fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Error>;

    /// Get storage capacity in bytes
    fn capacity(&self) -> u64;
}

/// Secure element interface
pub trait SecureElement {
    /// Generate random bytes
    async fn random(&mut self, buffer: &mut [u8]) -> Result<(), Error>;

    /// Sign message
    async fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], Error>;

    /// Verify signature
    async fn verify(&mut self, message: &[u8], signature: &[u8]) -> Result<bool, Error>;
}

/// HAL error types
#[derive(Debug)]
pub enum Error {
    /// Display error
    DisplayError,
    /// Storage error
    StorageError,
    /// Secure element error
    SecureError,
    /// Not implemented
    NotImplemented,
    /// Invalid parameter
    InvalidParameter,
}
