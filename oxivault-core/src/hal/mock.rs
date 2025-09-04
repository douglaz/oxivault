//! Mock HAL implementation for testing and simulation
//! 
//! Provides a software-based implementation of all HAL traits for testing
//! without requiring actual hardware.

use crate::{Result, Error};
use super::{
    Display, DisplayCapabilities, TextSize,
    Input, InputEvent, Button,
    Storage, StorageInfo,
    Camera, CameraInfo,
    RandomSource, Power, Communication,
    HardwareAbstractionLayer, Platform, PlatformInfo,
};

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format, collections::BTreeMap as HashMap};

/// Mock display implementation
pub struct MockDisplay {
    width: u16,
    height: u16,
    /// Screen buffer as 2D character array
    buffer: Vec<Vec<char>>,
    /// Current QR code being displayed
    qr_display: Option<String>,
    /// Brightness level
    brightness: u8,
}

impl MockDisplay {
    pub fn new(width: u16, height: u16) -> Self {
        let buffer = vec![vec![' '; width as usize]; height as usize];
        Self {
            width,
            height,
            buffer,
            qr_display: None,
            brightness: 128,
        }
    }
    
    /// Get the current screen content as a string
    pub fn get_content(&self) -> String {
        self.buffer.iter()
            .map(|row| row.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Get QR display if active
    pub fn get_qr(&self) -> Option<&str> {
        self.qr_display.as_deref()
    }
}

impl Display for MockDisplay {
    fn capabilities(&self) -> DisplayCapabilities {
        DisplayCapabilities {
            width: self.width,
            height: self.height,
            colors: 1,  // Monochrome
            partial_refresh: true,
        }
    }
    
    fn clear(&mut self) -> Result<()> {
        for row in &mut self.buffer {
            row.fill(' ');
        }
        self.qr_display = None;
        Ok(())
    }
    
    fn draw_text(&mut self, x: u16, y: u16, text: &str, _size: TextSize) -> Result<()> {
        let y = y as usize;
        let x = x as usize;
        
        if y >= self.buffer.len() {
            return Err(Error::InvalidParameter("Y coordinate out of bounds".into()));
        }
        
        for (i, ch) in text.chars().enumerate() {
            if x + i < self.buffer[y].len() {
                self.buffer[y][x + i] = ch;
            }
        }
        
        Ok(())
    }
    
    fn draw_bitmap(&mut self, x: u16, y: u16, width: u16, height: u16, data: &[u8]) -> Result<()> {
        // Store bitmap as QR for testing
        let qr_string = format!("QR@{}x{} ({}x{}): {} bytes", x, y, width, height, data.len());
        self.qr_display = Some(qr_string);
        
        // Draw placeholder in buffer
        let placeholder = "[QR CODE]";
        self.draw_text(x, y, placeholder, TextSize::Normal)?;
        
        Ok(())
    }
    
    fn draw_rect(&mut self, x: u16, y: u16, width: u16, height: u16, filled: bool) -> Result<()> {
        let x = x as usize;
        let y = y as usize;
        let width = width as usize;
        let height = height as usize;
        
        if filled {
            for dy in 0..height {
                for dx in 0..width {
                    if y + dy < self.buffer.len() && x + dx < self.buffer[0].len() {
                        self.buffer[y + dy][x + dx] = '█';
                    }
                }
            }
        } else {
            // Draw borders only
            for dx in 0..width {
                if y < self.buffer.len() && x + dx < self.buffer[0].len() {
                    self.buffer[y][x + dx] = '─';
                }
                if y + height - 1 < self.buffer.len() && x + dx < self.buffer[0].len() {
                    self.buffer[y + height - 1][x + dx] = '─';
                }
            }
            for dy in 0..height {
                if y + dy < self.buffer.len() && x < self.buffer[0].len() {
                    self.buffer[y + dy][x] = '│';
                }
                if y + dy < self.buffer.len() && x + width - 1 < self.buffer[0].len() {
                    self.buffer[y + dy][x + width - 1] = '│';
                }
            }
            // Corners
            if y < self.buffer.len() && x < self.buffer[0].len() {
                self.buffer[y][x] = '┌';
            }
            if y < self.buffer.len() && x + width - 1 < self.buffer[0].len() {
                self.buffer[y][x + width - 1] = '┐';
            }
            if y + height - 1 < self.buffer.len() && x < self.buffer[0].len() {
                self.buffer[y + height - 1][x] = '└';
            }
            if y + height - 1 < self.buffer.len() && x + width - 1 < self.buffer[0].len() {
                self.buffer[y + height - 1][x + width - 1] = '┘';
            }
        }
        
        Ok(())
    }
    
    fn update(&mut self) -> Result<()> {
        // In mock, update is a no-op
        Ok(())
    }
    
    fn set_brightness(&mut self, level: u8) -> Result<()> {
        self.brightness = level;
        Ok(())
    }
}

/// Mock input implementation
pub struct MockInput {
    /// Queue of pending events
    event_queue: Vec<InputEvent>,
    /// Currently pressed buttons
    pressed: Vec<Button>,
}

impl MockInput {
    pub fn new() -> Self {
        Self {
            event_queue: Vec::new(),
            pressed: Vec::new(),
        }
    }
    
    /// Simulate a button press
    pub fn press_button(&mut self, button: Button) {
        if !self.pressed.contains(&button) {
            self.pressed.push(button);
            self.event_queue.push(InputEvent::ButtonPress(button));
        }
    }
    
    /// Simulate a button release
    pub fn release_button(&mut self, button: Button) {
        if let Some(pos) = self.pressed.iter().position(|&b| b == button) {
            self.pressed.remove(pos);
            self.event_queue.push(InputEvent::ButtonRelease(button));
        }
    }
    
    /// Simulate a touch event
    pub fn touch(&mut self, x: u16, y: u16) {
        self.event_queue.push(InputEvent::Touch(x, y));
    }
    
    /// Simulate rotation
    pub fn rotate(&mut self, delta: i8) {
        self.event_queue.push(InputEvent::Rotation(delta));
    }
}

impl Input for MockInput {
    fn poll(&mut self) -> Option<InputEvent> {
        if self.event_queue.is_empty() {
            None
        } else {
            Some(self.event_queue.remove(0))
        }
    }
    
    fn wait(&mut self) -> InputEvent {
        // In testing, simulate a select button press if queue is empty
        if self.event_queue.is_empty() {
            InputEvent::ButtonPress(Button::Select)
        } else {
            self.event_queue.remove(0)
        }
    }
    
    fn is_pressed(&self, button: Button) -> bool {
        self.pressed.contains(&button)
    }
}

/// Mock storage implementation
pub struct MockStorage {
    data: HashMap<String, Vec<u8>>,
    capacity: usize,
}

impl MockStorage {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::new(),
            capacity,
        }
    }
}

impl Storage for MockStorage {
    fn info(&self) -> StorageInfo {
        let used: usize = self.data.values().map(|v| v.len()).sum();
        StorageInfo {
            capacity: self.capacity,
            available: self.capacity - used,
            encrypted: false,
            wear_leveling: false,
        }
    }
    
    fn read(&self, key: &str) -> Result<Vec<u8>> {
        self.data.get(key)
            .cloned()
            .ok_or(Error::InvalidParameter(format!("Key not found: {}", key)))
    }
    
    fn write(&mut self, key: &str, data: &[u8]) -> Result<()> {
        self.data.insert(key.to_string(), data.to_vec());
        Ok(())
    }
    
    fn delete(&mut self, key: &str) -> Result<()> {
        self.data.remove(key)
            .ok_or(Error::InvalidParameter(format!("Key not found: {}", key)))?;
        Ok(())
    }
    
    fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self.data.keys().cloned().collect())
    }
    
    fn exists(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }
    
    fn wipe_all(&mut self) -> Result<()> {
        self.data.clear();
        Ok(())
    }
}

/// Mock camera implementation
pub struct MockCamera {
    captured_data: Option<Vec<u8>>,
    preview_active: bool,
    flash_enabled: bool,
}

impl MockCamera {
    pub fn new() -> Self {
        Self {
            captured_data: None,
            preview_active: false,
            flash_enabled: false,
        }
    }
    
    /// Set mock captured data
    pub fn set_captured_data(&mut self, data: Vec<u8>) {
        self.captured_data = Some(data);
    }
}

impl Camera for MockCamera {
    fn info(&self) -> CameraInfo {
        CameraInfo {
            width: 640,
            height: 480,
            auto_focus: true,
            has_flash: true,
        }
    }
    
    fn capture(&mut self) -> Result<Vec<u8>> {
        self.captured_data.clone()
            .ok_or(Error::InvalidParameter("No mock data available".into()))
    }
    
    fn start_preview(&mut self) -> Result<()> {
        self.preview_active = true;
        Ok(())
    }
    
    fn stop_preview(&mut self) -> Result<()> {
        self.preview_active = false;
        Ok(())
    }
    
    fn get_frame(&mut self) -> Result<Vec<u8>> {
        if !self.preview_active {
            return Err(Error::InvalidParameter("Preview not active".into()));
        }
        self.capture()
    }
    
    fn set_flash(&mut self, enabled: bool) -> Result<()> {
        self.flash_enabled = enabled;
        Ok(())
    }
}

/// Mock random source
pub struct MockRandom {
    seed: u32,
}

impl MockRandom {
    pub fn new(seed: u32) -> Self {
        Self { seed }
    }
    
    /// Simple LCG for deterministic "random" numbers
    fn next_u32(&mut self) -> u32 {
        self.seed = self.seed.wrapping_mul(1664525).wrapping_add(1013904223);
        self.seed
    }
}

impl RandomSource for MockRandom {
    fn get_random(&mut self, output: &mut [u8]) -> Result<()> {
        for chunk in output.chunks_mut(4) {
            let random = self.next_u32();
            let bytes = random.to_le_bytes();
            for (i, byte) in chunk.iter_mut().enumerate() {
                if i < bytes.len() {
                    *byte = bytes[i];
                }
            }
        }
        Ok(())
    }
    
    fn get_random_u32(&mut self) -> Result<u32> {
        Ok(self.next_u32())
    }
    
    fn reseed(&mut self, seed: &[u8]) -> Result<()> {
        if seed.len() >= 4 {
            self.seed = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]);
        }
        Ok(())
    }
}

/// Mock power management
pub struct MockPower {
    battery_level: u8,
    charging: bool,
    sleeping: bool,
}

impl MockPower {
    pub fn new() -> Self {
        Self {
            battery_level: 75,
            charging: false,
            sleeping: false,
        }
    }
    
    /// Set mock battery level
    pub fn set_battery(&mut self, level: u8, charging: bool) {
        self.battery_level = level.min(100);
        self.charging = charging;
    }
}

impl Power for MockPower {
    fn battery_level(&self) -> u8 {
        self.battery_level
    }
    
    fn is_charging(&self) -> bool {
        self.charging
    }
    
    fn sleep(&mut self) -> Result<()> {
        self.sleeping = true;
        Ok(())
    }
    
    fn wake(&mut self) -> Result<()> {
        self.sleeping = false;
        Ok(())
    }
    
    fn set_auto_sleep(&mut self, _seconds: u32) -> Result<()> {
        Ok(())
    }
}

/// Mock communication interface
pub struct MockComm {
    connected: bool,
    rx_buffer: Vec<u8>,
    tx_buffer: Vec<u8>,
}

impl MockComm {
    pub fn new() -> Self {
        Self {
            connected: false,
            rx_buffer: Vec::new(),
            tx_buffer: Vec::new(),
        }
    }
    
    /// Simulate connection
    pub fn connect(&mut self) {
        self.connected = true;
    }
    
    /// Add data to receive buffer
    pub fn add_rx_data(&mut self, data: &[u8]) {
        self.rx_buffer.extend_from_slice(data);
    }
    
    /// Get transmitted data
    pub fn get_tx_data(&self) -> &[u8] {
        &self.tx_buffer
    }
}

impl Communication for MockComm {
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(Error::InvalidParameter("Not connected".into()));
        }
        self.tx_buffer.extend_from_slice(data);
        Ok(())
    }
    
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if !self.connected {
            return Err(Error::InvalidParameter("Not connected".into()));
        }
        
        let len = buffer.len().min(self.rx_buffer.len());
        if len > 0 {
            buffer[..len].copy_from_slice(&self.rx_buffer[..len]);
            self.rx_buffer.drain(..len);
        }
        Ok(len)
    }
    
    fn wait_receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        // For testing, simulate some data if buffer is empty
        if self.rx_buffer.is_empty() {
            self.rx_buffer.extend_from_slice(b"TEST_DATA");
        }
        self.receive(buffer)
    }
}

/// Complete mock HAL implementation
pub struct MockHAL {
    pub display: MockDisplay,
    pub input: MockInput,
    pub storage: MockStorage,
    pub camera: MockCamera,
    pub random: MockRandom,
    pub power: MockPower,
    pub comm: MockComm,
    uptime_start: u64,
}

impl MockHAL {
    pub fn new() -> Self {
        Self {
            display: MockDisplay::new(128, 64),
            input: MockInput::new(),
            storage: MockStorage::new(1024 * 1024), // 1MB
            camera: MockCamera::new(),
            random: MockRandom::new(12345),
            power: MockPower::new(),
            comm: MockComm::new(),
            uptime_start: 0,
        }
    }
}

impl HardwareAbstractionLayer for MockHAL {
    type Display = MockDisplay;
    type Input = MockInput;
    type Storage = MockStorage;
    type Camera = MockCamera;
    type Random = MockRandom;
    type Power = MockPower;
    type Comm = MockComm;
    
    fn display(&mut self) -> &mut Self::Display {
        &mut self.display
    }
    
    fn input(&mut self) -> &mut Self::Input {
        &mut self.input
    }
    
    fn storage(&mut self) -> &mut Self::Storage {
        &mut self.storage
    }
    
    fn camera(&mut self) -> Option<&mut Self::Camera> {
        Some(&mut self.camera)
    }
    
    fn random(&mut self) -> &mut Self::Random {
        &mut self.random
    }
    
    fn power(&mut self) -> &mut Self::Power {
        &mut self.power
    }
    
    fn communication(&mut self) -> Option<&mut Self::Comm> {
        Some(&mut self.comm)
    }
    
    fn init(&mut self) -> Result<()> {
        self.display.clear()?;
        self.uptime_start = 0; // Would use system time in std
        Ok(())
    }
    
    fn shutdown(&mut self) -> Result<()> {
        self.display.clear()?;
        self.power.sleep()?;
        Ok(())
    }
}

impl Platform for MockHAL {
    fn info(&self) -> PlatformInfo {
        PlatformInfo {
            name: "Mock HAL Simulator".into(),
            version: "1.0.0".into(),
            device_id: vec![0x01, 0x02, 0x03, 0x04],
            ram_size: 256 * 1024,
            flash_size: 1024 * 1024,
        }
    }
    
    fn platform_init(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn cpu_temperature(&self) -> Option<f32> {
        Some(25.0) // Room temperature
    }
    
    fn uptime_ms(&self) -> u64 {
        // Would calculate from system time in std
        1000
    }
    
    fn reboot(&mut self) -> ! {
        // In testing, panic instead of actual reboot
        panic!("Mock reboot requested");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mock_display() {
        let mut display = MockDisplay::new(128, 64);
        
        assert_eq!(display.capabilities().width, 128);
        assert_eq!(display.capabilities().height, 64);
        
        display.draw_text(0, 0, "Hello", TextSize::Normal).unwrap();
        assert!(display.get_content().contains("Hello"));
        
        display.clear().unwrap();
        assert!(!display.get_content().contains("Hello"));
    }
    
    #[test]
    fn test_mock_input() {
        let mut input = MockInput::new();
        
        input.press_button(Button::Select);
        assert!(input.is_pressed(Button::Select));
        
        if let Some(InputEvent::ButtonPress(button)) = input.poll() {
            assert_eq!(button, Button::Select);
        } else {
            panic!("Expected button press event");
        }
        
        input.release_button(Button::Select);
        assert!(!input.is_pressed(Button::Select));
    }
    
    #[test]
    fn test_mock_storage() {
        let mut storage = MockStorage::new(1024);
        
        storage.write("test_key", b"test_data").unwrap();
        assert!(storage.exists("test_key"));
        
        let data = storage.read("test_key").unwrap();
        assert_eq!(data, b"test_data");
        
        storage.delete("test_key").unwrap();
        assert!(!storage.exists("test_key"));
    }
    
    #[test]
    fn test_mock_random() {
        let mut rng = MockRandom::new(42);
        
        let val1 = rng.get_random_u32().unwrap();
        let val2 = rng.get_random_u32().unwrap();
        assert_ne!(val1, val2);
        
        let mut buf = [0u8; 16];
        rng.get_random(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 16]);
    }
    
    #[test]
    fn test_mock_hal() {
        let mut hal = MockHAL::new();
        
        hal.init().unwrap();
        
        hal.display().draw_text(0, 0, "OxiVault", TextSize::Large).unwrap();
        hal.input().press_button(Button::Select);
        hal.storage().write("seed", b"test_seed").unwrap();
        
        assert!(hal.display().get_content().contains("OxiVault"));
        assert!(hal.input().is_pressed(Button::Select));
        assert!(hal.storage().exists("seed"));
    }
}