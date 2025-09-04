#![no_std]

//! IronVault Embedded - Hardware wallet firmware using Embassy-rs

pub mod hal;
pub mod drivers;
pub mod secure_element;
#[cfg(feature = "nrf52840")]
pub mod hal_nrf;

use defmt::info;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use heapless::{Vec, String};

/// Hardware abstraction trait for different platforms
pub trait HardwareWallet {
    /// Initialize the hardware
    async fn init(&mut self);
    
    /// Display text on screen
    async fn display_text(&mut self, text: &str);
    
    /// Display QR code
    async fn display_qr(&mut self, data: &[u8]);
    
    /// Wait for button press
    async fn wait_for_button(&mut self) -> ButtonEvent;
    
    /// Get entropy from hardware RNG
    async fn get_entropy(&mut self) -> [u8; 32];
}

/// Button events
#[derive(Debug, Clone, Copy)]
pub enum ButtonEvent {
    Up,
    Down,
    Select,
    Cancel,
}

/// Main wallet state machine
pub struct WalletStateMachine<H: HardwareWallet> {
    hardware: H,
    state: WalletState,
}

/// Wallet states
#[derive(Debug, Clone)]
pub enum WalletState {
    Idle,
    GeneratingMnemonic,
    DisplayingMnemonic(Vec<&'static str, 24>),
    DerivingAddress,
    DisplayingAddress(String<64>),
    SigningTransaction,
}

impl<H: HardwareWallet> WalletStateMachine<H> {
    pub fn new(hardware: H) -> Self {
        Self {
            hardware,
            state: WalletState::Idle,
        }
    }

    /// Run the main state machine
    pub async fn run(&mut self) {
        self.hardware.init().await;
        
        loop {
            match &self.state {
                WalletState::Idle => {
                    self.hardware.display_text("IronVault Ready\nPress SELECT to start").await;
                    let button = self.hardware.wait_for_button().await;
                    if matches!(button, ButtonEvent::Select) {
                        self.state = WalletState::GeneratingMnemonic;
                    }
                }
                WalletState::GeneratingMnemonic => {
                    self.hardware.display_text("Generating mnemonic...").await;
                    let entropy = self.hardware.get_entropy().await;
                    
                    // For now, show a placeholder until no_std mnemonic generation is fixed
                    self.hardware.display_text("Mnemonic generated (placeholder)").await;
                    Timer::after(Duration::from_secs(2)).await;
                    self.state = WalletState::Idle;
                }
                WalletState::DisplayingMnemonic(words) => {
                    let mut display = heapless::String::<256>::new();
                    for (i, word) in words.iter().enumerate() {
                        use core::fmt::Write;
                        let _ = write!(display, "{}. {}\n", i + 1, word);
                        if (i + 1) % 4 == 0 {
                            self.hardware.display_text(&display).await;
                            self.hardware.wait_for_button().await;
                            display.clear();
                        }
                    }
                    self.state = WalletState::Idle;
                }
                WalletState::DerivingAddress => {
                    self.hardware.display_text("Deriving address...").await;
                    // Address derivation logic here
                    Timer::after(Duration::from_millis(500)).await;
                    self.state = WalletState::Idle;
                }
                WalletState::DisplayingAddress(address) => {
                    self.hardware.display_text(address).await;
                    self.hardware.wait_for_button().await;
                    self.state = WalletState::Idle;
                }
                WalletState::SigningTransaction => {
                    self.hardware.display_text("Signing transaction...").await;
                    // PSBT signing logic here
                    Timer::after(Duration::from_secs(1)).await;
                    self.state = WalletState::Idle;
                }
            }
        }
    }
}

/// Example task for Embassy executor
#[embassy_executor::task]
pub async fn heartbeat_task() {
    loop {
        info!("IronVault heartbeat");
        Timer::after(Duration::from_secs(10)).await;
    }
}

/// Example main entry point for nRF52840
#[cfg(feature = "nrf52840")]
pub async fn main_nrf(spawner: Spawner) {
    info!("IronVault starting on nRF52840");
    spawner.spawn(heartbeat_task()).unwrap();
    
    // Hardware initialization would go here
    // let mut wallet = WalletStateMachine::new(Nrf52Hardware::new());
    // wallet.run().await;
}

/// Example main entry point for RP2040
#[cfg(feature = "rp2040")]
pub async fn main_rp(spawner: Spawner) {
    info!("IronVault starting on RP2040");
    spawner.spawn(heartbeat_task()).unwrap();
    
    // Hardware initialization would go here
    // let mut wallet = WalletStateMachine::new(Rp2040Hardware::new());
    // wallet.run().await;
}