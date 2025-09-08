//! OxiVault Embedded - Hardware wallet firmware using Embassy-rs

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod backup;
pub mod drivers;
pub mod hal;
#[cfg(feature = "nrf52840")]
pub mod hal_nrf;
pub mod secure_element;

use alloc::boxed::Box;
use core::fmt::Write;
use defmt::info;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use heapless::{String, Vec};

// Re-export core components
pub use secure_element::{PinManager, ProtectedWallet, SecureWallet};

/// Hardware abstraction trait for different platforms
pub trait HardwareWallet {
    /// Initialize the hardware
    async fn init(&mut self);

    /// Display text on screen
    async fn display_text(&mut self, text: &str);

    /// Display QR code (only available with "qr" feature)
    #[cfg(feature = "qr")]
    async fn display_qr(&mut self, data: &[u8]);

    /// Wait for button press
    async fn wait_for_button(&mut self) -> ButtonEvent;

    /// Get entropy from hardware RNG
    async fn get_entropy(&mut self) -> [u8; 32];

    /// Sign transaction with secure element
    async fn sign_transaction(&mut self, hash: &[u8; 32]) -> Option<[u8; 64]>;

    /// Get public key from secure element
    async fn get_public_key(&mut self) -> Option<[u8; 64]>;
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
    pin_attempts: u8,
    authenticated: bool,
}

/// Wallet states
#[derive(Debug, Clone)]
pub enum WalletState {
    Idle,
    Locked,
    EnteringPin,
    GeneratingMnemonic,
    DisplayingMnemonic(Box<Vec<&'static str, 24>>),
    DerivingAddress,
    DisplayingAddress(String<64>),
    SigningTransaction,
    ShowingSignature(String<128>),
}

impl<H: HardwareWallet> WalletStateMachine<H> {
    pub fn new(hardware: H) -> Self {
        Self {
            hardware,
            state: WalletState::Locked,
            pin_attempts: 3,
            authenticated: false,
        }
    }

    /// Generate mock mnemonic words from entropy
    /// In production, this would use BIP39 word list
    fn generate_mock_mnemonic(entropy: &[u8; 32]) -> Vec<&'static str, 24> {
        // Mock word list - in production, use actual BIP39 words
        const WORDS: [&str; 24] = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        ];

        let mut result = Vec::new();
        for i in 0..WORDS.len() {
            // Use entropy to pseudo-randomize word selection
            let idx = (entropy[i % 32] as usize + i) % WORDS.len();
            let _ = result.push(WORDS[idx]);
        }
        result
    }

    /// Run the main state machine
    pub async fn run(&mut self) {
        self.hardware.init().await;

        loop {
            match &self.state {
                WalletState::Locked => {
                    let mut display = String::<64>::new();
                    let _ = write!(display, "OxiVault Locked\nAttempts: {}", self.pin_attempts);
                    self.hardware.display_text(&display).await;
                    let button = self.hardware.wait_for_button().await;
                    if matches!(button, ButtonEvent::Select) {
                        self.state = WalletState::EnteringPin;
                    }
                }
                WalletState::EnteringPin => {
                    // Simplified PIN entry (in production, implement proper PIN input)
                    self.hardware
                        .display_text("Enter PIN\n(Press SELECT)")
                        .await;
                    let button = self.hardware.wait_for_button().await;
                    if matches!(button, ButtonEvent::Select) {
                        // Simulate successful PIN entry
                        self.authenticated = true;
                        self.state = WalletState::Idle;
                    } else if matches!(button, ButtonEvent::Cancel) {
                        self.state = WalletState::Locked;
                    }
                }
                WalletState::Idle => {
                    if !self.authenticated {
                        self.state = WalletState::Locked;
                        continue;
                    }
                    self.hardware
                        .display_text("OxiVault Ready\n1:Gen 2:Sign 3:Addr")
                        .await;
                    let button = self.hardware.wait_for_button().await;
                    match button {
                        ButtonEvent::Select => self.state = WalletState::GeneratingMnemonic,
                        ButtonEvent::Up => self.state = WalletState::SigningTransaction,
                        ButtonEvent::Down => self.state = WalletState::DerivingAddress,
                        ButtonEvent::Cancel => {
                            self.authenticated = false;
                            self.state = WalletState::Locked;
                        }
                    }
                }
                WalletState::GeneratingMnemonic => {
                    self.hardware.display_text("Generating mnemonic...").await;
                    let entropy = self.hardware.get_entropy().await;

                    // Store entropy for seed generation
                    // In a real implementation, we would generate BIP39 mnemonic words here
                    // For now, create a mock mnemonic from entropy
                    let words = Self::generate_mock_mnemonic(&entropy);

                    self.state = WalletState::DisplayingMnemonic(Box::new(words));
                }
                WalletState::DisplayingMnemonic(words) => {
                    let mut display = heapless::String::<256>::new();
                    for (i, word) in words.iter().enumerate() {
                        use core::fmt::Write;
                        let _ = writeln!(display, "{}. {}", i + 1, word);
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
                    if !self.authenticated {
                        self.state = WalletState::Locked;
                        continue;
                    }
                    self.hardware.display_text("Signing transaction...").await;

                    // Sign with secure element
                    let dummy_hash = [0x55u8; 32];
                    if let Some(signature) = self.hardware.sign_transaction(&dummy_hash).await {
                        let sig_hex = hex::encode(&signature[0..8]);
                        let mut display = String::<128>::new();
                        use core::fmt::Write;
                        let _ = write!(display, "Signed!\n{}", sig_hex);
                        self.state = WalletState::ShowingSignature(display);
                    } else {
                        self.hardware.display_text("Signing failed").await;
                        Timer::after(Duration::from_secs(2)).await;
                        self.state = WalletState::Idle;
                    }
                }
                WalletState::ShowingSignature(sig) => {
                    self.hardware.display_text(sig).await;
                    self.hardware.wait_for_button().await;
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
        info!("OxiVault heartbeat");
        Timer::after(Duration::from_secs(10)).await;
    }
}

/// Example main entry point for nRF52840
#[cfg(feature = "nrf52840")]
pub async fn main_nrf(spawner: Spawner) {
    info!("OxiVault starting on nRF52840");
    spawner.spawn(heartbeat_task()).unwrap();

    // Hardware initialization would go here
    // let mut wallet = WalletStateMachine::new(Nrf52Hardware::new());
    // wallet.run().await;
}

/// Example main entry point for RP2040
#[cfg(feature = "rp2040")]
pub async fn main_rp(spawner: Spawner) {
    info!("OxiVault starting on RP2040");
    spawner.spawn(heartbeat_task()).unwrap();

    // Hardware initialization would go here
    // let mut wallet = WalletStateMachine::new(Rp2040Hardware::new());
    // wallet.run().await;
}
