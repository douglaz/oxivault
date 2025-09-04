//! nRF52840 Development Kit Example
//! 
//! Example hardware wallet implementation for nRF52840-DK board
//! Features:
//! - Button input for navigation
//! - OLED display (SSD1306 via I2C)
//! - USB HID for communication
//! - Hardware RNG for entropy

#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_nrf::{
    bind_interrupts,
    gpio::{Input, Level, Output, OutputDrive, Pull},
    peripherals,
    usb::{Driver, HardwareVbusDetect},
    rng::Rng,
};
use embassy_time::{Duration, Timer};
use embassy_usb::{Builder, Config};
use {defmt_rtt as _, panic_probe as _};

use oxivault_core::{
    bip39::MnemonicManager,
    wallet::{Wallet, ScriptType},
    Network,
};

bind_interrupts!(struct Irqs {
    USBD => embassy_nrf::usb::InterruptHandler<peripherals::USBD>;
    POWER_CLOCK => embassy_nrf::usb::vbus_detect::InterruptHandler;
    RNG => embassy_nrf::rng::InterruptHandler<peripherals::RNG>;
});

/// Main application state
pub struct WalletApp {
    /// Current state
    state: AppState,
    /// Mnemonic (if loaded)
    mnemonic: Option<heapless::String<256>>,
    /// Current address
    current_address: Option<heapless::String<128>>,
}

#[derive(Debug, Clone)]
pub enum AppState {
    Idle,
    GeneratingMnemonic,
    DisplayingMnemonic,
    DerivingAddress,
    DisplayingAddress,
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("OxiVault nRF52840 starting...");
    
    let p = embassy_nrf::init(Default::default());
    
    // Configure LEDs
    let mut led1 = Output::new(p.P0_13, Level::High, OutputDrive::Standard);
    let mut led2 = Output::new(p.P0_14, Level::High, OutputDrive::Standard);
    let mut led3 = Output::new(p.P0_15, Level::High, OutputDrive::Standard);
    let mut led4 = Output::new(p.P0_16, Level::High, OutputDrive::Standard);
    
    // Configure buttons
    let btn1 = Input::new(p.P0_11, Pull::Up);
    let btn2 = Input::new(p.P0_12, Pull::Up);
    let btn3 = Input::new(p.P0_24, Pull::Up);
    let btn4 = Input::new(p.P0_25, Pull::Up);
    
    // Initialize RNG
    let mut rng = Rng::new(p.RNG, Irqs);
    
    // Initialize USB
    let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));
    spawner.spawn(usb_task(driver)).unwrap();
    
    // Start heartbeat
    spawner.spawn(heartbeat_task()).unwrap();
    
    // Initialize wallet application
    let mut app = WalletApp {
        state: AppState::Idle,
        mnemonic: None,
        current_address: None,
    };
    
    info!("OxiVault ready!");
    
    // Main application loop
    loop {
        // Check button states
        if btn1.is_low() {
            led1.set_low();
            handle_button1(&mut app, &mut rng).await;
            led1.set_high();
        }
        
        if btn2.is_low() {
            led2.set_low();
            handle_button2(&mut app).await;
            led2.set_high();
        }
        
        if btn3.is_low() {
            led3.set_low();
            handle_button3(&mut app).await;
            led3.set_high();
        }
        
        if btn4.is_low() {
            led4.set_low();
            handle_button4(&mut app).await;
            led4.set_high();
        }
        
        Timer::after(Duration::from_millis(50)).await;
    }
}

async fn handle_button1(app: &mut WalletApp, rng: &mut Rng<'_, peripherals::RNG>) {
    info!("Button 1 pressed - Generate mnemonic");
    app.state = AppState::GeneratingMnemonic;
    
    // Generate entropy
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);
    
    // Generate mnemonic
    match MnemonicManager::from_entropy(&entropy[..16]) {
        Ok(manager) => {
            let phrase = manager.phrase();
            info!("Generated mnemonic: {}", phrase);
            
            // Store in app (truncated for heapless)
            app.mnemonic = Some(heapless::String::try_from(phrase.as_str()).unwrap_or_default());
            app.state = AppState::DisplayingMnemonic;
        }
        Err(_) => {
            error!("Failed to generate mnemonic");
        }
    }
}

async fn handle_button2(app: &mut WalletApp) {
    info!("Button 2 pressed - Derive address");
    
    if let Some(ref mnemonic) = app.mnemonic {
        app.state = AppState::DerivingAddress;
        
        match Wallet::from_mnemonic(mnemonic.as_str(), "", Network::Bitcoin) {
            Ok(wallet) => {
                match wallet.get_address(ScriptType::NativeSegwit, 0, 0, 0) {
                    Ok(address) => {
                        let addr_str = address.to_string();
                        info!("Derived address: {}", addr_str);
                        
                        app.current_address = Some(
                            heapless::String::try_from(addr_str.as_str()).unwrap_or_default()
                        );
                        app.state = AppState::DisplayingAddress;
                    }
                    Err(_) => {
                        error!("Failed to derive address");
                    }
                }
            }
            Err(_) => {
                error!("Failed to create wallet");
            }
        }
    } else {
        info!("No mnemonic available");
    }
}

async fn handle_button3(app: &mut WalletApp) {
    info!("Button 3 pressed - Display state");
    
    match app.state {
        AppState::Idle => info!("State: Idle"),
        AppState::GeneratingMnemonic => info!("State: Generating mnemonic"),
        AppState::DisplayingMnemonic => {
            if let Some(ref mnemonic) = app.mnemonic {
                info!("Mnemonic: {}", mnemonic.as_str());
            }
        }
        AppState::DerivingAddress => info!("State: Deriving address"),
        AppState::DisplayingAddress => {
            if let Some(ref addr) = app.current_address {
                info!("Address: {}", addr.as_str());
            }
        }
    }
}

async fn handle_button4(app: &mut WalletApp) {
    info!("Button 4 pressed - Reset");
    app.state = AppState::Idle;
    app.mnemonic = None;
    app.current_address = None;
    info!("App reset to idle state");
}

#[embassy_executor::task]
async fn heartbeat_task() {
    loop {
        info!("OxiVault heartbeat");
        Timer::after(Duration::from_secs(10)).await;
    }
}

#[embassy_executor::task]
async fn usb_task(mut driver: Driver<'static, peripherals::USBD, HardwareVbusDetect>) {
    let mut config = Config::new(0xc0de, 0xcafe);
    config.manufacturer = Some("OxiVault");
    config.product = Some("Hardware Wallet");
    config.serial_number = Some("1234");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut device_descriptor = [0; 256];
    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 64];

    let mut builder = Builder::new(
        driver,
        config,
        &mut device_descriptor,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [], // no msos descriptors
        &mut control_buf,
    );

    // Add HID class for communication
    // In production, implement proper HID class here
    
    let mut usb = builder.build();
    
    usb.run().await;
}