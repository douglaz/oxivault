//! IronVault nRF52840 Example Firmware
//! 
//! Demonstrates a basic hardware wallet on nRF52840 development board

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_nrf::{gpio::{Input, Output, Level, OutputDrive, Pull}, peripherals};
use embassy_time::Timer;
use defmt::*;
use defmt_rtt as _; // global logger
use panic_probe as _;
use ironvault_core::{Network, wallet::ScriptType};
use ironvault_embedded::{ButtonEvent, HardwareWallet, WalletState, WalletStateMachine};
use heapless::{Vec, String};

/// Mock hardware implementation for demo
pub struct Nrf52Hardware {
    led: Output<'static>,
    button: Input<'static>,
}

impl Nrf52Hardware {
    pub fn new(
        led_pin: peripherals::P0_13,
        button_pin: peripherals::P0_11,
    ) -> Self {
        let led = Output::new(led_pin, Level::Low, OutputDrive::Standard);
        let button = Input::new(button_pin, Pull::Up);
        
        Self { led, button }
    }
}

impl HardwareWallet for Nrf52Hardware {
    async fn init(&mut self) {
        info!("Initializing nRF52840 hardware wallet");
        
        // Flash LED 3 times to indicate startup
        for _ in 0..3 {
            self.led.set_high();
            Timer::after_millis(200).await;
            self.led.set_low();
            Timer::after_millis(200).await;
        }
        
        info!("Hardware initialized");
    }
    
    async fn display_text(&mut self, text: &str) {
        info!("Display: {}", text);
        // In real implementation, write to OLED display
    }
    
    async fn display_qr(&mut self, data: &[u8]) {
        info!("Displaying QR code with {} bytes", data.len());
        // In real implementation, render QR on display
    }
    
    async fn wait_for_button(&mut self) -> ButtonEvent {
        // Wait for button press
        loop {
            if self.button.is_low() {
                // Debounce
                Timer::after_millis(50).await;
                
                // Wait for release
                while self.button.is_low() {
                    Timer::after_millis(10).await;
                }
                
                info!("Button pressed");
                return ButtonEvent::Select;
            }
            
            Timer::after_millis(10).await;
        }
    }
    
    async fn get_entropy(&mut self) -> [u8; 32] {
        // In real implementation, use hardware RNG
        // For demo, return deterministic value
        let mut entropy = [0u8; 32];
        for (i, byte) in entropy.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }
        entropy
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());
    
    info!("IronVault nRF52840 Demo Starting");
    info!("================================");
    
    // Initialize hardware
    let hardware = Nrf52Hardware::new(p.P0_13, p.P0_11);
    let mut wallet = WalletStateMachine::new(hardware);
    
    // Spawn heartbeat task
    spawner.spawn(heartbeat_task(p.P0_14)).unwrap();
    
    // Run the main wallet state machine
    info!("Starting wallet state machine");
    wallet.run().await;
}

#[embassy_executor::task]
async fn heartbeat_task(led_pin: peripherals::P0_14) {
    let mut led = Output::new(led_pin, Level::Low, OutputDrive::Standard);
    
    loop {
        led.toggle();
        Timer::after_secs(1).await;
        debug!("Heartbeat");
    }
}

// Required for cortex-m-rt
#[cortex_m_rt::exception]
unsafe fn DefaultHandler(_: i16) -> ! {
    const SCB_ICSR: *const u32 = 0xE000_ED04 as *const u32;
    let irqn = core::ptr::read_volatile(SCB_ICSR) as u8 as i16 - 16;
    panic!("Unhandled IRQ {}", irqn);
}

#[cortex_m_rt::exception]
unsafe fn HardFault(_frame: &cortex_m_rt::ExceptionFrame) -> ! {
    panic!("HardFault");
}