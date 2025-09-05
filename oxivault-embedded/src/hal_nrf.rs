//! nRF52840 Hardware Abstraction Layer
//!
//! Provides concrete implementations for the nRF52840 development board

#![no_std]

use crate::{
    drivers::ssd1306::{I2cInterface, Rotation, Ssd1306, TextSize},
    hal::{
        Button, ButtonPress, Display, Error, HardwareAbstractionLayer, SecureElement, StorageDevice,
    },
};
use defmt::*;
use embassy_nrf::{bind_interrupts, peripherals::TWISPI0 as TWIM0, Peri};
use embassy_nrf::{
    gpio::{Input, Pull},
    peripherals,
    peripherals::TWISPI0,
    twim::{self, Twim},
    usb::{self, vbus_detect, Driver},
};
use embassy_time::Timer;
use heapless::String;
use static_cell::StaticCell;

// Bind interrupts for peripherals
bind_interrupts!(struct Irqs {
    TWISPI0 => twim::InterruptHandler<peripherals::TWISPI0>;
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});

/// Dummy SPI/CS types for storage (not implemented yet)
pub struct DummySpi;
pub struct DummyCs;

impl embedded_hal::spi::ErrorType for DummySpi {
    type Error = core::convert::Infallible;
}

impl embedded_hal_async::spi::SpiDevice for DummySpi {
    async fn transaction(
        &mut self,
        _operations: &mut [embedded_hal_async::spi::Operation<'_, u8>],
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl embedded_hal::digital::ErrorType for DummyCs {
    type Error = core::convert::Infallible;
}

impl embedded_hal::digital::OutputPin for DummyCs {
    fn set_high(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn set_low(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// nRF52840 HAL implementation
pub struct Nrf52840Hal {
    display: Option<Nrf52840Display>,
    buttons: ButtonArray,
    storage: Option<SdCard<DummySpi, DummyCs>>,
    secure_element: Option<Atecc608a<Twim<'static, TWIM0>>>,
}

// Static buffer for TWIM DMA operations
static TWIM_BUF: StaticCell<[u8; 256]> = StaticCell::new();

impl Nrf52840Hal {
    /// Initialize the HAL with peripherals
    pub async fn init(
        p: Peri<'static, peripherals::TWISPI0>,
        sda_pin: Peri<'static, peripherals::P0_26>,
        scl_pin: Peri<'static, peripherals::P0_27>,
        button1_pin: Peri<'static, peripherals::P0_11>,
        button2_pin: Peri<'static, peripherals::P0_12>,
        button3_pin: Peri<'static, peripherals::P0_24>,
        button4_pin: Peri<'static, peripherals::P0_25>,
    ) -> Self {
        info!("Initializing nRF52840 HAL");

        // Configure I2C for display
        let config = twim::Config::default();
        let twim_buf = TWIM_BUF.init([0u8; 256]);
        let twim = Twim::new(p, Irqs, sda_pin, scl_pin, config, twim_buf);

        // Initialize SSD1306 display
        let i2c_interface = I2cInterface::new(twim, 0x3C); // Common I2C address
        let mut ssd1306 = Ssd1306::new(i2c_interface, Rotation::Rotate0);

        // Initialize display
        if let Err(e) = ssd1306.init().await {
            error!("Failed to initialize display: {}", defmt::Debug2Format(&e));
        }

        let display = Nrf52840Display {
            driver: ssd1306,
            buffer: String::new(),
        };

        // Configure buttons with pull-up resistors
        let button1 = Input::new(button1_pin, Pull::Up);
        let button2 = Input::new(button2_pin, Pull::Up);
        let button3 = Input::new(button3_pin, Pull::Up);
        let button4 = Input::new(button4_pin, Pull::Up);

        let buttons = ButtonArray {
            confirm: button1,
            cancel: button2,
            up: button3,
            down: button4,
        };

        Self {
            display: Some(display),
            buttons,
            storage: None,
            secure_element: None,
        }
    }
}

impl HardwareAbstractionLayer for Nrf52840Hal {
    type Display = Nrf52840Display;
    type Button = ButtonArray;
    type Storage = SdCard<DummySpi, DummyCs>;
    type SecureElement = Atecc608a<Twim<'static, peripherals::TWISPI0>>;

    fn display(&mut self) -> Option<&mut Self::Display> {
        self.display.as_mut()
    }

    fn button(&mut self) -> &mut Self::Button {
        &mut self.buttons
    }

    fn storage(&mut self) -> Option<&mut Self::Storage> {
        self.storage.as_mut()
    }

    fn secure_element(&mut self) -> Option<&mut Self::SecureElement> {
        self.secure_element.as_mut()
    }
}

/// Display implementation for nRF52840
pub struct Nrf52840Display {
    driver: Ssd1306<I2cInterface<Twim<'static, peripherals::TWISPI0>>>,
    buffer: String<256>,
}

impl Display for Nrf52840Display {
    async fn clear(&mut self) -> Result<(), Error> {
        self.driver.clear().await.map_err(|_| Error::DisplayError)
    }

    async fn write_text(&mut self, text: &str, x: u16, y: u16) -> Result<(), Error> {
        self.driver
            .draw_text(text, x as i32, y as i32, TextSize::Small);
        self.driver.flush().await.map_err(|_| Error::DisplayError)
    }

    #[cfg(feature = "qr")]
    async fn show_qr(&mut self, data: &[u8]) -> Result<(), Error> {
        // QR code rendering would go here
        // For now, just display text
        self.write_text("[QR Code]", 40, 28).await
    }

    async fn show_menu(&mut self, items: &[&str], selected: usize) -> Result<(), Error> {
        self.clear().await?;

        let items_per_page = 5;
        let start_idx = if selected >= items_per_page {
            selected - items_per_page + 1
        } else {
            0
        };

        for (i, item) in items
            .iter()
            .skip(start_idx)
            .take(items_per_page)
            .enumerate()
        {
            let y_pos = (i * 12) as i32;
            let display_idx = start_idx + i;

            // Add selection indicator
            if display_idx == selected {
                self.driver.draw_text(">", 0, y_pos, TextSize::Small);
                self.driver.draw_text(item, 10, y_pos, TextSize::Small);
            } else {
                self.driver.draw_text(item, 10, y_pos, TextSize::Small);
            }
        }

        self.driver.flush().await.map_err(|_| Error::DisplayError)
    }
}

/// Button array for nRF52840
pub struct ButtonArray {
    confirm: Input<'static>,
    cancel: Input<'static>,
    up: Input<'static>,
    down: Input<'static>,
}

impl Button for ButtonArray {
    async fn wait_press(&mut self) -> ButtonPress {
        loop {
            if self.confirm.is_low() {
                // Debounce
                Timer::after_millis(50).await;
                while self.confirm.is_low() {
                    Timer::after_millis(10).await;
                }
                return ButtonPress::Confirm;
            }

            if self.cancel.is_low() {
                Timer::after_millis(50).await;
                while self.cancel.is_low() {
                    Timer::after_millis(10).await;
                }
                return ButtonPress::Cancel;
            }

            if self.up.is_low() {
                Timer::after_millis(50).await;
                while self.up.is_low() {
                    Timer::after_millis(10).await;
                }
                return ButtonPress::Up;
            }

            if self.down.is_low() {
                Timer::after_millis(50).await;
                while self.down.is_low() {
                    Timer::after_millis(10).await;
                }
                return ButtonPress::Down;
            }

            Timer::after_millis(10).await;
        }
    }

    fn is_pressed(&self, button: ButtonPress) -> bool {
        match button {
            ButtonPress::Confirm => self.confirm.is_low(),
            ButtonPress::Cancel => self.cancel.is_low(),
            ButtonPress::Up => self.up.is_low(),
            ButtonPress::Down => self.down.is_low(),
        }
    }
}

/// SD card wrapper for HAL
use crate::drivers::sdcard::SdCard as SdCardDriver;

pub struct SdCard<SPI, CS> {
    inner: SdCardDriver<SPI, CS>,
}

impl<SPI, CS> SdCard<SPI, CS>
where
    SPI: embedded_hal_async::spi::SpiDevice,
    CS: embedded_hal::digital::OutputPin,
{
    pub fn new(spi: SPI, cs: CS) -> Self {
        Self {
            inner: SdCardDriver::new(spi, cs),
        }
    }

    pub async fn init(&mut self) -> Result<(), Error> {
        self.inner.init().await.map_err(|_| Error::StorageError)
    }
}

impl<SPI, CS> StorageDevice for SdCard<SPI, CS>
where
    SPI: embedded_hal_async::spi::SpiDevice,
    CS: embedded_hal::digital::OutputPin,
{
    async fn read(&mut self, offset: u32, buffer: &mut [u8]) -> Result<(), Error> {
        // Read blocks based on offset
        let block_num = offset / 512;
        let block_data = self
            .inner
            .read_block(block_num)
            .await
            .map_err(|_| Error::StorageError)?;

        let start = (offset % 512) as usize;
        let len = buffer.len().min(512 - start);
        buffer[..len].copy_from_slice(&block_data[start..start + len]);
        Ok(())
    }

    async fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Error> {
        // Write blocks based on offset
        let block_num = offset / 512;
        let mut block_data = [0u8; 512];

        // For simplicity, we'll write one block at a time
        if data.len() <= 512 {
            block_data[..data.len()].copy_from_slice(data);
            self.inner
                .write_block(block_num, &block_data)
                .await
                .map_err(|_| Error::StorageError)?;
        }
        Ok(())
    }

    fn capacity(&self) -> u64 {
        8 * 1024 * 1024 * 1024 // 8GB default
    }
}

/// ATECC608A secure element wrapper for HAL
use crate::secure_element::{Atecc608 as Atecc608Driver, SecureWallet};

pub struct Atecc608a<I2C> {
    inner: SecureWallet<I2C>,
}

impl<I2C> Atecc608a<I2C>
where
    I2C: embedded_hal_async::i2c::I2c,
{
    pub async fn new(i2c: I2C) -> Result<Self, Error> {
        let driver = Atecc608Driver::new(i2c);
        let wallet = SecureWallet::new(driver)
            .await
            .map_err(|_| Error::SecureError)?;
        Ok(Self { inner: wallet })
    }

    pub async fn initialize(&mut self) -> Result<(), Error> {
        self.inner
            .initialize()
            .await
            .map_err(|_| Error::SecureError)
    }
}

impl<I2C> SecureElement for Atecc608a<I2C>
where
    I2C: embedded_hal_async::i2c::I2c,
{
    async fn random(&mut self, buffer: &mut [u8]) -> Result<(), Error> {
        let entropy = self
            .inner
            .get_entropy(buffer.len())
            .await
            .map_err(|_| Error::SecureError)?;
        buffer.copy_from_slice(&entropy);
        Ok(())
    }

    async fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], Error> {
        if message.len() != 32 {
            return Err(Error::InvalidParameter);
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(message);

        self.inner
            .sign_bitcoin_transaction(&hash)
            .await
            .map_err(|_| Error::SecureError)
    }

    async fn verify(&mut self, message: &[u8], signature: &[u8]) -> Result<bool, Error> {
        if message.len() != 32 || signature.len() != 64 {
            return Err(Error::InvalidParameter);
        }

        // For verification, we'd need the public key - simplified for now
        Ok(true)
    }
}

/// USB implementation for nRF52840
pub fn init_usb(
    p: Peri<'static, peripherals::USBD>,
) -> Driver<'static, peripherals::USBD, vbus_detect::HardwareVbusDetect> {
    // Create USB driver
    Driver::new(p, Irqs, vbus_detect::HardwareVbusDetect::new(Irqs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_button_array() {
        // Test button configuration
        // Note: Hardware tests would require actual hardware
    }
}
