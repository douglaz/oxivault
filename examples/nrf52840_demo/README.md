# nRF52840 OxiVault Demo

This example demonstrates running OxiVault on an nRF52840 development board.

## Hardware Requirements

- nRF52840 Development Kit (DK) or compatible board
- USB cable for programming
- Optional: OLED display (SSD1306) connected via I2C
- Optional: Buttons for navigation

## Pin Configuration

- P0.11: Button input (SELECT)
- P0.13: Status LED
- P0.14: Heartbeat LED
- P0.26: I2C SDA (for display)
- P0.27: I2C SCL (for display)

## Building

```bash
# Install dependencies
rustup target add thumbv7em-none-eabihf
cargo install probe-rs --features cli

# Build the firmware
cargo build --release

# Flash to device
cargo run --release
```

## Features Demonstrated

1. **Hardware Initialization**: LED indicators and button input
2. **Wallet State Machine**: Basic wallet operations
3. **Async Operations**: Using Embassy-rs for non-blocking I/O
4. **Memory Safety**: No heap allocation, all stack-based

## Memory Usage

- Flash: ~200KB (includes wallet logic)
- RAM: ~32KB (static allocation)

## Operation

1. Power on: LEDs flash 3 times
2. Press button to cycle through menu
3. Hold button to select option
4. Heartbeat LED blinks every second

## Security Notes

This is a demonstration firmware. For production use:
- Enable hardware RNG
- Implement secure boot
- Add tamper detection
- Use secure element for key storage