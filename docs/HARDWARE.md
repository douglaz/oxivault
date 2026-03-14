# OxiVault Hardware Assembly Guide

This guide provides detailed instructions for building your own OxiVault hardware wallet using commonly available development boards and components.

## Table of Contents

1. [Supported Platforms](#supported-platforms)
2. [Bill of Materials](#bill-of-materials)
3. [Pin Connections](#pin-connections)
4. [Assembly Instructions](#assembly-instructions)
5. [Flashing Firmware](#flashing-firmware)
6. [Troubleshooting](#troubleshooting)

## Supported Platforms

### Production Ready
- **nRF52840 DK** - Nordic's official development kit with built-in debugger
- **Adafruit Feather nRF52840** - Compact form factor with battery support
- **STM32L476 Discovery** - Ultra-low power with LCD display

### DIY Friendly
- **Raspberry Pi Pico (RP2040)** - Most affordable option
- **ESP32-C3 DevKit** - RISC-V based, WiFi disabled for security
- **STM32 Blue Pill** - Classic choice, widely available

## Bill of Materials

### Essential Components

| Component | Part Number | Quantity | Price (USD) | Notes |
|-----------|------------|----------|-------------|-------|
| **MCU Board** | | | | |
| nRF52840 DK | PCA10056 | 1 | $40 | Recommended for development |
| *or* Raspberry Pi Pico | SC0915 | 1 | $4 | Budget option |
| **Display** | | | | |
| 128x64 OLED | SSD1306 | 1 | $5 | I2C version recommended |
| **Buttons** | | | | |
| Tactile Switch | 6x6mm | 4 | $2 | Confirm, Cancel, Up, Down |
| Pull-up Resistors | 10kΩ | 4 | $1 | For button debouncing |
| **Security** (Optional) | | | | |
| ATECC608A | ATECC608A-MAHDA | 1 | $3 | Secure element for key storage |
| **Storage** (Optional) | | | | |
| MicroSD Breakout | Adafruit 4682 | 1 | $8 | For backup storage |
| **Power** | | | | |
| LiPo Battery | 3.7V 500mAh | 1 | $10 | Optional for portability |
| **Misc** | | | | |
| Breadboard | 830 points | 1 | $5 | For prototyping |
| Jumper Wires | M-M, M-F | 20 | $3 | For connections |
| Enclosure | 3D printed | 1 | $10 | Optional, STL files provided |

**Total Cost: ~$30-50** (depending on MCU choice)

## Pin Connections

### nRF52840 Development Kit

```
Component        | nRF52840 Pin | Direction | Notes
-----------------|--------------|-----------|------------------------
SSD1306 SDA      | P0.26        | I2C       | I2C Data
SSD1306 SCL      | P0.27        | I2C       | I2C Clock
SSD1306 VCC      | VDD          | Power     | 3.3V
SSD1306 GND      | GND          | Ground    |
Button Confirm   | P0.11        | Input     | Internal pull-up
Button Cancel    | P0.12        | Input     | Internal pull-up
Button Up        | P0.24        | Input     | Internal pull-up
Button Down      | P0.25        | Input     | Internal pull-up
ATECC608A SDA    | P0.26        | I2C       | Shared with display
ATECC608A SCL    | P0.27        | I2C       | Shared with display
SD Card MISO     | P1.13        | SPI       | Optional
SD Card MOSI     | P1.14        | SPI       | Optional
SD Card SCK      | P1.15        | SPI       | Optional
SD Card CS       | P1.12        | GPIO      | Optional
Status LED       | P0.13        | Output    | Optional indicator
```

### Raspberry Pi Pico (RP2040)

```
Component        | Pico Pin     | Direction | Notes
-----------------|--------------|-----------|------------------------
SSD1306 SDA      | GP4 (Pin 6)  | I2C       | I2C0 Data
SSD1306 SCL      | GP5 (Pin 7)  | I2C       | I2C0 Clock
SSD1306 VCC      | 3V3 (Pin 36) | Power     | 3.3V
SSD1306 GND      | GND (Pin 38) | Ground    |
Button Confirm   | GP15 (Pin 20)| Input     | External pull-up needed
Button Cancel    | GP14 (Pin 19)| Input     | External pull-up needed
Button Up        | GP13 (Pin 17)| Input     | External pull-up needed
Button Down      | GP12 (Pin 16)| Input     | External pull-up needed
ATECC608A SDA    | GP4 (Pin 6)  | I2C       | Shared with display
ATECC608A SCL    | GP5 (Pin 7)  | I2C       | Shared with display
Status LED       | GP25         | Output    | Built-in LED
```

### ESP32-C3 DevKit

```
Component        | ESP32-C3 Pin | Direction | Notes
-----------------|--------------|-----------|------------------------
SSD1306 SDA      | GPIO8        | I2C       | I2C Data
SSD1306 SCL      | GPIO9        | I2C       | I2C Clock
SSD1306 VCC      | 3V3          | Power     | 3.3V
SSD1306 GND      | GND          | Ground    |
Button Confirm   | GPIO0        | Input     | Boot button can be reused
Button Cancel    | GPIO1        | Input     | External pull-up needed
Button Up        | GPIO2        | Input     | External pull-up needed
Button Down      | GPIO3        | Input     | External pull-up needed
Status LED       | GPIO10       | Output    | External LED
```

## Assembly Instructions

### Step 1: Prepare the Breadboard

1. Place your MCU board on the breadboard
2. Connect power rails:
   - Connect MCU 3.3V to positive rail
   - Connect MCU GND to negative rail

### Step 2: Connect the Display

1. Insert the OLED display module into the breadboard
2. Connect using the pin mapping table above:
   ```
   OLED VCC → 3.3V rail
   OLED GND → GND rail
   OLED SDA → MCU I2C Data pin
   OLED SCL → MCU I2C Clock pin
   ```
3. Add 4.7kΩ pull-up resistors from SDA and SCL to 3.3V (if not built-in)

### Step 3: Wire the Buttons

1. Insert tactile switches into breadboard
2. For each button:
   - Connect one pin to MCU input pin
   - Connect opposite pin to GND
   - Add 10kΩ pull-up resistor from input pin to 3.3V
   
   Example for Confirm button:
   ```
   Button Pin 1 → MCU Input Pin
   Button Pin 2 → GND
   10kΩ resistor → MCU Input Pin to 3.3V
   ```

### Step 4: Add Secure Element (Optional)

1. Connect ATECC608A breakout board:
   ```
   ATECC VCC → 3.3V rail
   ATECC GND → GND rail
   ATECC SDA → Same as OLED SDA (I2C bus is shared)
   ATECC SCL → Same as OLED SCL
   ```
2. The ATECC608A uses address 0x60 (OLED uses 0x3C, no conflict)

### Step 5: Add SD Card Module (Optional)

1. Connect SD card breakout for backup storage:
   ```
   SD VCC → 3.3V rail
   SD GND → GND rail
   SD MISO → MCU SPI MISO pin
   SD MOSI → MCU SPI MOSI pin
   SD SCK → MCU SPI Clock pin
   SD CS → MCU Chip Select pin
   ```

### Step 6: Power Connections

1. For development: USB power is sufficient
2. For portable use: Connect LiPo battery to battery input (if available)
3. Add power switch between battery and MCU (optional)

## Flashing Firmware

### Prerequisites

```bash
# Install Rust and required tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add thumbv7em-none-eabihf  # For ARM Cortex-M4
rustup target add riscv32imc-unknown-none-elf  # For ESP32-C3

# Install flashing tools
cargo install probe-rs --features cli
cargo install cargo-embed
```

### Building the Firmware

```bash
# Clone the repository
git clone https://github.com/yourusername/oxivault
cd oxivault

# Build for nRF52840
cargo build -p oxivault-embedded --features nrf52840 --target thumbv7em-none-eabihf --release

# Build for RP2040
cargo build -p oxivault-embedded --features rp2040 --target thumbv6m-none-eabi --release

# Build for ESP32-C3
cargo build -p oxivault-embedded --features esp32c3 --target riscv32imc-unknown-none-elf --release
```

### Flashing nRF52840

1. Connect the board via USB
2. Flash using probe-rs:
```bash
probe-rs run --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/oxivault-embedded
```

### Flashing Raspberry Pi Pico

1. Hold BOOTSEL button while connecting USB
2. Pico appears as USB drive
3. Copy the UF2 file:
```bash
# Convert ELF to UF2
elf2uf2-rs target/thumbv6m-none-eabi/release/oxivault-embedded oxivault.uf2

# Copy to Pico (adjust path as needed)
cp oxivault.uf2 /media/RPI-RP2/
```

### Flashing ESP32-C3

1. Install esptool:
```bash
pip install esptool
```

2. Flash the firmware:
```bash
esptool.py --chip esp32c3 --port /dev/ttyUSB0 write_flash 0x0 target/riscv32imc-unknown-none-elf/release/oxivault-embedded.bin
```

## Troubleshooting

### Display Not Working

1. **Check I2C connections**: Ensure SDA and SCL are correctly connected
2. **Verify pull-up resistors**: 4.7kΩ resistors needed on both lines
3. **Check I2C address**: Default is 0x3C, some displays use 0x3D
4. **Test with I2C scanner**: Use example code to scan for devices

### Buttons Not Responding

1. **Check pull-up resistors**: Each button needs 10kΩ to 3.3V
2. **Verify connections**: Button should connect input to GND when pressed
3. **Test with multimeter**: Check continuity when button is pressed
4. **Adjust debounce time**: Increase delay in firmware if needed

### Firmware Won't Flash

1. **Check USB cable**: Must be data cable, not charge-only
2. **Install drivers**: Some boards need specific USB drivers
3. **Try different USB port**: USB 2.0 ports often more reliable
4. **Reset board**: Hold reset while connecting, then release

### Random Resets or Crashes

1. **Check power supply**: Ensure stable 3.3V supply
2. **Add capacitors**: 100µF on power rail for stability
3. **Check for shorts**: Inspect all connections
4. **Monitor serial output**: Use `defmt` logging for debugging

### Secure Element Not Detected

1. **Check I2C address**: ATECC608A uses 0x60 by default
2. **Verify power**: Needs stable 3.3V supply
3. **Check configuration**: May need initialization on first use
4. **Test with scanner**: Use I2C scanner to detect device

## Additional Resources

- [OxiVault GitHub Repository](https://github.com/yourusername/oxivault)
- [Embassy-rs Documentation](https://embassy.dev/)
- [nRF52840 Product Specification](https://www.nordicsemi.com/Products/nRF52840)
- [Raspberry Pi Pico Datasheet](https://datasheets.raspberrypi.org/pico/pico-datasheet.pdf)
- [ESP32-C3 Technical Reference](https://www.espressif.com/sites/default/files/documentation/esp32-c3_technical_reference_manual_en.pdf)

## Safety Notes

⚠️ **Important Safety Considerations:**

1. **Static Protection**: Use anti-static wrist strap when handling components
2. **Power Limits**: Never exceed 3.3V on any GPIO pin
3. **Current Limits**: Each GPIO typically limited to 10-20mA
4. **Heat Management**: Add heatsinks if running intensive operations
5. **Battery Safety**: Use protected LiPo batteries with built-in BMS

## Community Support

Join our community for help and discussions:
- Discord: [OxiVault Community](https://discord.gg/oxivault)
- Matrix: #oxivault:matrix.org
- GitHub Issues: [Report problems](https://github.com/yourusername/oxivault/issues)

---

*Last updated: December 2024*