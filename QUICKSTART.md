# OxiVault Quick Start Guide

Welcome to OxiVault! This guide will help you get started with the next-generation Rust hardware wallet.

## Table of Contents

1. [Installation](#installation)
2. [Desktop Simulator](#desktop-simulator)
3. [Basic Operations](#basic-operations)
4. [Hardware Setup](#hardware-setup)
5. [Advanced Features](#advanced-features)
6. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

- Rust 1.74.0 or later
- Git
- (Optional) USB drivers for hardware devices

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/oxivault
cd oxivault

# Build the project
cargo build --release

# The simulator binary will be at:
# target/release/oxivault-sim
```

### Quick Install

```bash
# Install directly with cargo
cargo install --git https://github.com/yourusername/oxivault oxivault-simulator

# Or download pre-built binaries from releases page
```

## Desktop Simulator

The desktop simulator allows you to test all OxiVault features without hardware.

### Running the Simulator

```bash
# Run with default settings
oxivault-sim

# Or use cargo run
cargo run --release -p oxivault-simulator --bin oxivault-sim
```

### Available Commands

```bash
# Generate a new mnemonic (12 or 24 words)
oxivault-sim generate --words 24

# Validate a mnemonic
oxivault-sim validate "your twelve word mnemonic phrase here"

# Derive addresses
oxivault-sim derive --script-type native-segwit --count 10

# Show help
oxivault-sim --help
```

## Basic Operations

### 1. Create a New Wallet

```bash
# Generate a 24-word mnemonic (recommended)
$ oxivault-sim generate --words 24

Generated 24 word mnemonic:
word1 word2 word3 ... word24

⚠️  Write this down and keep it safe!
⚠️  This is your only backup!
```

### 2. Derive Bitcoin Addresses

```bash
# Derive first 5 native segwit addresses
$ echo "your mnemonic here" | oxivault-sim derive --script-type native-segwit --count 5

Deriving 5 addresses for native-segwit
Network: Bitcoin Mainnet
Derivation: BIP-84

m/84'/0'/0'/0/0: bc1q...
m/84'/0'/0'/0/1: bc1q...
m/84'/0'/0'/0/2: bc1q...
m/84'/0'/0'/0/3: bc1q...
m/84'/0'/0'/0/4: bc1q...
```

### 3. Address Types

OxiVault supports all modern Bitcoin address types:

- **Legacy (P2PKH)**: Starts with `1`
  ```bash
  oxivault-sim derive --script-type legacy
  ```

- **Nested SegWit (P2SH-P2WPKH)**: Starts with `3`
  ```bash
  oxivault-sim derive --script-type nested-segwit
  ```

- **Native SegWit (P2WPKH)**: Starts with `bc1q`
  ```bash
  oxivault-sim derive --script-type native-segwit
  ```

- **Taproot (P2TR)**: Starts with `bc1p`
  ```bash
  oxivault-sim derive --script-type taproot
  ```

## Hardware Setup

### Supported Platforms

#### Budget Options ($10-30)
- **Raspberry Pi Pico (RP2040)**
- **ESP32-C3**
- **STM32 Blue Pill**

#### Production Ready ($30-50)
- **nRF52840 Development Kit**
- **STM32L4 Discovery**

### Building for Hardware

```bash
# Install target for ARM Cortex-M4 (nRF52840, STM32L4)
rustup target add thumbv7em-none-eabihf

# Build for nRF52840
cargo build --release --package oxivault-embedded \
  --no-default-features --features nrf52840 \
  --target thumbv7em-none-eabihf

# Flash to device (requires probe-rs)
cargo embed --release --chip nRF52840_xxAA
```

### Pin Configuration (nRF52840)

| Pin | Function |
|-----|----------|
| P0.11 | Button SELECT |
| P0.13 | Status LED |
| P0.14 | Heartbeat LED |
| P0.26 | I2C SDA (Display) |
| P0.27 | I2C SCL (Display) |

## Advanced Features

### Multisig Wallets

OxiVault supports multisig configurations up to 15-of-15:

```rust
// Example: 2-of-3 multisig
let config = MultisigBuilder::new()
    .threshold(2)
    .add_cosigner("Alice", fingerprint1, xpub1, path1)
    .add_cosigner("Bob", fingerprint2, xpub2, path2)
    .add_cosigner("Charlie", fingerprint3, xpub3, path3)
    .build();
```

### Taproot Support

Full BIP-340/341/342 implementation:

```rust
let taproot_key = TaprootKey::new(secret_key, Network::Bitcoin);
let address = taproot_key.simple_address();
```

### SLIP-39 Shamir Backup

Split your seed into multiple shares:

```rust
// Create 3 shares, need 2 to recover
let config = ShareConfig {
    threshold: 2,
    total_shares: 3,
    identifier: 1234,
};
let shares = Slip39::split_secret(&seed, &config);
```

### Miniscript Policies

Create complex spending conditions:

```rust
// Inheritance: Owner OR (Heir after 1 year)
let policy = PolicyBuilder::inheritance(owner_key, heir_key, 52560);
```

## Troubleshooting

### Common Issues

#### "Cannot find mnemonic"
Make sure you're piping the mnemonic to stdin or passing it as an argument.

#### Binary too large
The release build is optimized for size (2.5MB). For embedded targets, use:
```toml
[profile.release]
opt-level = "z"
strip = true
lto = "fat"
```

#### Hardware not detected
1. Check USB drivers are installed
2. Verify device permissions (may need udev rules on Linux)
3. Try different USB cable/port

### Getting Help

- GitHub Issues: [github.com/yourusername/oxivault/issues](https://github.com/yourusername/oxivault/issues)
- Documentation: [docs.rs/oxivault](https://docs.rs/oxivault)
- Discord: [discord.gg/oxivault](https://discord.gg/oxivault)

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never share your mnemonic phrase**
2. **Always verify addresses on device screen**
3. **Use passphrase for additional security**
4. **Keep firmware updated**
5. **Verify signatures when downloading binaries**

## Next Steps

- Read the [full documentation](./docs/README.md)
- Explore [API documentation](./docs/API.md)
- Check out [examples](./examples/)
- Contribute on [GitHub](https://github.com/yourusername/oxivault)

---

OxiVault - Forging the future of Bitcoin hardware wallets with Rust 🦀