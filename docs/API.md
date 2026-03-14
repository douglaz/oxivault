# OxiVault API Documentation

## Core Library (`oxivault-core`)

### Wallet Management

```rust
use oxivault_core::{
    wallet::{Wallet, ScriptType},
    Network,
};

// Create wallet from mnemonic
let wallet = Wallet::from_mnemonic(
    "your twelve word mnemonic phrase",
    "optional_passphrase",
    Network::Bitcoin,
)?;

// Derive addresses
let address = wallet.get_address(
    ScriptType::NativeSegwit,  // BIP-84
    0,  // Account
    0,  // Change (0=external, 1=internal)
    0,  // Index
)?;
```

### Mnemonic Generation

```rust
use oxivault_core::bip39::MnemonicManager;

// Generate new mnemonic
let mnemonic = MnemonicManager::generate(24)?;
println!("Words: {}", mnemonic.phrase());

// Validate existing mnemonic
if MnemonicManager::validate("word1 word2 ...") {
    println!("Valid mnemonic");
}
```

### PSBT Signing

```rust
use oxivault_core::psbt::PsbtSigner;
use bitcoin::psbt::Psbt;

let psbt_bytes = base64::decode("cHNidP8B...")?;
let mut psbt = Psbt::deserialize(&psbt_bytes)?;

// Sign with wallet
let signer = PsbtSigner::new(wallet);
signer.sign_psbt(&mut psbt)?;
```

### Multisig Coordination

```rust
use oxivault_core::multisig::{MultisigBuilder, MultisigScriptType};

let config = MultisigBuilder::new()
    .threshold(2)
    .add_cosigner("Alice", fingerprint1, xpub1, path1)
    .add_cosigner("Bob", fingerprint2, xpub2, path2)
    .add_cosigner("Charlie", fingerprint3, xpub3, path3)
    .network(Network::Bitcoin)
    .script_type(MultisigScriptType::P2wsh)
    .build()?;

// Derive multisig address
let address = config.derive_address(0, 0)?;
```

### Taproot Support

```rust
use oxivault_core::taproot::TaprootKey;
use bitcoin::secp256k1::SecretKey;

let secret = SecretKey::from_slice(&[0x01; 32])?;
let taproot_key = TaprootKey::new(secret, Network::Bitcoin);

// Simple key-path address
let address = taproot_key.simple_address();

// With script tree
let (address, spend_info) = taproot_key.address_with_scripts(vec![
    script1,
    script2,
])?;
```

### Miniscript Policies

```rust
use oxivault_core::miniscript::{PolicyBuilder, MiniscriptCompiler};

// 2-of-3 multisig
let policy = PolicyBuilder::multisig_2_of_3(pk1, pk2, pk3);

// Inheritance (owner OR heir after 1 year)
let policy = PolicyBuilder::inheritance(owner_pk, heir_pk, 52560);

// Compile to Bitcoin Script
let miniscript = MiniscriptCompiler::compile(&policy)?;
let script = MiniscriptCompiler::to_script(&miniscript)?;
```

### SLIP-39 Shamir Backup

```rust
use oxivault_core::slip39::{Slip39, ShareConfig};

// Split secret into shares
let config = ShareConfig {
    threshold: 2,
    total_shares: 3,
    identifier: 1234,
};

let shares = Slip39::split_secret(&secret_data, &config)?;

// Recover from shares
let secret = Slip39::combine_shares(&[share1, share2])?;
```

### Encrypted Backup

```rust
use oxivault_core::backup::{BackupManager, BackupMetadata};

let mut manager = BackupManager::new();

// Create encrypted backup
let backup = manager.create_backup(
    &extended_private_key,
    "strong_passphrase",
    metadata,
)?;

// Restore from backup
let restored = manager.restore_backup(&backup, "strong_passphrase")?;
```

## Embedded Library (`oxivault-embedded`)

### Hardware Abstraction

```rust
use oxivault_embedded::{HardwareWallet, ButtonEvent};

#[derive(Clone)]
struct MyHardware;

impl HardwareWallet for MyHardware {
    async fn init(&mut self) {
        // Initialize hardware
    }
    
    async fn display_text(&mut self, text: &str) {
        // Show on display
    }
    
    async fn wait_for_button(&mut self) -> ButtonEvent {
        // Wait for user input
    }
    
    async fn get_entropy(&mut self) -> [u8; 32] {
        // Hardware RNG
    }
}
```

### Display Driver

```rust
use oxivault_embedded::drivers::ssd1306::{Ssd1306, I2cInterface};

// Initialize display
let i2c_interface = I2cInterface::new(i2c_bus, 0x3C);
let mut display = Ssd1306::new(i2c_interface, Rotation::Rotate0);
display.init().await?;

// Draw text
display.draw_text("OxiVault", 10, 10, TextSize::Large);
display.flush().await?;
```

## HWI Protocol

```rust
use oxivault_core::hwi::{HwiProtocol, HwiCommand};

let mut protocol = HwiProtocol::new(fingerprint, network);

// Process HWI commands
let response = protocol.process_command(HwiCommand::GetXpub {
    path: "m/84'/0'/0'".to_string(),
}).await;

// USB transport
let mut transport = UsbTransport::new();
let command = transport.read_command().await?;
transport.write_response(&response).await?;
```

## Error Handling

All functions return `Result<T, Error>` where Error is:

```rust
pub enum Error {
    InvalidMnemonic,
    InvalidDerivationPath(String),
    InvalidNetwork,
    Secp256k1Error,
    BitcoinError(String),
    PsbtError(String),
    InsufficientEntropy,
    InvalidKey,
    InvalidEntropy(String),
    InvalidParameter(String),
    ChecksumError,
    Taproot(String),
    BackupError(String),
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wallet_derivation() {
        let wallet = Wallet::from_mnemonic(
            TEST_MNEMONIC,
            "",
            Network::Testnet,
        ).unwrap();
        
        let addr = wallet.get_address(
            ScriptType::NativeSegwit,
            0, 0, 0
        ).unwrap();
        
        assert!(addr.to_string().starts_with("tb1"));
    }
}
```