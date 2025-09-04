//! OxiVault Hardware Wallet Simulator

use clap::{Parser, Subcommand};
use oxivault_core::{
    bip39::MnemonicManager,
    wallet::{Wallet, ScriptType},
    Network,
};

mod cli;
mod tui;
mod tui_enhanced;
mod tui_signing;
mod qr_import;

#[derive(Parser)]
#[command(name = "oxivault-sim")]
#[command(about = "OxiVault Hardware Wallet Simulator", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new mnemonic phrase
    Generate {
        /// Number of words (12, 15, 18, 21, or 24)
        #[arg(short, long, default_value = "24")]
        words: usize,
    },
    /// Derive addresses from a mnemonic
    Derive {
        /// Mnemonic phrase (or use test mnemonic if not provided)
        #[arg(short, long)]
        mnemonic: Option<String>,
        /// BIP39 passphrase
        #[arg(short, long, default_value = "")]
        passphrase: String,
        /// Script type (legacy, nested-segwit, native-segwit, taproot)
        #[arg(short, long, default_value = "native-segwit")]
        script_type: String,
        /// Number of addresses to generate
        #[arg(short, long, default_value = "5")]
        count: usize,
    },
    /// Validate a mnemonic phrase
    Validate {
        /// Mnemonic phrase to validate
        mnemonic: String,
    },
    /// Run the transaction signing workflow
    Sign,
    /// Run the enhanced TUI with QR export
    Enhanced,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // No command specified, run TUI
            tui::App::run()?;
        }
        Some(command) => match command {
        Commands::Generate { words } => {
            generate_mnemonic(words)?;
        }
        Commands::Derive {
            mnemonic,
            passphrase,
            script_type,
            count,
        } => {
            let mnemonic = mnemonic.unwrap_or_else(|| {
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()
            });
            derive_addresses(&mnemonic, &passphrase, &script_type, count)?;
        }
                Commands::Validate { mnemonic } => {
                validate_mnemonic(&mnemonic)?;
            }
            Commands::Sign => {
                // Run the transaction signing workflow
                tui_signing::run_signing_workflow()?;
            }
            Commands::Enhanced => {
                // Run the enhanced TUI (placeholder for now)
                println!("Enhanced TUI with QR export - coming soon!");
            }
        }
    }

    Ok(())
}

fn generate_mnemonic(words: usize) -> Result<(), Box<dyn std::error::Error>> {
    let manager = MnemonicManager::generate(words)?;
    println!("Generated {} word mnemonic:", words);
    println!("{}", manager.phrase());
    println!("\n⚠️  Write this down and keep it safe!");
    println!("⚠️  This is your only backup!");
    Ok(())
}

fn derive_addresses(
    mnemonic: &str,
    passphrase: &str,
    script_type_str: &str,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let script_type = match script_type_str {
        "legacy" => ScriptType::Legacy,
        "nested-segwit" => ScriptType::NestedSegwit,
        "native-segwit" => ScriptType::NativeSegwit,
        "taproot" => ScriptType::Taproot,
        _ => {
            return Err("Invalid script type. Use: legacy, nested-segwit, native-segwit, or taproot".into());
        }
    };

    let wallet = Wallet::from_mnemonic(mnemonic, passphrase, Network::Bitcoin)?;
    
    println!("Deriving {} addresses for {}", count, script_type_str);
    println!("Network: Bitcoin Mainnet");
    println!("Derivation: BIP-{}", script_type.bip_number());
    println!();

    for i in 0..count {
        let address = wallet.get_address(script_type, 0, 0, i as u32)?;
        println!("m/{}'/{}'/{}'/{}/{}: {}", 
            script_type.bip_number(),
            0,  // Bitcoin
            0,  // Account
            0,  // External chain
            i,
            address
        );
    }

    Ok(())
}

fn validate_mnemonic(mnemonic: &str) -> Result<(), Box<dyn std::error::Error>> {
    if MnemonicManager::validate(mnemonic) {
        println!("✅ Valid mnemonic phrase");
        let manager = MnemonicManager::from_phrase(mnemonic)?;
        let words = manager.words();
        println!("Word count: {}", words.len());
    } else {
        println!("❌ Invalid mnemonic phrase");
        println!("Please check:");
        println!("- All words are from the BIP-39 word list");
        println!("- The checksum is valid");
        println!("- The phrase has 12, 15, 18, 21, or 24 words");
    }
    Ok(())
}