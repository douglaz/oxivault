//! Command-line interface for QR operations

use clap::{Parser, Subcommand};
use ironvault_core::bip39::MnemonicManager;
use ironvault_qr::{
    QrGenerator, AsciiQrRenderer,
    BBQrEncoder, BBQrDecoder, FileType, EncodingType,
};
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate QR codes
    Generate {
        #[command(subcommand)]
        subcommand: GenerateCommands,
    },
    /// Import from QR codes
    Import {
        #[command(subcommand)]
        subcommand: ImportCommands,
    },
    /// Export to QR codes
    Export {
        #[command(subcommand)]
        subcommand: ExportCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum GenerateCommands {
    /// Generate QR for Bitcoin address
    Address {
        /// Bitcoin address
        address: String,
        /// Output file (optional, displays to terminal if not provided)
        #[arg(short, long)]
        output: Option<String>,
        /// Use compact rendering
        #[arg(short, long)]
        compact: bool,
    },
    /// Generate QR for arbitrary text
    Text {
        /// Text to encode
        text: String,
        /// Output file (optional, displays to terminal if not provided)
        #[arg(short, long)]
        output: Option<String>,
        /// Use compact rendering
        #[arg(short, long)]
        compact: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ImportCommands {
    /// Import mnemonic from BBQr parts
    Mnemonic {
        /// Input files containing BBQr parts
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Import PSBT from BBQr parts
    Psbt {
        /// Input files containing BBQr parts
        #[arg(required = true)]
        files: Vec<String>,
        /// Output file for the reconstructed PSBT
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ExportCommands {
    /// Export mnemonic as BBQr parts
    Mnemonic {
        /// Mnemonic phrase (or file containing it)
        mnemonic: String,
        /// Output directory for BBQr parts
        #[arg(short, long, default_value = ".")]
        output_dir: String,
        /// Maximum bytes per QR code
        #[arg(short, long, default_value = "100")]
        fragment_size: usize,
    },
    /// Export PSBT as BBQr parts
    Psbt {
        /// PSBT file or hex string
        psbt: String,
        /// Output directory for BBQr parts
        #[arg(short, long, default_value = ".")]
        output_dir: String,
        /// Maximum bytes per QR code
        #[arg(short, long, default_value = "200")]
        fragment_size: usize,
    },
    /// Export address as single QR
    Address {
        /// Bitcoin address
        address: String,
        /// Output file
        #[arg(short, long)]
        output: Option<String>,
        /// Use compact rendering
        #[arg(short, long)]
        compact: bool,
    },
}

impl Cli {
    pub fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.command {
            Commands::Generate { subcommand } => self.handle_generate(subcommand),
            Commands::Import { subcommand } => self.handle_import(subcommand),
            Commands::Export { subcommand } => self.handle_export(subcommand),
        }
    }

    fn handle_generate(&self, cmd: &GenerateCommands) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            GenerateCommands::Address { address, output, compact } => {
                let qr = QrGenerator::generate(address)
                    .map_err(|e| format!("Failed to generate QR: {}", e))?;
                
                let rendered = if *compact {
                    AsciiQrRenderer::render_compact(&qr)
                } else {
                    AsciiQrRenderer::render(&qr)
                };

                self.output_result(&rendered, output.as_deref())?;
            }
            GenerateCommands::Text { text, output, compact } => {
                let qr = QrGenerator::generate(text)
                    .map_err(|e| format!("Failed to generate QR: {}", e))?;
                
                let rendered = if *compact {
                    AsciiQrRenderer::render_compact(&qr)
                } else {
                    AsciiQrRenderer::render(&qr)
                };

                self.output_result(&rendered, output.as_deref())?;
            }
        }
        Ok(())
    }

    fn handle_import(&self, cmd: &ImportCommands) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            ImportCommands::Mnemonic { files } => {
                let mut decoder = BBQrDecoder::new();
                
                for file in files {
                    let content = fs::read_to_string(file)?;
                    decoder.add_part(&content)
                        .map_err(|e| format!("Failed to add part from {}: {}", file, e))?;
                    
                    let (received, total) = decoder.progress();
                    println!("Progress: {}/{} parts", received, total);
                }
                
                if !decoder.is_complete() {
                    return Err("Not all parts received".into());
                }
                
                let data = decoder.combine()
                    .map_err(|e| format!("Failed to combine parts: {}", e))?;
                
                let mnemonic = String::from_utf8(data)?;
                
                // Validate the mnemonic
                if !MnemonicManager::validate(&mnemonic) {
                    return Err("Invalid mnemonic recovered from QR".into());
                }
                
                println!("Successfully imported mnemonic:");
                println!("{}", mnemonic);
            }
            ImportCommands::Psbt { files, output } => {
                let mut decoder = BBQrDecoder::new();
                
                for file in files {
                    let content = fs::read_to_string(file)?;
                    decoder.add_part(&content)
                        .map_err(|e| format!("Failed to add part from {}: {}", file, e))?;
                    
                    let (received, total) = decoder.progress();
                    println!("Progress: {}/{} parts", received, total);
                }
                
                if !decoder.is_complete() {
                    return Err("Not all parts received".into());
                }
                
                let data = decoder.combine()
                    .map_err(|e| format!("Failed to combine parts: {}", e))?;
                
                // Convert to hex string for PSBT
                let hex = hex::encode(&data);
                
                if let Some(output_file) = output {
                    fs::write(output_file, hex)?;
                    println!("PSBT saved to {}", output_file);
                } else {
                    println!("PSBT (hex):");
                    println!("{}", hex);
                }
            }
        }
        Ok(())
    }

    fn handle_export(&self, cmd: &ExportCommands) -> Result<(), Box<dyn std::error::Error>> {
        match cmd {
            ExportCommands::Mnemonic { mnemonic, output_dir, fragment_size } => {
                // Read mnemonic from file if it exists, otherwise use as-is
                let mnemonic_text = if fs::metadata(mnemonic).is_ok() {
                    fs::read_to_string(mnemonic)?
                } else {
                    mnemonic.clone()
                };
                
                // Validate mnemonic
                if !MnemonicManager::validate(&mnemonic_text) {
                    return Err("Invalid mnemonic".into());
                }
                
                let encoder = BBQrEncoder::new(FileType::Text, EncodingType::Raw, *fragment_size);
                let parts = encoder.split(mnemonic_text.as_bytes())
                    .map_err(|e| format!("Failed to split mnemonic: {}", e))?;
                
                println!("Generating {} BBQr parts...", parts.len());
                
                for (i, part) in parts.iter().enumerate() {
                    let filename = format!("{}/mnemonic_part_{:03}.txt", output_dir, i + 1);
                    fs::write(&filename, part)?;
                    
                    // Also generate QR image
                    if let Ok(qr) = QrGenerator::generate(part) {
                        let qr_filename = format!("{}/mnemonic_part_{:03}_qr.txt", output_dir, i + 1);
                        let rendered = AsciiQrRenderer::render_compact(&qr);
                        fs::write(&qr_filename, rendered)?;
                    }
                    
                    println!("Wrote {}", filename);
                }
                
                println!("Successfully exported {} BBQr parts", parts.len());
            }
            ExportCommands::Psbt { psbt, output_dir, fragment_size } => {
                // Read PSBT from file if it exists, otherwise treat as hex
                let psbt_bytes = if fs::metadata(psbt).is_ok() {
                    fs::read(psbt)?
                } else {
                    hex::decode(psbt)?
                };
                
                let encoder = BBQrEncoder::new(FileType::Psbt, EncodingType::Raw, *fragment_size);
                let parts = encoder.split(&psbt_bytes)
                    .map_err(|e| format!("Failed to split PSBT: {}", e))?;
                
                println!("Generating {} BBQr parts...", parts.len());
                
                for (i, part) in parts.iter().enumerate() {
                    let filename = format!("{}/psbt_part_{:03}.txt", output_dir, i + 1);
                    fs::write(&filename, part)?;
                    
                    // Also generate QR image
                    if let Ok(qr) = QrGenerator::generate(part) {
                        let qr_filename = format!("{}/psbt_part_{:03}_qr.txt", output_dir, i + 1);
                        let rendered = AsciiQrRenderer::render_compact(&qr);
                        fs::write(&qr_filename, rendered)?;
                    }
                    
                    println!("Wrote {}", filename);
                }
                
                println!("Successfully exported {} BBQr parts", parts.len());
            }
            ExportCommands::Address { address, output, compact } => {
                let qr = QrGenerator::generate(address)
                    .map_err(|e| format!("Failed to generate QR: {}", e))?;
                
                let rendered = if *compact {
                    AsciiQrRenderer::render_compact(&qr)
                } else {
                    AsciiQrRenderer::render(&qr)
                };

                self.output_result(&rendered, output.as_deref())?;
            }
        }
        Ok(())
    }

    fn output_result(&self, data: &str, output_file: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(file) = output_file {
            fs::write(file, data)?;
            println!("Output saved to {}", file);
        } else {
            println!("{}", data);
        }
        Ok(())
    }
}