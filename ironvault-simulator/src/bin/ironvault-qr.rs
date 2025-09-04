//! IronVault QR command-line tool

use clap::Parser;
use ironvault_simulator::cli::Cli;

fn main() {
    let cli = Cli::parse();
    
    if let Err(e) = cli.execute() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}