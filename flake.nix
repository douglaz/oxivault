{
  description = "OxiVault - Next-Generation Rust Hardware Wallet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        
        # Rust toolchain with embedded targets
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
          targets = [ 
            "thumbv7em-none-eabihf"     # ARM Cortex-M4 (nRF52840, STM32L4)
            "thumbv6m-none-eabi"         # ARM Cortex-M0+ (RP2040)
            "riscv32imc-unknown-none-elf" # RISC-V (ESP32-C3)
          ];
        };
      in
      {
        # Default package: simulator desktop app
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "oxivault-simulator";
          version = "0.1.0";
          src = ./.;
          
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          
          nativeBuildInputs = with pkgs; [
            pkg-config
            rustToolchain
          ];
          
          buildInputs = with pkgs; [
            openssl
          ] ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
          ];
          
          # Build only the simulator
          buildAndTestSubdir = "oxivault-simulator";
          
          meta = with pkgs.lib; {
            description = "OxiVault Bitcoin hardware wallet simulator";
            homepage = "https://github.com/douglaz/oxivault";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
        
        # Core library package (no_std verification)
        packages.oxivault-core = pkgs.rustPlatform.buildRustPackage {
          pname = "oxivault-core";
          version = "0.1.0";
          src = ./.;
          
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          
          nativeBuildInputs = with pkgs; [
            rustToolchain
          ];
          
          # Build core without std
          buildPhase = ''
            runHook preBuild
            
            echo "Building oxivault-core with no_std..."
            cargo build \
              --release \
              --package oxivault-core \
              --no-default-features \
              --offline \
              -j $NIX_BUILD_CORES
            
            runHook postBuild
          '';
          
          # Skip install for library crate
          installPhase = ''
            runHook preInstall
            
            mkdir -p $out
            echo "oxivault-core built successfully (no_std verified)" > $out/build-info.txt
            
            runHook postInstall
          '';
          
          doCheck = false;
          
          meta = with pkgs.lib; {
            description = "OxiVault core Bitcoin library (no_std)";
            homepage = "https://github.com/douglaz/oxivault";
            license = licenses.mit;
            maintainers = [ ];
          };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            bashInteractive
            rustToolchain
            pkg-config
            
            # Embedded development tools
            probe-rs-tools
            cargo-binutils
            gcc-arm-embedded    # ARM cross-compiler toolchain
            
            # Development tools
            cargo-edit
            cargo-outdated
            cargo-watch
            cargo-expand
            rust-analyzer
            
            # Git tools
            gh
            git
            
            # System dependencies
            openssl
            libusb1
            
            # Cross-compilation tools
            llvmPackages.bintools
          ] ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
          ];

          # Environment variables
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          
          # Cross-compilation settings for ARM targets
          CC_thumbv7em_none_eabihf = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-gcc";
          AR_thumbv7em_none_eabihf = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-ar";
          CC_thumbv6m_none_eabi = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-gcc";
          AR_thumbv6m_none_eabi = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-ar";
          
          # Tell Cargo to use the ARM linker
          CARGO_TARGET_THUMBV7EM_NONE_EABIHF_LINKER = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-gcc";
          CARGO_TARGET_THUMBV6M_NONE_EABI_LINKER = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-gcc";
          
          shellHook = ''
            echo "🦀 OxiVault development environment"
            echo ""
            echo "Available embedded targets:"
            echo "  • thumbv7em-none-eabihf    - nRF52840, STM32L4"
            echo "  • thumbv6m-none-eabi       - RP2040 (Raspberry Pi Pico)"
            echo "  • riscv32imc-unknown-none-elf - ESP32-C3"
            echo ""
            echo "Commands:"
            echo "  • cargo build -p oxivault-simulator     - Build desktop simulator"
            echo "  • cargo build -p oxivault-core --no-default-features - Build core (no_std)"
            echo "  • cargo build -p oxivault-embedded --target thumbv7em-none-eabihf --features nrf52840"
            echo "  • cargo test --all                      - Run all tests"
            echo "  • cargo clippy --all                    - Run linter"
            echo "  • cargo fmt                             - Format code"
            echo ""
            
            # Automatically configure Git hooks for code quality
            if [ -d .git ] && [ -d .githooks ]; then
              current_hooks_path=$(git config core.hooksPath || echo "")
              if [ "$current_hooks_path" != ".githooks" ]; then
                echo "📎 Setting up Git hooks for code quality checks..."
                git config core.hooksPath .githooks
                echo "✅ Git hooks configured automatically!"
                echo "   • pre-commit: Checks code formatting"
                echo "   • pre-push: Runs formatting and clippy checks"
                echo ""
                echo "To disable: git config --unset core.hooksPath"
              fi
            fi
          '';
        };
      }
    );
}