# Contributing to OxiVault

Thank you for your interest in contributing to OxiVault! This guide will help you get started.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use issue templates when available
3. Provide detailed reproduction steps
4. Include system information (OS, Rust version, hardware)

### Suggesting Features

1. Open a discussion first for major features
2. Explain the use case and benefits
3. Consider security implications
4. Be willing to implement it yourself

### Submitting Code

#### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/oxivault
cd oxivault

# Install development tools
rustup component add rustfmt clippy
cargo install cargo-audit cargo-outdated

# Run tests
cargo test --all
```

#### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation

4. **Run quality checks**
   ```bash
   # Format code
   cargo fmt --all
   
   # Run linter
   cargo clippy --all -- -D warnings
   
   # Run tests
   cargo test --all
   
   # Check no_std compatibility
   cargo build --package oxivault-core --no-default-features
   ```

5. **Commit your changes**
   ```bash
   git commit -m "feat: add new feature
   
   - Detailed description
   - Closes #123"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

We use conventional commits:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### Code Style Guidelines

#### Rust Code

- Use `rustfmt` for formatting
- Follow Rust API guidelines
- Prefer `Result` over `panic!`
- Document public APIs
- Use meaningful variable names

#### Error Handling

```rust
// Good
pub fn parse_data(input: &str) -> Result<Data, Error> {
    input.parse()
        .map_err(|e| Error::ParseError(e.to_string()))
}

// Bad
pub fn parse_data(input: &str) -> Data {
    input.parse().unwrap()
}
```

#### Testing

- Write unit tests for logic
- Add integration tests for workflows
- Use property-based testing where appropriate
- Maintain >80% code coverage

### Security Considerations

#### Required for Crypto Code

1. Use constant-time operations
2. Clear sensitive data from memory
3. Validate all inputs
4. Document security assumptions
5. Request security review for critical changes

#### Example: Secure Key Handling

```rust
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
struct SecretKey {
    data: [u8; 32],
}
```

### Documentation

#### Code Documentation

```rust
/// Derives a Bitcoin address from the wallet.
///
/// # Arguments
///
/// * `script_type` - The type of script to use
/// * `account` - Account number (hardened)
/// * `change` - 0 for external, 1 for internal
/// * `index` - Address index
///
/// # Returns
///
/// The derived Bitcoin address
///
/// # Example
///
/// ```
/// let address = wallet.get_address(
///     ScriptType::NativeSegwit,
///     0,  // account
///     0,  // external chain
///     0,  // first address
/// )?;
/// ```
pub fn get_address(
    &self,
    script_type: ScriptType,
    account: u32,
    change: u32,
    index: u32,
) -> Result<Address> {
    // Implementation
}
```

### Review Process

#### PR Requirements

- [ ] Tests pass (CI green)
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] No security vulnerabilities
- [ ] Code reviewed by maintainer

#### Review Timeline

- Simple fixes: 1-3 days
- Features: 3-7 days
- Major changes: 1-2 weeks

### Areas Needing Help

#### High Priority

- Hardware device testing
- Security auditing
- Documentation improvements
- Performance optimization

#### Good First Issues

Look for issues labeled:
- `good-first-issue`
- `help-wanted`
- `documentation`

### Development Tips

#### Running Benchmarks

```bash
cargo bench --all
```

#### Profiling

```bash
cargo build --release
perf record --call-graph=dwarf target/release/oxivault-sim
perf report
```

#### Testing Hardware

```bash
# Install probe-rs
cargo install probe-rs --features cli

# Flash and monitor
cargo embed --release --chip nRF52840_xxAA
```

### Getting Help

- Discord: [discord.gg/oxivault](https://discord.gg/oxivault)
- GitHub Discussions: [github.com/yourusername/oxivault/discussions](https://github.com/yourusername/oxivault/discussions)
- Email: oxivault@example.com

### License

By contributing, you agree that your contributions will be dual-licensed under MIT OR Apache-2.0.

---

Thank you for contributing to OxiVault! 🦀