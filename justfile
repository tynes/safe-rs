# Anvil rate-limiting configuration
anvil_compute_units := "100"
anvil_retries := "10"
anvil_timeout := "4000"
anvil_env := "ANVIL_COMPUTE_UNITS_PER_SECOND=" + anvil_compute_units + " ANVIL_RETRIES=" + anvil_retries + " ANVIL_TIMEOUT=" + anvil_timeout

# Default recipe
default:
    @just --list

# Run all tests (library, CLI and feature-gated suites)
test:
    cargo test --workspace --all-features

# Run E2E tests with rate-limited Anvil config (requires ETH_RPC_URL)
test-e2e:
    cargo test --test e2e -- --test-threads=1

# Run E2E tests with rate-limited Anvil config (requires ETH_RPC_URL)
test-e2e-rpc:
    {{anvil_env}} cargo test --test e2e -- --test-threads=1 --nocapture

# Run specific E2E test module with rate limiting
test-e2e-rpc-filter filter:
    {{anvil_env}} cargo test {{filter}} --test e2e -- --test-threads=1 --nocapture

# Run clippy
lint:
    cargo clippy --all-targets --all-features

# Lint each library feature set and the CLI on its own. Per package and
# without dev-dependencies, so another crate's features cannot hide a missing one.
check-features:
    cargo clippy -p safe-rs --lib --no-default-features -- -D warnings
    cargo clippy -p safe-rs --lib -- -D warnings
    cargo clippy -p safe-rs --lib --no-default-features --features keystore -- -D warnings
    cargo clippy -p safe-rs --lib --no-default-features --features hd-wallet -- -D warnings
    cargo clippy -p safe-rs --lib --no-default-features --features ledger -- -D warnings
    cargo clippy -p safe-rs-cli --lib --bins -- -D warnings
    cargo clippy -p safe-rs-cli --lib --bins --no-default-features -- -D warnings
    cargo clippy -p safe-rs-cli --lib --bins --no-default-features --features hd-wallet -- -D warnings

# Check advisories, bans, licenses and sources (deny.toml)
deny:
    cargo deny --all-features --locked check

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check

# Build the project
build:
    cargo build

# Build release
build-release:
    cargo build --release

# Clean build artifacts
clean:
    cargo clean

# Run tests with coverage and generate HTML report
coverage:
    {{anvil_env}} cargo llvm-cov --workspace --html

# Run coverage and open HTML report in browser
coverage-open:
    {{anvil_env}} cargo llvm-cov --workspace --html --open

# Run coverage including E2E tests (requires ETH_RPC_URL)
coverage-e2e:
    {{anvil_env}} cargo llvm-cov --workspace --html -- --test-threads=1

# Generate LCOV format for CI integration
coverage-lcov:
    {{anvil_env}} cargo llvm-cov --workspace --lcov --output-path coverage.lcov

# Clean coverage artifacts
coverage-clean:
    cargo llvm-cov clean --workspace
