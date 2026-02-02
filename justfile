# Anvil rate-limiting configuration
anvil_compute_units := "100"
anvil_retries := "10"
anvil_timeout := "4000"
anvil_env := "ANVIL_COMPUTE_UNITS_PER_SECOND=" + anvil_compute_units + " ANVIL_RETRIES=" + anvil_retries + " ANVIL_TIMEOUT=" + anvil_timeout

# Default recipe
default:
    @just --list

# Run all tests
test:
    cargo test

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
