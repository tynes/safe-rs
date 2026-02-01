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
# Uses 100 compute units/sec, 10 retries, 2 second timeout
test-e2e-rpc:
    ANVIL_COMPUTE_UNITS_PER_SECOND=100 \
    ANVIL_RETRIES=10 \
    ANVIL_TIMEOUT=2000 \
    cargo test --test e2e -- --test-threads=1 --nocapture

# Run specific E2E test module with rate limiting
test-e2e-rpc-filter filter:
    ANVIL_COMPUTE_UNITS_PER_SECOND=100 \
    ANVIL_RETRIES=10 \
    ANVIL_TIMEOUT=2000 \
    cargo test {{filter}} --test e2e -- --test-threads=1 --nocapture

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
