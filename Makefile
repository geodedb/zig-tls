# Makefile for ztls TLS 1.3 implementation
#
# Usage:
#   make              - Build and run all tests
#   make test         - Run unit tests only
#   make conformance  - Run conformance tests (requires libssl-dev)
#   make clean        - Clean build artifacts
#   make help         - Show this help message

.PHONY: all build test test-unit test-vectors test-conformance conformance clean check fmt help install-deps

# Default target - build and run all tests (excluding conformance which requires OpenSSL)
all: build test-unit test-vectors test-conformance
	@echo ""
	@echo "✅ All builds and tests completed successfully!"
	@echo ""
	@echo "💡 Tip: Run 'make test-conformance' to test against OpenSSL/BoringSSL (requires libssl-dev)"
	@echo ""

# Build the library
build:
	@echo "🔨 Building ztls library..."
	@zig build

# Run all standard tests (unit + vectors)
test: test-unit test-vectors
	@echo ""
	@echo "✅ Standard tests completed"

# Run unit tests for all modules
test-unit:
	@echo "🧪 Running unit tests..."
	@zig build test --summary all

# Run RFC 8446 test vectors
test-vectors:
	@echo "📋 Running RFC 8446/9001 test vectors..."
	@zig build test-vectors --summary all

# Run conformance tests against BoringSSL/OpenSSL
test-conformance: check-openssl
	@echo "🔐 Running conformance tests..."
	@zig build test-conformance --summary all

# Alias for conformance tests
conformance: test-conformance

# Check if OpenSSL development libraries are installed
check-openssl:
	@echo "🔍 Checking for OpenSSL development libraries..."
	@command -v pkg-config >/dev/null 2>&1 || { \
		echo "❌ Error: pkg-config not found. Please install pkg-config."; \
		exit 1; \
	}
	@pkg-config --exists openssl 2>/dev/null || { \
		echo ""; \
		echo "⚠️  OpenSSL development libraries not found!"; \
		echo ""; \
		echo "Install with:"; \
		echo "  Ubuntu/Debian: sudo apt-get install libssl-dev pkg-config"; \
		echo "  Fedora/RHEL:   sudo dnf install openssl-devel pkg-config"; \
		echo "  Arch Linux:    sudo pacman -S openssl pkg-config"; \
		echo "  macOS:         brew install openssl pkg-config"; \
		echo ""; \
		exit 1; \
	}
	@echo "✅ OpenSSL development libraries found"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf zig-cache zig-out .zig-cache
	@echo "✅ Clean complete"

# Check syntax without building
check:
	@echo "🔍 Checking syntax..."
	@find src -name "*.zig" -exec zig ast-check {} \;
	@echo "✅ Syntax check complete"

# Format all Zig source files
fmt:
	@echo "📝 Formatting source files..."
	@zig fmt src/ tests/ build.zig
	@echo "✅ Format complete"

# Install development dependencies (OS-specific)
install-deps:
	@echo "📦 Installing development dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "Detected Debian/Ubuntu system"; \
		sudo apt-get update && sudo apt-get install -y libssl-dev pkg-config; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "Detected Fedora/RHEL system"; \
		sudo dnf install -y openssl-devel pkg-config; \
	elif command -v pacman >/dev/null 2>&1; then \
		echo "Detected Arch Linux system"; \
		sudo pacman -S --noconfirm openssl pkg-config; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "Detected macOS system"; \
		brew install openssl pkg-config; \
	else \
		echo "❌ Unknown package manager. Please install manually:"; \
		echo "   - OpenSSL development libraries (libssl-dev)"; \
		echo "   - pkg-config"; \
		exit 1; \
	fi
	@echo "✅ Dependencies installed"

# Run tests with optimization levels
test-release-safe:
	@echo "🧪 Running tests with ReleaseSafe optimization..."
	@zig build test -Doptimize=ReleaseSafe --summary all

test-release-fast:
	@echo "🧪 Running tests with ReleaseFast optimization..."
	@zig build test -Doptimize=ReleaseFast --summary all

test-release-small:
	@echo "🧪 Running tests with ReleaseSmall optimization..."
	@zig build test -Doptimize=ReleaseSmall --summary all

# Run all optimization level tests
test-all-optimizations: test-unit test-release-safe test-release-fast test-release-small
	@echo "✅ All optimization level tests completed"

# Continuous integration target
ci: clean build test test-conformance
	@echo ""
	@echo "✅ CI pipeline completed successfully!"

# Development workflow - quick iteration
dev: fmt check test-unit
	@echo "✅ Development checks passed"

# Show help message
help:
	@echo "ztls TLS 1.3 Implementation - Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Main Targets:"
	@echo "  all              - Build and run all tests (default)"
	@echo "  build            - Build the library"
	@echo "  test             - Run unit tests and RFC vectors"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-vectors     - Run RFC 8446/9001 test vectors"
	@echo "  test-conformance - Run BoringSSL/OpenSSL conformance tests"
	@echo "  conformance      - Alias for test-conformance"
	@echo ""
	@echo "Development Targets:"
	@echo "  clean            - Remove build artifacts"
	@echo "  check            - Check syntax without building"
	@echo "  fmt              - Format all Zig source files"
	@echo "  dev              - Quick development workflow (fmt + check + test-unit)"
	@echo ""
	@echo "Optimization Testing:"
	@echo "  test-release-safe  - Run tests with ReleaseSafe"
	@echo "  test-release-fast  - Run tests with ReleaseFast"
	@echo "  test-release-small - Run tests with ReleaseSmall"
	@echo "  test-all-optimizations - Run tests with all optimization levels"
	@echo ""
	@echo "Setup:"
	@echo "  install-deps     - Install OpenSSL development libraries"
	@echo "  check-openssl    - Verify OpenSSL dev libraries are installed"
	@echo ""
	@echo "CI/CD:"
	@echo "  ci               - Full CI pipeline (clean + build + all tests)"
	@echo ""
	@echo "Documentation:"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Run everything"
	@echo "  make test               # Quick test iteration"
	@echo "  make dev                # Development workflow"
	@echo "  make clean build test   # Clean rebuild and test"
	@echo ""
	@echo "Requirements:"
	@echo "  - Zig 0.15.1 or compatible"
	@echo "  - OpenSSL development libraries (for conformance tests)"
	@echo ""
	@echo "For more information, see BUILD_SYSTEM.md"
