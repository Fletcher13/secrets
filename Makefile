.PHONY: build test clean example vendor

# Build the library
build:
	@echo "Building secrets library..."
	@go build -v ./...

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run example
example:
	@echo "Running example..."
	@go run example/main.go

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf test_*
	@rm -rf example_secret_store
	@go clean

# Download dependencies to vendor directory
vendor:
	@echo "Downloading dependencies..."
	@go mod vendor

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	@golangci-lint run || echo "golangci-lint not installed, skipping..."

# Run all checks
check: fmt lint test

# Build everything
all: deps vendor build test

# Help
help:
	@echo "Available targets:"
	@echo "  build    - Build the library"
	@echo "  test     - Run tests"
	@echo "  example  - Run the example"
	@echo "  clean    - Clean build artifacts"
	@echo "  vendor   - Download dependencies to vendor"
	@echo "  deps     - Install dependencies"
	@echo "  fmt      - Format code"
	@echo "  lint     - Lint code"
	@echo "  check    - Run format, lint, and test"
	@echo "  all      - Run all checks and build"
	@echo "  help     - Show this help"
