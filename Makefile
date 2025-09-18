.PHONY: build test clean example vendor

# Build the library
build:
	@echo "Building secrets library..."
	@go build -v ./...

# Run tests
test:
	@echo "Running tests..."
	@go test -v --cover ./...

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
	go mod tidy
	go mod vendor

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run

# Run benchmark
bench:
	@echo "Running benchmark tests..."
	go test -bench=. ./...

# Run all checks
check: lint test

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
