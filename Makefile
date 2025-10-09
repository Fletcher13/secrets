.PHONY: build test clean example vendor

# Build the library
build:
	@echo "Building secrets library..."
	go build -v ./...

# Run tests
test:
	@echo "Running tests..."
	rm -rf test_*
	go test -v --cover `go list ./... | egrep -v 'example'`

# Run coverage report
cover:
	@echo "Running coverage report..."
	mkdir -p cov
	rm -rf test_*
	go test -v --cover -coverprofile=cov/coverage.out `go list ./... | egrep -v 'example'`
	go tool cover -html=cov/coverage.out -o cov/coverage.html

# Run example
example:
	@echo "Running example..."
	go run example/main.go

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf test_* cov example_secret_store
	go clean

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
	go test -bench=. -run=^$

# Build everything
all: build lint test

# Help
help:
	@echo "Available targets:"
	@echo "  build    - Build the library"
	@echo "  test     - Run tests"
	@echo "  example  - Run the example"
	@echo "  clean    - Clean build artifacts"
	@echo "  vendor   - Download dependencies to vendor"
	@echo "  deps     - Install dependencies"
	@echo "  lint     - Lint code"
	@echo "  bench    - Run benchmarks"
	@echo "  all      - Run all checks and build"
	@echo "  help     - Show this help"
