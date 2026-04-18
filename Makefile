.PHONY: build test clean run-devnet fmt vet tidy lint

# Build binaries into bin/
build:
	go build -o bin/malairte-node ./cmd/malairte-node
	go build -o bin/malairte-cli ./cmd/malairte-cli

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with race detector
test-race:
	go test -race ./...

# Clean build artifacts and devnet data
clean:
	rm -rf bin/ data/

# Run a local devnet (testnet with mining enabled)
run-devnet:
	./bin/malairte-node \
		--network=testnet \
		--mine \
		--data-dir=./data/devnet \
		--rpc-addr=127.0.0.1:19332 \
		--p2p-addr=0.0.0.0:19333 \
		--log-level=debug

# Format all Go source files
fmt:
	gofmt -w .

# Run go vet
vet:
	go vet ./...

# Download and tidy dependencies
tidy:
	go mod tidy

# Build Docker image
docker-build:
	docker build -t malairte-node:latest .

# Run in Docker
docker-run:
	docker run -d \
		-p 9333:9333 \
		-p 9332:9332 \
		-v malairte-node-data:/data \
		--name malairte-node \
		malairte-node:latest \
		--data-dir=/data

# Print help
help:
	@echo "Malairt blockchain node build targets:"
	@echo ""
	@echo "  build        Build malairte-node and malairte-cli binaries"
	@echo "  test         Run all unit tests"
	@echo "  test-verbose Run tests with verbose output"
	@echo "  test-race    Run tests with race detector"
	@echo "  clean        Remove build artifacts and devnet data"
	@echo "  run-devnet   Start a local devnet node with mining"
	@echo "  fmt          Format all Go source files"
	@echo "  vet          Run go vet"
	@echo "  tidy         Download and tidy dependencies"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run node in Docker"
