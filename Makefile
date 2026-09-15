.PHONY: build test test-race lint clean

# Build output directory
BIN_DIR := bin

## build: compile binary to bin/gear
build:
	go build -o $(BIN_DIR)/gear ./cmd/gear/

## test: run all tests (no cache)
test:
	go test -count=1 ./...

## test-race: run all tests with race detector
test-race:
	go test -race -count=1 ./...

## lint: run linter (golangci-lint if available, otherwise go vet)
lint:
	@if command -v golangci-lint > /dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		go vet ./...; \
	fi

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR)
