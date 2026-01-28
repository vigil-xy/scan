.PHONY: build build-linux build-darwin build-all clean test run help

BINARY=vigil
VERSION?=0.1.0
BUILD_DIR=./build
CMD_DIR=./cmd/vigil
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

help:
	@echo "Vigil Security Scanner - Build commands:"
	@echo "  make build          - Build for current OS"
	@echo "  make build-linux    - Build for Linux (amd64, arm64)"
	@echo "  make build-darwin   - Build for macOS"
	@echo "  make build-all      - Build all platforms"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make run            - Run scanner"
	@echo "  make test           - Run tests"
	@echo "  make install        - Install locally"

build:
	mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./$(CMD_DIR)

build-linux:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./$(CMD_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64 ./$(CMD_DIR)

build-darwin:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./$(CMD_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./$(CMD_DIR)

build-all: build-linux build-darwin
	@echo "✅ Built all platforms:"
	@ls -lh $(BUILD_DIR)/

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test -v ./...

run: build
	./$(BUILD_DIR)/$(BINARY)

install: build
	install -m 755 $(BUILD_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)

release: build-all
	@echo "📦 Creating release artifacts..."
	cd $(BUILD_DIR) && sha256sum vigil-* > CHECKSUMS && cd -
	@echo "✅ Ready to push to GitHub Releases"

.PHONY: ebpf
ebpf:
	@echo "⚠️  eBPF support coming soon (requires clang/llvm)"
