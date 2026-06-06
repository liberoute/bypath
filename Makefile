BINARY_NAME=bypath
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
BUILD_DIR=build
PKG=github.com/liberoute/bypath/internal/build

LDFLAGS=-ldflags "-s -w \
	-X $(PKG).Version=$(VERSION) \
	-X $(PKG).Commit=$(COMMIT) \
	-X $(PKG).BuildDate=$(BUILD_DATE)"

.PHONY: all lite full test lint clean

all: lint test lite

# ============================================================
# TESTING
# ============================================================

## Run all tests
test:
	@echo "🧪 Running tests..."
	go test -v -race ./...

## Run tests with coverage
test-cover:
	@echo "🧪 Running tests with coverage..."
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report: coverage.html"

## Run linter
lint:
	@echo "🔍 Running vet..."
	go vet ./...

# ============================================================
# LITE BUILD
# ============================================================

lite:
	@echo "🪶 Building LITE for Linux amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-lite-linux-amd64-$(VERSION) ./cmd/bypath

lite-windows:
	@echo "🪶 Building LITE for Windows amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-lite-windows-amd64-$(VERSION).exe ./cmd/bypath

lite-arm:
	@echo "🪶 Building LITE for Linux ARM64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-lite-linux-arm64-$(VERSION) ./cmd/bypath

lite-mips:
	@echo "🪶 Building LITE for Linux MIPS..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-lite-linux-mipsle-$(VERSION) ./cmd/bypath

lite-all: lite lite-windows lite-arm lite-mips

# ============================================================
# FULL BUILD
# ============================================================

TUN2SOCKS_VERSION=v2.5.2
TUN2SOCKS_BASE=https://github.com/xjasonlyu/tun2socks/releases/download/$(TUN2SOCKS_VERSION)

full:
	@echo "🔋 Building FULL for Linux amd64 (sing-box + xray in-process, native TUN = zero deps)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags full $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-full-linux-amd64-$(VERSION) ./cmd/bypath

full-windows:
	@echo "🔋 Building FULL for Windows amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags full $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-full-windows-amd64-$(VERSION).exe ./cmd/bypath

full-arm:
	@echo "🔋 Building FULL for Linux ARM64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags full $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-full-linux-arm64-$(VERSION) ./cmd/bypath

full-all: full full-windows full-arm

# Full build with embedded tun2socks binary (for legacy TUN mode without installing tun2socks)
fetch-tun2socks-amd64:
	@echo "⬇️  Downloading tun2socks $(TUN2SOCKS_VERSION) for linux/amd64..."
	@mkdir -p assets/embed
	curl -fL $(TUN2SOCKS_BASE)/tun2socks-linux-amd64.zip -o assets/embed/tun2socks.zip
	unzip -o assets/embed/tun2socks.zip tun2socks-linux-amd64 -d assets/embed/
	mv assets/embed/tun2socks-linux-amd64 assets/embed/tun2socks
	rm assets/embed/tun2socks.zip
	chmod +x assets/embed/tun2socks

fetch-tun2socks-arm:
	@echo "⬇️  Downloading tun2socks $(TUN2SOCKS_VERSION) for linux/armv7..."
	@mkdir -p assets/embed
	curl -fL $(TUN2SOCKS_BASE)/tun2socks-linux-armv7.zip -o assets/embed/tun2socks.zip
	unzip -o assets/embed/tun2socks.zip tun2socks-linux-armv7 -d assets/embed/
	mv assets/embed/tun2socks-linux-armv7 assets/embed/tun2socks
	rm assets/embed/tun2socks.zip
	chmod +x assets/embed/tun2socks

full-embed-amd64: fetch-tun2socks-amd64
	@echo "🔋 Building FULL+EMBED for Linux amd64 (with embedded tun2socks)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags "full embed_tun2socks" $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-full-embed-linux-amd64-$(VERSION) ./cmd/bypath

full-embed-arm: fetch-tun2socks-arm
	@echo "🔋 Building FULL+EMBED for Linux ARMv7 (with embedded tun2socks)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm CGO_ENABLED=0 GOARM=7 go build -tags "full embed_tun2socks" $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-full-embed-linux-armv7-$(VERSION) ./cmd/bypath

# ============================================================
# COMMON
# ============================================================

## Build Docker image
docker:
	docker build -t $(BINARY_NAME):$(VERSION) .

## Run locally
run:
	go run ./cmd/bypath --config configs/default.yaml

## Clean
clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

## Dependencies
deps:
	go mod tidy
	go mod download

# ============================================================
# WHITE-LABEL BUILD
# ============================================================
# Example: make lite VERSION=1.0.0 BINARY_NAME=mygateway \
#          LDFLAGS='-ldflags "-s -w -X $(PKG).Name=MyGateway -X $(PKG).Org=MyCompany -X $(PKG).Version=1.0.0"'
