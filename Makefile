BINARY_NAME=bypath
VERSION?=3.0.0
COMMIT=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
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

lite-armv7:
	@echo "🪶 Building LITE for Linux ARMv7..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-lite-linux-armv7-$(VERSION) ./cmd/bypath

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
# Digests of the official v2.5.2 release assets (tag commit 2b494a7). The
# download is rejected unless it matches; the same digests are pinned in
# internal/engine/artifacts.go for runtime provisioning.
TUN2SOCKS_SHA256_AMD64=4aa7737009a9f06b9f4957c4fc12932ae0cd2039471d2ae4e5d4666ffeb40a2e
TUN2SOCKS_SHA256_ARMV7=089dd9652baa70862d00f465c81a5df3ab7129e82dca73edea36d0cfd8152b89
TUN2SOCKS_SHA256_ARM64=b83bc4961b33aa3ec0399c801a97c2c47766462991ffa488a4cbaee1ab3e0bff

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

full-armv7:
	@echo "🔋 Building FULL for Linux ARMv7..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -tags full $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-full-linux-armv7-$(VERSION) ./cmd/bypath

full-all: full full-windows full-arm full-armv7

# Full build with embedded tun2socks binary (transparent gateway for xray and
# OpenVPN without installing or downloading anything at runtime).
#
# Every target stages an arch-specific file under internal/embedbin/assets and
# verifies it before the build: the release-archive digest, the extracted
# binary digest, the ELF machine and the upstream build information. A build
# cannot embed an amd64 helper into an arm64 or armv7 binary. After a build,
# `go run ./tools/verify-embedded-binary -binary <out> -goarch <arch>` checks
# the produced artifact the same way.
TUN2SOCKS_ASSET_DIR=internal/embedbin/assets
TUN2SOCKS_BIN_SHA256_AMD64=baa6237fd5fbf5f5330f8f0e3578416ed47e85e34a7c973b248bb516fd0ed101
TUN2SOCKS_BIN_SHA256_ARM64=a359b4a8a1ebde80b7a8164f8ab1e1de62f11187ce99a3e9065cdb1be53e87b2
TUN2SOCKS_BIN_SHA256_ARMV7=5e255b6f932b3ac8428a94ec0725ae664f6526e0d588f72cc1e29b905128bc6c

## Verify every staged tun2socks asset (skips architectures that are not staged)
verify-tun2socks:
	@go run ./tools/verify-tun2socks

# stage-tun2socks-asset: stage one architecture, reusing an already-verified
# copy and otherwise downloading from the pinned release and checking both the
# archive digest and the extracted binary digest.
stage-tun2socks-amd64:
	@mkdir -p $(TUN2SOCKS_ASSET_DIR)
	@set -e; \
	asset=$(TUN2SOCKS_ASSET_DIR)/tun2socks_linux_amd64; \
	if [ -f $$asset ] && echo "$(TUN2SOCKS_BIN_SHA256_AMD64)  $$asset" | sha256sum -c - >/dev/null 2>&1; then \
	  echo "tun2socks linux/amd64 already staged"; \
	else \
	  echo "downloading tun2socks $(TUN2SOCKS_VERSION) for linux/amd64"; \
	  curl -fL --retry 2 --connect-timeout 20 --max-time 180 $(TUN2SOCKS_BASE)/tun2socks-linux-amd64.zip -o $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip; \
	  echo "$(TUN2SOCKS_SHA256_AMD64)  $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip" | sha256sum -c -; \
	  unzip -p $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip tun2socks-linux-amd64 > $$asset; \
	  rm -f $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip; \
	  chmod +x $$asset; \
	fi
	@go run ./tools/verify-tun2socks -asset $(TUN2SOCKS_ASSET_DIR)/tun2socks_linux_amd64 -goos linux -goarch amd64

stage-tun2socks-arm64:
	@mkdir -p $(TUN2SOCKS_ASSET_DIR)
	@set -e; \
	asset=$(TUN2SOCKS_ASSET_DIR)/tun2socks_linux_arm64; \
	if [ -f $$asset ] && echo "$(TUN2SOCKS_BIN_SHA256_ARM64)  $$asset" | sha256sum -c - >/dev/null 2>&1; then \
	  echo "tun2socks linux/arm64 already staged"; \
	else \
	  echo "downloading tun2socks $(TUN2SOCKS_VERSION) for linux/arm64"; \
	  curl -fL --retry 2 --connect-timeout 20 --max-time 180 $(TUN2SOCKS_BASE)/tun2socks-linux-arm64.zip -o $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip; \
	  echo "$(TUN2SOCKS_SHA256_ARM64)  $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip" | sha256sum -c -; \
	  unzip -p $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip tun2socks-linux-arm64 > $$asset; \
	  rm -f $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip; \
	  chmod +x $$asset; \
	fi
	@go run ./tools/verify-tun2socks -asset $(TUN2SOCKS_ASSET_DIR)/tun2socks_linux_arm64 -goos linux -goarch arm64

stage-tun2socks-armv7:
	@mkdir -p $(TUN2SOCKS_ASSET_DIR)
	@set -e; \
	asset=$(TUN2SOCKS_ASSET_DIR)/tun2socks_linux_armv7; \
	if [ -f $$asset ] && echo "$(TUN2SOCKS_BIN_SHA256_ARMV7)  $$asset" | sha256sum -c - >/dev/null 2>&1; then \
	  echo "tun2socks linux/armv7 already staged"; \
	else \
	  echo "downloading tun2socks $(TUN2SOCKS_VERSION) for linux/armv7"; \
	  curl -fL --retry 2 --connect-timeout 20 --max-time 180 $(TUN2SOCKS_BASE)/tun2socks-linux-armv7.zip -o $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip; \
	  echo "$(TUN2SOCKS_SHA256_ARMV7)  $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip" | sha256sum -c -; \
	  unzip -p $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip tun2socks-linux-armv7 > $$asset; \
	  rm -f $(TUN2SOCKS_ASSET_DIR)/tun2socks.zip; \
	  chmod +x $$asset; \
	fi
	@go run ./tools/verify-tun2socks -asset $(TUN2SOCKS_ASSET_DIR)/tun2socks_linux_armv7 -goos linux -goarch arm -goarm 7

# Historical aliases kept for existing build notes.
fetch-tun2socks-amd64: stage-tun2socks-amd64
fetch-tun2socks-arm64: stage-tun2socks-arm64
fetch-tun2socks-armv7: stage-tun2socks-armv7
fetch-tun2socks-arm: stage-tun2socks-armv7

full-embed-amd64: stage-tun2socks-amd64
	@echo "🔋 Building FULL+EMBED for Linux amd64 (with embedded tun2socks)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags "full embed_tun2socks" $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-full-embed-linux-amd64-$(VERSION) ./cmd/bypath

full-embed-armv7: stage-tun2socks-armv7
	@echo "🔋 Building FULL+EMBED for Linux ARMv7 (with embedded tun2socks)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -tags "full embed_tun2socks" $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-full-embed-linux-armv7-$(VERSION) ./cmd/bypath

full-embed-arm64: stage-tun2socks-arm64
	@echo "🔋 Building FULL+EMBED for Linux ARM64 (with embedded tun2socks)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags "full embed_tun2socks" $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME)-full-embed-linux-arm64-$(VERSION) ./cmd/bypath

# Historical alias kept for existing build notes.
full-embed-arm: full-embed-armv7

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
