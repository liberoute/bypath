#!/usr/bin/env bash
# ============================================================
# Bypath Installer
# Interactive installer for Bypath network gateway.
#
# Usage:
#   ./install.sh                    # Interactive (latest, lite)
#   ./install.sh v2.3.0             # Specific version, lite
#   ./install.sh v2.3.0 full        # Specific version, full
#   ./install.sh latest full        # Latest version, full
#
# Environment variables:
#   BYPATH_INSTALL_DIR   Override install directory (default: /opt/bypath)
#   BYPATH_NO_SYSTEMD    Set to 1 to skip systemd service creation
# ============================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────
REPO="liberoute/bypath"
GITHUB_API="https://api.github.com/repos/${REPO}/releases"
GITHUB_DL="https://github.com/${REPO}/releases/download"
INSTALL_DIR="${BYPATH_INSTALL_DIR:-/opt/bypath}"
BINARY_NAME="bypath"
GEOIP_URL="https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs"

# ─── Colors ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ─── Helpers ─────────────────────────────────────────────────
info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✅${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠️${NC}  $*"; }
err()   { echo -e "${RED}❌${NC} $*" >&2; }
die()   { err "$*"; exit 1; }

need_cmd() {
    if ! command -v "$1" &>/dev/null; then
        die "Required command not found: $1. Please install it first."
    fi
}

# ─── Detect OS & Arch ────────────────────────────────────────
detect_platform() {
    local os arch

    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      die "Unsupported OS: $os. Bypath only supports Linux and macOS." ;;
    esac

    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)       ARCH="amd64" ;;
        aarch64|arm64)      ARCH="arm64" ;;
        armv7l|armv7|armhf) ARCH="arm" ;;
        mips|mipsel|mipsle) ARCH="mipsle" ;;
        *)                  die "Unsupported architecture: $arch" ;;
    esac
}

# ─── Get latest version from GitHub ─────────────────────────
get_latest_version() {
    local url="${GITHUB_API}/latest"
    local tag

    if command -v curl &>/dev/null; then
        tag=$(curl -fsSL "$url" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    elif command -v wget &>/dev/null; then
        tag=$(wget -qO- "$url" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    else
        die "Neither curl nor wget found. Please install one of them."
    fi

    # If no stable release, try dev
    if [ -z "$tag" ]; then
        if command -v curl &>/dev/null; then
            tag=$(curl -fsSL "${GITHUB_API}" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
        else
            tag=$(wget -qO- "${GITHUB_API}" 2>/dev/null | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
        fi
    fi

    [ -z "$tag" ] && die "Could not determine latest version. Check your internet connection."
    echo "$tag"
}

# ─── Download file ───────────────────────────────────────────
download() {
    local url="$1" dest="$2"
    info "Downloading: $url"
    if command -v curl &>/dev/null; then
        curl -fSL --progress-bar -o "$dest" "$url" || return 1
    elif command -v wget &>/dev/null; then
        wget --show-progress -qO "$dest" "$url" || return 1
    fi
}

# ─── Detect package manager ──────────────────────────────────
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
    else
        PKG_MGR=""
    fi
}

pkg_install() {
    local pkg="$1"
    info "Installing ${pkg}..."
    case "$PKG_MGR" in
        apt)    apt-get install -y -qq "$pkg" >/dev/null 2>&1 ;;
        yum)    yum install -y -q "$pkg" >/dev/null 2>&1 ;;
        dnf)    dnf install -y -q "$pkg" >/dev/null 2>&1 ;;
        pacman) pacman -S --noconfirm "$pkg" >/dev/null 2>&1 ;;
        apk)    apk add --quiet "$pkg" >/dev/null 2>&1 ;;
        *)      return 1 ;;
    esac
}

# ─── Install sing-box ────────────────────────────────────────
install_sing_box() {
    local sb_version="1.11.0"
    local sb_arch="$ARCH"
    [ "$sb_arch" = "arm" ] && sb_arch="armv7"

    local sb_url="https://github.com/SagerNet/sing-box/releases/download/v${sb_version}/sing-box-${sb_version}-linux-${sb_arch}.tar.gz"
    local tmp_tar
    tmp_tar=$(mktemp)

    info "Downloading sing-box v${sb_version}..."
    if download "$sb_url" "$tmp_tar"; then
        tar xzf "$tmp_tar" -C /usr/local/bin/ --strip-components=1 --wildcards '*/sing-box' 2>/dev/null || \
        tar xzf "$tmp_tar" -C /usr/local/bin/ --strip-components=1 "sing-box-${sb_version}-linux-${sb_arch}/sing-box" 2>/dev/null
        chmod +x /usr/local/bin/sing-box
        rm -f "$tmp_tar"
        if command -v sing-box &>/dev/null; then
            ok "sing-box v${sb_version} installed"
            return 0
        fi
    fi
    rm -f "$tmp_tar"
    warn "Failed to install sing-box automatically"
    return 1
}

# ─── Install tun2socks ───────────────────────────────────────
install_tun2socks() {
    local t2s_version="2.5.2"
    local t2s_arch="$ARCH"
    case "$t2s_arch" in
        amd64)  t2s_arch="amd64" ;;
        arm64)  t2s_arch="arm64" ;;
        arm)    t2s_arch="armv7" ;;
        *)      warn "No tun2socks binary for $t2s_arch"; return 1 ;;
    esac

    local t2s_url="https://github.com/xjasonlyu/tun2socks/releases/download/v${t2s_version}/tun2socks-linux-${t2s_arch}.zip"
    local tmp_zip
    tmp_zip=$(mktemp)

    info "Downloading tun2socks v${t2s_version}..."
    if download "$t2s_url" "$tmp_zip"; then
        # Ensure unzip is available
        if ! command -v unzip &>/dev/null; then
            pkg_install unzip >/dev/null 2>&1
        fi
        if command -v unzip &>/dev/null; then
            unzip -o -q "$tmp_zip" -d /usr/local/bin/ 2>/dev/null
        elif command -v python3 &>/dev/null; then
            python3 -c "import zipfile; zipfile.ZipFile('$tmp_zip').extractall('/usr/local/bin/')" 2>/dev/null
        else
            rm -f "$tmp_zip"
            warn "Cannot extract zip (no unzip or python3)"
            return 1
        fi
        chmod +x /usr/local/bin/tun2socks-linux-${t2s_arch} 2>/dev/null
        # Rename to tun2socks
        if [ -f "/usr/local/bin/tun2socks-linux-${t2s_arch}" ]; then
            mv /usr/local/bin/tun2socks-linux-${t2s_arch} /usr/local/bin/tun2socks
        fi
        rm -f "$tmp_zip"
        if command -v tun2socks &>/dev/null; then
            ok "tun2socks v${t2s_version} installed"
            return 0
        fi
    fi
    rm -f "$tmp_zip"
    warn "Failed to install tun2socks automatically"
    return 1
}

# ─── Check and install runtime dependencies ──────────────────
check_deps() {
    echo ""
    info "Checking and installing runtime dependencies..."
    echo ""

    detect_pkg_manager

    # iptables (required for gateway mode on Linux)
    if [ "$OS" = "linux" ]; then
        if ! command -v iptables &>/dev/null; then
            if [ -n "$PKG_MGR" ]; then
                pkg_install iptables && ok "iptables installed" || warn "Could not install iptables"
            else
                warn "iptables NOT found — install manually"
            fi
        else
            ok "iptables found"
        fi

        if ! command -v ip &>/dev/null; then
            if [ -n "$PKG_MGR" ]; then
                pkg_install iproute2 && ok "iproute2 installed" || warn "Could not install iproute2"
            else
                warn "iproute2 NOT found — install manually"
            fi
        else
            ok "iproute2 (ip) found"
        fi
    fi

    # curl (needed for health checks, bench)
    if ! command -v curl &>/dev/null; then
        if [ -n "$PKG_MGR" ]; then
            pkg_install curl && ok "curl installed" || warn "Could not install curl"
        else
            warn "curl NOT found — install manually"
        fi
    else
        ok "curl found"
    fi

    # sing-box (required)
    if command -v sing-box &>/dev/null; then
        local sb_ver
        sb_ver=$(sing-box version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
        ok "sing-box found (v${sb_ver})"
    elif [ -x "${INSTALL_DIR}/engines/sing-box" ]; then
        ok "sing-box found (${INSTALL_DIR}/engines/sing-box)"
    else
        install_sing_box || warn "sing-box not installed — bypath will try to download it on first run"
    fi

    # tun2socks (required for gateway mode in lite build)
    if [ "$VARIANT" = "lite" ]; then
        if command -v tun2socks &>/dev/null; then
            ok "tun2socks found"
        else
            install_tun2socks || warn "tun2socks not installed — gateway mode won't work without it"
        fi
    else
        info "tun2socks: not needed for full build (skipped)"
    fi

    # dns2socks (recommended, not critical)
    if command -v dns2socks &>/dev/null; then
        ok "dns2socks found"
    else
        info "dns2socks not found (optional — DNS will use sing-box built-in)"
    fi

    echo ""
}

# ─── Create systemd service ─────────────────────────────────
install_systemd() {
    if [ "${BYPATH_NO_SYSTEMD:-0}" = "1" ]; then
        info "Skipping systemd service (BYPATH_NO_SYSTEMD=1)"
        return
    fi

    if [ "$OS" != "linux" ]; then
        return
    fi

    if ! command -v systemctl &>/dev/null; then
        info "systemd not found, skipping service installation."
        return
    fi

    echo ""
    local answer
    read -rp "$(echo -e "${CYAN}?${NC}  Create systemd service? [Y/n] ")" answer
    answer="${answer:-y}"

    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        info "Skipping systemd service."
        return
    fi

    local service_file="/etc/systemd/system/bypath.service"

    cat > "$service_file" <<EOF
[Unit]
Description=Bypath Network Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/bypath run
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# Logging
StandardOutput=append:/var/log/bypath/access.log
StandardError=append:/var/log/bypath/error.log

# Security hardening
NoNewPrivileges=no
ProtectSystem=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    ok "systemd service created: ${service_file}"
    info "Enable with: systemctl enable bypath"
    info "Start with:  systemctl start bypath"
}

# ─── Download geoip-ir.srs ──────────────────────────────────
install_geoip() {
    local geo_dir="/etc/bypath/geo"
    local geo_file="${geo_dir}/geoip-ir.srs"

    if [ -f "$geo_file" ]; then
        info "geoip-ir.srs already exists, skipping."
        return
    fi

    echo ""
    local answer
    read -rp "$(echo -e "${CYAN}?${NC}  Download geoip-ir.srs (Iran IP list for whitelist)? [Y/n] ")" answer
    answer="${answer:-y}"

    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        info "Skipping geoip download."
        return
    fi

    mkdir -p "$geo_dir"
    if download "$GEOIP_URL" "$geo_file"; then
        ok "geoip-ir.srs downloaded to ${geo_file}"
    else
        warn "Failed to download geoip-ir.srs. You can download it manually later."
    fi
}

# ─── Main ────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       Bypath Installer               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    echo ""

    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        die "This installer must be run as root. Try: sudo ./install.sh"
    fi

    # Parse arguments
    local arg_version="${1:-}"
    local arg_variant="${2:-}"

    # Detect platform
    detect_platform
    ok "Detected platform: ${OS}/${ARCH}"

    # Determine version
    if [ -z "$arg_version" ] || [ "$arg_version" = "latest" ]; then
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
    else
        VERSION="$arg_version"
        # Ensure version starts with 'v'
        [[ "$VERSION" != v* ]] && VERSION="v${VERSION}"
    fi
    ok "Version: ${VERSION}"

    # Determine variant
    if [ -n "$arg_variant" ]; then
        VARIANT="$arg_variant"
    else
        echo ""
        echo -e "  ${CYAN}1)${NC} lite  — Lightweight, requires external sing-box/tun2socks"
        echo -e "  ${CYAN}2)${NC} full  — Batteries included, embeds sing-box engine"
        echo ""
        local choice
        read -rp "$(echo -e "${CYAN}?${NC}  Select variant [1/2] (default: 1): ")" choice
        choice="${choice:-1}"
        case "$choice" in
            1|lite)  VARIANT="lite" ;;
            2|full)  VARIANT="full" ;;
            *)       VARIANT="lite" ;;
        esac
    fi
    ok "Variant: ${VARIANT}"

    # Build download URL
    local filename="${BINARY_NAME}-${VARIANT}-${OS}-${ARCH}"
    local url="${GITHUB_DL}/${VERSION}/${filename}"

    echo ""
    info "Download URL: ${url}"
    echo ""

    # Create install directory
    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}/engines"

    # Create standard Linux paths for installed mode
    mkdir -p "/etc/bypath/profiles"
    mkdir -p "/etc/bypath/geo"
    mkdir -p "/var/log/bypath"

    # Download binary
    local tmp_file
    tmp_file=$(mktemp)
    if ! download "$url" "$tmp_file"; then
        rm -f "$tmp_file"
        die "Download failed. Check version/variant or your internet connection."
    fi

    # Install binary
    mv "$tmp_file" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
    ok "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"

    # Symlink to PATH
    if [ -d "/usr/local/bin" ]; then
        ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "/usr/local/bin/${BINARY_NAME}"
        ok "Symlinked to /usr/local/bin/${BINARY_NAME}"
    fi

    # Create default config if not exists
    local config_file="/etc/bypath/config.yaml"
    if [ ! -f "$config_file" ]; then
        cat > "$config_file" <<'EOF'
# Bypath Configuration

server:
  api_port: 8080
  dns_port: 53
  socks_port: 2801
  api_token: ""

gateway:
  enabled: true
  interface: ""
  dns_upstream:
    - "1.1.1.1"
    - "8.8.8.8"

engines:
  directory: "/opt/bypath/engines"
  prefer_system: true
  preferred: ""

whitelist:
  countries: ["ir"]
  update_interval: "24h"

isolation:
  enabled: true

sni_spoof:
  enabled: false
  sni: "digikala.com"
EOF
        ok "Default config created: ${config_file}"
    else
        info "Config already exists, not overwriting: ${config_file}"
    fi

    # Create default profile if not exists
    local profile_file="/etc/bypath/profiles/default.json"
    if [ ! -f "$profile_file" ]; then
        cat > "$profile_file" <<'EOF'
{
  "version": 1,
  "groups": [
    {
      "name": "default",
      "links": []
    }
  ],
  "subscriptions": [],
  "active_group": "default",
  "active_index": 0
}
EOF
        ok "Default profile created: ${profile_file}"
    fi

    # Download geoip
    install_geoip

    # Check runtime deps
    check_deps

    # Install systemd service
    install_systemd

    # Done
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✅ Bypath installed successfully!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════${NC}"
    echo ""
    info "Paths:"
    echo "    Binary:   ${INSTALL_DIR}/${BINARY_NAME}"
    echo "    Config:   /etc/bypath/config.yaml"
    echo "    Profiles: /etc/bypath/profiles/"
    echo "    Geo:      /etc/bypath/geo/"
    echo "    Logs:     /var/log/bypath/"
    echo "    Engines:  ${INSTALL_DIR}/engines/"
    echo ""
    info "Quick start:"
    echo "    1. Add a server:  bypath add <link>"
    echo "    2. Start gateway: bypath run"
    echo "    3. Open TUI:      bypath"
    echo ""
    info "Or use systemd:"
    echo "    systemctl enable --now bypath"
    echo ""
}

main "$@"
