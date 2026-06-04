#!/usr/bin/env bash
# ============================================================
# Bypath Installer
# Interactive installer for Bypath network gateway.
#
# Usage:
#   ./install.sh                                    # Interactive (latest, lite)
#   ./install.sh v2.3.0                             # Specific version, lite
#   ./install.sh v2.3.0 full                        # Specific version, full
#   ./install.sh latest full                        # Latest version, full
#   ./install.sh latest lite socks5://1.2.3.4:1080  # Use proxy for downloads
#
# Environment variables:
#   BYPATH_INSTALL_DIR   Override install directory (default: /opt/bypath)
#   BYPATH_NO_SYSTEMD    Set to 1 to skip systemd service creation
# ============================================================

set -euo pipefail

# ─── Interactive mode detection ──────────────────────────────
# Reliable check: stdin is a real TTY, OR /dev/tty is usable.
# Avoid [ -e /dev/tty ] alone — the file may exist but be inaccessible
# (e.g. inside containers or when piped from curl over SSH).
IS_INTERACTIVE=0
if [ -t 0 ]; then
    IS_INTERACTIVE=1
elif (exec 0</dev/tty) 2>/dev/null; then
    IS_INTERACTIVE=1
fi

# ─── Constants ───────────────────────────────────────────────
REPO="liberoute/bypath"
GITHUB_API="https://api.github.com/repos/${REPO}/releases"
GITHUB_DL="https://github.com/${REPO}/releases/download"
INSTALL_DIR="${BYPATH_INSTALL_DIR:-/opt/bypath}"
BINARY_NAME="bypath"
GEOIP_URL="https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs"
PROXY_ENV=""  # Will be set if --proxy argument is provided

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
        if [ -n "$PROXY_ENV" ]; then
            curl -fSL --progress-bar ${PROXY_ENV:+-x "$PROXY_ENV"} -o "$dest" "$url" || return 1
        else
            curl -fSL --progress-bar -o "$dest" "$url" || return 1
        fi
    elif command -v wget &>/dev/null; then
        if [ -n "$PROXY_ENV" ]; then
            https_proxy="$PROXY_ENV" http_proxy="$PROXY_ENV" wget --show-progress -qO "$dest" "$url" || return 1
        else
            wget --show-progress -qO "$dest" "$url" || return 1
        fi
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
    # Use latest stable sing-box (1.12+)
    local sb_version
    sb_version=$(curl -fsSL ${PROXY_ENV:+-x "$PROXY_ENV"} "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed -E 's/.*"v([^"]+)".*/\1/') || true
    [ -z "$sb_version" ] && sb_version="1.13.0"

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
    local tmp_zip tmp_dir
    tmp_zip=$(mktemp)
    tmp_dir=$(mktemp -d)

    info "Downloading tun2socks v${t2s_version} (${t2s_arch})..."
    if download "$t2s_url" "$tmp_zip"; then
        # Ensure unzip is available
        if ! command -v unzip &>/dev/null; then
            pkg_install unzip >/dev/null 2>&1
        fi
        if command -v unzip &>/dev/null; then
            unzip -o -q "$tmp_zip" -d "$tmp_dir" 2>/dev/null
        elif command -v python3 &>/dev/null; then
            python3 -c "import zipfile; zipfile.ZipFile('$tmp_zip').extractall('$tmp_dir')" 2>/dev/null
        else
            rm -f "$tmp_zip"; rm -rf "$tmp_dir"
            warn "Cannot extract zip (no unzip or python3)"
            return 1
        fi

        # Find the extracted binary (name varies by release)
        local extracted
        extracted=$(find "$tmp_dir" -type f -name 'tun2socks*' | head -1)
        if [ -n "$extracted" ]; then
            cp "$extracted" /usr/local/bin/tun2socks
            chmod +x /usr/local/bin/tun2socks
        fi

        rm -f "$tmp_zip"; rm -rf "$tmp_dir"

        # Validate arch
        if command -v tun2socks &>/dev/null; then
            if tun2socks --version >/dev/null 2>&1 || tun2socks -version >/dev/null 2>&1; then
                ok "tun2socks v${t2s_version} installed (${t2s_arch})"
                return 0
            else
                warn "tun2socks installed but may have arch issues (verify with: tun2socks --version)"
                ok "tun2socks v${t2s_version} installed (${t2s_arch})"
                return 0
            fi
        fi
    fi
    rm -f "$tmp_zip"; rm -rf "$tmp_dir"
    warn "Failed to install tun2socks automatically"
    return 1
}

# ─── Install xray geo data ──────────────────────────────────
install_xray_geo_dir() {
    # Download geoip.dat and geosite.dat for xray routing rules into the given directory
    local xray_geo_dir="${1:-/usr/local/share/xray}"
    mkdir -p "$xray_geo_dir"

    local geoip_url="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
    local geosite_url="https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"

    if [ ! -f "${xray_geo_dir}/geoip.dat" ]; then
        info "Downloading xray geoip.dat to ${xray_geo_dir}..."
        if download "$geoip_url" "${xray_geo_dir}/geoip.dat"; then
            local size
            size=$(stat -c%s "${xray_geo_dir}/geoip.dat" 2>/dev/null || echo 0)
            [ "$size" -gt 1000 ] && ok "xray geoip.dat downloaded" || { rm -f "${xray_geo_dir}/geoip.dat"; warn "xray geoip.dat: download failed"; }
        else
            warn "xray geoip.dat: download failed (routing rules may not work)"
        fi
    else
        ok "xray geoip.dat already exists (${xray_geo_dir})"
    fi

    if [ ! -f "${xray_geo_dir}/geosite.dat" ]; then
        info "Downloading xray geosite.dat to ${xray_geo_dir}..."
        if download "$geosite_url" "${xray_geo_dir}/geosite.dat"; then
            local size
            size=$(stat -c%s "${xray_geo_dir}/geosite.dat" 2>/dev/null || echo 0)
            [ "$size" -gt 1000 ] && ok "xray geosite.dat downloaded" || { rm -f "${xray_geo_dir}/geosite.dat"; warn "xray geosite.dat: download failed"; }
        else
            warn "xray geosite.dat: download failed (domain routing may not work)"
        fi
    else
        ok "xray geosite.dat already exists (${xray_geo_dir})"
    fi
}

install_xray_geo() {
    install_xray_geo_dir "/usr/local/share/xray"
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
            # Validate arch
            if tun2socks --version >/dev/null 2>&1 || tun2socks -version >/dev/null 2>&1; then
                ok "tun2socks found"
            else
                warn "tun2socks found but wrong architecture — reinstalling..."
                rm -f "$(command -v tun2socks)"
                install_tun2socks || warn "tun2socks reinstall failed"
            fi
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

    # xray (optional but recommended as fallback engine)
    local embedded_xray="${INSTALL_DIR}/engines/xray"
    if command -v xray &>/dev/null; then
        local xray_ver
        xray_ver=$(xray version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9.]+' | head -1 || echo "unknown")
        ok "xray found (v${xray_ver})"
        # Check xray geo data in standard locations
        local xray_geo_dir=""
        for d in /usr/local/share/xray /usr/share/xray; do
            if [ -f "${d}/geoip.dat" ]; then
                xray_geo_dir="$d"
                break
            fi
        done
        if [ -n "$xray_geo_dir" ]; then
            ok "xray geo data found (${xray_geo_dir})"
        else
            info "xray geo data not found — downloading..."
            install_xray_geo
        fi
    elif [ -x "$embedded_xray" ]; then
        local xray_ver
        xray_ver=$("$embedded_xray" version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9.]+' | head -1 || echo "unknown")
        ok "xray found (embedded, v${xray_ver})"
    else
        info "xray not found (optional — sing-box is the primary engine)"
    fi

    # For embedded xray, always ensure geo data exists next to the binary
    # (xray looks for geoip.dat in its own directory when XRAY_LOCATION_ASSET is not set)
    if [ -x "$embedded_xray" ] && [ ! -f "${INSTALL_DIR}/engines/geoip.dat" ]; then
        info "Downloading xray geo data for embedded engine..."
        install_xray_geo_dir "${INSTALL_DIR}/engines"
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

    # Skip interactive prompt if no TTY (e.g. piped install)
    if [ "$IS_INTERACTIVE" = "0" ]; then
        info "No TTY detected, skipping systemd service (run with BYPATH_NO_SYSTEMD=0 to force)."
        return
    fi

    echo ""
    local answer
    read -rp "$(echo -e "${CYAN}?${NC}  Create systemd service? [Y/n] ")" answer </dev/tty 2>/dev/null || answer="y"
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

# ─── Download geoip/geosite .srs files ──────────────────────
install_geo() {
    local geo_dir="/etc/bypath/geo"
    mkdir -p "$geo_dir"

    # Countries to download (matches KnownCountries in branding.go)
    local countries=("ir" "cn" "us" "ru" "tr" "de" "fr" "gb" "ae")
    # geoip: Chocolate4U (raw GitHub, no redirect issues, covers all countries)
    local geoip_url_tmpl="https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-COUNTRY.srs"
    # geosite: Chocolate4U for what they have, SagerNet as fallback
    # SagerNet geosite uses a specific release tag format
    local geosite_chocolate_tmpl="https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-COUNTRY.srs"
    local geosite_sagernet_tmpl="https://raw.githubusercontent.com/SagerNet/sing-geosite/refs/heads/rule-set/geosite-COUNTRY.srs"

    # Check if we already have a valid ir file
    local ir_size
    ir_size=$(stat -c%s "${geo_dir}/geoip-ir.srs" 2>/dev/null || echo 0)
    if [ "$ir_size" -gt 100 ]; then
        info "Geo files already present, skipping download."
        return
    fi

    # Prompt if TTY available
    local answer="y"
    if [ "$IS_INTERACTIVE" = "1" ]; then
        echo ""
        read -rp "$(echo -e "${CYAN}?${NC}  Download geo rule sets (geoip+geosite for IR + common countries)? [Y/n] ")" answer </dev/tty 2>/dev/null || answer="y"
    else
        info "No TTY — auto-downloading geo rule sets..."
    fi
    answer="${answer:-y}"
    [[ ! "$answer" =~ ^[Yy]$ ]] && { info "Skipping geo download."; return; }

    echo ""
    info "Downloading geo rule sets for: ${countries[*]}"
    local failed=0

    for country in "${countries[@]}"; do
        local geoip_file="${geo_dir}/geoip-${country}.srs"
        local geosite_file="${geo_dir}/geosite-${country}.srs"
        local url size

        # geoip
        url="${geoip_url_tmpl/COUNTRY/$country}"
        if download "$url" "$geoip_file" 2>/dev/null; then
            size=$(stat -c%s "$geoip_file" 2>/dev/null || echo 0)
            if [ "$size" -gt 100 ]; then
                ok "geoip-${country}.srs"
            else
                rm -f "$geoip_file"
                warn "geoip-${country}.srs: empty response"
                failed=$((failed+1))
            fi
        else
            warn "geoip-${country}.srs: download failed"
            failed=$((failed+1))
        fi

        # geosite — try Chocolate4U first, fallback to SagerNet raw
        url="${geosite_chocolate_tmpl/COUNTRY/$country}"
        local geosite_ok=0
        if download "$url" "$geosite_file" 2>/dev/null; then
            size=$(stat -c%s "$geosite_file" 2>/dev/null || echo 0)
            if [ "$size" -gt 100 ]; then
                ok "geosite-${country}.srs"
                geosite_ok=1
            else
                rm -f "$geosite_file"
            fi
        fi
        # Fallback to SagerNet raw
        if [ "$geosite_ok" -eq 0 ]; then
            url="${geosite_sagernet_tmpl/COUNTRY/$country}"
            if download "$url" "$geosite_file" 2>/dev/null; then
                size=$(stat -c%s "$geosite_file" 2>/dev/null || echo 0)
                if [ "$size" -gt 100 ]; then
                    ok "geosite-${country}.srs"
                    geosite_ok=1
                else
                    rm -f "$geosite_file"
                fi
            fi
        fi
        [ "$geosite_ok" -eq 0 ] && warn "geosite-${country}.srs: not available (geoip only)"
    done

    [ "$failed" -gt 0 ] && warn "${failed} geo files failed — run 'bypath geo update' later to retry"
    echo ""
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
    local arg_proxy="${3:-}"

    # Check for --proxy flag anywhere in args
    for arg in "$@"; do
        if [[ "$arg" == --proxy=* ]]; then
            arg_proxy="${arg#--proxy=}"
        elif [[ "$arg" == "--proxy" ]]; then
            : # handled by next arg, skip
        fi
    done
    # Simple positional: install.sh [version] [variant] [proxy]
    [ -n "$arg_proxy" ] && PROXY_ENV="$arg_proxy"

    if [ -n "$PROXY_ENV" ]; then
        ok "Using proxy: ${PROXY_ENV}"
    fi

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
    elif [ "$IS_INTERACTIVE" = "0" ]; then
        VARIANT="lite"
        info "No TTY, defaulting to lite variant"
    else
        echo ""
        echo -e "  ${CYAN}1)${NC} lite  — Lightweight, requires external sing-box/tun2socks"
        echo -e "  ${CYAN}2)${NC} full  — Batteries included, embeds sing-box engine"
        echo ""
        local choice
        read -rp "$(echo -e "${CYAN}?${NC}  Select variant [1/2] (default: 1): ")" choice </dev/tty 2>/dev/null || choice="1"
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
  native_tun: true
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
  bypass_domains:
    - "cloudflare.com"
    - "ip-api.com"
    - "ipinfo.io"
    - "api.myip.com"
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

    # Download geo rule sets
    install_geo

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
