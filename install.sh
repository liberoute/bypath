#!/usr/bin/env bash
# ============================================================
# Bypath installer
#
# Installs one version-pinned Bypath release, verifies its checksum, creates
# the systemd unit, and hands over to the interactive first-run wizard.
#
# The installer never changes routes, DNS, DHCP, firewall rules or any other
# network setting. It never stops systemd-resolved, dnsmasq, NetworkManager or
# a VPN that is already running. Configuration is written only by `bypath
# setup`, and only when no configuration exists yet.
#
# Usage (download and verify the pinned installer first; see INSTALL.md):
#   sudo ./install.sh --version v3.0.0-rc.2
#   sudo ./install.sh --dry-run
#   sudo ./install.sh --version v3.0.0-rc.2 --non-interactive --mode proxy
#   sudo ./install.sh --version v3.0.0-rc.2 --non-interactive --mode gateway \
#        --interface eth0 --install-packages   # approve apt for gateway packages
#   sudo ./install.sh --uninstall            # keep configuration and data
#   sudo ./install.sh --uninstall --purge    # also remove configuration and data
#   sudo ./install.sh --rollback             # restore the previous binary
#
# Exit codes: 0 success, 1 refused/failed, 2 usage error.
# ============================================================

set -Eeuo pipefail

# ─── Constants ───────────────────────────────────────────────
REPO="liberoute/bypath"
DEFAULT_VERSION="v3.0.0-rc.2"
INSTALL_DIR="/opt/bypath"
BIN_LINK="/usr/local/bin/bypath"
CONFIG_DIR="/etc/bypath"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
LOG_DIR="/var/log/bypath"
RUN_DIR="/run/bypath"
CONTROL_DIR="/run/bypath-control"
UNIT_FILE="/etc/systemd/system/bypath.service"
MIN_DISK_MB=100
MIN_MEM_MB=128

VERSION="$DEFAULT_VERSION"
DRY_RUN=0
NONINTERACTIVE=0
ALLOW_UNSUPPORTED=0
NO_SYSTEMD=0
NO_SETUP=0
ASSUME_YES=0
INSTALL_PACKAGES=0
LOCAL_BINARY=""
LOCAL_SHA256=""
PROXY_URL=""
ACTION="install"
PURGE=0
SETUP_ARGS=()

TMP_DIR=""
WORK_DIR=""
STAGED_BIN=""

# ─── Output ──────────────────────────────────────────────────
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; BOLD=""; NC=""
fi
info() { printf '%s\n' "${BLUE}i${NC} $*"; }
ok()   { printf '%s\n' "${GREEN}ok${NC} $*"; }
warn() { printf '%s\n' "${YELLOW}!${NC} $*" >&2; }
err()  { printf '%s\n' "${RED}x${NC} $*" >&2; }
die()  { err "$*"; exit 1; }
usage_die() { err "$*"; exit 2; }
section() { printf '\n%s\n' "${BOLD}$*${NC}"; }

cleanup() {
    local status=$?
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then rm -rf "$WORK_DIR"; fi
    if [ -n "$STAGED_BIN" ] && [ -e "$STAGED_BIN" ]; then rm -f "$STAGED_BIN"; fi
    exit "$status"
}
trap cleanup EXIT
trap 'err "interrupted; the binary is installed atomically, but configuration may be incomplete. Re-run the installer or \"sudo bypath setup\" to finish."; exit 130' INT TERM

# ─── Arguments ───────────────────────────────────────────────
usage() {
    cat <<'EOF'
Bypath installer — one pinned release, verified, no network changes.

  --version VERSION        Release tag to install (default v3.0.0-rc.2)
  --dry-run                Report the host and the plan; change nothing
  --non-interactive        Never prompt; pass answers as flags
  --allow-unsupported      Continue on a platform outside the tested matrix
  --no-systemd             Install the binary only, no service unit
  --no-setup               Skip the first-run wizard
  --local-binary PATH      Use an already-downloaded binary
  --local-sha256 HEX       Expected SHA-256 for --local-binary
  --proxy URL              Use this proxy for downloads
  --yes                    Do not ask for confirmation on uninstall/purge
  --uninstall              Remove the binary and unit; keep config and data
  --purge                  With --uninstall: also remove config, data, logs
  --rollback               Restore the binary saved by the previous install
  -h, --help               Show this help

First-run answers (passed to `bypath setup`):
  --mode proxy|gateway     --interface NAME      --trusted-cidr CIDR
  --socks-port N           --listen localhost|lan|all
  --listen-ip ADDR         --dns-port N          --dns-upstream ADDR
  --web off|loopback|lan   --web-port N          --uri URI
  --subscription URL       --group NAME          --select NAME
  --start-service          start now and verify the first connection
  --enable-service         also enable the unit at boot (verified start first)
  --enable-gateway         carry the LAN after a verified start
  --install-packages       let the wizard apt-get install missing gateway
                           packages (iproute2, iptables); never implied

  Starting, enabling and gateway mode are three different things:
    --start-service   runs the service until the next reboot
    --enable-service  also starts it automatically at boot
    --enable-gateway  routes the LAN through the tunnel (after verification)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)          [ $# -ge 2 ] || usage_die "--version needs a value"; VERSION="$2"; shift 2 ;;
        --dry-run)          DRY_RUN=1; shift ;;
        --non-interactive)  NONINTERACTIVE=1; shift ;;
        --allow-unsupported) ALLOW_UNSUPPORTED=1; shift ;;
        --no-systemd)       NO_SYSTEMD=1; shift ;;
        --no-setup)         NO_SETUP=1; shift ;;
        --local-binary)     [ $# -ge 2 ] || usage_die "--local-binary needs a path"; LOCAL_BINARY="$2"; shift 2 ;;
        --local-sha256)     [ $# -ge 2 ] || usage_die "--local-sha256 needs a value"; LOCAL_SHA256="$2"; shift 2 ;;
        --proxy)            [ $# -ge 2 ] || usage_die "--proxy needs a URL"; PROXY_URL="$2"; shift 2 ;;
        --yes|-y)           ASSUME_YES=1; shift ;;
        --uninstall)        ACTION="uninstall"; shift ;;
        --purge)            PURGE=1; ACTION="uninstall"; shift ;;
        --rollback)         ACTION="rollback"; shift ;;
        -h|--help)          usage; exit 0 ;;
        --mode|--interface|--socks-port|--listen|--listen-ip|--dns-port|--web|--web-port|--group|--select)
                            [ $# -ge 2 ] || usage_die "$1 needs a value"
                            SETUP_ARGS+=("$1" "$2"); shift 2 ;;
        --trusted-cidr|--dns-upstream|--uri|--subscription)
                            [ $# -ge 2 ] || usage_die "$1 needs a value"
                            SETUP_ARGS+=("$1" "$2"); shift 2 ;;
        --start-service|--enable-service|--enable-gateway)
                            SETUP_ARGS+=("$1"); shift ;;
        --install-packages) INSTALL_PACKAGES=1; SETUP_ARGS+=("$1"); shift ;;
        *)                  usage_die "unknown option: $1 (see --help)" ;;
    esac
done

if [ "$INSTALL_PACKAGES" -eq 1 ] && [ "$NO_SETUP" -eq 1 ]; then
    usage_die "--install-packages approves package installation inside the first-run wizard; it has no effect with --no-setup"
fi

if [ "$VERSION" = "latest" ]; then
    usage_die "this installer is pinned to one release; pass an exact tag such as v3.0.0-rc.2"
fi
if ! printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; then
    usage_die "--version '$VERSION' is not a release tag"
fi
if [ -n "$LOCAL_SHA256" ] && [ -z "$LOCAL_BINARY" ]; then
    usage_die "--local-sha256 is only valid together with --local-binary"
fi
if [ -n "$LOCAL_BINARY" ] && [ -z "$LOCAL_SHA256" ]; then
    usage_die "--local-binary must be paired with --local-sha256 (builds are never installed unverified)"
fi

# ─── Helpers ─────────────────────────────────────────────────
need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "this step needs root. Re-run with sudo, or use --dry-run."
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

download_stdout() {
    local url="$1" dest="$2"
    if have curl; then
        local -a args=(--fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$dest")
        if [ -n "$PROXY_URL" ]; then args+=(--proxy "$PROXY_URL"); fi
        curl "${args[@]}" "$url"
    elif have wget; then
        local -a args=(--quiet --https-only --output-document="$dest")
        if [ -n "$PROXY_URL" ]; then
            https_proxy="$PROXY_URL" wget "${args[@]}" "$url"
        else
            wget "${args[@]}" "$url"
        fi
    else
        die "neither curl nor wget is installed; install one of them first"
    fi
}

port_in_use() { # $1 = port, $2 = t|u
    local port="$1" proto="$2"
    if have ss; then
        if [ "$proto" = "t" ]; then
            ss -H -ltn "sport = :${port}" 2>/dev/null | grep -q .
        else
            ss -H -lun "sport = :${port}" 2>/dev/null | grep -q .
        fi
        return
    fi
    if have netstat; then
        if [ "$proto" = "t" ]; then
            netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}\$"
        else
            netstat -lun 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}\$"
        fi
        return
    fi
    return 1
}

service_active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

# Packages that gateway mode needs and apt can provide. TUN is a kernel module,
# so it is reported but never part of the package list.
gateway_missing_packages() {
    local pkgs=""
    have ip || pkgs="iproute2"
    if ! have iptables || ! have ip6tables; then pkgs="${pkgs:+$pkgs }iptables"; fi
    printf '%s' "$pkgs"
}

gateway_prereq_summary() {
    local pkgs tun_note=""
    pkgs="$(gateway_missing_packages)"
    [ -c /dev/net/tun ] || tun_note="; TUN missing (sudo modprobe tun)"
    if [ -z "$pkgs" ] && [ -z "$tun_note" ]; then
        printf 'prerequisites present (ip, iptables, ip6tables, TUN)'
    elif [ -z "$pkgs" ]; then
        printf 'packages present%s' "$tun_note"
    else
        printf 'missing %s (sudo apt install %s, or --install-packages)%s' "$pkgs" "$pkgs" "$tun_note"
    fi
}

# ─── Preflight ───────────────────────────────────────────────
OS_ID=""; OS_LIKE=""; OS_NAME=""; OS_VERSION=""; ARCH=""; ARCH_RAW=""
SYSTEMD=0; TUN_OK=0; IPTABLES=0; NFTABLES=0
EXISTING=0; EXISTING_VERSION=""
DNS_SERVICES=""; PORT_NOTES=""; PLATFORM_OK=0

# Read one /etc/os-release field in a subshell: sourcing it directly would
# clobber installer variables such as VERSION with the OS release version.
os_release_field() {
    local key="$1"
    (
        # shellcheck disable=SC1091
        . /etc/os-release 2>/dev/null || exit 0
        eval "printf '%s' \"\${${key}:-}\""
    )
}

detect_platform() {
    ARCH_RAW="$(uname -m)"
    case "$ARCH_RAW" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              ARCH="" ;;
    esac

    if [ -r /etc/os-release ]; then
        OS_ID="$(os_release_field ID)"
        OS_ID="${OS_ID:-unknown}"
        OS_LIKE="$(os_release_field ID_LIKE)"
        OS_NAME="$(os_release_field PRETTY_NAME)"
        [ -n "$OS_NAME" ] || OS_NAME="$(os_release_field NAME)"
        [ -n "$OS_NAME" ] || OS_NAME="$OS_ID"
        OS_VERSION="$(os_release_field VERSION_ID)"
    else
        OS_ID="unknown"
        OS_NAME="$(uname -s)"
    fi

    case "$ARCH:$OS_ID" in
        amd64:debian|amd64:ubuntu|arm64:debian|arm64:ubuntu|arm64:armbian)
            PLATFORM_OK=1 ;;
        *:debian|*:ubuntu|*:armbian)
            # Debian-family derivatives are allowed only when the architecture
            # has a tested release asset.
            case "$ARCH" in amd64|arm64) PLATFORM_OK=1 ;; esac ;;
    esac
    if [ "$PLATFORM_OK" -eq 0 ] && printf '%s' "$OS_LIKE" | grep -qiw debian; then
        case "$ARCH" in amd64|arm64) PLATFORM_OK=1 ;; esac
    fi
}

detect_environment() {
    if [ -d /run/systemd/system ] && have systemctl; then SYSTEMD=1; fi
    if [ -c /dev/net/tun ]; then TUN_OK=1; fi
    if have iptables; then IPTABLES=1; fi
    if have nft; then NFTABLES=1; fi

    local svc
    for svc in systemd-resolved dnsmasq unbound named; do
        if service_active "$svc"; then
            DNS_SERVICES+="${DNS_SERVICES:+, }${svc}"
        fi
    done

    if [ -x "${INSTALL_DIR}/bypath" ]; then
        EXISTING=1
        EXISTING_VERSION="$("${INSTALL_DIR}/bypath" version 2>/dev/null | head -n 1 || true)"
    elif [ -x "${BIN_LINK}" ]; then
        EXISTING=1
        EXISTING_VERSION="$("${BIN_LINK}" version 2>/dev/null | head -n 1 || true)"
    fi

    if port_in_use 53 u || port_in_use 53 t; then
        PORT_NOTES+="  port 53 is in use: ${DNS_SERVICES:-another process holds it}. "
    fi
    if port_in_use 8080 t; then PORT_NOTES+="  port 8080 (management API) is in use. "; fi
    if port_in_use 2801 t; then PORT_NOTES+="  port 2801 (proxy default) is in use. "; fi
}

report_host() {
    section "Host"
    printf '  OS:        %s\n' "$OS_NAME"
    printf '  Platform:  %s / %s\n' "$OS_ID" "$ARCH_RAW"
    printf '  Release:   %s\n' "${OS_VERSION:-unknown}"
    printf '  systemd:   %s\n' "$([ "$SYSTEMD" = 1 ] && echo present || echo absent)"
    printf '  TUN:       %s\n' "$([ "$TUN_OK" = 1 ] && echo '/dev/net/tun present' || echo 'not available (proxy-only only)')"
    local fw=""
    if [ "$IPTABLES" -eq 1 ]; then fw="iptables "; fi
    if [ "$NFTABLES" -eq 1 ]; then fw+="nft "; fi
    printf '  Firewall:  %s\n' "${fw:-none detected}"
    printf '  Gateway:   %s\n' "$(gateway_prereq_summary)"
    printf '  DNS:       %s\n' "${DNS_SERVICES:-no known resolver service active}"
    printf '  Existing:  %s\n' "$([ "$EXISTING" = 1 ] && echo "${EXISTING_VERSION:-installed}" || echo none)"
    if [ -n "$PORT_NOTES" ]; then
        printf '  Ports:     %s\n' "$PORT_NOTES"
    fi

    local mem_mb disk_mb
    mem_mb="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
    disk_mb="$(df -Pk /opt 2>/dev/null | awk 'NR==2 {print int($4/1024)}' || true)"
    printf '  Memory:    %s MiB\n' "${mem_mb:-unknown}"
    printf '  Disk:      %s MiB free on /opt\n' "${disk_mb:-unknown}"
    if [ -n "${mem_mb:-}" ] && [ "${mem_mb:-0}" -gt 0 ] && [ "$mem_mb" -lt "$MIN_MEM_MB" ]; then
        warn "less than ${MIN_MEM_MB} MiB of memory: the embedded engines may not fit"
    fi
    if [ -n "${disk_mb:-}" ] && [ "${disk_mb:-0}" -gt 0 ] && [ "$disk_mb" -lt "$MIN_DISK_MB" ]; then
        warn "less than ${MIN_DISK_MB} MiB free on /opt"
    fi

    section "Network (observed, never changed)"
    if have ip; then
        ip -o -4 addr show scope global 2>/dev/null | awk '{printf "  %s  %s\n", $2, $4}' || true
        local def
        def="$(ip route show default 2>/dev/null | head -n 1 || true)"
        printf '  default route: %s\n' "${def:-none}"
    else
        info "the 'ip' command is not installed; interface details are unavailable"
    fi
    cat <<EOF

  The installer does not alter interfaces, routes, DNS, DHCP or firewall
  rules. ${DNS_SERVICES:+Active resolvers ($DNS_SERVICES) are left running. }
  If port 53 is already served, the first-run wizard offers a free port or
  asks you to free it yourself; it never stops another resolver.
EOF
}

preflight() {
    section "Preflight"
    detect_platform
    detect_environment

    if [ "$PLATFORM_OK" -eq 0 ]; then
        if [ "$ALLOW_UNSUPPORTED" -eq 0 ]; then
            die "unsupported platform ${OS_ID}/${ARCH_RAW}. Tested: Debian/Ubuntu amd64, Debian/Ubuntu/Armbian arm64. Use --allow-unsupported to continue at your own risk."
        fi
        warn "platform ${OS_ID}/${ARCH_RAW} is outside the tested matrix; continuing because --allow-unsupported was given"
    fi
    if [ -z "$ARCH" ]; then
        die "no release asset exists for architecture ${ARCH_RAW}"
    fi
    if [ "$SYSTEMD" -eq 0 ] && [ "$NO_SYSTEMD" -eq 0 ]; then
        warn "systemd was not detected; the service unit will be skipped"
        NO_SYSTEMD=1
    fi

    report_host
}

# ─── Install ─────────────────────────────────────────────────
ASSET=""
COMPUTED_SHA=""

fetch_asset() {
    ASSET="bypath-linux-${ARCH}"
    local base="https://github.com/${REPO}/releases/download/${VERSION}"
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bypath-fetch.XXXXXX")"
    local binary="${WORK_DIR}/${ASSET}"
    local sums="${WORK_DIR}/SHA256SUMS"

    if [ -n "$LOCAL_BINARY" ]; then
        [ -f "$LOCAL_BINARY" ] || die "local binary not found: $LOCAL_BINARY"
        cp "$LOCAL_BINARY" "$binary"
        COMPUTED_SHA="$(sha256sum "$binary" | awk '{print $1}')"
        [ "$COMPUTED_SHA" = "$LOCAL_SHA256" ] || die "SHA-256 mismatch for $LOCAL_BINARY"
        ok "local binary matches the supplied SHA-256"
        return
    fi

    info "downloading ${ASSET} from ${VERSION}"
    download_stdout "${base}/${ASSET}" "$binary" || die "download failed; no file was installed"
    download_stdout "${base}/SHA256SUMS" "$sums" || die "SHA256SUMS is not published for ${VERSION}; refusing to install unverified"

    local expected actual
    expected="$(awk -v a="$ASSET" '$2 == a || $2 == ("*" a) {print $1; exit}' "$sums")"
    [ -n "$expected" ] || die "SHA256SUMS does not list ${ASSET}; refusing to install unverified"
    actual="$(sha256sum "$binary" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || die "checksum mismatch for ${ASSET}: expected ${expected}, got ${actual}"
    COMPUTED_SHA="$actual"
    ok "checksum verified (${actual:0:12}…)"
}

chmod_bin() { chmod 0755 "$1"; }

# clear_stale_staging removes staging files left by a killed installer. A
# staging file whose process is gone holds a complete or partial copy of the
# release binary and must not be left behind.
clear_stale_staging() {
    local dir="$1" f pid
    for f in "${dir}"/.bypath-staging-*; do
        [ -e "$f" ] || continue
        pid="${f##*/.bypath-staging-}"
        case "$pid" in ''|*[!0-9]*) continue ;; esac
        if kill -0 "$pid" 2>/dev/null; then continue; fi
        rm -f "$f" && info "removed a staging file left by an interrupted install: ${f}"
    done
}

install_binary() {
    fetch_asset

    # Stage next to the install directory and smoke-test there: /tmp is
    # commonly mounted noexec, and a rename across filesystems is not atomic,
    # so the binary must be verified on the filesystem that will hold it.
    local parent
    parent="$(dirname "$INSTALL_DIR")"
    clear_stale_staging "$parent"
    STAGED_BIN="${parent}/.bypath-staging-$$"
    rm -f "$STAGED_BIN"
    cp "${WORK_DIR}/${ASSET}" "$STAGED_BIN"
    chmod_bin "$STAGED_BIN"
    if ! "$STAGED_BIN" version >/dev/null 2>&1; then
        die "the downloaded binary failed its version check when executed from ${parent}; nothing was installed"
    fi
    local staged="$STAGED_BIN"

    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR" \
             "${CONFIG_DIR}/profiles" "${CONFIG_DIR}/geo" \
             "${INSTALL_DIR}/engines"

    if [ -x "${INSTALL_DIR}/bypath" ] && cmp -s "$staged" "${INSTALL_DIR}/bypath"; then
        ok "${VERSION} is already installed; configuration left untouched"
    else
        if [ -x "${INSTALL_DIR}/bypath" ]; then
            cp -f "${INSTALL_DIR}/bypath" "${INSTALL_DIR}/bypath.previous"
            chmod 0755 "${INSTALL_DIR}/bypath.previous"
            info "previous binary saved as ${INSTALL_DIR}/bypath.previous"
        fi
        chmod 0755 "$staged"
        mv -f "$staged" "${INSTALL_DIR}/bypath"
        ok "installed ${INSTALL_DIR}/bypath (${COMPUTED_SHA:0:12}…)"
    fi
    ln -sfn "${INSTALL_DIR}/bypath" "$BIN_LINK"
    ok "linked ${BIN_LINK}"
}

install_unit() {
    if [ "$NO_SYSTEMD" -eq 1 ]; then
        info "systemd unit skipped (--no-systemd or no systemd)"
        return
    fi

    if ! getent group bypath >/dev/null 2>&1; then
        if groupadd --system bypath >/dev/null 2>&1; then
            ok "created the 'bypath' group for control-socket access (root-equivalent; add only trusted admins)"
        else
            warn "could not create the 'bypath' group; the control socket stays root-only"
        fi
    fi

    local tmp="${UNIT_FILE}.new"
    cat > "$tmp" <<EOF
[Unit]
Description=Bypath network gateway
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# The resolver override lives under /run and these hooks sweep it on every exit
# and before every start, so a crash, SIGKILL or failed start cannot leave the
# host pointing at a dead local DNS listener. A non-zero exit is ignored: the
# hook is a correction, not a condition for running.
ExecStartPre=-${INSTALL_DIR}/bypath host-dns restore
ExecStart=${INSTALL_DIR}/bypath run
ExecStopPost=-${INSTALL_DIR}/bypath host-dns restore
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
StandardOutput=append:${LOG_DIR}/access.log
StandardError=append:${LOG_DIR}/error.log

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$tmp"
    mv -f "$tmp" "$UNIT_FILE"
    systemctl daemon-reload
    ok "created ${UNIT_FILE} (not enabled or started)"

    cat <<EOF

  The unit exists but is deliberately not enabled or started: installation
  must not take over this host. Starting, enabling and gateway mode differ:
      start now:      sudo systemctl start bypath
      start at boot:  sudo systemctl enable bypath
      carry the LAN:  gateway mode, enabled only after a verified connection
  The first-run wizard offers the boot enable after a verified start, or pass
  --enable-service.

EOF
}

run_setup() {
    if [ "$NO_SETUP" -eq 1 ]; then
        info "first-run wizard skipped (--no-setup)"
        return 0
    fi
    if [ -f "$CONFIG_FILE" ] && [ "${#SETUP_ARGS[@]}" -eq 0 ]; then
        info "configuration already exists at ${CONFIG_FILE}; leaving it untouched"
        info "run 'sudo bypath setup' to change it"
        return 0
    fi
    local -a cmd=("${INSTALL_DIR}/bypath" "setup")
    cmd+=("${SETUP_ARGS[@]}")

    section "First-run setup"
    if [ -f "$CONFIG_FILE" ]; then
        info "an existing configuration was found; the wizard shows current answers"
    fi

    local rc=0
    if [ "$NONINTERACTIVE" -eq 0 ] && (exec 0</dev/tty) 2>/dev/null; then
        # Piped installers have a script on stdin; the wizard needs the terminal.
        "${cmd[@]}" </dev/tty || rc=$?
    else
        # --non-interactive, or no terminal to prompt on: the wizard must not
        # prompt either way.
        cmd+=(--non-interactive)
        "${cmd[@]}" || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        warn "setup did not complete (exit ${rc}). Nothing was started; re-run 'sudo bypath setup'."
        return 1
    fi
    ok "configuration written to ${CONFIG_FILE}"
}

do_install() {
    preflight
    if [ "$DRY_RUN" -eq 1 ]; then
        section "Dry run"
        local unit_note="would verify SHA256SUMS and create ${UNIT_FILE}"
        if [ "$NO_SYSTEMD" -eq 1 ]; then unit_note="would verify SHA256SUMS and skip the service unit"; fi
        info "would install ${VERSION} (${ASSET:-bypath-linux-${ARCH}}) to ${INSTALL_DIR}"
        info "$unit_note"
        info "would leave existing configuration at ${CONFIG_FILE} untouched"
        if [ "$NO_SETUP" -eq 0 ] && [ "${#SETUP_ARGS[@]}" -gt 0 ]; then
            # Connection URIs and subscription URLs can embed credentials.
            local -a shown=()
            local arg redact_next=0
            for arg in "${SETUP_ARGS[@]}"; do
                if [ "$redact_next" -eq 1 ]; then shown+=("<redacted>"); redact_next=0; continue; fi
                case "$arg" in --uri|--subscription) redact_next=1 ;; esac
                shown+=("$arg")
            done
            info "would run: ${INSTALL_DIR}/bypath setup ${shown[*]}"
        fi
        if [ "$INSTALL_PACKAGES" -eq 1 ]; then
            local pkgs
            pkgs="$(gateway_missing_packages)"
            if [ -n "$pkgs" ]; then
                info "--install-packages: the gateway wizard may run 'apt-get install -y ${pkgs}'; nothing is installed in a dry run"
            else
                info "--install-packages: no gateway package is missing; nothing would be installed"
            fi
        fi
        info "no file was written, no package was installed and no service was changed"
        return 0
    fi
    need_root
    if ! have sha256sum; then die "sha256sum is required to verify the release"; fi

    install_binary
    install_unit
    if run_setup; then
        section "Installed"
        printf '  Binary:  %s -> %s\n' "$BIN_LINK" "${INSTALL_DIR}/bypath"
        printf '  Config:  %s\n' "$CONFIG_FILE"
        printf '  Logs:    %s\n' "$LOG_DIR"
        printf '  Version: %s\n' "$VERSION"
        cat <<EOF

  Next steps
    bypath doctor            read-only installation and safety report
    bypath status            current gateway state
    sudo bypath setup        change the first-run answers
    sudo bypath geo status   optional geo databases (none are downloaded)

  Starting, enabling and gateway mode are separate steps:
    start    runs the service now (wizard --start-service)
    enable   also starts it at boot (wizard --enable-service)
    gateway  routes the LAN through the tunnel (wizard --enable-gateway)

  This installer changed no interface, route, DNS resolver, DHCP lease or
  global firewall rule.
EOF
    else
        exit 1
    fi
}

# ─── Uninstall / rollback ────────────────────────────────────
confirm() {
    if [ "$ASSUME_YES" -eq 1 ]; then return 0; fi
    if [ "$NONINTERACTIVE" -eq 1 ]; then die "refusing to continue without --yes in non-interactive mode"; fi
    local answer
    read -r -p "$1 [y/N] " answer </dev/tty || return 1
    case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

do_uninstall() {
    need_root
    section "Uninstall"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "would stop and remove the bypath unit, ${INSTALL_DIR} and ${BIN_LINK}"
        if [ "$PURGE" -eq 1 ]; then info "would also remove ${CONFIG_DIR}, ${LOG_DIR} and ${RUN_DIR}"; else info "would keep ${CONFIG_DIR} and ${LOG_DIR}"; fi
        info "would remove the runtime directories ${RUN_DIR} and ${CONTROL_DIR} (control socket)"
        info "no file was changed"
        return 0
    fi
    if [ "$SYSTEMD" -eq 1 ] && [ -f "$UNIT_FILE" ]; then
        if systemctl is-active --quiet bypath 2>/dev/null; then
            confirm "Stop the running Bypath service?" || die "uninstall cancelled"
            systemctl stop bypath || warn "could not stop bypath"
        fi
        systemctl disable bypath >/dev/null 2>&1 || true
        rm -f "$UNIT_FILE"
        systemctl daemon-reload || true
        ok "removed ${UNIT_FILE}"
    fi
    rm -f "$BIN_LINK"
    rm -rf "$INSTALL_DIR"
    # Runtime state, including the control socket directory, must not outlive
    # the binary even when the configuration is kept.
    rm -rf "$RUN_DIR" "$CONTROL_DIR"
    ok "removed ${INSTALL_DIR}, ${BIN_LINK} and the runtime directories ${RUN_DIR} ${CONTROL_DIR}"

    if [ "$PURGE" -eq 1 ]; then
        if confirm "Delete configuration, profiles, geo data and logs? This cannot be undone."; then
            rm -rf "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR" "$CONTROL_DIR"
            ok "removed ${CONFIG_DIR}, ${LOG_DIR}, ${RUN_DIR} and ${CONTROL_DIR}"
        else
            info "configuration preserved"
        fi
    else
        info "configuration and data preserved in ${CONFIG_DIR}; logs in ${LOG_DIR}"
        info "re-run with --purge --yes to remove them explicitly"
    fi
    info "no interface, route, DNS resolver, DHCP lease or firewall rule was changed"
}

do_rollback() {
    section "Rollback"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "would restore ${INSTALL_DIR}/bypath.previous over ${INSTALL_DIR}/bypath"
        return 0
    fi
    need_root
    if [ ! -x "${INSTALL_DIR}/bypath.previous" ]; then
        die "no previous binary is recorded at ${INSTALL_DIR}/bypath.previous"
    fi
    local was_active=0
    if [ "$SYSTEMD" -eq 1 ] && systemctl is-active --quiet bypath 2>/dev/null; then
        was_active=1
        systemctl stop bypath
    fi
    cp -f "${INSTALL_DIR}/bypath" "${INSTALL_DIR}/bypath.failed"
    cp -f "${INSTALL_DIR}/bypath.previous" "${INSTALL_DIR}/bypath"
    chmod 0755 "${INSTALL_DIR}/bypath"
    ok "restored the previous binary; the failed one is at ${INSTALL_DIR}/bypath.failed"
    if [ "$was_active" -eq 1 ]; then
        systemctl start bypath || warn "the previous binary was restored but the service did not start"
    fi
}

# ─── Main ────────────────────────────────────────────────────
case "$ACTION" in
    install)    do_install ;;
    uninstall)  detect_platform; detect_environment; do_uninstall ;;
    rollback)   detect_platform; detect_environment; do_rollback ;;
esac
