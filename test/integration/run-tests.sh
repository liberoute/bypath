#!/bin/bash
set -e

PASS=0
FAIL=0
TOTAL=0

pass() {
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    echo "  ✅ PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    echo "  ❌ FAIL: $1 — $2"
}

check() {
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc" "command failed: $*"
    fi
}

check_output() {
    local desc="$1"
    local expected="$2"
    shift 2
    local output
    output=$("$@" 2>&1) || true
    if echo "$output" | grep -q "$expected"; then
        pass "$desc"
    else
        fail "$desc" "expected '$expected' in output, got: $(echo "$output" | head -3)"
    fi
}

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Bypath Integration Tests                  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ============================================================
# LITE BUILD TESTS
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  LITE BUILD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Binary exists and is executable
check "lite: binary exists" test -x /usr/local/bin/bypath-lite

# Version command works
check_output "lite: version command" "Bypath" bypath-lite version

# Variant is lite
check_output "lite: variant is lite" "lite" bypath-lite version

# Help command works
check_output "lite: help command" "Usage:" bypath-lite help

# Unknown command returns error
if bypath-lite nonexistent > /dev/null 2>&1; then
    fail "lite: unknown command exits non-zero" "should have failed"
else
    pass "lite: unknown command exits non-zero"
fi

# Sub commands without args show usage
check_output "lite: sub usage" "Usage:" bypath-lite sub

# Add command without args shows usage
check_output "lite: add usage" "Usage:" bypath-lite add

# Select command without args shows usage
check_output "lite: select usage" "Usage:" bypath-lite select

# List with no profiles
check_output "lite: list empty" "No groups" bypath-lite list

# Parse a vmess link (add + list)
mkdir -p /tmp/bypath-lite-test/data/profiles /tmp/bypath-lite-test/configs
cat > /tmp/bypath-lite-test/configs/default.yaml << 'EOF'
server:
  api_port: 8080
  dns_port: 5353
gateway:
  enabled: false
whitelist:
  countries: ["ir"]
EOF

cd /tmp/bypath-lite-test
VMESS_LINK="vmess://eyJ2IjoiMiIsInBzIjoidGVzdC1zZXJ2ZXIiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTBhYiIsImFpZCI6MCwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii93cyIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIn0="
check_output "lite: add vmess link" "Added" bypath-lite add "$VMESS_LINK"
check_output "lite: list shows link" "vmess" bypath-lite list
check_output "lite: select by number" "Active link" bypath-lite select 1

# Parse a vless link
VLESS_LINK="vless://uuid-test@example.com:443?type=ws&security=tls&sni=example.com&path=/vless#my-vless"
check_output "lite: add vless link" "Added" bypath-lite add "$VLESS_LINK"

# Parse a trojan link
TROJAN_LINK="trojan://password123@trojan.server.com:8443?sni=trojan.server.com#trojan-test"
check_output "lite: add trojan link" "Added" bypath-lite add "$TROJAN_LINK"

# Parse a shadowsocks link
SS_LINK="ss://YWVzLTI1Ni1nY206bXlwYXNz@1.2.3.4:8388#ss-test"
check_output "lite: add ss link" "Added" bypath-lite add "$SS_LINK"

# Binary size check (lite should be < 20MB)
LITE_SIZE=$(stat -c%s /usr/local/bin/bypath-lite 2>/dev/null || stat -f%z /usr/local/bin/bypath-lite)
if [ "$LITE_SIZE" -lt 20000000 ]; then
    pass "lite: binary size reasonable ($(echo "$LITE_SIZE / 1048576" | bc)MB)"
else
    fail "lite: binary size too large" "${LITE_SIZE} bytes"
fi

echo ""

# ============================================================
# FULL BUILD TESTS
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  FULL BUILD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Binary exists and is executable
check "full: binary exists" test -x /usr/local/bin/bypath-full

# Version command works
check_output "full: version command" "Bypath" bypath-full version

# Variant is full
check_output "full: variant is full" "full" bypath-full version

# Help command works
check_output "full: help command" "Usage:" bypath-full help

# Full build should have embedded engines registered
check_output "full: version shows full variant" "full" bypath-full version

# Parse links work the same
cd /tmp
mkdir -p /tmp/bypath-full-test/data/profiles
cd /tmp/bypath-full-test
check_output "full: add vmess link" "Added" bypath-full add "$VMESS_LINK"
check_output "full: list shows link" "vmess" bypath-full list

# Binary size check (full should be > lite but still reasonable)
FULL_SIZE=$(stat -c%s /usr/local/bin/bypath-full 2>/dev/null || stat -f%z /usr/local/bin/bypath-full)
if [ "$FULL_SIZE" -ge "$LITE_SIZE" ]; then
    pass "full: binary size >= lite ($(echo "$FULL_SIZE / 1048576" | bc)MB)"
else
    fail "full: binary should be >= lite" "full=${FULL_SIZE} lite=${LITE_SIZE}"
fi

echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  RESULTS: $PASS passed, $FAIL failed, $TOTAL total"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "❌ SOME TESTS FAILED"
    exit 1
fi

echo "✅ ALL TESTS PASSED"
exit 0
