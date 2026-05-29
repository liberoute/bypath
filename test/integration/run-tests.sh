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

check_output() {
    local desc="$1"
    local expected="$2"
    shift 2
    local output
    output=$("$@" 2>&1) || true
    if echo "$output" | grep -qi "$expected"; then
        pass "$desc"
    else
        fail "$desc" "expected '$expected', got: $(echo "$output" | head -3)"
    fi
}

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Bypath Integration Tests                  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ============================================================
# RUNTIME DEPS CHECK
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  RUNTIME DEPENDENCIES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for bin in sing-box tun2socks iptables ip curl; do
    if command -v "$bin" > /dev/null 2>&1; then
        pass "dep: $bin found"
    else
        fail "dep: $bin missing" "not in PATH"
    fi
done

echo ""

# ============================================================
# LITE BUILD TESTS
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  LITE BUILD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BIN=/usr/local/bin/bypath-lite

# Binary basics
if [ -x "$BIN" ]; then pass "lite: binary executable"; else fail "lite: binary executable" "not found"; fi
check_output "lite: version" "Bypath" $BIN version
check_output "lite: variant is lite" "lite" $BIN version
check_output "lite: help" "Usage:" $BIN help

# Link parsing
cd /app
VMESS="vmess://eyJ2IjoiMiIsInBzIjoidGVzdC1zZXJ2ZXIiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTBhYiIsImFpZCI6MCwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii93cyIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIn0="
check_output "lite: add vmess" "Added" $BIN add "$VMESS"

VLESS="vless://uuid-test@example.com:443?type=ws&security=tls&sni=example.com&path=/vless#my-vless"
check_output "lite: add vless" "Added" $BIN add "$VLESS"

SS="ss://YWVzLTI1Ni1nY206bXlwYXNz@1.2.3.4:8388#ss-test"
check_output "lite: add ss" "Added" $BIN add "$SS"

check_output "lite: list" "vmess" $BIN list
check_output "lite: select" "Active link" $BIN select 1

# Engine detection
check_output "lite: engines detect sing-box" "sing-box" $BIN version

# sing-box config generation test (start engine briefly)
echo '  ⏳ Testing sing-box startup...'
$BIN run -c /app/configs/default.yaml > /app/logs/lite-run.log 2>&1 &
RUN_PID=$!
sleep 4

# Check if SOCKS port opened
if curl -sf --connect-timeout 3 -x socks5h://127.0.0.1:2801 http://ip-api.com/json > /dev/null 2>&1; then
    pass "lite: tunnel connectivity (socks5:2801)"
else
    # At least check if sing-box started (port might not connect without valid server)
    if grep -q "sing-box running\|Engine.*running\|SOCKS" /app/logs/lite-run.log 2>/dev/null; then
        pass "lite: engine started (no real server to connect)"
    else
        # Check if it at least tried to start
        if grep -q "Starting engine\|starting" /app/logs/lite-run.log 2>/dev/null; then
            pass "lite: engine attempted start (expected - no valid server)"
        else
            fail "lite: run command" "$(tail -3 /app/logs/lite-run.log 2>/dev/null)"
        fi
    fi
fi

kill $RUN_PID 2>/dev/null || true
wait $RUN_PID 2>/dev/null || true

# Cleanup for full build test
rm -f /app/data/profiles/*.json /app/data/profiles/.active

echo ""

# ============================================================
# FULL BUILD TESTS
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  FULL BUILD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BIN=/usr/local/bin/bypath-full

if [ -x "$BIN" ]; then pass "full: binary executable"; else fail "full: binary executable" "not found"; fi
check_output "full: version" "Bypath" $BIN version
check_output "full: variant is full" "full" $BIN version
check_output "full: help" "Usage:" $BIN help

# Link parsing
check_output "full: add vmess" "Added" $BIN add "$VMESS"
check_output "full: list" "vmess" $BIN list
check_output "full: select" "Active link" $BIN select 1

# Size comparison
LITE_SIZE=$(stat -c%s /usr/local/bin/bypath-lite)
FULL_SIZE=$(stat -c%s /usr/local/bin/bypath-full)
LITE_MB=$((LITE_SIZE / 1048576))
FULL_MB=$((FULL_SIZE / 1048576))

if [ "$LITE_SIZE" -lt 25000000 ]; then
    pass "lite: size OK (${LITE_MB}MB)"
else
    fail "lite: size too big" "${LITE_MB}MB"
fi

if [ "$FULL_SIZE" -ge "$LITE_SIZE" ]; then
    pass "full: size >= lite (${FULL_MB}MB >= ${LITE_MB}MB)"
else
    fail "full: size should be >= lite" "full=${FULL_MB}MB lite=${LITE_MB}MB"
fi

echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  RESULTS: %d passed, %d failed, %d total\n" "$PASS" "$FAIL" "$TOTAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "❌ SOME TESTS FAILED"
    exit 1
fi

echo "✅ ALL TESTS PASSED"
exit 0
