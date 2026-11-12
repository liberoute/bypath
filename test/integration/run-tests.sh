#!/bin/bash
# Clean-container smoke test. Runs without a provider, a connection or network
# access to any private service. Every check is read-only except for the
# configuration written under /tmp by the wizard.
set -u

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s — %s\n' "$1" "$2"; }

expect_contains() { # label, needle, command...
    local label="$1" needle="$2"
    shift 2
    local output
    output="$("$@" 2>&1)"
    if printf '%s' "$output" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label" "'$needle' not found in: $(printf '%s' "$output" | head -n 3 | tr '\n' ' ')"
    fi
}

echo "== binaries =="
expect_contains "lite build runs" "bypath" /opt/bypath/bypath version
expect_contains "full build runs" "bypath" /opt/bypath/bypath-full version

echo "== neutral first run =="
CONFIG=/tmp/bypath-test/config.yaml
mkdir -p /tmp/bypath-test
if /opt/bypath/bypath-full setup --non-interactive --config "$CONFIG" \
        --mode proxy --listen localhost --socks-port 2801 --web off >/tmp/setup.log 2>&1; then
    pass "wizard writes a proxy-only configuration"
else
    fail "wizard writes a proxy-only configuration" "$(tail -n 3 /tmp/setup.log | tr '\n' ' ')"
fi

if [ -f "$CONFIG" ]; then
    if grep -qiE 'airvpn|subscription|provider' "$CONFIG"; then
        fail "configuration carries no provider or subscription" "unexpected provider field"
    else
        pass "configuration carries no provider or subscription"
    fi
    if grep -qE 'enabled: false' "$CONFIG"; then
        pass "gateway is disabled by default"
    else
        fail "gateway is disabled by default" "gateway.enabled is not false"
    fi
else
    fail "configuration exists" "$CONFIG was not written"
fi

echo "== doctor =="
expect_contains "doctor reports proxy/listener state" "proxy" \
    /opt/bypath/bypath-full doctor --config "$CONFIG" --json
expect_contains "doctor names the config path" "$CONFIG" \
    /opt/bypath/bypath-full doctor --config "$CONFIG" --json

echo "== no service taken over =="
if /opt/bypath/bypath-full status >/tmp/status.log 2>&1; then
    fail "status without a daemon is not success" "status exited 0 with no daemon"
else
    pass "status without a daemon reports failure instead of pretending"
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
