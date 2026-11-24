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
    if printf '%s' "$output" | grep -qF -- "$needle"; then
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

echo "== setup --dry-run never installs packages =="
# A recording apt-get: any invocation leaves a trace, so its absence proves the
# dry run executed nothing even with package installation approved.
cat >/usr/local/bin/apt-get <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>/tmp/apt-calls
exit 0
EOF
chmod 0755 /usr/local/bin/apt-get
rm -f /tmp/apt-calls
DRY=/tmp/bypath-dry/config.yaml
mkdir -p /tmp/bypath-dry
/opt/bypath/bypath-full setup --non-interactive --dry-run --install-packages --config "$DRY" \
    --mode gateway --interface eth0 >/tmp/dry.log 2>&1
rc=$?
if [ -e /tmp/apt-calls ]; then
    fail "dry run with --install-packages runs no apt-get" "$(tr '\n' ' ' </tmp/apt-calls)"
else
    pass "dry run with --install-packages runs no apt-get"
fi
if [ -e "$DRY" ]; then fail "dry run writes no configuration" "$DRY exists"; else pass "dry run writes no configuration"; fi
if [ "$rc" -ne 0 ] && grep -qF "a real run would execute" /tmp/dry.log; then
    pass "dry run previews the approved install and exits non-zero"
else
    fail "dry run previews the approved install and exits non-zero" "rc=$rc $(tr '\n' ' ' </tmp/dry.log | cut -c1-300)"
fi
# With a connection the preview runs to the end and still refuses to claim success.
/opt/bypath/bypath-full setup --non-interactive --dry-run --install-packages --config "$DRY" \
    --mode gateway --interface eth0 --uri "socks5://192.0.2.10:1080#doc" >/tmp/dry.log 2>&1
rc=$?
if [ "$rc" -ne 0 ] && grep -qF "real run would stop at the gateway prerequisites" /tmp/dry.log \
        && grep -qF "nothing was written, installed, imported or started" /tmp/dry.log \
        && [ ! -e /tmp/apt-calls ] && [ ! -e "$DRY" ]; then
    pass "full dry-run preview ends with the prerequisite verdict and changes nothing"
else
    fail "full dry-run preview ends with the prerequisite verdict and changes nothing" "rc=$rc $(tail -n 3 /tmp/dry.log | tr '\n' ' ')"
fi
/opt/bypath/bypath-full setup --non-interactive --install-packages --config "$DRY" \
    --mode gateway --interface eth0 >/tmp/real.log 2>&1
if grep -qF "install -y" /tmp/apt-calls 2>/dev/null; then
    pass "control: the same command without --dry-run does reach apt-get"
else
    fail "control: the same command without --dry-run does reach apt-get" "$(tail -n 3 /tmp/real.log | tr '\n' ' ')"
fi
if [ -e "$DRY" ]; then fail "unsatisfied prerequisites write no configuration" "$DRY exists"; else pass "unsatisfied prerequisites write no configuration"; fi
rm -f /usr/local/bin/apt-get /tmp/apt-calls

# Installer checks replace /opt/bypath/bypath, so they run last.
. /installer-tests.sh

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
