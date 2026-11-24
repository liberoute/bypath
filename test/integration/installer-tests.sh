#!/bin/bash
# Installer option-contract tests. Sourced by run-tests.sh inside the disposable
# integration container (shares pass/fail/expect_contains). Runs last because
# it replaces /opt/bypath/bypath. --allow-unsupported because the image is
# Alpine; --no-systemd because the container has no init system.
INSTALLER=/install.sh
INSTALL_FLAGS=(--allow-unsupported --no-systemd)

echo "== installer: option contract =="
if bash -n "$INSTALLER"; then pass "install.sh parses"; else fail "install.sh parses" "bash -n failed"; fi
expect_contains "installer --help documents --install-packages" "--install-packages" bash "$INSTALLER" --help

bash "$INSTALLER" --bogus-option >/tmp/inst.log 2>&1
rc=$?
if [ "$rc" -eq 2 ]; then pass "unknown installer option is a usage error"; else fail "unknown installer option is a usage error" "rc=$rc"; fi

bash "$INSTALLER" --install-packages --no-setup >/tmp/inst.log 2>&1
rc=$?
if [ "$rc" -eq 2 ] && grep -qF "no effect with --no-setup" /tmp/inst.log; then
    pass "--install-packages with --no-setup is refused instead of ignored"
else
    fail "--install-packages with --no-setup is refused instead of ignored" "rc=$rc $(tr '\n' ' ' </tmp/inst.log | cut -c1-200)"
fi

echo "== installer: dry run with --install-packages changes nothing =="
before="$(ls -la /opt/bypath; ls -la /etc/bypath 2>&1)"
bash "$INSTALLER" --dry-run "${INSTALL_FLAGS[@]}" --non-interactive --mode gateway --interface eth0 --install-packages >/tmp/inst.log 2>&1
rc=$?
after="$(ls -la /opt/bypath; ls -la /etc/bypath 2>&1)"
if [ "$rc" -eq 0 ]; then pass "installer dry run succeeds"; else fail "installer dry run succeeds" "rc=$rc $(tail -n 3 /tmp/inst.log | tr '\n' ' ')"; fi
for needle in "would run: /opt/bypath/bypath setup --mode gateway --interface eth0 --install-packages" \
              "nothing is installed in a dry run" \
              "no package was installed" \
              "Gateway:   missing"; do
    if grep -qF -- "$needle" /tmp/inst.log; then pass "dry run reports '$needle'"; else fail "dry run reports '$needle'" "$(tr '\n' ' ' </tmp/inst.log | cut -c1-300)"; fi
done
if [ "$before" = "$after" ]; then pass "installer dry run leaves /opt/bypath and /etc/bypath unchanged"; else fail "installer dry run leaves /opt/bypath and /etc/bypath unchanged" "listing changed"; fi

bash "$INSTALLER" --dry-run "${INSTALL_FLAGS[@]}" --non-interactive --mode gateway --interface eth0 \
    --uri "vless://secret-user-id@192.0.2.10:443#doc" --subscription "https://example.invalid/sub?token=secret-token" >/tmp/inst.log 2>&1
if grep -qF "secret-" /tmp/inst.log; then
    fail "dry-run plan never prints connection credentials" "$(grep -F 'secret-' /tmp/inst.log)"
elif grep -qF -- "--uri <redacted> --subscription <redacted>" /tmp/inst.log; then
    pass "dry-run plan never prints connection credentials"
else
    fail "dry-run plan never prints connection credentials" "$(grep -F 'would run' /tmp/inst.log)"
fi

echo "== installer: forwards --install-packages and --non-interactive to the wizard =="
cat >/tmp/stub-bypath <<'EOF'
#!/bin/sh
if [ "$1" = "version" ]; then echo "bypath stub"; exit 0; fi
printf '%s\n' "$@" >/tmp/stub-argv
exit 0
EOF
chmod 0755 /tmp/stub-bypath
stub_sha="$(sha256sum /tmp/stub-bypath | awk '{print $1}')"
rm -f /tmp/stub-argv
bash "$INSTALLER" "${INSTALL_FLAGS[@]}" --local-binary /tmp/stub-bypath --local-sha256 "$stub_sha" \
    --non-interactive --mode gateway --interface eth0 --install-packages >/tmp/inst.log 2>&1
rc=$?
want="$(printf '%s\n' setup --mode gateway --interface eth0 --install-packages --non-interactive)"
got="$(cat /tmp/stub-argv 2>/dev/null)"
if [ "$rc" -eq 0 ] && [ "$got" = "$want" ]; then
    pass "wizard receives exactly: setup --mode gateway --interface eth0 --install-packages --non-interactive"
else
    fail "wizard receives the forwarded flags" "rc=$rc argv=$(printf '%s' "$got" | tr '\n' ' ')"
fi

rm -f /tmp/stub-argv
bash "$INSTALLER" "${INSTALL_FLAGS[@]}" --local-binary /tmp/stub-bypath --local-sha256 "$stub_sha" \
    --non-interactive --mode gateway --interface eth0 >/tmp/inst.log 2>&1
if grep -qx -- "--install-packages" /tmp/stub-argv 2>/dev/null; then
    fail "package approval is never implied" "--install-packages forwarded without being requested"
else
    pass "package approval is never implied"
fi

echo "== installer: the real wizard accepts the forwarded flag =="
real_sha="$(sha256sum /opt/bypath/bypath-full | awk '{print $1}')"
cp /opt/bypath/bypath-full /tmp/bypath-real
rm -f /etc/bypath/config.yaml
bash "$INSTALLER" "${INSTALL_FLAGS[@]}" --local-binary /tmp/bypath-real --local-sha256 "$real_sha" \
    --non-interactive --mode gateway --interface eth0 --install-packages >/tmp/inst.log 2>&1
rc=$?
if grep -qF "flag provided but not defined" /tmp/inst.log; then
    fail "real wizard accepts --install-packages" "$(grep -F 'flag provided' /tmp/inst.log)"
else
    pass "real wizard accepts --install-packages"
fi
if [ "$rc" -ne 0 ] && grep -qF "apt-get is not available" /tmp/inst.log; then
    pass "without apt the approved install stops with the manual command"
else
    fail "without apt the approved install stops with the manual command" "rc=$rc $(tail -n 4 /tmp/inst.log | tr '\n' ' ')"
fi
if [ -f /etc/bypath/config.yaml ]; then
    fail "a refused gateway setup writes no configuration" "/etc/bypath/config.yaml exists"
else
    pass "a refused gateway setup writes no configuration"
fi
