# Quick start (v3.0.0-rc.2)

This is the shortest path from a fresh Debian/Ubuntu machine to a working
proxy. It assumes Linux amd64 or arm64 and root access via `sudo`.

If you want the gateway (whole-network) mode or a non-interactive install, read
[INSTALL.md](INSTALL.md) instead.

## 1. Verify the release artifacts

```bash
VERSION=v3.0.0-rc.2
mkdir bypath-install && cd bypath-install
curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/install.sh"
curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
```

Both commands must succeed. If `sha256sum` reports a mismatch, stop and do not
install.

## 2. Install

```bash
sudo bash install.sh --version "$VERSION"
```

The installer prints what it detected (distribution, architecture, systemd,
TUN, firewall backend, DNS services, busy ports, existing installation) and
then starts the first-run wizard. It writes no network configuration and does
not start the service.

## 3. Run the wizard

Answer the ten steps:

1. **LAN interface** — the wizard lists interfaces it detected. If you only
   want a local proxy, the answer still determines which LAN address is offered
   later; nothing is changed yet.
2. **Trusted client subnets** — press Enter to accept the subnet it derived
   from the interface, or type an explicit CIDR. This list is what will be
   allowed to reach the proxy if you expose it to the LAN.
3. **Mode** — choose `proxy-only` for the first run. You can enable gateway
   mode later from the panel or by rerunning setup.
4. **Proxy port** — `2801` unless it is busy.
5. **Proxy listener** — `localhost` is the safe default.
6. **DNS** — skipped in proxy-only mode. In gateway mode a busy port 53 is
   reported and you must choose a different port or free it yourself.
7. **Connection** — paste a proxy URI or a subscription URL you are entitled to
   use, or skip and add it later from the panel.
8. **Select and verify** — choose the imported connection and let the wizard
   test it.
9. **Panel** — `loopback` or `off`. A LAN panel requires explicit confirmation
   and the administrator account is created on first local visit.
10. **Review** — read the printed summary. Nothing is written before this point.

## 4. Confirm with doctor

```bash
sudo bypath doctor
```

Every check should be `PASS` or an explained `WARN`. Exit code is non-zero when
a check fails. Use `bypath doctor --egress` to prove the tunnel leaves from a
different address than your direct connection.

## 5. Use the proxy

For applications that accept a SOCKS5 proxy:

```
socks5://127.0.0.1:2801
```

Mixed SOCKS5/HTTP is served on the same port. To test from the same machine:

```bash
curl -x socks5h://127.0.0.1:2801 https://example.com -I
```

## 6. Start on boot (optional)

The installer wrote `/etc/systemd/system/bypath.service` but did not enable it.

```bash
sudo systemctl enable --now bypath
sudo systemctl status bypath
```

Disabling the unit and stopping the daemon removes all listeners:

```bash
sudo bypath stop
```

## Next steps

- Add or refresh a subscription: `bypath sub add <url>`, `bypath sub update`.
- Switch the active connection: `bypath select <name|number>`.
- Enable the browser panel and sign in from the machine itself.
- Read [CONFIGURATION.md](CONFIGURATION.md) before changing routing or DNS.
- If something fails, run `bypath doctor -v` and see
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
