# Installing Bypath v3.0.0-rc.1

This document covers the supported installation procedure for the
`v3.0.0-rc.1` pre-release, the non-interactive form, upgrades, rollback and
uninstall.

## Supported targets

| | Supported and tested | Notes |
|---|---|---|
| Debian/Ubuntu amd64 | Yes | Native installation tested. |
| Debian/Ubuntu/Armbian arm64 | Yes (emulated validation) | No native arm64 board was used for this release. |
| Other Linux amd64/arm64 distributions | Best effort | systemd assumed for service supervision. |
| armv7, 386, mipsle, riscv64, Windows, macOS | No | Not built for this release. `--allow-unsupported` overrides the refusal, with no support claim. |

The installer requires Bash, `curl`, `sha256sum` (or `shasum`) and `tar`.
On Debian/Ubuntu these are present or installed by the base system; the
installer reports a missing tool instead of installing one.

## 1. Download and verify

```bash
VERSION=v3.0.0-rc.1
mkdir bypath-install && cd bypath-install

curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/install.sh"
curl -fsSLO "https://github.com/liberoute/bypath/releases/download/$VERSION/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
```

`SHA256SUMS` lists the installer, both binaries and `THIRD_PARTY_NOTICES.md`.
The `--ignore-missing` flag lets you verify only the files you downloaded.
A mismatch, a missing file, or a failed download is a stop condition.

Never install from a `/releases/latest` URL: this pre-release is not marked
"latest", and the installer is version-pinned by design.

## 2. Preflight

```bash
sudo ./install.sh --dry-run
```

`--dry-run` performs no writes, removes nothing, starts nothing and can run
without root. It reports:

- distribution, kernel and architecture, and whether the target is supported;
- systemd availability and any existing `bypath` unit state;
- TUN support (`/dev/net/tun`);
- iptables and nftables availability;
- active DNS services (`systemd-resolved`, `dnsmasq`, `unbound`, `named`);
- listeners already holding ports 53, 8080 or 2801;
- memory and free disk;
- an existing installation and configuration;
- private IPv4 interfaces with their address and subnet, plus the default route.

Nothing in the preflight changes the host.

## 3. Install

```bash
sudo ./install.sh --version "$VERSION"
```

The installer verifies the pinned release again, downloads
`bypath-linux-amd64` or `bypath-linux-arm64`, checks its SHA-256 against
`SHA256SUMS`, and stages it before moving it into place. It then:

1. creates `/opt/bypath` and saves any existing binary as
   `/opt/bypath/bypath.previous`;
2. installs `/opt/bypath/bypath` and links `/usr/local/bin/bypath`;
3. creates the `bypath` system group (it never adds accounts to it);
4. writes `/etc/systemd/system/bypath.service` via a temporary file and
   `mv`, then runs `systemctl daemon-reload`. **The unit is not enabled and not
   started.**
5. runs `bypath setup` for the first-run wizard.

Existing configuration at `/etc/bypath/config.yaml` is never overwritten by the
installer. The wizard is told an existing configuration was found and shows its
current answers.

### What the installer never does

- It does not stop, disable or reconfigure `systemd-resolved`, `dnsmasq`,
  `unbound`, `named`, NetworkManager or another VPN.
- It does not rewrite `/etc/resolv.conf`, `/etc/hosts`, routes, the default
  gateway, DHCP settings or global firewall policy.
- It does not open a listener on a LAN address unless the wizard was told to.
- It does not start an empty gateway.

## 4. Non-interactive installation

```bash
sudo ./install.sh --version "$VERSION" --non-interactive \
  --mode proxy \
  --listen localhost \
  --socks-port 2801 \
  --web off
```

`--non-interactive` requires `--mode`. Every other answer has a safe default:

| Flag | Default when omitted |
|---|---|
| `--interface NAME` | Not assumed; required for gateway mode if more than one LAN interface exists. |
| `--trusted-cidr CIDR` | Derived from the chosen interface, shown in the review. Required before a LAN bind. |
| `--listen localhost\|lan\|all` | `localhost`. |
| `--dns-port N` | `53`. |
| `--dns-upstream ADDR` | Only used in gateway mode; pass one or more explicitly. |
| `--web off\|loopback\|lan` | `off`. |
| `--uri` / `--subscription` | Nothing is imported. |
| `--start-service` | Absent: the unit is left stopped. |
| `--enable-gateway` | Absent: gateway mode stays staged and disabled. |

The wizard still prints the review block. In non-interactive mode it does not
wait for confirmation.

A gateway-mode non-interactive install that should not activate the network
looks like this:

```bash
sudo ./install.sh --version "$VERSION" --non-interactive \
  --mode gateway \
  --interface eth0 \
  --trusted-cidr 192.0.2.0/24 \
  --listen localhost \
  --dns-upstream 1.1.1.1 --dns-upstream 8.8.8.8 \
  --web loopback \
  --subscription "https://subscription.example.net/list" \
  --start-service
```

`--start-service` starts the unit only after the wizard has written a
configuration; the gateway itself is enabled only if `--enable-gateway` was
also passed, or later from the panel after verifying a connection.

## 5. Verify

```bash
sudo bypath doctor
sudo bypath doctor --egress
sudo systemctl status bypath
```

A healthy proxy-only installation reports a passing configuration, a reachable
proxy listener and, once the gateway runs, tunnel egress through an address
different from the direct one. `doctor` exits non-zero when a check fails.

## 6. Enable at boot

```bash
sudo systemctl enable --now bypath
```

This is the step that makes Bypath part of the boot path. Do it after the
wizard has produced a verified connection.

## Upgrade

An upgrade is the same command with a newer exact tag. The running binary is
preserved as `/opt/bypath/bypath.previous` before replacement. The unit file is
rewritten; a running service is not restarted automatically. Restart it
yourself after reviewing the new release notes:

```bash
sudo ./install.sh --version vX.Y.Z
sudo systemctl restart bypath
```

## Rollback

```bash
sudo ./install.sh --rollback
```

Restores `/opt/bypath/bypath.previous` over `/opt/bypath/bypath`, keeps the
failed binary as `/opt/bypath/bypath.failed`, and restarts the service only if
it is currently active. If no previous binary is recorded, the installer
refuses and changes nothing.

Rollback does not revert configuration changes. Keep a copy of
`/etc/bypath/config.yaml` before you upgrade if you expect to need it.

## Uninstall

```bash
sudo ./install.sh --uninstall
```

Stops and disables `bypath.service`, removes the unit and
`/opt/bypath/bypath`, and removes the `/usr/local/bin/bypath` link. It keeps
`/etc/bypath` (configuration, profiles, geo data, panel state) and
`/var/log/bypath` so a reinstall keeps your setup and so you can inspect the
logs.

```bash
sudo ./install.sh --uninstall --purge
```

Also removes `/etc/bypath`, `/run/bypath` and `/var/log/bypath`. This deletes
your configuration, imported connections and any stored credentials. The
installer asks for confirmation unless `--yes` is passed. The `bypath` group is
left in place; remove it manually only if no account still belongs to it.

## Installing from a local binary

On a host without outbound access, fetch the release asset elsewhere and pass
it with the checksum from the published `SHA256SUMS`:

```bash
sudo ./install.sh --version "$VERSION" \
  --local-binary ./bypath-linux-amd64 \
  --local-sha256 <sha256 from SHA256SUMS>
```

`--local-sha256` is mandatory with `--local-binary`: the file is verified with
the same check as a download, and the installer refuses without it.

## Interrupted installation

The installer stages the binary beside `/opt/bypath`, runs the staged copy
once (`bypath version`) to prove it executes on this host, and only then renames
it into place on the same filesystem. If it is interrupted:

- no partial binary replaces the working one;
- a partial staging file at `/opt/.bypath-staging-<pid>` and a download
  directory under `/tmp/bypath-fetch.*` may remain; the next run detects and
  removes a staging file whose installer process is gone;
- rerun the same command. Installation is idempotent: the current binary is
  preserved as `bypath.previous` only when it differs.

Because the smoke test runs from `/opt`, a host whose `/tmp` is mounted
`noexec` (common on hardened Debian/Ubuntu images) installs normally. If
`/opt` itself is `noexec`, the installer refuses instead of installing a
binary that cannot run.

If the wizard fails after a successful binary install, the message points you
at `sudo bypath setup`. Nothing was started.

## Dependency and platform notes

- A missing `sha256sum`/`shasum` stops the installation; the installer never
  installs an unverified binary.
- A missing TUN device does not block a proxy-only install, but gateway mode
  will not work and the wizard says so before it asks you to proceed.
- Gateway mode additionally requires `iptables` and `ip6tables`. The wizard
  refuses a gateway configuration when either is missing, because it will not
  start a gateway whose routing and fail-closed rules it cannot enforce.
- Gateway mode manages `/etc/resolv.conf` and refuses if that file is a bind
  mount (the usual case inside a container). Install Bypath on the LAN host
  itself, or use proxy-only mode in a container.
- If port 53 is busy, the wizard reports which service holds it and refuses to
  take it. Choose a free port, resolve the conflict yourself, or use proxy-only
  mode. Bypath never stops another resolver.
- systemd is optional with `--no-systemd`; without it, supervise
  `/opt/bypath/bypath run` yourself.
- Files installed: `/opt/bypath/bypath`, `/usr/local/bin/bypath` (link),
  `/etc/systemd/system/bypath.service`. Configuration is written by the wizard
  to `/etc/bypath/config.yaml`.
