# Troubleshooting

Start with the read-only report. It answers most questions without changing
anything:

```bash
sudo bypath doctor        # summary
sudo bypath doctor -v     # every check with detail
sudo bypath doctor --json # structured output for a bug report
```

`doctor` exits non-zero when a check fails. Remove secrets before sharing a
report: it already redacts credentials, tokens and subscription URLs, but
hostnames and interface names are visible.

## The installer refuses to run

- **"unsupported platform"** — this release builds only Linux amd64 and arm64.
  Do not pass `--allow-unsupported` on a production system; there is no tested
  artefact for other targets.
- **"sha256sum is required"** — install `coreutils` (Debian/Ubuntu) and rerun.
  The installer never proceeds without a checksum tool.
- **"an exact release tag is required"** — pass `--version v3.0.0-rc.2`. The
  installer deliberately rejects `latest`.
- **"failed its version check when executed from /opt"** — the binary could not
  run where it is installed. Usually `/opt` is mounted `noexec`; install
  somewhere executable or fix the mount. Nothing was installed.

## Checksum mismatch

Stop. Delete the downloaded files and download them again from the pinned
release URL. If the mismatch persists, do not install: report it on the
repository with the file name and the two hashes.

## Port 53 is already in use

Gateway DNS needs UDP/TCP 53. Common holders are `systemd-resolved`, `dnsmasq`,
`unbound` and `named`.

- The wizard reports which service holds the port. It does not stop it.
- Options: choose a different `--dns-port`, move the other resolver to another
  port yourself, or install in proxy-only mode.
- If you disable `systemd-resolved`, understand that other software on the host
  may depend on it. Bypath will not do this for you.

### Nonstandard DNS port (5335)

A port other than 53 cannot be expressed by DHCP or by ordinary client DNS
settings: those carry only an address. If the wizard selected 5335, every LAN
client must be pointed at the gateway address **and port 5335** explicitly, or
the client needs a local port-53 redirect. The gateway's own host resolution is
handled separately: when `systemd-resolved` is in use, Bypath writes a
bypath-owned drop-in that forwards the stub resolver to `127.0.0.1:5335` and
removes it when the gateway stops. On hosts without the resolved stub, host DNS
is left untouched and the gateway logs that it could not be redirected.

## The wizard refuses gateway mode

- **"needs /dev/net/tun"** — the TUN device is absent. Load the `tun` module,
  give the container `--device /dev/net/tun`, or choose proxy-only mode.
- **"needs iptables"** / **"needs ip6tables"** — install `iptables`. Bypath
  refuses to start a gateway whose routing and fail-closed rules it cannot
  enforce; there is no partial gateway.
- **"it is a bind mount"** — `/etc/resolv.conf` is bind-mounted, so a container
  runtime owns it and rewriting it would break the host resolver without
  serving the container's private network namespace. Run Bypath on the LAN host
  itself or use proxy-only mode.

## Gateway starts but clients have no internet

1. `bypath doctor` — check configuration, TUN, routing and connection checks.
2. `bypath doctor --egress` — it measures the tunnel exit and the direct exit.
   Same address means traffic is not entering the tunnel.
3. Confirm the selected connection is healthy: `bypath status`, then test it
   with `bypath test <name>`.
4. Confirm the client uses the Bypath host as gateway **and** DNS. A client with
   the right gateway and a public DNS server bypasses routing decisions.
5. In gateway mode, IPv6 is dropped by design. A client preferring IPv6 may see
   failures until it falls back to IPv4.

## Native TUN fails

`doctor` reports whether `/dev/net/tun` is present and whether the selected
engine can create the device. Bypath reports the failure instead of silently
falling back to tun2socks. Check:

- the host is not a container without `--device /dev/net/tun` and `NET_ADMIN`;
- the kernel module is available;
- the engine variant embedded in this build matches the architecture.

Proxy-only mode does not need TUN.

## The LAN cannot reach the proxy

The proxy binds loopback unless configured otherwise. A LAN bind requires:

1. `server.socks_allow_lan: true`;
2. a `server.socks_trusted_cidrs` entry that contains the client and belongs to
   an up, non-loopback interface;
3. Bypath's firewall rules, which are installed by the supervised proxy apply
   operation.

`doctor` reports the effective listeners and the allow-list. If the client is
in the allow-list but still blocked, check that the client is on the interface
whose subnet you listed, and that no other firewall rule precedes Bypath's
chain.

## The panel is unreachable

- It is disabled by default. Enable it in configuration or from the setup
  wizard, then restart the service.
- A loopback panel is only reachable from the host itself. A LAN panel requires
  `server.web.allow_lan: true` and explicit confirmation; the administrator
  account is created on the first local visit.
- The panel, the management API and the proxy are three separate listeners with
  separate ports. Changing one does not move the others.

## A connection tests as "inconclusive" or "blocked"

- **Inconclusive** means the test could not produce trustworthy evidence —
  for example, the isolated test path is not verified on this host
  (`tests.isolation_verified: false`). It is not a pass.
- **Blocked by network** means a controlled probe also showed that direct egress
  was unavailable. It is not a pass either.
- Re-run after confirming general connectivity, or select a different
  connection.

## Subscription import fails

- The URL must be reachable from the host, without a browser-only session.
- Providers may require a token in the URL or a user agent; if the provider
  documents a required header, import the individual links instead.
- Malformed lines are reported and skipped; the successful links are still
  stored. `bypath sub update` shows a summary per subscription.
- A subscription is your data. Reports and screenshots should not contain the
  full URL: the token in it usually *is* the credential.

## OpenVPN profile is rejected

- Directives that execute code or change host state (`up`, `down`, `plugin`,
  `script-security`, `route-up`, `management`, ...) are rejected by design.
- Referenced certificate, key and TLS files must live inside the profile's own
  directory. Absolute paths, drive-letter/UNC paths and traversal are refused.
- OpenVPN links need an external sing-box binary of version 1.14 or newer on
  the host (`bypath engines` shows what was found).

## The service does not start after reboot

```bash
systemctl status bypath
journalctl -u bypath -n 100 --no-pager
```

The installer does not enable the unit. Enabling it is a separate, deliberate
step:

```bash
sudo systemctl enable --now bypath
```

If the unit runs but exits immediately, `journalctl` plus `bypath doctor` will
show whether the configuration, the engine or the selected connection is at
fault.

## Collecting a useful report

```bash
bypath version
sudo bypath doctor --json > doctor.json
sudo journalctl -u bypath -n 200 --no-pager > journal.txt
```

Check both files for hostnames, interface names, addresses and anything else
you do not want to publish before attaching them to an issue.
