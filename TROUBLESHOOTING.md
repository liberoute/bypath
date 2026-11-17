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
settings: those carry only an address. Clients therefore keep the gateway
address on port 53. While gateway mode runs, Bypath redirects DNS on port 53
arriving from the LAN subnet on the gateway interface to its 5335 listener, so
no client setting has to change. The gateway's own host resolution is
handled separately: when `systemd-resolved` is in use, Bypath writes a
bypath-owned drop-in under `/run/systemd/resolved.conf.d` that forwards the stub
resolver to `127.0.0.1:5335`, and removes it when the gateway stops. The
installed unit also sweeps it in `ExecStartPre` and `ExecStopPost`, so a crash,
a SIGKILL or a failed start cannot leave the host on a dead listener; a reboot
clears the `/run` file even after a power loss. The sweep deletes only a file
whose content is exactly what Bypath wrote, and skips the restart while the
gateway listener is still answering. If you ever need it by hand:

```bash
sudo bypath host-dns restore
```

On hosts without the resolved stub, host DNS is left untouched and the gateway
logs that it could not be redirected.

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
- A loopback panel is only reachable from the host itself. To use it from
  another computer without exposing it, tunnel the configured panel port over
  SSH, for example `ssh -N -L 8081:127.0.0.1:8081 user@gateway-address`, then
  open `http://127.0.0.1:8081` there (the wizard prints the exact command with
  your port). A LAN panel requires `server.web.allow_lan: true` and explicit
  confirmation; the administrator account is created on the first local visit.
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

## The proxy guard refuses to start after a crash or an upgrade

`Proxy firewall setup failed: refusing foreign proxy firewall chain`,
`retaining unverified proxy firewall ownership`, or
`proxy guard state directory is not shared with the firewall owner` means
`BYPATH_PROXY_IN` is installed but cannot be proven to belong to this run.

The ownership record (`/var/lib/bypath/proxy-input.json`) is the only proof.
A chain is removed only when the record names it and the installed rules still
match what the record describes, allowing for a removal that a crash cut short.
A chain without a record is never adopted, even when `/var/lib/bypath` already
exists and the chain has the expected shape: an existing directory does not
prove that two host-network containers share it, and each can mount its own.
Startup refuses such a chain and leaves it untouched.

The guard is owned by a process as well as by a record. The daemon holds an
exclusive abstract-socket lease for its whole lifetime and also creates and
holds the lock file `/var/lib/bypath/proxy-guard.lock`:

- The lease is an abstract Unix socket name, so it has no file to delete,
  cannot be unlinked or recreated, and is released automatically when the
  process dies. Its scope is the network namespace, exactly the scope of the
  iptables state it protects. It excludes every current build: a second
  daemon, a supervisor restart, a stop command, another host-network container.
- The lock file excludes builds that already used a lock (3.0.0-rc.4 builds
  from `2916c1e`) in both directions. A current daemon creates it and keeps it
  locked, so a running legacy daemon is excluded as well as a legacy stop or
  start that finds the current daemon. The lease remains authoritative for
  current builds, so deleting and recreating the lock file can never let a
  current build act. The file lives in `/var/lib/bypath`, must persist, and
  must not be deleted while bypath runs.

Neither mechanism is a defence against a process that already has host root.
Builds older than every lock (`d175a19`, `bb11c37`) cannot be excluded by
anything they do not participate in: a fresh `run` of such a binary removes
whatever the shared record names and installs its own guard. What current
builds guarantee in that case is detection, not prevention: the running daemon
re-checks the record and, when it no longer names its own guard, logs
`Proxy guard ownership changed while running` and stops instead of serving the
LAN unguarded. That is why the migration procedure below is mandatory.

The ownership record and the lock file must live in the same `/var/lib/bypath`
for every process that manages the same firewall. The Compose file mounts it;
keep that mount. Without it a second container cannot prove whose chain it
sees, so it fails closed instead of guessing:

- Starting a LAN-mode guard in a container with its own empty state directory
  is refused while a chain it cannot attribute is installed, and
  `bypath stop` reports `Proxy guard kept: this state directory holds no record
  of the installed guard.` leaving the guard installed.
- Mount `/var/lib/bypath` into every host-network container that runs bypath.

`bypath stop` removes only the guard of the run it stopped, and these messages
mean a guard was deliberately kept:

- `Proxy guard kept: it belongs to a bypath process that is still running.`
  Another bypath process, typically an automatic restart, owns the guard and
  keeps its containment.
- `Proxy guard kept: a newer bypath run installed its own guard.`
  The stopped run's record was replaced before the cleanup ran; the newer run's
  guard is left alone.
- `Proxy guard kept: this state directory holds no record of the installed
  guard.`
  See the shared state directory note above.
- `Proxy guard kept: the guard lock file was removed or replaced while bypath
  was running.`
  The lock file that excludes older builds is gone or belongs to someone else.
  Run `bypath stop` again: once the daemon has exited, the stop reconciles the
  guard with a fresh lock file.

None of them is an error. To remove that guard, stop the running bypath service
first. The stop command waits up to two seconds for the guard lease before
reporting any of them.

A failed install never flushes the chain. Rules are deleted one at a time and
`BYPATH_PROXY_IN` is deleted only after a fresh listing shows it empty; if chain
creation itself failed, the chain that already carried the name is left alone.
When ownership cannot be proven, the record and the chain stay in place and the
error says so.

A loopback-only listener (`server.socks_listen: 127.0.0.1`) installs no guard
and needs no `iptables` access, including in containers without `NET_ADMIN`. A
guard left by an earlier LAN-mode run stays installed and keeps clients blocked
until a LAN-mode start or `bypath stop` reconciles it.

## Changing the binary while a guard is installed

Every supported change of the installed binary follows the same order: stop
with the installed build, verify the firewall is clean, swap the binary, start.

```bash
sudo bypath stop
sudo iptables -S BYPATH_PROXY_IN        # must report no chain
sudo ./install.sh --rollback            # or --version vX.Y.Z
sudo systemctl start bypath
```

`bypath stop` with a current build removes the guard of the daemon it stopped,
including one left by a SIGKILL, so the older binary starts from a clean
firewall. It refuses to remove a guard that a still-running process owns.

Rolling back from a current build to `d175a19` with this procedure is
supported and covered by the lifecycle tests. Skipping the stop is not: an
older unmodified executable started while the current daemon runs cannot be
prevented from taking the guard, as described above. If that happens, the
current daemon exits within a few seconds and reports the ownership change in
its log; stop the older daemon, then start the current build again so it
re-establishes a verified guard. Do not delete `BYPATH_PROXY_IN`, its INPUT
jumps, or `/var/lib/bypath/proxy-guard.lock` by hand unless the rules are
visibly foreign.

## Collecting a useful report

```bash
bypath version
sudo bypath doctor --json > doctor.json
sudo journalctl -u bypath -n 200 --no-pager > journal.txt
```

Check both files for hostnames, interface names, addresses and anything else
you do not want to publish before attaching them to an issue.
