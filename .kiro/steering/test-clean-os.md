# Clean-OS Test Checklist

Full end-to-end test procedure for a **fresh machine** (no prior bypath install).
Each section covers real failures that were hit in production. Run top to bottom.

---

## 0. Install

```bash
# Non-interactive — add link via env var so the installer adds the server
BYPATH_INIT_LINK="vless://..." bash <(curl -s https://raw.githubusercontent.com/liberoute/bypath/main/install.sh) latest full

# If GitHub downloads are blocked (Iranian ISP), pass a proxy:
BYPATH_INIT_LINK="vless://..." bash <(curl -s https://raw.githubusercontent.com/liberoute/bypath/main/install.sh) latest full socks5://your-proxy:port

# Or interactively (prompts for variant and server link):
curl -s https://raw.githubusercontent.com/liberoute/bypath/main/install.sh | bash
```

> **If GitHub itself is blocked** and you can't even fetch install.sh: copy the binary manually,
> run it once, then `bypath add <link>`.

---

## 1. Pre-flight: System

These must pass before bypath starts.

```bash
# 1a. Root check
id -u   # must be 0

# 1b. Network interface name
ip link show   # note the interface name — ens33, eth0, enp0s3, etc.

# 1c. iptables present (required for gateway mode)
iptables --version   # missing → install: apt-get install -y iptables iproute2

# 1d. curl present (required for health checks and tests below)
curl --version       # missing → install: apt-get install -y curl

# 1e. sing-box present (lite build only)
sing-box version     # missing → bypath will auto-download on first run, OR:
                     #   bash <(curl -s .../install.sh) latest full  (no external sing-box needed)
```

**Common gotcha**: Debian 12 minimal has none of curl, iptables, or iproute2 installed.
The installer (`install.sh`) installs them automatically. Manual binary installs do not.

---

## 2. Pre-flight: Config

```bash
cat /etc/bypath/config.yaml
```

Must contain all of these — if any are missing or wrong, fix before starting:

```yaml
gateway:
  enabled: true          # REQUIRED for GATEWAY mode. Missing → PROXY ONLY mode.
  native_tun: true       # Use sing-box TUN (no tun2socks needed). Default: true.
  interface: ""          # Empty = auto-detect. Hard-coding eth0 breaks on ens33 etc.

routing:
  rules:
    - match: "geoip:ir"
      outbound: "direct"
    - match: "default"
      outbound: "proxy"
```

**Check**: `interface: ""` (auto-detect) is strongly preferred over naming it.
If you named it, verify it matches `ip link show` output.

---

## 3. Pre-flight: Server link

```bash
bypath list   # must show at least one server with a ✓ or (active) marker
```

If empty:
```bash
bypath add "vless://..."   # paste the full link
bypath list                # verify it appears
```

No server → bypath starts but immediately fails (no tunnel to establish).

---

## 4. Start and verify startup

```bash
bypath run &          # or: systemctl start bypath
sleep 5
tail -30 /var/log/bypath/error.log
```

### What to look for in the log

**Good** — all of these should appear:

```
✅ Downloaded geoip-ir.srs              ← auto-download on first run
✅ sing-box running on :2801            ← engine started
🚀 Using sing-box native TUN mode      ← TUN mode active
✅ Routing configured (native TUN: ...)
Mode: GATEWAY                          ← the final status line
```

**Bad** — diagnose immediately if you see:

| Log line | Root cause | Fix |
|----------|------------|-----|
| `port :2801 not ready within 10s` | sing-box config error (check sing-box log) | Check if geoip .srs file exists; re-run with a working profile |
| `could not detect local IP on eth0` | Wrong interface name in config | Set `interface: ""` (auto-detect) or correct the name |
| `gateway.enabled is false` / Mode: PROXY ONLY | `enabled: true` missing from config | Add `gateway: { enabled: true }` |
| `tun2socks not found` | Legacy TUN fallback; lite build on old config | Set `native_tun: true`; full build avoids this entirely |
| `iptables: command not found` | iptables not installed | `apt-get install -y iptables iproute2` |

---

## 5. TUN and routing verification

```bash
# tun0 must exist
ip link show tun0          # must show UP

# iptables must have FORWARD rules
iptables -L FORWARD -n     # must show ACCEPT rules for tun0

# DNS must be listening
ss -ulnp | grep :53        # must show bypath or sing-box listening
```

If `tun0` is missing: check that `gateway.enabled: true` AND `gateway.native_tun: true` in config.

---

## 6. Traffic routing (the 4 real tests)

```bash
P="socks5h://127.0.0.1:2801"

echo "1. icanhazip (non-IR IP expected):"
curl -s --max-time 20 -x $P https://icanhazip.com

echo "2. mahex (IR IP expected):"
curl -s --max-time 20 -x $P http://wp.mahex.com/ip

echo "3. youtube (200 expected):"
curl -s -o/dev/null -w "%{http_code}\n" --max-time 20 -x $P https://www.youtube.com

echo "4. samandehi (NOT 403 expected):"
curl -s -o/dev/null -w "%{http_code}\n" --max-time 20 -x $P https://login.samandehi.ir
```

### Expected

```
1. icanhazip:   <non-Iranian IP — e.g. 104.x, 162.x, 2a01:4f8:...>
2. mahex:       <Iranian IP — e.g. 185.x, 91.x, 188.121.x>
3. youtube:     200
4. samandehi:   200  (or 301/307 — anything except 403)
```

### Failure diagnosis

| Test | Fail result | Root cause | Fix |
|------|-------------|------------|-----|
| icanhazip | IR IP or timeout | Tunnel not working | Check server link is active; check proxy reachability |
| youtube | `000` | curl can't connect at all — SOCKS proxy not up | Check `:2801` is listening: `ss -tlnp | grep 2801` |
| youtube | `403` | Tunnel works but youtube blocked at exit node | Try a different server |
| youtube | `200` but wrong page | ISP redirecting — verify IP from test 1 is non-IR | — |
| samandehi | `403` | `geoip:ir` rule not matching — domain not resolved to IP | Check `/etc/bypath/geo/geoip-ir.srs` exists; check log for resolve errors |
| samandehi | same IP as icanhazip | IR traffic going through tunnel | Config has `geoip:ir → proxy` instead of `direct` |
| mahex | non-IR IP | Same as samandehi 403 root cause | `geoip:ir` not matching |

---

## 7. ISP DNS poisoning check

Iranian ISPs return bogon/private IPs for blocked domains. Bypath bypasses this using
DoH (DNS-over-HTTPS) inside the tunnel. Verify the poisoning is present and bypath beats it:

```bash
# This WILL return a bogon IP (10.x or similar) — ISP poisoning
dig youtube.com @8.8.8.8

# This MUST return a real IP — bypath's DoH through the tunnel
curl -s --max-time 10 -x socks5h://127.0.0.1:2801 https://icanhazip.com
# + youtube returning 200 proves DoH is working
```

If `dig` returns a real IP: ISP not poisoning on this network (less common).
If `dig` returns `10.10.x.x` or `127.x.x.x`: poisoning confirmed — bypath's DoH must be working for youtube to return 200.

---

## 8. What install.sh handles automatically

So you know what you **don't** need to do manually after a `curl | bash`:

| Task | install.sh does it? |
|------|---------------------|
| Install iptables, iproute2, curl | ✅ yes |
| Install sing-box (lite) | ✅ yes |
| Create /opt/bypath, /etc/bypath, /var/log/bypath | ✅ yes |
| Write default config with `gateway.enabled: true` | ✅ yes |
| Download geoip/geosite .srs files | ✅ yes (install time) |
| Auto-download geoip on first `bypath run` | ✅ yes (startup auto-download) |
| Add server link | ✅ if `BYPATH_INIT_LINK` set, else prompts interactively |
| Create systemd service | ✅ yes (prompts interactively, auto in non-TTY) |
| Interface name detection | ✅ yes (`interface: ""` in default config = auto) |
| Start bypath | ❌ you must run `systemctl start bypath` or `bypath run` |

---

## 9. Restart test

After a full restart (simulate real deployment):

```bash
reboot   # or: systemctl restart bypath
sleep 15
tail -20 /var/log/bypath/error.log
```

Key things to verify:
- `✅ geoip-ir.srs is up to date` (not re-downloaded — shows staleness check works)
- `Mode: GATEWAY` (not PROXY ONLY — TUN comes back up)
- Re-run tests from section 6 (all 4 must still pass)

---

## 10. Known issues (do not re-investigate — already fixed)

These were real failures in prior sessions. They are now fixed in code:

| Symptom | Was caused by | Fixed in |
|---------|---------------|----------|
| `port :2801 not ready within 10s` on first run | geoip .srs missing → sing-box config error | `configgen.go`: existence check skips missing rule-set |
| samandehi returns 403 | `resolve` action missing → geoip:ir never matched | `configgen.go`: added `resolve: dns-tunnel` action |
| youtube returns `000` or wrong IP | `dns-tunnel` was UDP → silently failed over VLESS-WS; ISP DNS returned bogon | `configgen.go`: changed dns-tunnel to HTTPS (DoH) |
| Mode: PROXY ONLY on fresh config | `gateway.enabled` not in old configs | `install.sh` now writes `enabled: true`; `createDefaultConfig()` also sets it |
| `could not detect local IP on eth0` | Config had hardcoded `eth0` | Default config now uses `interface: ""` (auto) |
