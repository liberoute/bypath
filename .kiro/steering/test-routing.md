# Routing Test Procedure

Run these after `bypath run` (or `systemctl start bypath`) to verify the tunnel and split-routing work.

Tests use `-x socks5h://127.0.0.1:2801` so DNS is also resolved through bypath — more reliable than
testing from the gateway machine's own resolver (which may have ISP DNS hijack issues).

## One-liner (quick check — run this)

```bash
P="socks5h://127.0.0.1:2801"

echo "1. icanhazip (non-IR IP expected):" && curl -s --max-time 20 -x $P https://icanhazip.com
echo "2. mahex (IR IP expected):"         && curl -s --max-time 20 -x $P http://wp.mahex.com/ip
echo "3. youtube (200 expected):"         && curl -s -o/dev/null -w "%{http_code}\n" --max-time 20 -x $P https://www.youtube.com
echo "4. samandehi (NOT 403 expected):"   && curl -s -o/dev/null -w "%{http_code}\n" --max-time 20 -x $P https://login.samandehi.ir
```

## Expected output

```
1. icanhazip (non-IR IP expected):
<non-Iranian IP — e.g. 104.x, 162.x, 2a01:4f8:...>

2. mahex (IR IP expected):
<Iranian IP — e.g. 185.x, 91.x, 5.x, 188.121.x>

3. youtube (200 expected):
200

4. samandehi (NOT 403 expected):
200   ← or 307, 301, etc — anything except 403
```

## What each result means

| Test | Pass | Fail | Meaning |
|------|------|------|---------|
| icanhazip | non-IR IP | IR IP / timeout | Tunnel is carrying foreign traffic |
| mahex | IR IP shown | non-IR IP | `geoip:ir` direct rule is working |
| youtube | 200 | 403 / 000 / blocked | Blocked content goes through tunnel |
| samandehi | 200/3xx | **403** | `geoip:ir` direct — IR site not going through proxy |

## Interpreting failures

- **icanhazip returns IR IP**: tunnel not routing foreign traffic — check `bypath list`, ensure a server is selected, check `bypath status`
- **samandehi returns 403**: geoip:ir direct rule not matching — check `routing.rules` in `/etc/bypath/config.yaml`, verify `/etc/bypath/geo/geoip-ir.srs` exists
- **youtube returns 000**: curl can't connect at all — DNS might be failing; try with `--dns-servers 1.1.1.1` or check `journalctl -u bypath -n 50`
- **mahex shows non-IR IP**: same root cause as samandehi 403

## Note on DNS from the gateway machine itself

When testing on the bypath server directly (not via SOCKS5), the system's resolv.conf may still
point to an ISP DNS server that hijacks foreign domains. Use `-x socks5h://127.0.0.1:2801` to
resolve DNS through the proxy, or ensure resolv.conf points to `127.0.0.1` with an immutable flag:

```bash
chattr -i /etc/resolv.conf
echo "nameserver 127.0.0.1" > /etc/resolv.conf
chattr +i /etc/resolv.conf
```
