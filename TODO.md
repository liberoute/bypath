# Bypath — TODO

## 🔴 Priority

- [ ] **sing-box TUN inbound** — حذف tun2socks و dns2socks. sing-box خودش TUN device بسازه + DNS handle کنه. نتیجه: یه process کمتر، latency کمتر.
- [ ] **xray fallback** — اگه sing-box با یه config fail شد، خودکار xray + tun2socks رو امتحان کنه.
- [ ] **Full build (zero deps)** — sing-box + xray + tun2socks embed شده داخل باینری. user فقط یه فایل دانلود می‌کنه.
- [ ] **Reality support** — pbk, sid, fingerprint رو از profile بخون و تو sing-box config بذار. الان reality links fail می‌شن.
- [ ] **TUI bench: download/upload** — بعد ping و relay، تست سرعت واقعی (download KB/s).
- [ ] **VPN detection bypass** — اپ‌های ایرانسل/همراه‌اول `cloudflare.com/cdn-cgi/trace` رو call می‌کنن و از `loc` فیلد می‌فهمن VPN فعاله. باید این endpoint (و مشابهش) رو force direct کنیم تا همیشه `loc=IR` برگردونه. domain‌های شناخته‌شده: `cloudflare.com/cdn-cgi/trace`, `ip-api.com`, `ipinfo.io`, `api.myip.com`.

## 🟡 Medium

- [ ] **Auto-reconnect** — اگه tunnel قطع شد، خودکار reconnect. اگه 3 بار fail شد، switch به لینک بعدی.
- [ ] **Health check timer** — هر 60 ثانیه connectivity check. اگه fail → restart engine.
- [ ] **systemd installer** — `bypath install` که service file بسازه و enable کنه.
- [ ] **Subscription auto-update** — هر 24h خودکار sub update بزنه (timer یا goroutine).
- [ ] **DHCP server** — کلاینت‌ها خودکار DNS/GW بگیرن. دیگه نیاز به تنظیم دستی نباشه.
- [ ] **Bench: skip info links** — لینک‌هایی که port 0 دارن یا address فارسی دارن رو skip کنه (الان skip می‌کنه ولی بهتر بشه).

## 🟢 Nice to have

- [ ] **Web UI** — یه dashboard ساده embed شده (static files). status, switch link, bench از browser.
- [ ] **Metrics (Prometheus)** — endpoint `/metrics` برای monitoring.
- [ ] **Windows gateway** — WinDivert برای routing بدون TUN.
- [ ] **mTLS for API** — API فقط با certificate قابل دسترسی باشه.
- [ ] **Multi-hop chain** — hop1 (vmess) → hop2 (wireguard) → internet.
- [ ] **sing-box as Go library** — بجای spawn process، in-process اجرا بشه (full build).
- [ ] **xray as Go library** — همون بالا برای xray.
- [ ] **Config hot-reload** — بدون restart، config عوض بشه.
- [ ] **Per-client routing** — هر کلاینت (MAC/IP) rule جدا داشته باشه.
- [ ] **Bandwidth limiter** — محدودیت سرعت per-client.

## ✅ Done

- [x] Whitelist IR از iptables/ipset به sing-box geoip rule_set منتقل شد
- [x] TUI menu (bubbletea) — start/stop/status/sub بدون flash
- [x] TUI bench page — live progress, ping/relay, sort, select
- [x] Parallel bench — همه لینک‌ها همزمان تست می‌شن
- [x] vless/reality/comma-SNI fix در config generation
- [x] Column alignment با runewidth
- [x] Subscription support (add/update/list)
- [x] Auto-fallback — اگه لینک اول fail شد، بقیه رو امتحان کنه
- [x] CLI commands: run, stop, add, list, select, bench, sub, test, engines, update
