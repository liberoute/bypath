# Bypath — Project Context

> خلاصه‌ای از وضعیت فعلی پروژه، معماری، و نقاط قابل بهبود.

## خلاصه پروژه

Bypath یک network gateway برای لینوکس (ARM/x86) هست که ترافیک LAN رو به صورت transparent از طریق تانل‌های رمزنگاری‌شده route می‌کنه. کلاینت‌ها فقط DNS و Gateway رو به IP دستگاه Bypath تنظیم می‌کنن و تمام.

**زبان:** Go 1.24+  
**لایسنس:** MIT  
**ریپو:** github.com/liberoute/bypath

---

## معماری فعلی

```
LAN clients → iptables (fwmark) → tun0 → tun2socks → SOCKS5:2801 → sing-box → tunnel
                                                                      ↓
                                                              geoip IR → direct
                                                              * → proxy outbound
```

### کامپوننت‌های اصلی

| کامپوننت | مسیر | وظیفه |
|-----------|------|--------|
| Gateway | `internal/gateway/` | ارکستراتور اصلی (start/stop/routing) |
| Config Generator | `internal/tunnel/configgen.go` | تولید کانفیگ sing-box/xray |
| Profile Manager | `internal/profile/` | مدیریت لینک‌ها، گروه‌ها، ساب‌ها |
| Paths | `internal/paths/` | تشخیص installed/local mode و resolve مسیرها |
| TUI | `internal/tui/` | رابط ترمینالی (bubbletea) |
| API | `internal/api/` | REST API روی پورت 8080 |
| Engine Manager | `internal/engine/` | شناسایی/دانلود engine ها |
| DNS Proxy | `internal/dns/` | DNS از طریق SOCKS5 |
| Whitelist | `internal/whitelist/` | مدیریت IP (legacy، الان sing-box انجام میده) |

---

## وابستگی‌های خارجی (Runtime)

| باینری | ضروری | کاربرد |
|--------|--------|--------|
| sing-box ≥1.10 | ✅ | موتور تانل |
| tun2socks | ✅ (gateway mode) | TUN → SOCKS5 |
| dns2socks | توصیه | DNS از طریق تانل |
| iptables + iproute2 | ✅ (gateway mode) | مسیریابی |
| curl | توصیه | bench + health check |

---

## پروتکل‌های پشتیبانی‌شده

VMess, VLESS, Trojan, Shadowsocks, WireGuard, SOCKS5, HTTP Proxy

---

## وضعیت فعلی (v2.4.0-dev)

### ✅ کارهای انجام‌شده
- TUI tab-based (Home/Servers/Subscriptions)
- Speed test موازی (ping + relay + download)
- Whitelist از طریق sing-box geoip rule_set
- Auto-fallback بین لینک‌ها
- Mixed proxy inbound (SOCKS5 + HTTP روی یه port)
- API token auth
- PID file management
- Subscription support کامل
- Engine selection (sing-box vs xray)
- SNI spoofing
- **install.sh** — اسکریپت نصب اتوماتیک با auto-install dependencies
- **Configurable SOCKS port** — از config خونده میشه (default: 2801)
- **Auto-create config** — اگه config نباشه اولین اجرا می‌سازتش
- **Path resolution** — auto-detect installed vs local mode
- **TUI port change** — تغییر port از داخل TUI
- **sing-box 1.11 DNS fix** — فرمت جدید DNS

### 🔴 مشکلات و کمبودهای اصلی

1. **VPN Detection** — اپ‌های اپراتور (ایرانسل، همراه اول) از `cloudflare.com/cdn-cgi/trace` تشخیص VPN میدن
2. **Reality support ناقص** — لینک‌های Reality (pbk, sid, fingerprint) ساپورت نمیشن
3. **CDN VLESS + HTTPS** — لینک‌های CDN فقط HTTP relay می‌کنن، HTTPS نه
4. **digikala timeout** — DNS از طریق تانل resolve میشه و CDN غیر-ایرانی برمیگرده
5. **وابستگی به tun2socks و dns2socks** — sing-box خودش TUN و DNS داره ولی استفاده نمیشه
6. **Auto-reconnect نداره** — اگه تانل قطع بشه باید دستی restart بشه
7. **systemd installer نداره** — نصب دستیه
8. **DHCP server نداره** — کلاینت‌ها باید دستی DNS/GW تنظیم کنن

---

## نقاط ضعف فنی (Code Quality)

### 1. تکرار کد (DRY violation)
- `buildOutbound()` در `main.go` و `singboxOutbounds()` در `configgen.go` تقریباً یکی هستن
- هر دو جا fix کامای SNI تکرار شده
- bench در main.go و bench در tui هر دو sing-box spawn می‌کنن با کد مشابه

### 2. main.go خیلی بزرگه (~1200 خط)
- همه CLI commands، bench logic، outbound builder، و helpers همه توی یه فایل
- باید به پکیج‌های جدا تقسیم بشه (مثلاً `internal/cli/`)

### 3. Error handling ضعیف در بعضی جاها
- `cmdRemove` مستقیم JSON می‌نویسه بجای استفاده از profile manager
- `cmdStop` از `pkill` استفاده می‌کنه بعنوان fallback (fragile)

### 4. تست‌های واحد کم
- فقط `config_test.go`، `parser_test.go`، `profile_test.go`، `configgen_test.go`، `socksproxy_test.go` وجود دارن
- gateway، tui، engine، api هیچ تستی ندارن
- integration test فقط یه Dockerfile هست

### 5. Whitelist package بلااستفاده‌ست
- `internal/whitelist/` وجود داره ولی whitelist واقعی داخل sing-box route rules هست
- این پکیج legacy هست و باید حذف یا refactor بشه

### 6. Windows support ناقص
- `gateway.go` یه بخش Windows detection داره ولی gateway mode روی Windows کار نمی‌کنه
- TUI از `/proc` استفاده می‌کنه که روی Windows نیست

### 7. ~~Hardcoded paths~~ ✅ حل شد
- پکیج `internal/paths` اضافه شد
- Auto-detect installed vs local mode
- همه path ها dynamic هستن

### 8. Concurrency concerns
- `Gateway.mu` فقط Start/Stop رو lock می‌کنه ولی accessor ها (`GetProfileManager` و...) بدون lock هستن
- TUI از goroutine ها بدون proper cancellation استفاده می‌کنه در bench

### 9. Security
- API token در config file plaintext ذخیره میشه
- `RawURI` شامل credentials هست و در JSON ذخیره میشه
- `os.WriteFile` با permission 0644 برای فایل‌هایی که credential دارن

### 10. ~~sing-box version coupling~~ ✅ بخشی حل شد
- DNS format برای sing-box 1.11+ فیکس شد (`address: "udp://1.1.1.1"`)
- هنوز version check وجود نداره

---

## پیشنهادات بهبود (به ترتیب اولویت)

1. ~~**حذف tun2socks/dns2socks**~~ — (در دست بررسی) از sing-box TUN inbound استفاده بشه
2. **Reality support** — خوندن pbk/sid/fp از URI و اضافه کردن به configgen
3. **Refactor main.go** — تقسیم به `internal/cli/` با subcommand ها
4. **حذف duplicate outbound builder** — یه تابع مشترک برای bench و configgen
5. **Auto-reconnect** — health check + auto restart/switch
6. **Domain-based whitelist** — برای digikala و سایت‌های ایرانی که geoip کافی نیست
7. **VPN detection bypass** — force direct برای endpoint های شناسایی IP
8. **افزایش test coverage** — حداقل برای configgen، profile، gateway
9. ~~**systemd installer**~~ ✅ — install.sh انجام میده
10. **DHCP server** — zero-config برای کلاینت‌ها

---

## نحوه Build

```bash
# Lite (ARM)
GOOS=linux GOARCH=arm GOARM=7 go build -o bypath ./cmd/bypath/

# Lite (ARM64)
GOOS=linux GOARCH=arm64 go build -o bypath ./cmd/bypath/

# Lite (x86_64)
GOOS=linux GOARCH=amd64 go build -o bypath ./cmd/bypath/
```

---

## Conventions

- Error wrapping: `fmt.Errorf("context: %w", err)`
- Logging: `log.Printf` با emoji (✅ ⚠️ ❌ 🚀 🔧 🌍)
- Concurrency: `sync.RWMutex` + `context.Context`
- JSON tags روی API/profile structs، YAML tags روی config structs
- Platform-specific: `_linux.go` / `_other.go`
- TUI: bubbletea با tab navigation، `tea.Cmd` برای async
