# Bypath — Deployment Guide

## چیه؟

Bypath یه gateway هست که روی یه SBC (مثل Orange Pi, Raspberry Pi) یا هر لینوکس اجرا می‌شه. کلاینت‌ها DNS و Gateway خودشون رو به IP این دستگاه تنظیم می‌کنن و ترافیکشون از tunnel رد می‌شه. IP‌های ایران (یا هر کشور دیگه) مستقیم می‌رن.

---

## نسخه‌ها

| | Lite | Full |
|---|---|---|
| سایز باینری | ~12 MB | ~50 MB |
| Engine ها | خارجی (sing-box/xray باید نصب باشه) | Embedded (داخل باینری) |
| نیازمندی‌ها | بیشتر | کمتر |
| ساخت | `make lite` یا `GOARM=7 go build` | `make full` (با `-tags full`) |

---

## نیازمندی‌ها

### هر دو نسخه

| چی | چرا |
|---|---|
| Linux (arm/arm64/amd64) | سیستم‌عامل |
| Root access | برای iptables, tun, routing |
| `iptables` | NAT و forwarding |
| `iproute2` (`ip` command) | routing tables, tun device |
| `tun2socks` | تبدیل TUN → SOCKS5 |
| `curl` | برای bench و health check |

### فقط Lite

| چی | چرا |
|---|---|
| `sing-box` (≥1.10) | tunnel engine اصلی |
| `dns2socks` (اختیاری) | DNS از طریق tunnel |

### اختیاری

| چی | چرا |
|---|---|
| `xray` | engine جایگزین |
| `dnsmasq` | fallback DNS (بدون tunnel) |

---

## نصب سریع (Lite روی Armbian/Debian)

```bash
# 1. نصب dependencies
apt update
apt install -y iptables iproute2 curl

# 2. نصب sing-box
bash -c "$(curl -fsSL https://sing-box.app/deb-install.sh)"
# یا دستی:
# wget https://github.com/SagerNet/sing-box/releases/latest/download/sing-box_*_linux_armv7.deb
# dpkg -i sing-box_*.deb

# 3. نصب tun2socks
wget https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-armv7 -O /usr/local/bin/tun2socks
chmod +x /usr/local/bin/tun2socks

# 4. نصب dns2socks (اختیاری — برای DNS امن از tunnel)
apt install -y dns2socks
# یا از source:
# git clone https://github.com/nicedoc/dns2socks && cd dns2socks && make && cp dns2socks /usr/local/bin/

# 5. دانلود geoip database (برای whitelist ایران)
mkdir -p /usr/share/sing-box
wget -O /usr/share/sing-box/geoip.db https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db

# 6. دانلود bypath
mkdir -p /opt/bypath
wget https://github.com/liberoute/bypath/releases/latest/download/bypath-lite-linux-armv7 -O /opt/bypath/bypath
chmod +x /opt/bypath/bypath

# 7. ساخت دایرکتوری‌ها
mkdir -p /opt/bypath/{configs,data/profiles,data/tmp,engines}

# 8. کپی config
cat > /opt/bypath/configs/default.yaml << 'EOF'
server:
  api_port: 8080
  dns_port: 53

gateway:
  enabled: true
  interface: ""

whitelist:
  countries: ["ir"]
  update_interval: "24h"

isolation:
  enabled: false
EOF

# 9. اضافه کردن subscription
cd /opt/bypath
./bypath sub add "YOUR_SUBSCRIPTION_URL"
./bypath sub update

# 10. تست سرعت و انتخاب بهترین
./bypath bench --auto

# 11. اجرا!
./bypath run
```

---

## استفاده

### TUI (منوی تعاملی)

```bash
cd /opt/bypath && ./bypath
```

منو:
- 📡 Add subscription
- 🔄 Update subscriptions
- ✅ Select server
- 🏁 Speed test
- 🚀 Start gateway
- 🛑 Stop gateway
- 📊 Status

### CLI

```bash
# اضافه کردن subscription
bypath sub add "https://..."
bypath sub update

# لیست سرورها
bypath list

# تست سرعت (parallel)
bypath bench --auto

# انتخاب دستی
bypath select 3

# شروع gateway
bypath run

# توقف
bypath stop

# اضافه کردن لینک تکی
bypath add "vmess://..."
bypath add "vless://..."
bypath add "ss://..."
```

---

## تنظیم کلاینت‌ها

بعد از `bypath run`، روی هر دستگاه تو شبکه:

| تنظیم | مقدار |
|---|---|
| Gateway | IP دستگاه Bypath (مثلاً `172.16.11.15`) |
| DNS | IP دستگاه Bypath (مثلاً `172.16.11.15`) |

### یا از طریق DHCP روتر:

اگه روتر اجازه می‌ده، DNS و Gateway پیش‌فرض DHCP رو به IP دستگاه Bypath تغییر بده. اینطوری همه دستگاه‌ها خودکار از tunnel استفاده می‌کنن.

---

## اجرا به صورت سرویس

```bash
cat > /etc/systemd/system/bypath.service << 'EOF'
[Unit]
Description=Bypath Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/bypath
ExecStart=/opt/bypath/bypath run
ExecStop=/opt/bypath/bypath stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable bypath
systemctl start bypath
```

---

## Whitelist (ایران direct)

Bypath از sing-box geoip rule_set استفاده می‌کنه. ترافیک به IP‌های ایران مستقیم می‌ره (بدون tunnel). این تو config تنظیم می‌شه:

```yaml
whitelist:
  countries: ["ir"]
```

sing-box خودش `geoip-ir.srs` رو از GitHub دانلود و cache می‌کنه. نیازی به ipset یا iptables match-set نیست.

---

## عیب‌یابی

```bash
# لاگ gateway
tail -f /opt/bypath/bypath.log

# چک کردن وضعیت
bypath version

# تست دستی tunnel
curl -x socks5h://127.0.0.1:2801 http://ip-api.com/json

# تست whitelist (باید مستقیم بره)
curl -x socks5h://127.0.0.1:2801 http://185.188.104.10 -H "Host: digikala.com"

# چک iptables
iptables -t mangle -L PREROUTING -n
iptables -t nat -L POSTROUTING -n
ip rule show
```

---

## Docker

```bash
cd /opt/bypath
docker-compose up -d
```

`docker-compose.yml`:
```yaml
services:
  bypath:
    build: .
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - ./configs:/app/configs
      - ./data:/app/data
    restart: unless-stopped
```

---

## Build from Source

```bash
git clone https://github.com/liberoute/bypath.git
cd bypath/v2

# Lite (برای ARM مثل Orange Pi)
GOOS=linux GOARCH=arm GOARM=7 go build -o bypath ./cmd/bypath/

# Lite (برای ARM64 مثل RPi 4)
GOOS=linux GOARCH=arm64 go build -o bypath ./cmd/bypath/

# Lite (برای x86_64)
GOOS=linux GOARCH=amd64 go build -o bypath ./cmd/bypath/

# Full (embedded engines)
go build -tags full -o bypath-full ./cmd/bypath/
```
