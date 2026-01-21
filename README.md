# ðŸ›¡ï¸ SOVEREIGNTY GATEWAY
## Complete Network Control for ChromeOS Linux

**See Everything. Control Everything. Trust Nothing by Default.**

A complete, production-ready sovereign network gateway running on ChromeOS Linux with transparent logging, DNSSEC-validated DNS, universal proxy auto-discovery, and real-time monitoring.

---

## ðŸ“‹ What This Is

A **complete network gateway** that runs in your Chromebook's Linux environment, providing:

- **Universal DHCP server** (auto-assigns IPs to all devices on your LAN)
- **DNSSEC-validated DNS** (Quad9 upstream over TLS)
- **Transparent HTTP/HTTPS proxy** (explicit, not MITM by default)
- **Automatic proxy discovery** (WPAD + PAC file)
- **Real-time monitoring dashboard** (Flask web UI)
- **Firewall & NAT** (network isolation with stateful filtering)
- **Service discovery** (mDNS/Bonjour for .local domains)
- **Complete logging** (all traffic visible, no hidden blocking)

All in **one bash script deployment**.

---

## ðŸŽ¯ Core Principle

> **Transparent control, not paranoid opacity. You see everything, control everything, trust nothing by default.**

- âœ… No secret blocking (everything logged)
- âœ… No paranoia theater (you decide policy)
- âœ… No external dependencies (all local)
- âœ… No phone-home (zero cloud connectivity)
- âœ… No trust by default (DNSSEC validation enforced)

---

## âš¡ Quick Start

### Installation (1 Command)

```bash
# In ChromeOS Linux Terminal:
cd ~
curl -fsSL https://github.com/your-repo/sovereignty-gateway/raw/main/sovereignty-complete.sh -o sovereignty-complete.sh
chmod +x sovereignty-complete.sh
sudo bash sovereignty-complete.sh
```

Or copy `sovereignty-complete.sh` and run locally:
```bash
sudo bash sovereignty-complete.sh
```

**Wait 5-10 minutes.** Script will:
- âœ… Detect your network interfaces
- âœ… Install all dependencies
- âœ… Configure bridge network (192.168.100.1)
- âœ… Set up DNSSEC DNS (Unbound)
- âœ… Configure DHCP server (dnsmasq)
- âœ… Install proxy server (Squid)
- âœ… Host PAC/WPAD files (Nginx)
- âœ… Create monitoring dashboard (Flask)
- âœ… Configure firewall & NAT (iptables)
- âœ… Enable all services on boot (systemd)

### Verify Installation

```bash
sovereignty-status
```

You should see all services marked âœ“

### Access Dashboard

```
http://192.168.100.1:8080
```

---

## ðŸ“± Connect Your Devices

### iOS/iPadOS
1. **Settings** â†’ **Wi-Fi** â†’ **(your network)** â†’ **Proxy**
2. Set **DNS**: `192.168.100.1`
3. **Automatic proxy**: `http://sovereignty-router.local/proxy.pac`

### Android/ChromeOS
1. **Settings** â†’ **Network & internet** â†’ **Wi-Fi** â†’ **Advanced**
2. **DNS 1**: `192.168.100.1`
3. **Proxy**: Automatic PAC
4. **PAC URL**: `http://sovereignty-router.local/proxy.pac`

### macOS
1. **System Preferences** â†’ **Network** â†’ **Advanced** â†’ **Proxies**
2. â˜‘ **Automatic Proxy Configuration**
3. URL: `http://sovereignty-router.local/proxy.pac`

### Windows
```powershell
netsh winhttp set proxy proxy-server="http://192.168.100.1:3128" bypass-list="*.local;localhost"
```

### Linux
```bash
export http_proxy=http://192.168.100.1:3128
export https_proxy=http://192.168.100.1:3129
```

---

## ðŸ“¦ Package Contents

```
sovereignty-gateway/
â”œâ”€â”€ sovereignty-complete.sh          â† RUN THIS FIRST
â”œâ”€â”€ README.md                        â† This file
â”œâ”€â”€ QUICKSTART.md                    â† User guide
â”œâ”€â”€ REFERENCE.md                     â† Technical deep-dive
â””â”€â”€ (embedded configs & scripts)     â† All included in main script
```

**That's it. One script, everything else is embedded.**

---

## ðŸš€ What You Get

### Services Running

| Service | Port | Purpose |
|---------|------|---------|
| **Unbound** | 53 | DNS with DNSSEC validation |
| **dnsmasq** | 67-68 | DHCP with WPAD discovery |
| **Squid** | 3128 | HTTP/HTTPS proxy |
| **Nginx** | 80 | PAC/WPAD file hosting |
| **Flask** | 8080 | Real-time monitoring dashboard |
| **Firewall** | -- | Network isolation + NAT |
| **mDNS** | 5353 | .local domain discovery |

### Features

âœ… **Real-time Dashboard** - Live device list, DNS/proxy stats, config editor
âœ… **Auto DHCP** - Devices get 192.168.100.100-250, with auto proxy config
âœ… **Universal Proxy** - PAC file works on iOS, Android, macOS, Windows, Linux
âœ… **DNSSEC Validation** - All DNS signed and verified (Quad9 upstream)
âœ… **Transparent Logging** - All activity visible, no hidden blocking
âœ… **Network Isolation** - LAN bridge with firewall protection
âœ… **Service Discovery** - mDNS/Bonjour for .local domains
âœ… **Zero Dependencies** - Everything runs locally, no cloud
âœ… **Auto-start** - All services restart automatically on reboot

---

## ðŸ› ï¸ Common Commands

```bash
# Check status
sovereignty-status

# Restart services
sovereignty-restart

# Run diagnostics
sovereignty-diag

# Watch logs
sudo journalctl -fu sovereignty-gateway
sudo journalctl -fu unbound
sudo journalctl -fu dnsmasq
sudo journalctl -fu squid

# Test DNS
dig @192.168.100.1 google.com

# Test proxy
curl --proxy http://192.168.100.1:3128 http://example.com

# View connected devices
cat /var/lib/misc/dnsmasq.leases

# Access dashboard
open http://192.168.100.1:8080
```

---

## ðŸ” Security Features

### By Design
- âœ… **DNSSEC Validation** - All DNS responses verified against root keys
- âœ… **DoT Upstream** - DNS over TLS to Quad9 (no snooping)
- âœ… **No SSL Interception** - Transparent principle (no MITM by default)
- âœ… **Stateful Firewall** - Drop by default, whitelist required ports
- âœ… **Network Bridging** - USB NIC for true L2 isolation
- âœ… **Transparent Logging** - Everything in logs, nothing hidden
- âœ… **Rate Limiting** - DNS query limits to prevent DoS
- âœ… **Local-only .local** - Service discovery scoped to your network

### What Gets Logged

| Source | Location | Contains |
|--------|----------|----------|
| DNS | `/var/log/unbound/unbound.log` | Queries, DNSSEC status |
| DHCP | `/var/log/dnsmasq.log` | Leases, forwards |
| Proxy | `/var/log/squid/access.log` | Requests, response codes |
| Dashboard | `/var/log/sovereignty/gateway.log` | Metrics, API calls |

**No blocking without your consent. No policies without your knowledge.**

---

## ðŸŒ Network Architecture

```
Chromebook (Crostini Linux)
    â”‚
    â”œâ”€ eth0 (Wi-Fi upstream to internet)
    â”‚
    â””â”€ eth1 (USB Ethernet to LAN) â†’ br0 (192.168.100.1)
         â”‚
         â”œâ”€ Unbound (53)  - DNSSEC DNS
         â”œâ”€ dnsmasq (67-68) - DHCP
         â”œâ”€ Squid (3128) - Proxy
         â”œâ”€ Nginx (80) - PAC/WPAD
         â”œâ”€ Firewall - NAT + filtering
         â””â”€ Dashboard (8080) - Monitoring

Connected Devices (192.168.100.100-250)
    â”œâ”€ iPhone
    â”œâ”€ iPad
    â”œâ”€ MacBook
    â”œâ”€ Windows PC
    â””â”€ Android Phone
```

All traffic flows through the gateway with complete transparency.

---

## ðŸ“Š Dashboard Overview

Access at `http://192.168.100.1:8080`

**Real-time stats:**
- Connected devices (name, IP, MAC, status)
- DNS query count (DNSSEC validated)
- Proxy request volume
- Blocked threat count
- System uptime

**Controls:**
- View/edit service configurations
- Monitor all activity live
- Auto-refreshes every 5 seconds
- Historical metrics in SQLite

---

## ðŸ”§ Configuration

All configs are embedded in `sovereignty-complete.sh`. After installation, edit directly:

```bash
# DNS (DNSSEC, forwarding, caching)
sudo nano /etc/unbound/unbound.conf

# DHCP (IP range, WPAD, options)
sudo nano /etc/dnsmasq.conf

# Proxy (filtering, caching, ACLs)
sudo nano /etc/squid/squid.conf

# PAC (proxy routing logic)
sudo nano /var/www/html/proxy.pac
```

Then restart:
```bash
sovereignty-restart
```

---

## ðŸš¨ Troubleshooting

### Devices can't get DHCP
```bash
sudo systemctl restart dnsmasq
sudo tail -20 /var/log/dnsmasq.log
```

### DNS not resolving
```bash
dig @192.168.100.1 google.com
sudo systemctl restart unbound
```

### Proxy returns 403
```bash
curl --proxy http://192.168.100.1:3128 http://example.com
sudo tail -20 /var/log/squid/access.log
```

### No internet from clients
```bash
# Check upstream
ping 8.8.8.8

# Check NAT
sudo iptables -t nat -L | grep POSTROUTING

# Check forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1
```

See **QUICKSTART.md** for complete troubleshooting guide.

---

## ðŸ“š Documentation

| File | Purpose |
|------|---------|
| `README.md` | Overview (this file) |
| `QUICKSTART.md` | Step-by-step installation & client setup |
| `REFERENCE.md` | Complete technical reference & advanced config |
| `sovereignty-complete.sh` | Main deployment script (read the code!) |

---

## ðŸŽ“ Learning Resources

### Inside the Package
- **Inline comments** in `sovereignty-complete.sh` explain each step
- **Config files** include detailed comments
- **Helper scripts** are well-documented

### External
- [Unbound Manual](https://unbound.docs.nlnetlabs.nl/)
- [dnsmasq Documentation](http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
- [Squid Wiki](https://wiki.squid-cache.org/)
- [PAC Specification](https://en.wikipedia.org/wiki/Proxy_auto-config)

---

## ðŸ”„ Updates & Maintenance

### Check for Updates
```bash
# Backup current config
sudo tar -czf sovereignty-backup-$(date +%s).tar.gz /etc/sovereignty

# Download latest script
curl -fsSL https://github.com/your-repo/sovereignty-gateway/raw/main/sovereignty-complete.sh -o sovereignty-complete.sh

# Redeploy (preserves configs)
sudo bash sovereignty-complete.sh
```

### Regular Maintenance
```bash
# Monthly: Check disk space
df -h /var/cache/squid /var/spool/squid

# Weekly: Review logs
sudo journalctl -u sovereignty-gateway --since "1 week ago"

# Daily: Monitor dashboard
http://192.168.100.1:8080
```

---

## ðŸ› Issues & Support

### Get Diagnostic Info
```bash
sovereignty-diag
```

This collects:
- Network configuration
- Service status
- System resources
- DNS test
- Proxy test
- Recent logs

### File a Bug Report
Include output from:
```bash
sovereignty-diag > diag.txt
sudo journalctl -u sovereignty-gateway -n 100 >> diag.txt
cat diag.txt
```

---

## âš ï¸ Requirements

### Hardware
- Chromebook with Linux (Crostini) enabled
- USB Ethernet adapter (for LAN)
- 2GB+ RAM recommended
- 5GB+ free storage

### Network
- Stable Wi-Fi connection (WAN upstream)
- Devices must connect to USB Ethernet (LAN)

### Software
- ChromeOS Linux terminal (built-in)
- Bash shell (built-in)
- sudo access (default in Crostini)

---

## ðŸ“ Architecture & Design

### Design Principles

1. **Transparency First** - All activity logged, visible, auditable
2. **Local-only** - Zero external dependencies or cloud connectivity
3. **User Control** - You decide policy, not the system
4. **Explicit Over Implicit** - Default deny, whitelist what you want
5. **Simplicity** - Single-file deployment, standard tools only

### Tech Stack

- **DNS**: Unbound (DNSSEC validator, cache, forwarder)
- **DHCP**: dnsmasq (lightweight, WPAD support)
- **Proxy**: Squid (standard, feature-rich, auditable)
- **Web**: Nginx (fast, minimal, PAC hosting)
- **Dashboard**: Flask (simple, Python, live metrics)
- **Monitoring**: SQLite (local DB, no cloud)
- **Firewall**: iptables (kernel-level, stateful)
- **Service Discovery**: Avahi (mDNS/Bonjour)
- **Process Manager**: systemd (standard, reliable)

### Why These Tools?

- âœ… **Well-established** - Proven, stable, auditable
- âœ… **Open-source** - Source code available for inspection
- âœ… **Standard** - Used in production environments
- âœ… **Lightweight** - Run on modest hardware
- âœ… **Transparent** - No hidden functionality
- âœ… **Local** - No cloud dependencies
- âœ… **Documented** - Extensive documentation available

---

## ðŸŽ¯ Use Cases

### Home Network
Run your own gateway, DNS, DHCP for your household.
```
Chromebook + USB NIC â†’ Home network (iPhone, iPad, Mac, PC, Android)
```

### Development/Testing
Inspect traffic, test DNS resolution, verify proxy behavior.
```
Chromebook + USB NIC â†’ Test devices
```

### Network Education
Learn how DNS, DHCP, proxies, firewalls actually work.
```
Read the code, modify config, observe results
```

### Personal Privacy
Maintain your own DNS (no ISP snooping), log your own traffic.
```
Control what upstream server you use (Quad9, Cloudflare, etc.)
```

---

## âœ… Verification Checklist

After installation, verify everything works:

```bash
# Service status
sovereignty-status

# Ping gateway
ping 192.168.100.1

# Ping by hostname
ping sovereignty-router.local

# Test DNS
dig @192.168.100.1 google.com

# Test proxy
curl --proxy http://192.168.100.1:3128 http://example.com

# Access dashboard
curl http://192.168.100.1:8080 | head -20

# View logs
sudo journalctl -fu sovereignty-gateway
```

All should succeed without errors.

---

## ðŸš€ Next Steps

1. **Read QUICKSTART.md** - Installation and client setup guide
2. **Run deployment script** - `sudo bash sovereignty-complete.sh`
3. **Verify with `sovereignty-status`** - Confirm all services running
4. **Open dashboard** - `http://192.168.100.1:8080`
5. **Connect first device** - Follow client setup in QUICKSTART.md
6. **Test it works** - Ping gateway, resolve DNS, access proxy
7. **Read REFERENCE.md** - Deep-dive into configuration & troubleshooting

---

## ðŸ“„ License

This project is provided as-is for educational and personal use.

---

## ðŸ’¡ Philosophy

**Sovereignty means:**

> You own your network. You see everything that happens on it. You control what happens on it. You trust nothing by default. You verify everything. You decide policy.

This gateway gives you the **tools** to achieve that.

---

## ðŸŽ‰ You Now Have Complete Network Sovereignty!

**What you control:**
- âœ… Which DNS server to use
- âœ… Which domains to block or allow
- âœ… Which traffic to proxy
- âœ… Which devices get IP addresses
- âœ… Which ports are open
- âœ… What to log and keep
- âœ… Who can connect

**What you can see:**
- âœ… Every DNS query
- âœ… Every DHCP lease
- âœ… Every proxy request
- âœ… Every blocked connection
- âœ… Device list & status
- âœ… Network traffic patterns
- âœ… Complete audit trail

**What is transparent:**
- âœ… All source code available
- âœ… All configs editable
- âœ… All logs readable
- âœ… All traffic auditable
- âœ… Zero secret blocking
- âœ… Zero dependencies

---

**Ready to begin? Start with QUICKSTART.md or run the deployment script.**

```bash
sudo bash sovereignty-complete.sh
```

**Welcome to network sovereignty.** ðŸ›¡ï¸
