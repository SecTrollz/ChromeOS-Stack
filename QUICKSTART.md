# SOVEREIGNTY GATEWAY - COMPLETE QUICK START GUIDE
## ChromeOS Linux Edition â€¢ Full Network Sovereignty

---

## ðŸ“‹ PRE-REQUIREMENTS

### Hardware
- **Chromebook** with Linux (Crostini) enabled
- **USB Ethernet adapter** (required for LAN bridging)
- Stable power supply

### Software
```bash
# Ensure you have Linux enabled:
# Settings â†’ Advanced â†’ Developers â†’ Linux (Beta)
# Then open Terminal
```

---

## ðŸš€ INSTALLATION (1 COMMAND)

### Step 1: Download the deployment script
```bash
# In ChromeOS Linux terminal:
cd ~
curl -fsSL https://github.com/your-repo/sovereignty-gateway/raw/main/sovereignty-complete.sh -o sovereignty-complete.sh
chmod +x sovereignty-complete.sh
```

Or copy the full script from this file:
```bash
sudo bash sovereignty-complete.sh
```

### Step 2: Wait for completion (5-10 minutes)
The script will:
- Install all dependencies (unbound, dnsmasq, squid, nginx, python3)
- Configure bridge network (br0)
- Set up DNSSEC DNS with Unbound
- Configure DHCP with WPAD discovery
- Install Squid proxy server
- Generate PAC (proxy auto-configuration) file
- Set up nginx for service discovery
- Create Python dashboard daemon
- Configure firewall & NAT
- Start all services

### Step 3: Verify installation
```bash
sovereignty-status
```

You should see:
```
âœ“ Unbound (DNS)
âœ“ dnsmasq (DHCP)
âœ“ Squid (Proxy)
âœ“ Nginx (PAC/Web)
âœ“ Dashboard
```

---

## ðŸ”Œ NETWORK SETUP

### Connect USB Ethernet Adapter
1. Plug USB Ethernet adapter into Chromebook
2. In Linux terminal, check interface name:
```bash
ip link
# Look for ethX (e.g., eth1, eth2)
```

3. If interface is different from eth1, redeploy:
```bash
LAN_IF=eth2 WAN_IF=eth0 sudo bash sovereignty-complete.sh
```

---

## ðŸ“± CONFIGURE CLIENTS

### iOS/iPadOS
1. **Settings** â†’ **Wi-Fi**
2. Select your network â†’ **More Settings** (i)
3. **Configure Proxy** â†’ **Automatic**
4. URL: `http://sovereignty-router.local/proxy.pac`
5. Also set **DNS**: `192.168.100.1` (if available)

### Android/ChromeOS
1. **Settings** â†’ **Network** â†’ **Wi-Fi**
2. Long-press network â†’ **Modify**
3. **Advanced options**
4. **Proxy**: Automatic PAC
5. **PAC URL**: `http://sovereignty-router.local/proxy.pac`
6. **DNS 1**: `192.168.100.1`

### macOS
1. **System Preferences** â†’ **Network**
2. Click **Advanced** (Wi-Fi selected)
3. **Proxies** tab
4. â˜‘ **Automatic Proxy Configuration**
5. URL: `http://sovereignty-router.local/proxy.pac`

### Windows 10/11
```powershell
# Run PowerShell as Administrator:
netsh winhttp set proxy proxy-server="http://192.168.100.1:3128" bypass-list="*.local;localhost;127.*"

# Or GUI:
# Settings â†’ Network & Internet â†’ Proxy
# Automatic proxy setup â†’ Use a proxy script
# Script address: http://sovereignty-router.local/proxy.pac
```

### Linux
```bash
export http_proxy=http://192.168.100.1:3128
export https_proxy=http://192.168.100.1:3129
export no_proxy="localhost,127.0.0.1,.local"

# Or in ~/.bashrc for persistence
echo 'export http_proxy=http://192.168.100.1:3128' >> ~/.bashrc
```

---

## ðŸ“Š ACCESSING THE DASHBOARD

### Open Dashboard
```
http://192.168.100.1:8080
```
or
```
http://sovereignty-router.local:8080
```

### What You See
- **Real-time device connections** (name, IP, MAC)
- **DNS query count** (DNSSEC validated)
- **Proxy request stats** (HTTP/HTTPS)
- **Blocked threats** (malicious domains, suspicious traffic)
- **System uptime** and last update timestamp
- **Configuration management** (view/edit service configs)

### Dashboard Features
- Auto-updates every 5 seconds
- Live device list with connection status
- Historical metrics stored in SQLite
- Config editor with JSON support
- Service health indicators

---

## ðŸ”§ COMMON COMMANDS

### Status Check
```bash
sovereignty-status
```

### View Logs
```bash
# Dashboard logs
sudo journalctl -fu sovereignty-gateway

# All services
sudo journalctl -fu unbound
sudo journalctl -fu dnsmasq
sudo journalctl -fu squid
sudo journalctl -fu nginx

# Or tail log files directly
sudo tail -f /var/log/unbound/unbound.log
sudo tail -f /var/log/dnsmasq.log
sudo tail -f /var/log/squid/access.log
sudo tail -f /var/log/sovereignty/gateway.log
```

### Restart Services
```bash
# Restart everything
sovereignty-restart

# Restart individual services
sudo systemctl restart unbound
sudo systemctl restart dnsmasq
sudo systemctl restart squid
sudo systemctl restart nginx
sudo systemctl restart sovereignty-gateway
```

### Run Diagnostics
```bash
sovereignty-diag
```

### Test DNS
```bash
# Test DNS from gateway
dig @192.168.100.1 google.com

# Test DNS from client (on same network)
nslookup google.com 192.168.100.1

# Test DNSSEC validation
dig @192.168.100.1 google.com +dnssec
```

### Test Proxy
```bash
# From Chromebook
curl --proxy http://192.168.100.1:3128 http://example.com

# Get proxy.pac file
curl http://sovereignty-router.local/proxy.pac
```

### View Connected Devices
```bash
# DHCP leases
cat /var/lib/misc/dnsmasq.leases

# Active connections
arp -a

# Or check dashboard at http://192.168.100.1:8080
```

---

## ðŸ” SECURITY FEATURES

### What's Enabled
- âœ“ **DNSSEC Validation** - Unbound validates all DNS responses against root keys
- âœ“ **Transparent Logging** - All queries/connections logged (no secret blocking)
- âœ“ **Firewall & NAT** - LAN isolated from upstream, stateful filtering
- âœ“ **Local-only Domain** - .local domain scoped to your network
- âœ“ **mDNS/Bonjour** - Service discovery for local devices
- âœ“ **IPv6 Ready** - Full IPv6 support
- âœ“ **Rate Limiting** - DNS query rate limits per client
- âœ“ **TLS Upstream** - Upstream DNS over TLS (Quad9)

### What's NOT Enabled (By Design)
- âœ— **No SSL/TLS Interception** - We don't MITM client HTTPS (transparency principle)
- âœ— **No Paranoia Blocking** - No predefined block lists (you control blocking)
- âœ— **No Phone-home** - Everything is local, no cloud dependencies
- âœ— **No Mandatory Auth** - Local network is trusted by default

### You Have Full Control Over:
1. **DNS**: Edit `/etc/unbound/unbound.conf` to block specific domains
2. **Proxy**: Edit `/etc/squid/squid.conf` for filtering rules
3. **DHCP**: Edit `/etc/dnsmasq.conf` for device management
4. **Firewall**: Edit iptables rules (netfilter-persistent)

---

## ðŸ“ TROUBLESHOOTING

### Dashboard not loading
```bash
# Check if service is running
sudo systemctl status sovereignty-gateway

# Restart it
sudo systemctl restart sovereignty-gateway

# Check if port 8080 is listening
sudo netstat -tlnp | grep 8080
```

### DNS not resolving
```bash
# Test unbound directly
dig @127.0.0.1 google.com

# Check dnsmasq forwarding
dig @192.168.100.1 google.com

# Restart DNS stack
sudo systemctl restart unbound
sudo systemctl restart dnsmasq

# Check logs
sudo tail -f /var/log/unbound/unbound.log
```

### DHCP not assigning IPs
```bash
# Check dnsmasq status
sudo systemctl status dnsmasq

# Verify bridge interface
ip link show br0

# Check DHCP log
sudo tail -f /var/log/dnsmasq.log

# Manually restart
sudo systemctl restart dnsmasq
```

### Proxy not working
```bash
# Test Squid connectivity
curl --proxy http://192.168.100.1:3128 http://httpbin.org/ip

# Check Squid status
sudo systemctl status squid

# Verify Squid is listening
sudo netstat -tlnp | grep squid

# Check access log
sudo tail -f /var/log/squid/access.log
```

### PAC file not found
```bash
# Check if nginx is running
sudo systemctl status nginx

# Verify PAC file exists
ls -la /var/www/html/proxy.pac

# Test PAC fetch
curl http://sovereignty-router.local/proxy.pac

# Nginx config test
sudo nginx -t
```

### Bridge interface issues
```bash
# Check current bridge
ip link show br0

# Verify LAN interface is in bridge
ip link show | grep -A1 "MASTER"

# Manual bridge recreation
sudo ip link del br0
sudo ip link add name br0 type bridge
sudo ip addr add 192.168.100.1/24 dev br0
sudo ip link set eth1 master br0
sudo ip link set br0 up
sudo ip link set eth1 up
```

### Performance issues
```bash
# Check system resources
free -h
df -h
top -b -n 1 | head -20

# Check network bridge stats
ip -s link show br0

# Reduce Squid cache if low on space
# Edit /etc/squid/squid.conf, change:
# cache_dir aufs /var/cache/squid 2000 16 256
# Then: sudo systemctl restart squid
```

---

## ðŸ”„ UPDATING/REDEPLOYING

### Update the gateway
```bash
# Backup current config (optional)
sudo tar -czf /opt/sovereignty/backup-$(date +%s).tar.gz /etc/sovereignty

# Pull latest script
curl -fsSL https://github.com/your-repo/sovereignty-gateway/raw/main/sovereignty-complete.sh -o sovereignty-complete.sh

# Redeploy (preserves configs)
sudo bash sovereignty-complete.sh
```

### Reset to defaults
```bash
# This will reinstall everything from scratch
sudo rm -rf /etc/sovereignty /var/lib/sovereignty
sudo bash sovereignty-complete.sh
```

---

## ðŸ“š CONFIGURATION FILES

### Key Files & Locations

| File | Purpose | Edit For |
|------|---------|----------|
| `/etc/unbound/unbound.conf` | DNSSEC DNS config | DNS rules, caching, upstream servers |
| `/etc/dnsmasq.conf` | DHCP server config | DHCP range, domain, WPAD |
| `/etc/squid/squid.conf` | Proxy server config | Filtering, caching, ACLs |
| `/etc/nginx/sites-available/sovereignty` | Web server config | PAC hosting, service endpoints |
| `/var/www/html/proxy.pac` | Auto-proxy config | Client proxy routing logic |
| `/etc/sovereignty/` | Saved configs | Persistent JSON configs |
| `/var/log/unbound/unbound.log` | DNS queries log | Debug DNS issues |
| `/var/log/dnsmasq.log` | DHCP/forwarding log | Debug DHCP/network |
| `/var/log/squid/access.log` | Proxy access log | Monitor proxy usage |
| `/var/log/sovereignty/gateway.log` | Dashboard log | Debug dashboard/metrics |

### Editing Configs

```bash
# Edit unbound DNS
sudo nano /etc/unbound/unbound.conf
sudo systemctl restart unbound

# Edit dnsmasq DHCP
sudo nano /etc/dnsmasq.conf
sudo systemctl restart dnsmasq

# Edit squid proxy
sudo nano /etc/squid/squid.conf
sudo systemctl restart squid

# Edit PAC file
sudo nano /var/www/html/proxy.pac
# (no restart needed - served as static file)
```

---

## ðŸŽ¯ ADVANCED TOPICS

### Block Malicious Domains in DNS
Edit `/etc/unbound/unbound.conf`:
```yaml
# Add in server: section
local-zone: "badexample.com" static
local-data: "badexample.com A 0.0.0.0"
```

Then restart:
```bash
sudo systemctl restart unbound
```

### Custom Proxy Rules
Edit `/etc/squid/squid.conf`:
```bash
acl blocksite dstdomain .facebook.com .twitter.com
http_access deny blocksite
```

Then reload:
```bash
sudo squid -k reconfigure
```

### Change DHCP Range
Edit `/etc/dnsmasq.conf`:
```bash
# Change from default 192.168.100.100-250 to custom range:
dhcp-range=192.168.100.50,192.168.100.200,255.255.255.0,24h
```

Then restart:
```bash
sudo systemctl restart dnsmasq
```

### Enable SSL Interception (Advanced)
âš ï¸ **This requires pushing a root CA to all clients!**

In `/etc/squid/squid.conf`, uncomment:
```bash
https_port 3129 cert=/etc/squid/ssl/cert.pem key=/etc/squid/ssl/key.pem ssl-bump

ssl_bump peek all
ssl_bump bump all
ssl_bump splice all
```

Then install the CA cert on all devices from `/etc/squid/ssl/cert.pem`.

---

## ðŸ“ž SUPPORT & DEBUGGING

### Gather diagnostic info
```bash
sovereignty-diag
```

### Full system report
```bash
echo "=== Kernel ===" && uname -a
echo "=== Memory ===" && free -h
echo "=== Disk ===" && df -h
echo "=== Network ===" && ip a
echo "=== Bridge ===" && ip link show br0
echo "=== Services ===" && systemctl status sovereignty-gateway unbound dnsmasq squid nginx | grep -E "^â—|Active:"
echo "=== DNS ===" && dig @192.168.100.1 google.com +short
echo "=== Proxy ===" && curl --proxy http://192.168.100.1:3128 -I http://example.com 2>&1 | head -3
```

### Real-time monitoring
```bash
# Watch all service logs
sudo journalctl -fu sovereignty-gateway &
sudo journalctl -fu unbound &
sudo journalctl -fu dnsmasq &
sudo journalctl -fu squid &

# In another terminal, run test traffic:
dig google.com
curl --proxy http://192.168.100.1:3128 http://example.com
```

---

## ðŸŽ“ LEARNING MORE

### Unbound Documentation
```bash
man unbound.conf
unbound-control -h
```

### Dnsmasq Manual
```bash
man dnsmasq
```

### Squid Configuration
- `/etc/squid/squid.conf.documented` (built-in reference)
- `https://wiki.squid-cache.org/`

### Firewall Rules
```bash
# View current iptables
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# View saved rules
sudo cat /etc/iptables/rules.v4
```

---

## ðŸ“„ LICENSE & WARRANTY

This is provided as-is for educational and personal network control purposes. Use at your own risk.

---

## ðŸš€ YOU NOW HAVE COMPLETE NETWORK SOVEREIGNTY!

**Next Steps:**
1. âœ“ Run `sovereignty-status` to confirm everything is working
2. âœ“ Connect a device and check dashboard at `http://192.168.100.1:8080`
3. âœ“ Test DNS: `dig @192.168.100.1 google.com`
4. âœ“ Test proxy: `curl --proxy http://192.168.100.1:3128 http://example.com`
5. âœ“ Configure client devices using PAC URL: `http://sovereignty-router.local/proxy.pac`

**You are now in complete control of your network.**

