# Phantom Grid - Quick Start Guide

## 5-Minute Setup

### Step 1: Install Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y clang llvm libbpf-dev golang make git

# Verify installation
clang --version
go version
```

### Step 2: Clone and Build

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
go mod tidy
make build
```

### Step 3: Identify Your Network Interface

```bash
# List all interfaces
ip link show

# Or
ifconfig

# Common interface names:
# - ens33 (VMware)
# - eth0 (Ethernet)
# - wlx00127b2163a6 (WiFi)
```

### Step 4: Run Phantom Grid

```bash
# With auto-detection
sudo ./phantom-grid

# Or specify interface
sudo ./phantom-grid -interface ens33
```

### Step 5: Verify It's Working

Wait for these log messages:
```
[SYSTEM] ✅ Honeypot is now ACCEPTING connections on port 9999
[SYSTEM] ✅ Ready to receive traffic from external hosts
```

### Step 6: Test from Another Machine

```bash
# Test TCP connection
nc <PHANTOM_IP> 9999

# Or scan ports
nmap <PHANTOM_IP>

# You should see many "open" ports (The Mirage effect)
```

## Common Issues

### Issue: "Cannot bind port 9999"
**Solution:**
```bash
# Find process using port 9999
sudo lsof -i :9999

# Kill it
sudo kill -9 <PID>
```

### Issue: "XDP attached to LOOPBACK interface"
**Solution:** Specify external interface:
```bash
sudo ./phantom-grid -interface ens33
```

### Issue: "Permission denied" for TC Egress
**Solution:** This is a warning, not critical. XDP still works. TC Egress DLP is optional.

### Issue: Traffic not captured from external hosts
**Solution:** 
1. Ensure XDP is attached to external interface (not `lo`)
2. Check firewall: `sudo iptables -L -n`
3. Verify interface has IP: `ip addr show <interface>`

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Try the [SPA Demo](README.md#single-packet-authorization-spa---zero-trust-access)
- Explore the [Dashboard](README.md#real-time-forensics-dashboard-tui)

## Support

For issues or questions, check:
- [Troubleshooting Guide](README.md#troubleshooting) (if available)
- GitHub Issues
- Documentation in README.md

