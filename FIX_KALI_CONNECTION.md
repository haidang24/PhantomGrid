# Fix: Kali Không Connect Được Nhưng Ubuntu Localhost Được

## 🔍 Vấn Đề

- ✅ **Ubuntu localhost**: `nc 192.168.174.163 9999` → **Hoạt động** (honeypot respond)
- ❌ **Kali external**: `nc 192.168.174.163 9999` → **Không hoạt động** (timeout/filtered)

## 🔎 Nguyên Nhân Có Thể

### 1. XDP Generic Mode Không Hỗ Trợ Packet Modification

**Vấn đề:** XDP Generic mode có thể không hỗ trợ modify packet headers (như destination port) đúng cách.

**Giải pháp:** Thử Native mode hoặc SKB mode:

```go
// Option 1: Native mode (nếu driver hỗ trợ)
l, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.PhantomProg,
    Interface: iface.Index,
    // Không có Flags → Native mode
})

// Option 2: SKB mode (fallback)
// XDP Generic mode có thể không modify packets tốt
```

### 2. Checksum Sai Khi Modify Port

**Vấn đề:** Khi modify destination port, checksum có thể không được tính lại đúng.

**Kiểm tra:**

- `update_csum16()` có đúng không?
- Checksum có được update TRƯỚC khi thay đổi port không?

### 3. XDP Chỉ Xử Lý SYN Packets

**Vấn đề:** Logic hiện tại có thể chỉ redirect SYN packets, không redirect các packets khác.

**Kiểm tra:** Logic có xử lý tất cả TCP packets không?

### 4. Firewall Chặn External Traffic

**Vấn đề:** iptables hoặc firewall khác có thể chặn traffic từ external IP.

**Kiểm tra:**

```bash
sudo iptables -L -n -v | grep 9999
```

### 5. Honeypot Chỉ Bind Localhost

**Vấn đề:** Honeypot có thể chỉ bind `127.0.0.1:9999` thay vì `0.0.0.0:9999`.

**Kiểm tra:**

```bash
sudo netstat -tlnp | grep 9999
# Should show: 0.0.0.0:9999 (not 127.0.0.1:9999)
```

## ✅ Giải Pháp

### Solution 1: Kiểm Tra Honeypot Binding

```bash
# Check honeypot bind address
sudo netstat -tlnp | grep 9999

# Expected:
# tcp  0  0  0.0.0.0:9999  0.0.0.0:*  LISTEN  <PID>/phantom-grid

# If shows 127.0.0.1:9999, fix in code:
# net.Listen("tcp", ":9999") → net.Listen("tcp", "0.0.0.0:9999")
```

### Solution 2: Test XDP Mode

```go
// Thử không dùng Generic mode
l, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.PhantomProg,
    Interface: iface.Index,
    // Comment dòng này để thử Native mode
    // Flags:     link.XDPGenericMode,
})
```

**Lưu ý:** Native mode yêu cầu driver hỗ trợ. Nếu không được, phải dùng Generic mode.

### Solution 3: Kiểm Tra Checksum

Có thể cần verify checksum calculation. Thử log checksum values để debug:

```c
// Tạm thời: Không modify port, chỉ PASS
// update_csum16(&tcp->check, old_port, new_port);
// tcp->dest = new_port;
// → Test xem có connect được không
```

### Solution 4: Kiểm Tra Firewall

```bash
# Check iptables
sudo iptables -L INPUT -n -v | grep 9999

# If blocking, allow:
sudo iptables -I INPUT -p tcp --dport 9999 -j ACCEPT
```

### Solution 5: Test Direct Connection

```bash
# Từ Kali
telnet 192.168.174.163 9999
# hoặc
nc -v 192.168.174.163 9999

# Check output:
# - Connection refused → Honeypot không listening
# - Connection timeout → XDP drop hoặc firewall chặn
# - Connected → OK
```

## 🧪 Debug Steps

### Step 1: Capture Packets

```bash
# Trên Ubuntu server
sudo tcpdump -i ens33 -n 'tcp port 9999' -v -X

# Từ Kali, connect
nc 192.168.174.163 9999

# Xem tcpdump:
# - Có thấy SYN packets từ Kali không?
# - Có thấy SYN-ACK response không?
# - Checksum có đúng không?
```

### Step 2: Check XDP Statistics

```bash
# Check attack stats (redirected packets)
sudo bpftool map dump name attack_stats

# Check stealth drops
sudo bpftool map dump name stealth_drops
```

### Step 3: Check Honeypot Logs

Trong dashboard, check:

- Có thấy "[TRAP HIT]" khi connect từ Kali không?
- Có thấy "[DEBUG] Honeypot accepted connection" không?

**Nếu không thấy:**

- Packets không đến honeypot
- XDP có thể đang drop

### Step 4: Test Without Port Modification

Tạm thời comment port redirect để test:

```c
// Comment redirect logic
// update_csum16(&tcp->check, old_port, new_port);
// tcp->dest = new_port;
// → Chỉ PASS packets đến port 9999
```

**Nếu connect được:**

- Vấn đề là port redirect/checksum
- Cần fix checksum hoặc XDP mode

**Nếu vẫn không connect được:**

- Vấn đề là XDP Generic mode hoặc firewall
- Cần thử Native mode hoặc check firewall

## 🎯 Root Cause Analysis

**Nếu packets không đến honeypot:**

- XDP đang drop (check return value)
- Checksum sai → kernel drop
- Generic mode không hoạt động đúng

**Nếu packets đến nhưng không respond:**

- Honeypot không accept từ external IP
- Connection bị close ngay
- Banner không được gửi

**Nếu SYN-ACK không được gửi:**

- Kernel không forward SYN đến listener
- Listener không accept
- TCP stack issue

## 🔧 Quick Fixes

### Fix 1: Đảm Bảo Honeypot Bind 0.0.0.0

```go
// Trong cmd/agent/main.go
ln9999, err := net.Listen("tcp", "0.0.0.0:9999")
// Hoặc
ln9999, err := net.Listen("tcp", ":9999") // Default là 0.0.0.0
```

### Fix 2: Thử Native Mode

```go
// Comment Generic mode
// Flags:     link.XDPGenericMode,
```

### Fix 3: Verify Checksum

```c
// Đảm bảo checksum được update đúng
update_csum16(&tcp->check, old_port, new_port);
tcp->dest = new_port;
```

## 📝 Next Steps

1. **Check honeypot binding**: `netstat -tlnp | grep 9999`
2. **Capture packets**: `tcpdump -i ens33 'tcp port 9999'`
3. **Test without port modification**: Comment redirect logic
4. **Try Native mode**: Remove Generic mode flag
5. **Check firewall**: `iptables -L -n -v`
