# Tại Sao Ports Vẫn Hiện "Filtered" - Phân Tích Chi Tiết

## 🔍 Vấn Đề

Mặc dù:
- ✅ Honeypot đang chạy
- ✅ Port 9999 đang listening
- ✅ XDP đã attach (xdpgeneric mode)
- ✅ Local connection hoạt động

Nhưng khi quét từ external machine, ports vẫn hiện **"filtered"**.

## 🔎 Nguyên Nhân Có Thể

### 1. TCP Three-Way Handshake

**Vấn đề quan trọng:** Để port hiện "open", cần hoàn thành TCP handshake:

```
Client (nmap)                Server (honeypot)
    |                            |
    |-------- SYN --------------->|
    |                            | XDP redirect: 80 → 9999
    |                            | Kernel forward SYN to listener
    |                            | Listener Accept() → Kernel sends SYN-ACK
    |<------- SYN-ACK -----------|
    |                            |
    |-------- ACK -------------->|
    |                            | Connection established
```

**Nếu SYN-ACK không được gửi:**
- Port sẽ hiện "filtered" (timeout)
- Hoặc "closed" (RST response)

### 2. XDP Redirect Có Thể Không Hoạt Động Đúng

**Vấn đề:** Khi redirect port trong XDP:
- Phải update checksum ĐÚNG
- Phải return XDP_PASS (không phải XDP_REDIRECT)
- Kernel phải forward packet đến listener

**Kiểm tra:**
```c
// Redirect logic
update_csum16(&tcp->check, old_port, new_port);
tcp->dest = new_port;
return XDP_PASS; // ← Đúng
```

### 3. Checksum Update Có Thể Sai

**Vấn đề:** Nếu checksum không đúng:
- Kernel sẽ drop packet
- Hoặc gửi RST thay vì forward

**Kiểm tra `update_csum16()`:**
```c
static __always_inline void update_csum16(__u16 *csum, __be16 old_val, __be16 new_val) {
    __u32 sum = (~(*csum) & 0xffff);
    __u16 old = bpf_ntohs(old_val);
    __u16 new = bpf_ntohs(new_val);
    sum += (~old & 0xffff);
    sum += (new & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    *csum = ~((sum & 0xffff) + (sum >> 16));
}
```

### 4. Honeypot Không Accept Connection

**Vấn đề:** Nếu honeypot không accept được:
- Kernel sẽ gửi RST
- Port hiện "closed"

**Kiểm tra logs:**
- Có thấy "[DEBUG] Honeypot accepted connection" không?
- Có thấy "[TRAP HIT]" không?

### 5. XDP Generic Mode Có Thể Có Vấn Đề

**Vấn đề:** Generic mode có thể không xử lý redirect đúng cách.

**Giải pháp:** Thử Native mode (nếu driver hỗ trợ):
```go
// Thử không dùng Generic mode
l, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.PhantomProg,
    Interface: iface.Index,
    // Không có Flags → Native mode
})
```

## ✅ Giải Pháp

### Solution 1: Kiểm Tra Packets Có Đến Honeypot Không

```bash
# Capture packets đến port 9999
sudo tcpdump -i ens33 -n 'tcp port 9999' -v

# Từ máy khác, quét
nmap -p 80 <SERVER_IP>

# Xem tcpdump output:
# - Có thấy SYN packets không?
# - Có thấy SYN-ACK response không?
```

### Solution 2: Kiểm Tra Honeypot Logs

Trong dashboard, check:
- Có thấy "[TRAP HIT]" khi quét không?
- Có thấy "[DEBUG] Honeypot accepted connection" không?

**Nếu không thấy:**
- Packets không đến honeypot
- XDP có thể đang drop packets

### Solution 3: Test Direct Connection

```bash
# Từ máy khác
nc <SERVER_IP> 9999
# Expected: Honeypot banner

# Nếu không connect được:
# - XDP đang drop
# - Firewall chặn
# - Honeypot không listening
```

### Solution 4: Kiểm Tra Checksum

Có thể cần verify checksum calculation. Thử disable checksum update tạm thời để test:

```c
// Tạm thời comment checksum update để test
// update_csum16(&tcp->check, old_port, new_port);
tcp->dest = new_port;
```

**Lưu ý:** Chỉ để test, không dùng production!

### Solution 5: Thử Không Dùng Generic Mode

```go
// Thử Native mode (nếu driver hỗ trợ)
l, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.PhantomProg,
    Interface: iface.Index,
    // Không có Flags → Native mode
})
```

## 🧪 Debug Steps

### Step 1: Capture Packets

```bash
# Terminal 1: Capture
sudo tcpdump -i ens33 -n 'tcp port 80 or tcp port 9999' -v -X

# Terminal 2: Quét từ máy khác
nmap -p 80 <SERVER_IP>
```

**Expected output:**
- SYN packet đến port 80
- SYN packet đến port 9999 (sau redirect)
- SYN-ACK từ port 9999

### Step 2: Check Honeypot Logs

Trong dashboard, check:
- "[TRAP HIT]" messages
- "[DEBUG] Honeypot accepted connection"

### Step 3: Test Direct Connection

```bash
# Từ máy khác
telnet <SERVER_IP> 9999
# Expected: Honeypot banner
```

### Step 4: Check XDP Statistics

```bash
# Check attack stats (redirected packets)
sudo bpftool map dump name attack_stats
```

## 📊 Expected vs Actual

| Scenario | Expected | Actual (nếu filtered) |
|----------|----------|----------------------|
| **SYN đến port 80** | Redirect → 9999 | Có thể không redirect |
| **SYN đến port 9999** | Forward to honeypot | Có thể không forward |
| **Honeypot Accept()** | Kernel sends SYN-ACK | Có thể không accept |
| **Client nhận SYN-ACK** | Port "open" | Port "filtered" |

## 🎯 Root Cause Analysis

**Nếu packets không đến honeypot:**
- XDP đang drop (check return value)
- Checksum sai → kernel drop
- Generic mode không hoạt động đúng

**Nếu packets đến nhưng không respond:**
- Honeypot không accept
- Connection bị close ngay
- Banner không được gửi

**Nếu SYN-ACK không được gửi:**
- Kernel không forward SYN đến listener
- Listener không accept
- TCP stack issue

## 🔧 Quick Fixes

### Fix 1: Đảm Bảo Return XDP_PASS

```c
// SAU KHI REDIRECT
update_csum16(&tcp->check, old_port, new_port);
tcp->dest = new_port;
mutate_os_personality(ip, tcp);
return XDP_PASS; // ← QUAN TRỌNG
```

### Fix 2: Verify Checksum Function

```c
// Test checksum calculation
// Có thể cần debug bằng cách log checksum values
```

### Fix 3: Test Without Generic Mode

```go
// Thử Native mode
Flags: link.XDPGenericMode, // ← Comment dòng này
```

## 📝 Next Steps

1. **Capture packets** với tcpdump để xem packets có đến không
2. **Check honeypot logs** để xem có accept connections không
3. **Test direct connection** đến port 9999
4. **Verify checksum** calculation
5. **Try different XDP mode** nếu cần

