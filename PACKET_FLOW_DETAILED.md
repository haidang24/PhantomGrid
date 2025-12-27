# Logic Gửi/Nhận Gói Tin Chi Tiết - Phantom Grid

## 📡 Tổng Quan Packet Flow

```
External Host (Kali/Windows)
    ↓
Network Interface (ens33/wlx*)
    ↓
XDP Hook (bpf/phantom.c) - INGRESS
    ↓
    ├─→ ICMP → PASS (ping responses)
    ├─→ UDP → SPA Logic
    │   ├─→ Port 1337 → Magic Packet Verification
    │   │   ├─→ Valid → Whitelist IP, DROP packet
    │   │   └─→ Invalid → DROP packet, update stats
    │   └─→ Other UDP → PASS (DNS, DHCP, etc.)
    │
    └─→ TCP → Defense & Redirection Logic
        ├─→ Critical Asset Port (22, 3306, etc.)
        │   ├─→ Whitelisted → PASS
        │   └─→ Not Whitelisted → DROP (Dead Host)
        │
        ├─→ Stealth Scan (Xmas, Null, FIN, ACK)
        │   └─→ DROP, update stats
        │
        ├─→ Port 9999 (Honeypot)
        │   └─→ PASS (tất cả packets: SYN, ACK, data, FIN, RST)
        │
        ├─→ Connection Tracked
        │   ├─→ Redirect to 9999 if needed
        │   └─→ PASS
        │
        ├─→ Fake Port (80, 443, etc.) - SYN packet
        │   ├─→ Redirect dest_port: 80 → 9999
        │   ├─→ Track connection: (src_ip, src_port) → original_port
        │   ├─→ Update checksum
        │   └─→ PASS (now dest_port = 9999)
        │
        └─→ Other Ports - SYN packet
            └─→ DROP (ẩn port thật)
```

## 🔍 Chi Tiết Từng Loại Packet

### 1. ICMP Packets (Ping, etc.)

**Flow:**
```
ICMP Packet → XDP Hook
    ↓
Check: ip->protocol == IPPROTO_ICMP
    ↓
return XDP_PASS
```

**Logic:**
- **Mục đích**: Cho phép ping và ICMP traffic để đảm bảo network connectivity
- **Xử lý**: PASS ngay lập tức, không kiểm tra gì thêm
- **Vị trí trong code**: `bpf/phantom.c:273-275`

**Ví dụ:**
```c
if (ip->protocol == IPPROTO_ICMP) {
    return XDP_PASS;  // Cho phép tất cả ICMP
}
```

---

### 2. UDP Packets - SPA Magic Packet

**Flow:**
```
UDP Packet → XDP Hook
    ↓
Check: ip->protocol == IPPROTO_UDP
    ↓
Check: udp->dest == 1337 (SPA_MAGIC_PORT)
    ↓
    ├─→ YES: Verify Magic Packet
    │   ├─→ Valid Token ("PHANTOM_GRID_SPA_2025")
    │   │   ├─→ Whitelist src_ip
    │   │   ├─→ Update success stats
    │   │   └─→ return XDP_DROP (drop Magic Packet)
    │   │
    │   └─→ Invalid Token
    │       ├─→ Update failed stats
    │       └─→ return XDP_DROP
    │
    └─→ NO: return XDP_PASS (DNS, DHCP, etc.)
```

**Logic Chi Tiết:**

#### 2.1. Magic Packet Verification
```c
// 1. Kiểm tra payload length
if ((void *)payload + SPA_TOKEN_LEN > data_end) return 0;

// 2. So sánh từng byte
const char *token = "PHANTOM_GRID_SPA_2025";
for (int i = 0; i < 21; i++) {
    if (payload[i] != token[i]) return 0;
}
return 1;  // Valid
```

#### 2.2. Whitelist IP
```c
// Thêm IP vào LRU hash map
bpf_map_update_elem(&spa_whitelist, &src_ip, &expiry, BPF_ANY);
// Update statistics
__sync_fetch_and_add(spa_auth_success, 1);
```

**Ví dụ thực tế:**
```
Client: echo -n "PHANTOM_GRID_SPA_2025" | nc -u server 1337
    ↓
XDP: Verify token → Valid
    ↓
XDP: Whitelist IP (192.168.1.100)
    ↓
XDP: DROP packet (không forward)
    ↓
Result: IP 192.168.1.100 có thể SSH trong 30 giây (LRU expiry)
```

---

### 3. TCP Packets - Critical Assets Protection

**Flow:**
```
TCP Packet → XDP Hook
    ↓
Check: is_critical_asset_port(tcp->dest)
    ├─→ Port 22 (SSH)
    ├─→ Port 3306 (MySQL)
    ├─→ Port 5432 (PostgreSQL)
    ├─→ Port 27017 (MongoDB)
    ├─→ Port 6379 (Redis)
    ├─→ Port 8080, 8443, 9000 (Admin Panels)
    ↓
    ├─→ YES: Check SPA Whitelist
    │   ├─→ Whitelisted → return XDP_PASS
    │   └─→ Not Whitelisted → return XDP_DROP (Dead Host)
    │
    └─→ NO: Continue to next check
```

**Logic Chi Tiết:**

#### 3.1. Critical Asset Check
```c
static __always_inline int is_critical_asset_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    return (p == 22 || p == 3306 || p == 5432 || ...);
}
```

#### 3.2. SPA Whitelist Check
```c
static __always_inline int is_spa_whitelisted(__be32 src_ip) {
    __u64 *expiry = bpf_map_lookup_elem(&spa_whitelist, &src_ip);
    return (expiry != NULL);  // Exists in map = whitelisted
}
```

**Ví dụ thực tế:**

**Scenario 1: Hacker quét SSH (không có SPA)**
```
Hacker: nmap -p 22 server
    ↓
SYN packet đến port 22
    ↓
XDP: is_critical_asset_port(22) → YES
    ↓
XDP: is_spa_whitelisted(hacker_ip) → NO
    ↓
XDP: return XDP_DROP
    ↓
Result: Không có response, server "chết" từ góc nhìn hacker
```

**Scenario 2: Admin SSH (đã gửi Magic Packet)**
```
Admin: ./spa-client server
    ↓
Magic Packet → Whitelist IP
    ↓
Admin: ssh admin@server
    ↓
SYN packet đến port 22
    ↓
XDP: is_critical_asset_port(22) → YES
    ↓
XDP: is_spa_whitelisted(admin_ip) → YES
    ↓
XDP: return XDP_PASS
    ↓
Result: SSH connection thành công
```

---

### 4. TCP Packets - Stealth Scan Detection

**Flow:**
```
TCP Packet → XDP Hook
    ↓
Check: is_stealth_scan(tcp)
    ↓
    ├─→ Xmas Scan (FIN+URG+PSH, no SYN/RST)
    ├─→ Null Scan (flags = 0)
    ├─→ FIN Scan (FIN only)
    ├─→ ACK Scan (ACK only, no SYN/FIN/RST)
    ↓
    ├─→ YES: Update stats → return XDP_DROP
    └─→ NO: Continue to next check
```

**Logic Chi Tiết:**
```c
static __always_inline int is_stealth_scan(struct tcphdr *tcp) {
    __u8 flags = *((__u8 *)tcp + 13);
    
    // Xmas: FIN + URG + PSH, no SYN/RST
    if ((flags & 0x01) && (flags & 0x20) && (flags & 0x08) && 
        !(flags & 0x02) && !(flags & 0x04)) return 1;
    
    // Null: flags = 0
    if (flags == 0) return 1;
    
    // FIN: FIN only
    if ((flags & 0x01) && !(flags & 0x02) && !(flags & 0x04) && 
        !(flags & 0x08) && !(flags & 0x10) && !(flags & 0x20)) return 1;
    
    // ACK: ACK only, no SYN/FIN/RST
    if ((flags & 0x10) && !(flags & 0x02) && !(flags & 0x01) && !(flags & 0x04)) return 1;
    
    return 0;
}
```

**Ví dụ thực tế:**
```
Hacker: nmap -sX server  (Xmas scan)
    ↓
XDP: is_stealth_scan() → YES (FIN+URG+PSH)
    ↓
XDP: Update stealth_drops stats
    ↓
XDP: return XDP_DROP
    ↓
Result: Scan bị chặn, không có response
```

---

### 5. TCP Packets - Honeypot Port (9999) - QUAN TRỌNG NHẤT

**Flow:**
```
TCP Packet → XDP Hook
    ↓
Check: tcp->dest == 9999 (HONEYPOT_PORT)
    ↓
    ├─→ YES: 
    │   ├─→ If SYN packet → Update attack stats
    │   ├─→ Mutate OS personality (TTL, Window)
    │   └─→ return XDP_PASS (KHÔNG CẦN TRACK)
    │
    └─→ NO: Continue to connection tracking
```

**Logic Chi Tiết:**
```c
// QUAN TRỌNG: Check này PHẢI ở TRƯỚC connection tracking
if (tcp->dest == bpf_htons(HONEYPOT_PORT)) {
    // Update statistics cho SYN packets
    if (syn && !ack) {
        __sync_fetch_and_add(&attack_stats, 1);
    }
    // Mutate OS fingerprint
    mutate_os_personality(ip, tcp);
    return XDP_PASS;  // PASS tất cả: SYN, ACK, data, FIN, RST
}
```

**Tại sao quan trọng:**
- **Tất cả packets đến honeypot PHẢI được PASS** (SYN, ACK, data, FIN, RST)
- **Đặt check này TRƯỚC** connection tracking để đảm bảo packets đến 9999 luôn được PASS
- **Không cần track** vì đây là destination cuối cùng

**Ví dụ thực tế:**
```
Client: nc server 9999
    ↓
SYN packet → dest_port = 9999
    ↓
XDP: Check port 9999 → YES
    ↓
XDP: Update stats, mutate OS personality
    ↓
XDP: return XDP_PASS
    ↓
Kernel: Forward to honeypot listener
    ↓
Honeypot: Accept connection, send banner
```

---

### 6. TCP Packets - Connection Tracking (The Portal)

**Flow:**
```
TCP Packet → XDP Hook
    ↓
Check: Connection already tracked?
    ↓
    ├─→ YES: 
    │   ├─→ Check: dest_port == original_port?
    │   │   ├─→ YES: Redirect to 9999
    │   │   │   ├─→ Update checksum
    │   │   │   └─→ dest_port = 9999
    │   │   └─→ NO: Already redirected (dest_port = 9999)
    │   │
    │   ├─→ Check: FIN or RST from client?
    │   │   └─→ YES: Cleanup tracking map
    │   │
    │   └─→ return XDP_PASS
    │
    └─→ NO: Continue to The Mirage
```

**Logic Chi Tiết:**

#### 6.1. Connection Key
```c
// Key: (src_ip << 32) | (src_port << 16)
// Dùng src_ip:src_port để track, KHÔNG dùng dest_port
// vì dest_port thay đổi sau redirect
__u64 conn_key = ((__u64)src_ip << 32) | ((__u64)bpf_ntohs(tcp->source) << 16);
```

#### 6.2. Lookup Original Port
```c
__be16 *original_port = bpf_map_lookup_elem(&redirect_map, &conn_key);
if (original_port) {
    // Connection đã được redirect
    if (tcp->dest == *original_port && tcp->dest != bpf_htons(HONEYPOT_PORT)) {
        // Redirect packet đến 9999
        update_csum16(&tcp->check, old_port, new_port);
        tcp->dest = bpf_htons(HONEYPOT_PORT);
    }
    // Cleanup on FIN/RST
    if ((fin || rst) && !ack) {
        bpf_map_delete_elem(&redirect_map, &conn_key);
    }
    return XDP_PASS;
}
```

**Ví dụ thực tế - Complete Connection Flow:**

**Step 1: SYN đến fake port 80**
```
Client: nc server 80
    ↓
SYN packet: src_ip=192.168.1.100, src_port=54321, dest_port=80
    ↓
XDP: Check port 9999 → NO
    ↓
XDP: Check connection tracking → NO (new connection)
    ↓
XDP: Check fake port → YES (80 is fake port)
    ↓
XDP: Track connection: (192.168.1.100:54321) → original_port=80
    ↓
XDP: Redirect: dest_port 80 → 9999
    ↓
XDP: Update checksum
    ↓
XDP: return XDP_PASS (now dest_port=9999)
    ↓
Kernel: Forward to honeypot on port 9999
```

**Step 2: SYN-ACK từ server**
```
Server: Send SYN-ACK
    ↓
Packet: src_port=9999, dest_port=54321
    ↓
XDP: This is OUTBOUND (from server)
    ↓
XDP: return XDP_PASS (outbound connections pass)
```

**Step 3: ACK từ client**
```
Client: Send ACK
    ↓
ACK packet: src_ip=192.168.1.100, src_port=54321, dest_port=9999
    ↓
XDP: Check port 9999 → YES
    ↓
XDP: return XDP_PASS (không cần track)
    ↓
Kernel: Forward to honeypot
```

**Step 4: Data từ client**
```
Client: Send data "GET / HTTP/1.1"
    ↓
Data packet: src_ip=192.168.1.100, src_port=54321, dest_port=9999
    ↓
XDP: Check port 9999 → YES
    ↓
XDP: return XDP_PASS
    ↓
Honeypot: Receive data, respond with fake HTTP banner
```

**Step 5: FIN từ client (connection close)**
```
Client: Send FIN
    ↓
FIN packet: src_ip=192.168.1.100, src_port=54321, dest_port=9999
    ↓
XDP: Check port 9999 → YES
    ↓
XDP: return XDP_PASS
    ↓
XDP: Connection tracking cleanup (if needed)
    ↓
Honeypot: Close connection
```

---

### 7. TCP Packets - The Mirage (Fake Ports)

**Flow:**
```
TCP Packet → XDP Hook
    ↓
Check: SYN packet && !ACK && !critical_asset
    ↓
    ├─→ YES: Check fake port
    │   ├─→ YES: Redirect to 9999
    │   │   ├─→ Track connection
    │   │   ├─→ Update checksum
    │   │   └─→ return XDP_PASS
    │   │
    │   └─→ NO: return XDP_DROP (ẩn port thật)
    │
    └─→ NO: Continue (non-SYN packets)
```

**Logic Chi Tiết:**
```c
// CHỈ xử lý SYN packets (inbound connection initiation)
if (syn && !ack && !is_critical_asset_port(tcp->dest)) {
    if (is_fake_port(tcp->dest) && tcp->dest != bpf_htons(HONEYPOT_PORT)) {
        // Track connection
        __be16 orig_port = tcp->dest;
        bpf_map_update_elem(&redirect_map, &conn_key, &orig_port, BPF_ANY);
        
        // Redirect to honeypot
        update_csum16(&tcp->check, old_port, new_port);
        tcp->dest = bpf_htons(HONEYPOT_PORT);
        
        return XDP_PASS;
    }
    // Not fake port → DROP (ẩn port thật)
    return XDP_DROP;
}
```

**Fake Ports List:**
- 80, 443 (HTTP/HTTPS)
- 3306, 5432, 1433, 1521 (Databases - fake)
- 6379, 11211 (Cache - fake)
- 27017, 27018 (MongoDB - fake)
- 8080, 8443, 9000 (Admin Panels - fake)
- 21, 23 (FTP, Telnet - fake)
- 3389, 5900 (RDP, VNC - fake)
- 9200, 5601 (Elasticsearch, Kibana - fake)
- 3000, 5000, 8000, 8888 (Web Apps - fake)

**Ví dụ thực tế:**
```
Hacker: nmap server
    ↓
SYN packets đến các port
    ↓
Port 80 (fake):
    ├─→ XDP: is_fake_port(80) → YES
    ├─→ Redirect: 80 → 9999
    ├─→ Track connection
    └─→ PASS → Honeypot responds → Port appears "OPEN"
    ↓
Port 22 (critical):
    ├─→ XDP: is_critical_asset_port(22) → YES
    ├─→ Check whitelist → NO
    └─→ DROP → Port appears "FILTERED" or "CLOSED"
    ↓
Port 12345 (other):
    ├─→ XDP: is_fake_port(12345) → NO
    ├─→ is_critical_asset_port(12345) → NO
    └─→ DROP → Port appears "FILTERED"
    ↓
Result: Hacker chỉ thấy fake ports "mở", không thấy port thật
```

---

### 8. TCP Packets - Outbound & Established Connections

**Flow:**
```
TCP Packet → XDP Hook
    ↓
Check: All previous conditions
    ↓
    ├─→ Not critical asset
    ├─→ Not stealth scan
    ├─→ Not port 9999
    ├─→ Not tracked connection
    ├─→ Not fake port SYN
    ↓
    └─→ Default: return XDP_PASS
```

**Logic:**
- **Outbound connections**: SYN từ server → PASS
- **Established connections**: ACK, data packets → PASS
- **Non-SYN packets**: Không match các điều kiện trên → PASS

**Ví dụ:**
```
Server: curl https://api.example.com
    ↓
SYN packet từ server (outbound)
    ↓
XDP: Check all conditions → None match
    ↓
XDP: return XDP_PASS
    ↓
Result: Outbound connection hoạt động bình thường
```

---

## 🔄 Complete Packet Flow Example

### Scenario: Hacker quét và tương tác với fake HTTP service

**Step 1: Nmap scan**
```
Hacker: nmap -p 80,443,22,3306 server
    ↓
SYN packets đến:
    - Port 80 (fake) → Redirect to 9999 → Honeypot responds → "OPEN"
    - Port 443 (fake) → Redirect to 9999 → Honeypot responds → "OPEN"
    - Port 22 (critical) → Not whitelisted → DROP → "FILTERED"
    - Port 3306 (critical) → Not whitelisted → DROP → "FILTERED"
    ↓
Result: Hacker thấy ports 80, 443 "mở", ports 22, 3306 "đóng"
```

**Step 2: HTTP request**
```
Hacker: curl http://server:80
    ↓
SYN packet → Port 80
    ↓
XDP: Redirect 80 → 9999, track connection
    ↓
Honeypot: Accept on port 9999, send fake HTTP banner
    ↓
Hacker: Send HTTP request "GET / HTTP/1.1"
    ↓
Data packet → Port 9999
    ↓
XDP: Check port 9999 → PASS
    ↓
Honeypot: Receive request, respond with fake HTML
    ↓
Hacker: Thấy "HTTP service" hoạt động (thực ra là honeypot)
```

**Step 3: Logging**
```
Honeypot: Log attack
    ├─→ IP: 192.168.1.100
    ├─→ Port: 80 (original)
    ├─→ Service: HTTP
    ├─→ Commands: "GET / HTTP/1.1"
    └─→ Timestamp: 2025-12-27T10:00:00Z
    ↓
Dashboard: Update statistics
    ├─→ Honeypot Connections: +1
    ├─→ Active Sessions: +1
    └─→ Threat Level: Increase
```

---

## 📊 Packet Statistics Flow

### XDP Statistics Maps

1. **attack_stats**: Packets redirected to honeypot
   - Updated: When SYN packet redirected to 9999
   - Location: `bpf/phantom.c:405`

2. **stealth_drops**: Stealth scans blocked
   - Updated: When stealth scan detected
   - Location: `bpf/phantom.c:327`

3. **os_mutations**: OS personality mutations
   - Updated: When TTL/Window modified
   - Location: `bpf/phantom.c:152`

4. **spa_auth_success**: Successful SPA authentications
   - Updated: When Magic Packet valid
   - Location: `bpf/phantom.c:234`

5. **spa_auth_failed**: Failed SPA attempts
   - Updated: When Magic Packet invalid
   - Location: `bpf/phantom.c:295`

### Dashboard Updates

```
XDP Statistics → User Space (Go)
    ↓
Dashboard goroutine (2s ticker)
    ↓
Read from BPF maps
    ↓
Update UI widgets
    ├─→ Redirected to Honeypot
    ├─→ Stealth Scan Drops
    ├─→ OS Mutations
    ├─→ SPA Success/Failed
    └─→ Threat Level Gauge
```

---

## 🔄 Egress Flow (TC Egress - DLP)

### Flow Diagram
```
Honeypot Response
    ↓
TCP Packet (source_port = 9999)
    ↓
TC Egress Hook (bpf/phantom_egress.c)
    ↓
Check: source_port == 9999?
    ├─→ NO: return TC_ACT_OK (pass through)
    └─→ YES: Extract payload
        ↓
        Detect Suspicious Patterns
        ├─→ /etc/passwd content
        ├─→ SSH private keys ("-----BEGIN")
        ├─→ Base64 data (>95% match, >64 bytes)
        └─→ SQL injection ("INSERT INTO")
        ↓
        ├─→ Pattern Found:
        │   ├─→ Update egress_blocks stats
        │   ├─→ Update suspicious_patterns stats
        │   └─→ return TC_ACT_OK (Demo Mode - not blocking)
        │
        └─→ No Pattern:
            └─→ return TC_ACT_OK
```

### Logic Chi Tiết

#### 1. Packet Filtering
```c
// Chỉ kiểm tra packets từ honeypot port
if (tcp->source != bpf_htons(HONEYPOT_PORT)) {
    return TC_ACT_OK;  // Pass through
}
```

#### 2. Payload Extraction
```c
// Calculate TCP header length
__u32 tcp_hdr_len = (tcp->doff) * 4;

// Get payload start
void *payload = (void *)((char *)tcp + tcp_hdr_len);

// Calculate payload length
__u32 payload_len = (__u32)(data_end - payload);
```

#### 3. Pattern Detection

**Pattern 1: /etc/passwd**
```c
char pattern[] = "root:x:0:0:";
if (data_len >= 11 && check_pattern(data, pattern, 11)) {
    return 1;  // Pattern type 1
}
```

**Pattern 2: SSH Private Key**
```c
char pattern[] = "-----BEGIN";
if (data_len >= 10 && check_pattern(data, pattern, 10)) {
    return 2;  // Pattern type 2
}
```

**Pattern 3: Base64**
```c
// Count Base64 characters (A-Z, a-z, 0-9, +, /, =)
__u32 base64_count = 0;
for (__u32 i = 0; i < data_len && i < 64; i++) {
    char c = ((char *)data)[i];
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
        (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
        base64_count++;
    }
}
// Only flag if >95% match and >64 bytes
if (base64_count * 100 > data_len * 95 && data_len > 64) {
    return 3;  // Pattern type 3
}
```

**Pattern 4: SQL Injection**
```c
char pattern[] = "INSERT INTO";
if (data_len >= 11 && check_pattern(data, pattern, 11)) {
    return 4;  // Pattern type 4
}
```

### Ví dụ thực tế

**Scenario: Hacker cố gắng exfiltrate /etc/passwd**
```
Hacker: cat /etc/passwd
    ↓
Honeypot: Simulate command, respond with fake /etc/passwd
    ↓
Response packet: source_port=9999, payload="root:x:0:0:..."
    ↓
TC Egress: Check source_port → YES (9999)
    ↓
TC Egress: Extract payload
    ↓
TC Egress: Detect pattern "root:x:0:0:" → Pattern type 1
    ↓
TC Egress: Update stats
    ├─→ egress_blocks: +1
    └─→ suspicious_patterns[1]: +1
    ↓
TC Egress: return TC_ACT_OK (Demo Mode - not blocking)
    ↓
Dashboard: Update "Egress Blocks (DLP)" counter
```

**Note**: Để chặn thực tế, đổi `TC_ACT_OK` thành `TC_ACT_SHOT` trong code.

---

## 🔐 Security Considerations

### 1. Packet Modification
- **Checksum Recalculation**: Required when modifying ports
- **Function**: `update_csum16()` handles 16-bit values (ports, windows)

### 2. Bounds Checking
- **Every packet access**: Check `(void *)(ptr + size) > data_end`
- **Prevents**: Kernel crashes from out-of-bounds access

### 3. Atomic Operations
- **Statistics updates**: Use `__sync_fetch_and_add()` for thread safety
- **Prevents**: Race conditions in concurrent packet processing

### 4. Map Management
- **LRU Hash Maps**: Auto-evict when full
- **Connection tracking**: Max 10k concurrent connections
- **SPA whitelist**: Max 100 whitelisted IPs

---

## 🎯 Key Takeaways

1. **Port 9999 Check FIRST**: Đảm bảo honeypot nhận được tất cả packets
2. **Connection Tracking**: Track bằng `(src_ip, src_port)`, không dùng `dest_port`
3. **Checksum Update**: Required khi modify packet headers
4. **Early Returns**: Optimize performance với early exits
5. **Atomic Stats**: Thread-safe statistics updates
6. **Bounds Checking**: Critical for kernel safety

---

## 📝 Code References

- **XDP Main Logic**: `bpf/phantom.c:256-441`
- **SPA Verification**: `bpf/phantom.c:208-223`
- **Connection Tracking**: `bpf/phantom.c:359-396`
- **The Mirage**: `bpf/phantom.c:398-430`
- **Honeypot Binding**: `cmd/agent/main.go:755-900`
- **Connection Handling**: `cmd/agent/main.go:956-1005`

