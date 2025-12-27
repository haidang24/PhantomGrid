//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

/* * PHANTOM GRID - eBPF KERNEL MODULE
 * Author: Mai Hai Dang (HD24 Security Lab)
 * Description: XDP Layer for Transparent Redirection & Stealth Trapping
 */

#define HONEYPOT_PORT 9999
#define SSH_PORT 22
#define SPA_MAGIC_PORT 1337
#define SPA_SECRET_TOKEN "PHANTOM_GRID_SPA_2025"
#define SPA_TOKEN_LEN 21  // Length of "PHANTOM_GRID_SPA_2025" (without null terminator)

// Critical Assets Ports - Protected by Phantom Protocol (Default: DROP all traffic)
// These ports are completely invisible to attackers unless whitelisted via SPA
#define MYSQL_PORT 3306
#define POSTGRES_PORT 5432
#define MONGODB_PORT 27017
#define REDIS_PORT 6379
#define ADMIN_PANEL_PORT_1 8080
#define ADMIN_PANEL_PORT_2 8443
#define ADMIN_PANEL_PORT_3 9000

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// OS Fingerprint Values
#define TTL_WINDOWS 128
#define TTL_LINUX 64
#define TTL_FREEBSD 64
#define TTL_SOLARIS 255

#define WINDOW_WINDOWS 65535
#define WINDOW_LINUX 29200
#define WINDOW_FREEBSD 65535

// MAP DEFINITIONS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} attack_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stealth_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} os_mutations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, __be32);
    __type(value, __u64);
} spa_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} spa_auth_success SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} spa_auth_failed SEC(".maps");

// HELPER: Manual Checksum Update for 16-bit values (ports, windows)
// Checksum is calculated in network byte order, so we work directly with __be16
static __always_inline void update_csum16(__u16 *csum, __be16 old_val, __be16 new_val) {
    __u32 sum = (~(*csum) & 0xffff);
    // Convert to host byte order for arithmetic, then back
    __u16 old = bpf_ntohs(old_val);
    __u16 new = bpf_ntohs(new_val);
    sum += (~old & 0xffff);
    sum += (new & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    *csum = ~((sum & 0xffff) + (sum >> 16));
}

static __always_inline void mutate_os_personality(struct iphdr *ip, struct tcphdr *tcp) {
    __u16 src_port = bpf_ntohs(tcp->source);
    __u8 os_type = (src_port % 4);
    
    __u8 old_ttl = ip->ttl;
    __u8 new_ttl;
    __be16 old_window = tcp->window;
    __be16 new_window;
    
    switch (os_type) {
        case 0: new_ttl = TTL_WINDOWS; new_window = bpf_htons(WINDOW_WINDOWS); break;
        case 1: new_ttl = TTL_LINUX; new_window = bpf_htons(WINDOW_LINUX); break;
        case 2: new_ttl = TTL_FREEBSD; new_window = bpf_htons(WINDOW_FREEBSD); break;
        case 3: new_ttl = TTL_SOLARIS; new_window = bpf_htons(WINDOW_LINUX); break;
        default: new_ttl = TTL_WINDOWS; new_window = bpf_htons(WINDOW_WINDOWS);
    }
    
    if (old_ttl != new_ttl) {
        ip->ttl = new_ttl;
        // IP checksum needs to account for TTL change
        // TTL is in the second byte of the IP header word containing TTL and protocol
        __be16 old_word = bpf_htons(((__u16)old_ttl << 8) | ip->protocol);
        __be16 new_word = bpf_htons(((__u16)new_ttl << 8) | ip->protocol);
        update_csum16(&ip->check, old_word, new_word);
    }
    
    if (old_window != new_window) {
        update_csum16(&tcp->check, old_window, new_window);
        tcp->window = new_window;
    }
    
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&os_mutations, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline int is_spa_whitelisted(__be32 src_ip) {
    __u64 *expiry = bpf_map_lookup_elem(&spa_whitelist, &src_ip);
    return (expiry != NULL);
}

// Helper: Check if port is a Critical Asset (protected by Phantom Protocol)
static __always_inline int is_critical_asset_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    return (p == SSH_PORT || 
            p == MYSQL_PORT || 
            p == POSTGRES_PORT || 
            p == MONGODB_PORT || 
            p == REDIS_PORT || 
            p == ADMIN_PANEL_PORT_1 || 
            p == ADMIN_PANEL_PORT_2 || 
            p == ADMIN_PANEL_PORT_3);
}

// Helper: Check if port is a Fake Port (The Mirage - honeypot will bind these ports)
// Danh sách này phải khớp với fakePorts trong cmd/agent/main.go
static __always_inline int is_fake_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    return (p == 80 ||      // HTTP
            p == 443 ||     // HTTPS
            p == 3306 ||    // MySQL (fake)
            p == 5432 ||    // PostgreSQL (fake)
            p == 6379 ||    // Redis (fake)
            p == 27017 ||   // MongoDB (fake)
            p == 8080 ||    // Admin Panel (fake)
            p == 8443 ||    // HTTPS Alt (fake)
            p == 9000 ||    // Admin Panel (fake)
            p == 21 ||      // FTP (fake)
            p == 23 ||      // Telnet (fake)
            p == 3389 ||    // RDP (fake)
            p == 5900 ||    // VNC (fake)
            p == 1433 ||    // MSSQL (fake)
            p == 1521 ||    // Oracle (fake)
            p == 5433 ||    // PostgreSQL Alt (fake)
            p == 11211 ||   // Memcached (fake)
            p == 27018 ||   // MongoDB Shard (fake)
            p == 9200 ||    // Elasticsearch (fake)
            p == 5601 ||    // Kibana (fake)
            p == 3000 ||    // Node.js (fake)
            p == 5000 ||    // Flask (fake)
            p == 8000 ||    // Django (fake)
            p == 8888 ||    // Jupyter (fake)
            p == 9999);     // Honeypot (fallback)
}

// FIX: Verify function now takes data_end and checks pointers directly
static __always_inline int verify_magic_packet(void *payload, void *data_end) {
    // Quan trọng: Kiểm tra con trỏ kết thúc trước khi truy cập bất kỳ byte nào
    if ((void *)payload + SPA_TOKEN_LEN > data_end) return 0;

    // Token string literal - so sánh trực tiếp với payload
    const char *token = SPA_SECRET_TOKEN;
    unsigned char *p = (unsigned char *)payload;
    const unsigned char *t = (const unsigned char *)token;
    
    // So sánh từng byte - chỉ so sánh đúng 21 bytes (không bao gồm null terminator)
    #pragma clang loop unroll(full)
    for (int i = 0; i < SPA_TOKEN_LEN; i++) {
        if (p[i] != t[i]) return 0;
    }
    return 1;
}

static __always_inline void spa_whitelist_ip(__be32 src_ip) {
    // Add IP to whitelist (LRU map will auto-evict when full)
    // Value is not used for expiry checking in this simple implementation
    __u64 expiry = 0;
    bpf_map_update_elem(&spa_whitelist, &src_ip, &expiry, BPF_ANY);
    
    // Update success statistics
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&spa_auth_success, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline int is_stealth_scan(struct tcphdr *tcp) {
    // tcp pointer already bounds checked in main prog
    __u8 *flags_byte = ((__u8 *)tcp + 13);
    __u8 flags = *flags_byte;
    
    __u8 fin = flags & 0x01;
    __u8 syn = flags & 0x02;
    __u8 rst = flags & 0x04;
    __u8 psh = flags & 0x08;
    __u8 ack = flags & 0x10;
    __u8 urg = flags & 0x20;
    
    if (fin && urg && psh && !syn && !rst) return 1; // Xmas
    if (flags == 0) return 1; // Null
    if (fin && !syn && !rst && !psh && !ack && !urg) return 1; // FIN
    if (ack && !syn && !fin && !rst) return 1; // ACK
    return 0;
}

SEC("xdp")
int phantom_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __be32 src_ip = ip->saddr;

    // --- SPA Logic (UDP) ---
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        // Kiểm tra header UDP (8 bytes)
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        
        // CHỈ xử lý SPA Magic Packet, cho phép tất cả UDP traffic khác đi qua
        // (DNS, DHCP, NTP, etc. cần hoạt động bình thường)
        if (udp->dest == bpf_htons(SPA_MAGIC_PORT)) {
            void *payload = (void *)(udp + 1);
            
            // Gọi hàm verify với data_end để kiểm tra biên bên trong
            if (verify_magic_packet(payload, data_end)) {
                spa_whitelist_ip(src_ip);
                return XDP_DROP; // Drop Magic Packet sau khi xử lý
            } else {
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&spa_auth_failed, &key);
                if (val) __sync_fetch_and_add(val, 1);
                return XDP_DROP; // Drop invalid Magic Packets
            }
        }
        // Cho phép tất cả UDP traffic khác đi qua (DNS, DHCP, etc.)
        return XDP_PASS;
    }

    // --- TCP Logic (Defense & Redirection) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        // Kiểm tra header TCP (20 bytes)
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // 1. THE PHANTOM PROTOCOL: Bảo vệ Critical Assets (SSH, Database, Admin Panel)
        // Nguyên lý: "Không thể tấn công thứ bạn không nhìn thấy"
        // Mặc định DROP toàn bộ traffic đến các cổng quan trọng
        // Chỉ cho phép nếu IP đã được whitelist qua SPA
        if (is_critical_asset_port(tcp->dest)) {
            if (!is_spa_whitelisted(src_ip)) {
                // Server hoàn toàn "chết" (Dead Host) dưới góc nhìn của hacker
                // Không có phản hồi, không có RST, hoàn toàn im lặng
                return XDP_DROP;
            }
            // IP đã được whitelist qua SPA - cho phép truy cập
            return XDP_PASS;
        }

        // 2. Chặn Scan
        if (is_stealth_scan(tcp)) {
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&stealth_drops, &key);
            if (val) __sync_fetch_and_add(val, 1);
            return XDP_DROP;
        }

        // 3. THE MIRAGE: Pass Fake Ports, Drop Real Ports
        // THE MIRAGE: Honeypot bind nhiều port giả (80, 443, 3306, etc.)
        // XDP pass các fake ports để honeypot có thể phản hồi SYN-ACK trực tiếp
        // Kết quả: Khi quét từ bên ngoài, nmap sẽ thấy nhiều port "mở" (honeypot phản hồi)
        // Các port thật (không phải fake ports) sẽ bị DROP → ẩn hoàn toàn
        
        __u8 *flags_byte = ((__u8 *)tcp + 13);
        __u8 flags = *flags_byte;
        __u8 syn = flags & 0x02;
        __u8 ack = flags & 0x10;
        
        // CHỈ xử lý SYN packets (không có ACK) - đây là inbound connection initiation
        // Bỏ qua các Critical Assets (đã được bảo vệ bởi Phantom Protocol)
        // Cho phép SYN+ACK, ACK, FIN, RST và các packets khác pass through
        // Điều này đảm bảo:
        // - Outbound connections (SYN từ server) hoạt động bình thường
        // - Established connections (ACK, data packets) hoạt động bình thường
        if (syn && !ack && !is_critical_asset_port(tcp->dest)) {
            // Nếu là fake port → REDIRECT đến port 9999 (honeypot fallback)
            // Điều này đảm bảo dù honeypot không bind được port gốc, vẫn có service listen trên 9999
            // Redirect đảm bảo packets được forward đến honeypot một cách chắc chắn
            if (is_fake_port(tcp->dest) && tcp->dest != bpf_htons(HONEYPOT_PORT)) {
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&attack_stats, &key);
                if (val) __sync_fetch_and_add(val, 1);

                __be16 old_port = tcp->dest;
                __be16 new_port = bpf_htons(HONEYPOT_PORT);
                
                update_csum16(&tcp->check, old_port, new_port);
                tcp->dest = new_port;
                
                mutate_os_personality(ip, tcp);
                return XDP_PASS; // Redirect đến honeypot port 9999
            }
            
            // Nếu là honeypot port (9999) → PASS (honeypot sẽ phản hồi SYN-ACK)
            if (tcp->dest == bpf_htons(HONEYPOT_PORT)) {
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&attack_stats, &key);
                if (val) __sync_fetch_and_add(val, 1);
                
                mutate_os_personality(ip, tcp);
                return XDP_PASS;
            }
            
            // Nếu không phải fake port và không phải critical asset → DROP (ẩn port)
            // Điều này đảm bảo hacker chỉ thấy các port giả, không thấy các port thật
            return XDP_DROP;
        }
        
        // Tất cả các packets khác (ACK, FIN, RST, data) sẽ pass through
        // Điều này cho phép:
        // - Outbound connections hoạt động bình thường
        // - Established connections tiếp tục hoạt động sau khi SYN được redirect
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";