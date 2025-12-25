//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

#define HONEYPOT_PORT 9999
#define MAX_PAYLOAD_SCAN 512

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} egress_blocks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} suspicious_patterns SEC(".maps");

// HELPER: So sánh chuỗi thủ công để vượt qua trình xác thực eBPF
static __always_inline int check_pattern(void *data, const char *pattern, __u32 len) {
    unsigned char *d = (unsigned char *)data;
    const unsigned char *p = (const unsigned char *)pattern;
    
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < 20; i++) { 
        if (i >= len) break;
        if (d[i] != p[i]) return 0;
    }
    return 1;
}

// HÀM KIỂM TRA DỮ LIỆU NHẠY CẢM
static __always_inline int detect_suspicious_pattern(void *data, __u32 data_len) {
    if (data_len == 0 || data_len > MAX_PAYLOAD_SCAN) return 0;
    
    // 1. Kiểm tra file passwd
    char p1[] = "root:x:0:0:";
    if (data_len >= 11 && check_pattern(data, p1, 11)) return 1;
    
    // 2. Kiểm tra SSH Key
    char p2[] = "-----BEGIN";
    if (data_len >= 10 && check_pattern(data, p2, 10)) return 2;
    
    // 3. Kiểm tra Base64 (Đã tối ưu ngưỡng 95% để tránh chặn nhầm banner)
    __u32 base64_count = 0;
    for (__u32 i = 0; i < data_len && i < 64; i++) {
        char c = ((char *)data)[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            base64_count++;
        }
    }
    // Chỉ đánh dấu là Base64 nếu tỷ lệ khớp cực cao (>95%) và độ dài đủ lớn
    if (base64_count * 100 > data_len * 95 && data_len > 64) return 3;
    
    // 4. Kiểm tra SQL Injection
    char p4[] = "INSERT INTO";
    if (data_len >= 11 && check_pattern(data, p4, 11)) return 4;
    
    return 0;
}

SEC("tc")
int phantom_egress_prog(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
    
    // Chỉ kiểm tra dữ liệu đi ra từ cổng Honeypot
    if (tcp->source != bpf_htons(HONEYPOT_PORT)) return TC_ACT_OK;
    
    __u32 tcp_hdr_len = (tcp->doff) * 4;
    void *payload = (void *)(tcp + 1);
    if ((void *)(payload + tcp_hdr_len) > data_end) return TC_ACT_OK;
    
    __u32 payload_len = (__u32)(data_end - (void *)payload);
    if (payload_len == 0) return TC_ACT_OK;
    if (payload_len > MAX_PAYLOAD_SCAN) payload_len = MAX_PAYLOAD_SCAN;
    
    int pattern_type = detect_suspicious_pattern(payload, payload_len);
    
    if (pattern_type > 0) {
        // Cập nhật số liệu vào Map để hiển thị lên Dashboard
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&egress_blocks, &key);
        if (val) __sync_fetch_and_add(val, 1);
        
        __u32 pattern_key = (__u32)pattern_type;
        __u64 *pattern_val = bpf_map_lookup_elem(&suspicious_patterns, &pattern_key);
        if (pattern_val) __sync_fetch_and_add(pattern_val, 1);

        // QUAN TRỌNG: Trả về TC_ACT_OK để không chặn gói tin (Demo Mode)
        // Nếu muốn chặn thực tế, hãy đổi thành TC_ACT_SHOT
        return TC_ACT_OK; 
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";