// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14
#define MAX_BUF_SIZE 64
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct so_event {
	__be32 src_addr;
	__be32 dst_addr;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 pkt_type;
	__u32 ifindex;
	__u32 payload_length;
	__u8 payload[MAX_BUF_SIZE];
};

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Taken from uapi/linux/tcp.h
struct __tcphdr
{
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

// 定义键结构体
struct request_key {
	__be32 src_addr;
	__be32 dst_addr;
	__be16 src_port;
	__be16 dst_port;
} __attribute__((packed)); // 添加 packed 属性以确保紧凑布局

// 定义哈希映射
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct request_key);
	__type(value, u64);
} requests SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

// 添加自定义的字符串比较函数
static __always_inline int compare_prefix(const char *str, const char *prefix, int n) {
	#pragma unroll
	for (int i = 0; i < 8; i++) {  // 使用固定大小的循环
		if (i >= n) return 0;      // 如果达到目标长度，说明匹配成功
		if (str[i] != prefix[i]) return -1;  // 如果字符不匹配，返回-1
	}
	return 0;  // 所有字符都匹配
}

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	struct so_event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;
	__u32 ip_proto = 0;
	__u32 tcp_hdr_len = 0;
	__u16 tlen;
	__u32 payload_offset = 0;
	__u32 payload_length = 0;
	__u8 hdr_len;

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP)
		return 0;

	if (ip_is_fragment(skb, nhoff))
		return 0;

	// ip4 header lengths are variable
	// access ihl as a u8 (linux/include/linux/skbuff.h)
	bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
	hdr_len &= 0x0f;
	hdr_len *= 4;

	/* verify hlen meets minimum size requirements */
	if (hdr_len < sizeof(struct iphdr))
	{
		return 0;
	}

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

	if (ip_proto != IPPROTO_TCP)
	{
		return 0;
	}

	tcp_hdr_len = nhoff + hdr_len;
	bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

	__u8 doff;
	bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
	doff &= 0xf0;																						// clean-up res1
	doff >>= 4;																							// move the upper 4 bits to low
	doff *= 4;																							// convert to bytes length

	payload_offset = ETH_HLEN + hdr_len + doff;
	payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

	char line_buffer[7];
	if (payload_length < 7 || payload_offset < 0)
	{
		return 0;
	}
	bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
//	bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
	
	// 如果是 HTTP 请求，更新统计信息
	if (compare_prefix(line_buffer, "GET", 3) == 0 ||
		compare_prefix(line_buffer, "POST", 4) == 0 ||
		compare_prefix(line_buffer, "PUT", 3) == 0 ||
		compare_prefix(line_buffer, "DELETE", 6) == 0 ||
		compare_prefix(line_buffer, "HTTP", 4) == 0)
	{
   
		struct request_key key = {};
		  u64 initval = 1, *valp;

		// 设置键值
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &key.src_addr, 4);
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &key.dst_addr, 4);
		
		// 获取源端口和目标端口
		__be32 ports;
		bpf_skb_load_bytes(skb, nhoff + hdr_len, &ports, 4);
		key.src_port = (__be16)(ports >> 16);
		key.dst_port = (__be16)ports;

        // 打印端口信息
        bpf_printk("http request: src_port:%d, dst_port:%d", 
                  bpf_ntohs(key.src_port), 
                  bpf_ntohs(key.dst_port));
        
        // 将 IP 地址分成两部分打印
        // bpf_printk("src_addr: %d.%d", 
        //           (key.src_addr) & 0xFF,
        //           (key.src_addr >> 8) & 0xFF);
        // bpf_printk("src_addr: %d.%d", 
        //           (key.src_addr >> 16) & 0xFF,
        //           (key.src_addr >> 24) & 0xFF);
        
        // bpf_printk("dst_addr: %d.%d",
        //           (key.dst_addr) & 0xFF,
        //           (key.dst_addr >> 8) & 0xFF);
        // bpf_printk("dst_addr: %d.%d",
        //           (key.dst_addr >> 16) & 0xFF,
        //           (key.dst_addr >> 24) & 0xFF);

		// 查找或创建计数器
		valp = bpf_map_lookup_elem(&requests, &key);
		if (!valp) {
			bpf_map_update_elem(&requests, &key, &initval, BPF_ANY);
		} else {
			__sync_fetch_and_add(valp, 1);
		}
	}

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ip_proto = ip_proto;
	bpf_skb_load_bytes(skb, nhoff + hdr_len, &(e->ports), 4);
	e->pkt_type = skb->pkt_type;
	e->ifindex = skb->ifindex;

	e->payload_length = payload_length;
	bpf_skb_load_bytes(skb, payload_offset, e->payload, MAX_BUF_SIZE);

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
	bpf_ringbuf_submit(e, 0);

	return skb->len;
}