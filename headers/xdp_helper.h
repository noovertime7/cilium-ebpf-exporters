
static inline int get_eth(struct xdp_md* ctx, struct ethhdr** ethhdr) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) {
        return -1;
    }
    *ethhdr = eth;
    return 0;
}
// 判断是否是否arp协议
static inline bool is_arp(struct ethhdr* eth) {
    return bpf_htons(eth->h_proto) == 2054;
}
static inline int get_arp(struct xdp_md* ctx, struct ethhdr* eth, struct arphdr** arp) {
    void* data_end = (void*)(long)ctx->data_end;
    struct arphdr* arp_p = (struct arphdr*)((char*)eth + sizeof(struct ethhdr));
    if ((void*)arp_p + sizeof(*arp_p) > data_end) {
        return -1;
    }
    *arp = arp_p;
    return 0;
}
static inline bool is_arp_request(struct arphdr* arp) {
    return bpf_htons(arp->ar_op) == 1;
}
static inline bool is_arp_reply(struct arphdr* arp) {
    return bpf_htons(arp->ar_op) == 2;
}
// 下面是获取IP数据包
static inline int get_iphdr(struct xdp_md* ctx, struct ethhdr* eth, struct iphdr** iph) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct iphdr* ip_p = data + sizeof(*eth);  // 得到了 ip层
    if ((void*)ip_p + sizeof(*ip_p) > data_end) {
        return -1;
    }
    *iph = ip_p;
    return 0;
}

// 使用arp层获取目标ip
static inline __u32 get_arp_targetip(struct xdp_md* ctx, struct arphdr* arp) {
    void* data_end = (void*)(long)ctx->data_end;
    /* Pointer to the start of addresses */
    unsigned char* addresses = (unsigned char*)(arp + 1);
    if ((void*)(addresses + arp->ar_hln + arp->ar_pln + arp->ar_hln) > data_end) {
        return 0;
    }
    struct in_addr* target_ip = (struct in_addr*)(addresses + 2 * arp->ar_hln + arp->ar_pln);
    if ((void*)(target_ip + 1) > data_end) {
        return 0;
    }
    return bpf_ntohl(target_ip->s_addr);
}
// 使用arp层获取来源ip
static inline __u32 get_arp_sourceip(struct xdp_md* ctx, struct arphdr* arp) {
    void* data_end = (void*)(long)ctx->data_end;
    /* Pointer to the start of addresses */
    unsigned char* addresses = (unsigned char*)(arp + 1);
    if ((void*)(addresses + arp->ar_hln) > data_end) {
        return 0;
    }
    struct in_addr* source_ip = (struct in_addr*)(addresses + arp->ar_hln);
    if ((void*)(source_ip + 1) > data_end) {
        return 0;
    }
    return bpf_ntohl(source_ip->s_addr);
}