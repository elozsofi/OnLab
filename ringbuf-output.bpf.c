// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include <linux/ip.h>  // For IPv4 header
#include <linux/pkt_cls.h>  // For TC
//#include <linux/skbuff.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

// struct for captured packet data
struct packet_info {
    __u32 src_ip;
    __u32 payload_size;
};

SEC("tp/sched/sched_process_exec")
int capture_ip_packets(struct __sk_buff *skb) {
    struct iphdr *ip_header = (struct iphdr*)(sizeof(struct ethhdr));
	
    __u32 payload_size = (__u32)(skb->len - (ip_header->ihl * 4));

    struct packet_info pkt_info;
    pkt_info.src_ip = ip_header->saddr;
    pkt_info.payload_size = payload_size;

    struct packet_info *info = bpf_ringbuf_reserve(&rb, sizeof(pkt_info), 0);
    if (info) {
        info->src_ip = pkt_info.src_ip;
        info->payload_size = pkt_info.payload_size;
        bpf_ringbuf_submit(info, 0);
    }

    return TC_ACT_OK;
}
