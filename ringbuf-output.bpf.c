// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>  // For TC

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key,int);  // key is packet number
	__type(value, struct packet); //value is packet
} heap SEC(".maps");

/* packet data*/
struct packet {
	int ip;
	//char payload[65*1024]; /*maximum TCP packet size is 65535kB*/
	int prot;
};

SEC("ingress")
int capture_packets(struct __sk_buff *skb) {

	void* rb_data = bpf_ringbuf_reserve(&rb, 512, 0);

	if (!rb_data){
		return TC_ACT_OK;
	}
	else{
		
		int ret = bpf_skb_load_bytes(skb,0,rb_data,512);

		if(ret < 0) { bpf_ringbuf_discard(rb_data,0); }
		else {

			struct packet *e;
			struct ethhdr *eth;
			struct iphdr *iph;
			int zero = 0;
			__u64 nh_off = sizeof(struct ethhdr);

			// invalid packet size
			if((skb->data + nh_off + sizeof(struct iphdr)) > skb->data_end) return TC_ACT_OK;

			e = bpf_map_lookup_elem(&heap, &zero);
			if (!e) return TC_ACT_OK;

			// parse headers
			eth = (struct ethhdr *)skb->data;
			iph = (struct iphdr *)(skb->data + nh_off);

			e->ip = iph->saddr;
			
			if(iph->protocol == 1){
				// icmp
				e->prot = 1;
			}
			if(iph->protocol == 6){
				// tcp
				e->prot = 6;
			}
			if(iph->protocol == 17){
				// udp
				e->prot = 17;
			}

			bpf_ringbuf_submit(e,0);
		
		}
	}
    return TC_ACT_OK;
}
