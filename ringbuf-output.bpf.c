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

SEC("ingress")
int capture_packets(struct __sk_buff *skb) {

	void* rb_data = bpf_ringbuf_reserve(&rb, sizeof(struct packet*), 0);

	if (!rb_data){
		return TC_ACT_OK;
	}
	else{
		
		int ret = bpf_skb_load_bytes(skb,0,rb_data,sizeof(struct packet*));

		if(ret < 0) { bpf_ringbuf_discard(rb_data,0); }
		else {
			struct packet *pkt;
			pkt->payload = skb->data;
			pkt = (struct packet *)rb_data;
			struct ethhdr *eth;
			int zero = 0;
			__u64 nh_off = sizeof(struct ethhdr);

			if ( (skb->data + nh_off + 4) > skb->data_end) 
				return 0;

			// invalid packet size
			if((skb->data + nh_off + sizeof(struct iphdr)) > skb->data_end){
				return TC_ACT_OK;
			}
			else{
				// parse headers
				eth = (struct ethhdr *)skb->data;
				__u16 h_proto = eth->h_proto;
				if(h_proto == (ETH_P_IP)){
					struct iphdr *iph = skb->data + nh_off;
					if(skb->data + nh_off + sizeof(struct iphdr) + 4 > skb->data_end){
						return 0;
					}
					else{
					pkt->ip = iph->saddr;
					
					if(iph->protocol == 1){
						// icmp
						pkt->prot = 1;
					}
					if(iph->protocol == 6){
						// tcp
						pkt->prot = 6;
					}
					if(iph->protocol == 17){
						// udp
						pkt->prot = 17;
					}
					bpf_ringbuf_submit(rb_data,0);
					}
				}

				// not ip packet
				else{
					return TC_ACT_OK;
				}
			}
		}
	}
    return TC_ACT_OK;
}
