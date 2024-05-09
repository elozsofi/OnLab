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

	struct packet *rb_data = (struct packet*)bpf_ringbuf_reserve(&rb, sizeof(struct packet), 0);

	if (!rb_data){
		return TC_ACT_OK;
	}
	else{
		//struct packet *pkt = (struct packet*)rb_data;
		int ret = bpf_skb_load_bytes(skb,0,&rb_data->payload,512);

		if(ret < 0) { goto cleanup; }
		else {
			//memcpy(pkt->payload,rb_data,512);
			struct ethhdr *eth;
			__u64 nh_off = sizeof(struct ethhdr);

			if ( (rb_data->payload + nh_off + 4) > (rb_data->payload+512)) 
				goto cleanup;

			else{
				// parse headers
				eth = (struct ethhdr *)rb_data->payload;
				__u16 h_proto = eth->h_proto;

				if(h_proto == (ETH_P_IP)){
					struct iphdr *iph = rb_data->payload + nh_off;
					if(rb_data->payload + nh_off + sizeof(struct iphdr) + 4 > (rb_data->payload+512)){
						goto cleanup;
					}

					else{
						rb_data->ip = iph->saddr;
						rb_data->prot = iph->protocol;
						bpf_ringbuf_submit(rb_data,0);
					}
				}
				// not ip packet
				else{ goto cleanup; }
			}
		}
	}
    return TC_ACT_OK;

/* throw packet away and return tc_act_ok (0)*/
cleanup:
	bpf_ringbuf_discard(rb_data,0);
	return TC_ACT_OK;

}
