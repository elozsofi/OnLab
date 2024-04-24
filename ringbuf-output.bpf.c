// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include <linux/ip.h>  // For IPv4 header
#include <linux/pkt_cls.h>  // For TC

//#define PIN_GLOBAL_NS		2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

// struct for captured packet data
/*struct packet_info {
  __u32 src_ip;
  __u32 payload_size;
};*/

/*struct bpf_elf_map snoop_packets SEC("maps") = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(int),
    .size_value     = sizeof(struct packet_info),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = PIN_GLOBAL_NS,
};*/

// xdp-re áttérni
// SEC("xdp")
// value a struktúra, key a csomagszám

//__u32 buff_array[512/4];


SEC("ingress")
int capture_packets(struct __sk_buff *skb) {

	struct ethhdr *eth;
	struct udphdr *udp;

    // Initialize packet data.
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
	unsigned long long len = data_end - data;

	// valid packet length
	if (len <= 0) return TC_ACT_OK;

	void* rb_data = bpf_ringbuf_reserve(&rb, 512, 0);

	if (!rb_data){
		return TC_ACT_OK;
	}
	else{
		//unsigned long long length = (len<512) ? len:512;
		
		int ret = bpf_skb_load_bytes(skb,0,rb_data,512);

		if (ret >= 0){
			bpf_ringbuf_submit(rb_data,0);
		}
		else{
			bpf_ringbuf_discard(rb_data, 0);
		}
		//memcpy(rb_data, buff_array);
		
		//bpf_ringbuf_output(&rb, data, sizeof(*data), 0);
	}


    return TC_ACT_OK;
}
