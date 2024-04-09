// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include <arpa/inet.h>
#include "ringbuf-output.skel.h"

struct packet_info {
    __u32 src_ip;
    __u32 payload_size;
};

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	char src_ip_str[INET_ADDRSTRLEN];
	struct packet_info *pkt = data;

	if (data_sz != sizeof(*pkt)) {
		fprintf(stderr, "Size mismatch %zu\n", data_sz);
		return -1; 
	}

	// convert src ip
	inet_ntop(AF_INET, &pkt->src_ip, src_ip_str, sizeof(src_ip_str));
    printf("%s\t%uB\n", src_ip_str, pkt->payload_size);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct ringbuf_output_bpf *skel;
	int err;

	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Load and verify BPF application */
	skel = ringbuf_output_bpf__open_and_load();
	if(!skel){
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	//////////////////
	err = ringbuf_output_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	/////////////////

	printf("%s\t%s\n", "SOURCE", "PAYLOAD");
	while(!exiting){
		err = ring_buffer__poll(rb, 100);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	ringbuf_output_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
