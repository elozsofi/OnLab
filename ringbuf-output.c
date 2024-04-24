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

// IPC shared memory
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <semaphore.h>
#define SHM_NAME "/packet_shm"
#define SHM_SIZE 4*1024*1024 // shared buffer size is 4MB
#define SEM_EMPTY_NAME "/sem_empty"
#define SEM_FULL_NAME "/sem_full"

int counter = 1;

void *shared_memory;
sem_t *empty, *full;

void init_shared_memory(){
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	ftruncate(fd, SHM_SIZE);
    shared_memory = mmap(0, SHM_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);

	//close(fd);

	empty = sem_open(SEM_EMPTY_NAME, O_CREAT, 0666, 1);
	full = sem_open(SEM_FULL_NAME, O_CREAT, 0666, 0);
}

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
	// fill shared buffer
	// shared buffert dinamikusan csökkenteni, tölteni -> globális változóval
	// wait helyett check shared_memory méret
	sem_wait(empty);
	memcpy(shared_memory, data, data_sz < SHM_SIZE ? data_sz : SHM_SIZE);
	sem_post(full);
	
	unsigned char* temp = data;
	size_t i = 0;
	printf("%d ", counter++);
	for(; i!=data_sz; ++temp){
  	  printf("%02x", *temp);
	  i++;
	}
	printf("\n\n");
	return 0;
}

int main(int argc, char **argv)
{

	init_shared_memory();

	struct ring_buffer *rb = NULL;
	int err;

	/* Set up libbpf logging callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* File descriptor for rb map*/
	int fd;
	fd = bpf_obj_get("/sys/fs/bpf/tc/globals/rb");
	if (fd < 0)
	{
		return -1;
	}

	rb = ring_buffer__new(fd,handle_event,NULL,NULL);

	printf("%s\n", "PACKET PAYLOAD");
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
	return err < 0 ? -err : 0;
}


int open_global()
{
	int fd;
	fd = bpf_obj_get("/sys/fs/bpf/tc/globals/rb");
	if (fd < 0)
	{
		return -1;
	}
	return fd;
}
