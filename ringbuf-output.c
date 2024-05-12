// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Andrii Nakryiko
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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
void *free_space;
sem_t *empty, *full;

void init_shared_memory(){
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	ftruncate(fd, SHM_SIZE);
    shared_memory = mmap(0, SHM_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);

	free_space = shared_memory;

	empty = sem_open(SEM_EMPTY_NAME, O_CREAT, 0666, 1);
	full = sem_open(SEM_FULL_NAME, O_CREAT, 0666, 0);

	sem_init(empty,1,0);
	sem_init(full,1,0);
		
}

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

/* swap from BE to LE, needed for
   ip address */
int swapEndianness(int num) {
    return ((num>>24)&0xff) | // shift első B
           ((num<<8)&0xff0000) | // shift második B
           ((num>>8)&0xff00) | // shift harmadik B
           ((num<<24)&0xff000000); // shift negyedik B
}

void printIPAddress(unsigned int ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\t", bytes[0], bytes[1], bytes[2], bytes[3]);    
}

void printProtocol(int i){
	if ( i == 1 ) { printf("ICMP\n"); }
	if ( i == 6 ) { printf("TCP\n"); }
	if ( i == 17 ) { printf("UDP\n"); }
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct packet *e = data;
	swapEndianness(e->ip);
	printIPAddress(e->ip);
	printProtocol(e->prot);

	int value;
	sem_getvalue(full, &value);
	if(sem_trywait(empty) == 0){
		if((shared_memory+SHM_SIZE) - free_space >= 512){
			memcpy(shared_memory, e->payload, 512);
			free_space += 512;
			sem_post(empty);
		}
		else{
			sem_post(full);
			printf("Buffer is done filling\n");
		}
	}
	else if(value == 0){
		printf("Buffer is emptied\n");
		free_space = shared_memory;
		sem_post(empty);
	}
	else{
		printf("Buffer is full\n");
	}

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

	printf("%s\n", "PACKET");
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
}
