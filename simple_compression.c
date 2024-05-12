#include <time.h>      // timestamp
#include <stdio.h>     // printf
#include <stdlib.h>    // free
#include <string.h>    // strlen, strcat, memset
#include <zstd.h>      // presumes zstd library is installed
#include "common.h"    // Helper functions, CHECK(), and CHECK_ZSTD()
#include <dirent.h>

// IPC shared memory    
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <semaphore.h>
#include <linux/time.h>
#define SHM_NAME "/packet_shm"
#define SHM_SIZE 4*1024*1024 // shared buffer size is 4MB
#define SEM_EMPTY_NAME "/sem_empty"
#define SEM_FULL_NAME "/sem_full"

void *shared_memory;
sem_t *empty, *full;

static void compress_orDie(void* data, size_t dataSize, void** compressedData, size_t* compressedSize, const size_t maxBufferSize);
size_t loadFile_orDie(const char* fileName, void* buffer, size_t bufferSize);

void init_shared_memory() {
    int fd = shm_open(SHM_NAME, O_RDONLY, 0666);
    shared_memory = mmap(0, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	full = sem_open(SEM_FULL_NAME, O_CREAT, 0666, 0);
}

void compress_and_report() {
    int counter = 1;
    while(1){
        sem_wait(full);

        // timestamps for compression runtime
        struct timespec start, end;
        unsigned long long tsm1, tsm2;
        clock_gettime(CLOCK_MONOTONIC, &start);
        tsm1 = start.tv_sec * 1000000000L + start.tv_nsec;

        // compressing buffer data
        void *compressedData = NULL;
        size_t compressedSize = 0;
        compress_orDie(shared_memory, SHM_SIZE, &compressedData, &compressedSize, SHM_SIZE);

        // calculating runtime
        clock_gettime(CLOCK_MONOTONIC, &end);
        tsm2 = end.tv_sec * 1000000000L + end.tv_nsec;
        float deltaTime = (float)(tsm2-tsm1);
        deltaTime *= 0.000001;

        float compSize = (float)compressedSize;
        float maxSize = (float)SHM_SIZE;
        float compressionRate = compSize/maxSize;
        printf("%d Before: %d\tAfter: %zu\tCompression rate: %.2f%%\tRuntime: %.2fms\n", counter++, SHM_SIZE, compressedSize, compressionRate*100, deltaTime);
        
        free(compressedData);
    }
}

void ACL(const int ip, unsigned long long rateLimit) {
    // TODO
}

static void compress_orDie(void* data, size_t dataSize, void** compressedData, size_t* compressedSize, const size_t maxBufferSize)
{
    // check dataSize
    if (dataSize > maxBufferSize) { printf("Input size too big!\n"); return; }

    // calculate buffer size for compressed data with compressBoud
    size_t const cBuffSize = ZSTD_compressBound(dataSize);
    *compressedData = malloc(cBuffSize); // memory for compressed data based on its buffer size
    if (*compressedData == NULL) { printf("Memory error!\n"); return; }

    // compressedSize needed for Packet struct
    *compressedSize = ZSTD_compress(*compressedData, cBuffSize, data, dataSize, 1);
    CHECK_ZSTD(*compressedSize);
}

int main(int argc, const char** argv)
{
    init_shared_memory();
    compress_and_report();
    return 0;
}
