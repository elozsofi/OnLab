#include <time.h>      // timestamp
#include <stdio.h>     // printf
#include <stdlib.h>    // free
#include <string.h>    // strlen, strcat, memset
#include <zstd.h>      // presumes zstd library is installed
#include "common.h"    // Helper functions, CHECK(), and CHECK_ZSTD()
#include <dirent.h>

#define MAX_FILE_NAME 256

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

void *shared_memory;
sem_t *empty, *full;

static void compress_orDie(void* data, size_t dataSize, void** compressedData, size_t* compressedSize, const size_t maxBufferSize);
size_t loadFile_orDie(const char* fileName, void* buffer, size_t bufferSize);

typedef struct Packet{
    size_t before;
    size_t after;
    int ip;
    double compress_rate;
}Packet;

void init_shared_memory() {
    int fd = shm_open(SHM_NAME, O_RDONLY, 0666);
    shared_memory = mmap(0, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    
    //close(fd);

    empty = sem_open(SEM_EMPTY_NAME, 0);
    full = sem_open(SEM_FULL_NAME, 0);
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

        void *compressedData = NULL;
        size_t compressedSize = 0;
        compress_orDie(shared_memory, SHM_SIZE, &compressedData, &compressedSize, SHM_SIZE);


        clock_gettime(CLOCK_MONOTONIC, &end);
        tsm2 = end.tv_sec * 1000000000L + end.tv_nsec;
        float deltaTime = (float)(tsm2-tsm1);
        deltaTime *= 0.000001;

        float compressionRate = compressedSize/SHM_SIZE*100;
        printf("%d Before: %zu\tAfter: %zu\tCompression rate: %f\tRuntime: %.2fms\n", counter++, SHM_SIZE, compressedSize, compressionRate, deltaTime);
        
        free(compressedData);
        sem_post(empty);
    }
}
/*
// get list of .pcap files in the curr directory
// used in loadInfo to get pcap files faster, make loading simpler
int getPcapFiles(char fileList[][MAX_FILE_NAME], int maxFiles) {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d == NULL) {
        return -1;
    }

    int count = 0;
    while ((dir = readdir(d)) != NULL && count < maxFiles) {
        if (strstr(dir->d_name, ".pcap")) {
            strncpy(fileList[count++], dir->d_name, MAX_FILE_NAME-1);
        }
    }

    closedir(d);
    return count;
}

Packet* getInfoFromKernel(const size_t maxBufferSize){
    char fileList[50][MAX_FILE_NAME];
    int files = getPcapFiles(fileList, 10);
    void* fileBuffer = malloc(maxBufferSize);
    Packet packetList[files];
    int packetIter = 0;

    // making buffer for file
    if (fileBuffer == NULL) { printf("Failed to load buffer\n"); }

    if (files == 0) { printf("No .pcap files in directory\n"); return; }

    for(int i = 0; i < files; i++) {

        Packet p;

        char* name = fileList[i];
        printf("Loading %s for compression\n", name);

        size_t fileSize = loadFile_orDie(name, fileBuffer, maxBufferSize);

        void* compressedData = NULL;
        size_t compressedSize = 0;

        // needed for compression runtime
        // fyi runtime stands for the total runtime of the 5 compressions
        struct timespec start, end;
        unsigned long long tsm1, tsm2;
        clock_gettime(CLOCK_MONOTONIC, &start);
        tsm1 = start.tv_sec * 1000000000L + start.tv_nsec;

        // compressing a file 5 times
        for(int j = 0; j < 5; j++){
            compress_orDie(fileBuffer, fileSize, &compressedData, &compressedSize, maxBufferSize);
        }
        
        // calculating compression runtime
        clock_gettime(CLOCK_MONOTONIC, &end);
        tsm2 = end.tv_sec * 1000000000L + end.tv_nsec;
        float deltaTime = (float)(tsm2-tsm1);
        deltaTime *= 0.000001;

        // structuring packet
        p.before = fileSize;
        p.after = compressedSize;
        p.ip = -1; // TODO
        p.compress_rate = (double)compressedSize/fileSize*100;
        packetList[packetIter++] = p;

        printf("Before: %zu B\tafter: %zu B\t runtime: %.2fms\n", fileSize*8, compressedSize*8, deltaTime);
        
        // free buffer for next file compression
        free(compressedData);
        compressedData = NULL;
    }
    free(fileBuffer);
    return packetList;
}
*/

// needed for ACL rule: ip address + rate limit (defined as num of packets / second)
// num of packets as an unsigned long long
// timestamp needed for timeout
// clock_gettime() -> 64b unix timestamp
void ACL(const int ip, unsigned long long rateLimit) {
    struct timespec ts;
    unsigned long long tsm64;

    clock_gettime(CLOCK_REALTIME, &ts);
    tsm64 = ts.tv_sec * 1000000000L + ts.tv_nsec;

    printf("Timestamp : %llu\n", tsm64);
}

// boundary is 8MB (defined in main)
// errsys log if input data size is too big (using printf for now)
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
    // maximum input buffer size is 8MB
    //const size_t maxBufferSize = 8 * 1024 * 1024;
    //Packet* p = getInfoFromKernel(maxBufferSize);
    
    init_shared_memory();
    compress_and_report();
    return 0;
}
