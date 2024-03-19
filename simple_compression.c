#include <stdio.h>     // printf
#include <stdlib.h>    // free
#include <string.h>    // strlen, strcat, memset
#include <zstd.h>      // presumes zstd library is installed
#include "common.h"    // Helper functions, CHECK(), and CHECK_ZSTD()
#include <time.h>

typedef struct Packet{
    size_t before;
    size_t after;
    int ip;
    double compress_rate;
}Packet;

Packet* getInfoFromKernel(void* something){
    // TODO
}

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

    // realloc for better memory usage
    *compressedData = realloc(*compressedData, *compressedSize);
    if (*compressedData == NULL) { printf("Memory allocation error!\n"); return;}
}

int main(int argc, const char** argv)
{
    // maximum input buffer size is 8MB
    const size_t maxBufferSize = 8 * 1024 * 1024;

    void* compr = NULL;
    size_t comprSize = 0;
    void* something;
    Packet* p = getInfoFromKernel(something);
    compress_orDie(something, sizeof(something), &compr, &comprSize, maxBufferSize);

    // structuring packet
    p->before = sizeof(something);
    p->after = comprSize;
    p->compress_rate = comprSize / sizeof(something) * 100;
    p->ip = -1; // TODO: need ip address

    printf("Before: %zu B, after: %zu B\n", sizeof(void), comprSize);
    free(compr);

    return 0;
}