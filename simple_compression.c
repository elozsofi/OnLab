#include <stdio.h>     // printf
#include <stdlib.h>    // free
#include <string.h>    // strlen, strcat, memset
#include <zstd.h>      // presumes zstd library is installed
#include "common.h"    // Helper functions, CHECK(), and CHECK_ZSTD()

typedef struct Packet{
    size_t before;
    size_t after;
    const int ip;
    const double compress_rate;
}Packet;

Packet* getInfoFromKernel(void* something){
    // TODO
}

//ACL szabályhoz kell: ip + rate limit (-> unsigned long long csomag/s fogadható)
//kell timeouthoz timestamp
//64bites unix timestamp kell clock_gettime()-ból
void ACL(void) {
    // TODO
}

//boundary kerneltől 8 MB out buffer (mainben)
//függvényben logolni ha túl nagy a bemeneti buffer (errsys log -> printfelni)
static void compress_orDie(void* data, size_t dataSize, void** compressedData, size_t* compressedSize, const size_t maxBufferSize)
{
    // check dataSize
    if (dataSize > maxBufferSize) { printf("bemeneti meret tul nagy!\n"); return; }

    // compressBound-dal a buffer kiszámolása
    size_t const cBuffSize = ZSTD_compressBound(dataSize);
    *compressedData = malloc(cBuffSize); // tömörített adatnak itt memóriafoglalás buffer mérete alapján
    if (*compressedData == NULL) { printf("nem sikerult memoriat foglalni!\n"); return; }

    // compressedSize-ot lementem, hogy később struktúrába mehessen
    *compressedSize = ZSTD_compress(*compressedData, cBuffSize, data, dataSize, 1);
    CHECK_ZSTD(*compressedSize);

    // még jobb memória kihasználtság kedvéért 
    *compressedData = realloc(*compressedData, *compressedSize);
    if (*compressedData == NULL) { printf("Nem sikerult a memoria allokacio!\n"); return;}
}

static char* createOutFilename_orDie(const char* filename)
{
    size_t const inL = strlen(filename);
    size_t const outL = inL + 5;
    void* const outSpace = malloc_orDie(outL);
    memset(outSpace, 0, outL);
    strcat(outSpace, filename);
    strcat(outSpace, ".zst");
    return (char*)outSpace;
}

int main(int argc, const char** argv)
{
    const size_t maxBufferSize = 8 * 1024 * 1024;

    // próba
    char* teszt = "blabla blaaaaa teszt Elek!!!!!!";
    size_t tesztMeret = strlen(teszt) + 1;
    void* tomoritett = NULL;
    size_t tomoritettMeret = 0;
    compress_orDie(teszt, tesztMeret, &tomoritett, &tomoritettMeret, maxBufferSize);

    printf("Elotte: %zu B, utana: %zu B\n", tesztMeret, tomoritettMeret);
    free(tomoritett);

    return 0;
}