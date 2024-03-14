#include <stdio.h>     // printf
#include <stdlib.h>    // free
#include <string.h>    // strlen, strcat, memset
#include <zstd.h>      // presumes zstd library is installed
#include "common.h"    // Helper functions, CHECK(), and CHECK_ZSTD()

/////////////////////////////////////////////
/*
tervezett működés:
    - apival előállítja a kellő struktúrát
        -> vagyis szétválasztja a (1)payload filera, (2)ip-re, (3)tömöríthetőséget (később kerül bele) 
        -> memóriát foglal le neki
        -> fel is szabadítja
    - Packet struktúra file változójára meghívja a tömörítő függvényt
    - Ekkor a packetnek kiszámolja a tömöríthetőségét (main-ben / tömörítés közben TBD)
    - ezután egy Packet-et tovább tud majd adni ACL-nek
    - (lehet a FILE* fp felesleges a struktúrába)


    -
*/
////////////////////////////////////////////

/*
typedef struct Packet{
    const int ip;
    const double compress_rate;
}Packet;
Packet* getInfo(void* something){
    ///get info from ???
    ///malloc memory for Packet
    ///free
    ///return Packet (ip+payload file)
}*/

//params  void* + hossz
//boundary kerneltől 8 MB out buffer (mainben)
//töm. méret < tömörítetlen (tényleg < 8 MB?)
//függvényben logolni ha túl nagy a bemeneti buffer (errsys log -> printfelni)
static void compress_orDie(const char* fname, const char* oname)
{
    size_t fSize;
    void* const fBuff = mallocAndLoadFile_orDie(fname, &fSize);
    size_t const cBuffSize = ZSTD_compressBound(fSize);
    void* const cBuff = malloc_orDie(cBuffSize);

    size_t const cSize = ZSTD_compress(cBuff, cBuffSize, fBuff, fSize, 1);
    CHECK_ZSTD(cSize);

    saveFile_orDie(oname, cBuff, cSize);

    printf("%25s : %6u -> %7u - %s \n", fname, (unsigned)fSize, (unsigned)cSize, oname);

    free(fBuff);
    free(cBuff);
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

double get_compression_rate(char* inFile, char* outFile){
    size_t sizeIn = get_file_size(inFile);
    size_t sizeOut = get_file_size(outFile);
    return (sizeOut / sizeIn) * 100;
}

size_t get_file_size(const char* file){
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int main(int argc, const char** argv)
{
    const char* const exeName = argv[0];

    /////////////////////
    if (argc!=2) {
        printf("wrong arguments\n");
        printf("usage:\n");
        printf("%s FILE\n", exeName);
        return 1;
    }
    /////////////////////

    const char* const inFilename = argv[1];
    char* const outFilename = createOutFilename_orDie(inFilename);
    compress_orDie(inFilename, outFilename);
    free(outFilename);

    double compr_rate = get_compression_rate(inFilename, outFilename);

    return 0;
}