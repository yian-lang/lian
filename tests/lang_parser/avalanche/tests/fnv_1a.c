/*
 FVN-1a and multi-word variant.
 <http://www.isthe.com/chongo/tech/comp/fnv/#FNV-1a>

 Compile with `-DMULTI_WORD` argument the experimental version.

 The driver program takes the following arguments:
 $ ./a.out input_src [key_len] [num_iter]

 The "avalanche" matrix is dumped to stdout as a whitespace-delimited table.
 */

#include "avalanche.h"
#include <stdlib.h>

#ifndef MULTI_WORD

const size_t hash_words = 1;

void fnv_1a(char *key, size_t key_len, uint32_t* value)
{
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < key_len; ++i) {
        hash ^= key[i];
        hash *= 0x01000193;
    }
    *value = hash;
}

#else

const size_t hash_words = 4;

void fnv_1a(char* key, size_t key_len, uint32_t* value)
{
    uint32_t hash[4] = {
        0x6295c58d, 0x62b82175, 0x07bb0142, 0x6c62272e
    };

    for (size_t i = 0; i < key_len; ++i) {
        hash[i % 4] ^= key[i];
        hash[i % 4] *= 0x01000193;
    }
    value[0] = hash[0];
    value[1] = hash[1];
    value[2] = hash[2];
    value[3] = hash[3];
}

#endif // MULTI_WORD

int main(int argc, char** argv)
{
    if (argc == 1) {
        fprintf(stderr, "must specify data source; see README\n");
        return 0;
    }
    char* in_name = argv[1];
    size_t key_len = (argc > 2) ? atoi(argv[2]) : 16;
    size_t max_iter = (argc > 3) ? atoi(argv[3]) : 10000;
    FILE* ins = fopen(in_name, "r");

    if (ins == NULL) {
        fprintf(stderr, "cannot open %s\n", in_name);
        return 1;
    }

    matrix_t* results = matrix_alloc(key_len * 8, hash_words * 32);

    avalanche(&fnv_1a, ins, max_iter, results);
    fclose(ins);
    
    matrix_fprintf(stdout, "% 6.4g", results);

    matrix_free(results);
    return 0;
}
