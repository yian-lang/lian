/* avalanche.c
 */
#include "avalanche.h"
#include <stdio.h>
#include <stdlib.h>

void avalanche(hash_f hash, FILE* ins, uint64_t max_iter, matrix_t* results)
{
    size_t key_size = results->n_rows / 8;
    size_t hash_words = results->n_cols / 32;

    char* key = malloc(key_size);
    uint32_t* hvalue = malloc(4 * hash_words);
    uint32_t* htemp = malloc(4 * hash_words);

    uint64_t key_count = 0;
    while (key_count < max_iter) {
        size_t n_in = fread(key, 1, key_size, ins);
        if (n_in < key_size)
            break;

        hash(key, key_size, hvalue);
        ++key_count;

        for (size_t i_byte = 0; i_byte < key_size; ++i_byte) {
            for (size_t i_bit = 0; i_bit < 8; ++i_bit) {
                size_t row = i_byte * 8 + i_bit;

                // flip the i-th bit of this byte and re-hash
                char i_mask = 0x80 >> i_bit;
                key[i_byte] ^= i_mask;
                hash(key, key_size, htemp);
                key[i_byte] ^= i_mask;

                for (size_t j_word = 0; j_word < hash_words; ++j_word) {
                    for (size_t j_bit = 0; j_bit < 32; ++j_bit) {
                        size_t col = j_word * 32 + j_bit;

                        // test whether hvalue & htemp differ at j-th bit.
                        uint32_t j_mask = 0x80000000 >> j_bit;
                        if ((hvalue[j_word] ^ htemp[j_word]) & j_mask) {
                            double curr = MATRIX_GET(results, row, col);
                            MATRIX_SET(results, row, col, curr + 1);
                        }
                    }
                }
            }
        }
    }

    free(key);
    free(hvalue);
    free(htemp);

    if (key_count) {
        // convert matrix entries to the mean values
        size_t n_vals = results->n_cols * results->n_rows;
        for (size_t k = 0; k < n_vals; ++k)
            results->vals[k] /= key_count;
    }
}

matrix_t* matrix_alloc(size_t n_rows, size_t n_cols) {
    matrix_t* M = malloc(sizeof(matrix_t));
    M->n_rows = n_rows;
    M->n_cols = n_cols;
    M->vals = calloc(sizeof(double), n_cols * n_rows);
    return M;
}

void matrix_free(matrix_t* M) {
    if (M == NULL)
        return;
    free(M->vals);
    free(M);
    M = NULL;
}

void matrix_fprintf(FILE* fout, const char* format, const matrix_t* M) {
    if (M == NULL)
        return;

    for (size_t r = 0; r < M->n_rows; ++r) {
        for (size_t c = 0; c < M->n_cols; ++c) {
            fprintf(fout, format, MATRIX_GET(M, r, c));
        }
        fprintf(fout, "\n");
    }
}
