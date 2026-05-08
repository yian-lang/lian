#ifndef AVALANCHE_H
#define AVALANCHE_H
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/** Protypical hash function: converts a `key` of bytes to a hash value,
 represented as an array of 32-bit blocks.
 */
typedef void (* hash_f)(char* key, size_t key_len, uint32_t* hash_value);

/** Simple matrix structure.
 */
typedef struct {
    size_t n_rows, n_cols;
    double* vals;
} matrix_t;

// macros for enforcing row-major layout of matrix
#define MATRIX_GET(M, ROW, COL) ((M)->vals[(ROW) * (M)->n_cols + (COL)])
#define MATRIX_SET(M, ROW, COL, VAL) ((M)->vals[(ROW) * (M)->n_cols + (COL)] = (VAL))

/** Avalanche test for hash function.

 All test keys are read successively from the stream `ins`, and the probability
 that flipping i-th input bit affects the j-th output bit is recorded as the
 ij-th entry of the matrix.

 All keys read have the same length, so that the key length and size of the
 hash value (in words) are parameterized by the row and columns of the mattrix.
 */
void avalanche(hash_f hash, FILE* ins, uint64_t max_iter, matrix_t* results);

matrix_t* matrix_alloc(size_t n_rows, size_t n_cols);
void matrix_free(matrix_t*);
void matrix_fprintf(FILE* fout, const char* format, const matrix_t*);

#endif // AVALANCHE_H
