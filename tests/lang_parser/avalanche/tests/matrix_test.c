/* avalanche_test.c
 */
#include "avalanche.h"
#include <assert.h>
#include <stdio.h>

void test_macros() {
    matrix_t* M = matrix_alloc(2, 2);
    assert(M->vals);

    for (int r = 0; r < 2; ++r) {
        for (int c = 0; c < 2; ++c)
            MATRIX_SET(M, r, c, 1.0 / (r + c + 1));
    }

    for (int r = 0; r < 2; ++r) {
        for (int c = 0; c < 2; ++c) {
            double expected = 1.0 / (r + c + 1);
            assert(expected == MATRIX_GET(M, r, c));
        }
    }

    matrix_free(M);
    printf("test_macros PASS\n");
}

void print_hilbert() {
    matrix_t* M = matrix_alloc(3, 3);
    assert(M->vals);

    for (int r = 0; r < 3; ++r) {
        for (int c = 0; c < 3; ++c)
            MATRIX_SET(M, r, c, 1.0 / (r + c + 1));
    }

    matrix_fprintf(stdout, "%8.4f", M);
    matrix_free(M);
}

int main() {
    test_macros();
    print_hilbert();
}
