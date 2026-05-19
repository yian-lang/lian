#include "../src/bigint.h"
#include <assert.h>
#include <stdio.h>


void test1();
void test2();
void test3();
void test4();
void test5();
void test6();

int main() {
    printf("Running test 1\n");
    test1();
    printf("Running test 2\n");
    test2();
    printf("Running test 3\n");
    test3();
    printf("Running test 4\n");
    test4();
    printf("Running test 5\n");
    test5();
    printf("Running test 6\n");
    test6();
    printf("All tests passed\n");
    return 0;
}

void test1() {
    // Initialize a big integer from a string
    bigint a = bigint_from_string("123456789012345678901234567890");

    // Initialize a big integer from an integer
    bigint b = bigint_from_int(1234567890);

    // Initialize a big integer from another big integer
    bigint c = bigint_copy(a);

    bigint_delete(a);
    bigint_delete(b);
    bigint_delete(c);
}

void test2() {
    // Initialize big integers
    bigint a = bigint_from_string("123456789012345678901234567890");
    bigint b = bigint_from_string("987654321098765432109876543210");

    // Perform arithmetic operations
    bigint c = bigint_add(a, b);
    bigint d = bigint_sub(a, b);
    bigint e = bigint_mul(a, b);
    bigint f = bigint_div(a, b);
    bigint g = bigint_mod(a, b);

    bigint_delete(a);
    bigint_delete(b);
    bigint_delete(c);
    bigint_delete(d);
    bigint_delete(e);
    bigint_delete(f);
    bigint_delete(g);
}

void test3() {
    // Initialize big integers
    bigint a = bigint_from_string("123456789012345678901234567890");
    bigint b = bigint_from_string("987654321098765432109876543210");

    // Compare big integers
    if (bigint_eq(a, b)) {
        printf("a == b\n");
    } else if (bigint_lt(a, b)) {
        printf("a < b\n");
    } else if (bigint_gt(a, b)) {
        printf("a > b\n");
    }

    bigint_delete(a);
    bigint_delete(b);
}

void test4() {
    // Initialize big integers
    bigint a = bigint_from_string("2");
    bigint b = bigint_from_string("1234");
    bigint m = bigint_from_string("10007");

    // Perform fast modular exponentiation
    bigint c = bigint_fast_pow(a, b, m);

    bigint_delete(a);
    bigint_delete(b);
    bigint_delete(c);
    bigint_delete(m);
}

void test5() {
    // Initialize a big integer
    bigint a = bigint_from_string("123456789012345678901234567890");

    // Check if the big integer is prime
    if (bigint_is_prime(a)) {
        printf("a is prime\n");
    } else {
        printf("a is not prime\n");
    }

    bigint_delete(a);
}

void test6() {
    // Initialize a big integer
    bigint a = bigint_from_string("123412341");

    // Calculate the square root
    bigint b = bigint_sqrt(a);

    bigint_delete(a);
    bigint_delete(b);
}