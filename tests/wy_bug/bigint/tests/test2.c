#include "../src/bigint.h"
#include <assert.h>
#include <stdio.h>

int main() {

    // Test the bigint_from_int function
    bigint x = bigint_from_int(100);
    bigint y = bigint_from_string("100");
    assert(bigint_eq(x, y));
    bigint_delete(x);
    bigint_delete(y);

    // Test comparison functions
    x = bigint_from_int(100);
    y = bigint_from_int(100);
    assert(bigint_eq(x, y));
    assert(bigint_le(x, y));
    assert(bigint_ge(x, y));
    assert(!bigint_lt(x, y));
    assert(!bigint_gt(x, y));
    bigint_delete(x);
    bigint_delete(y);

    x = bigint_from_int(100);
    y = bigint_from_int(101);
    assert(!bigint_eq(x, y));
    assert(bigint_le(x, y));
    assert(!bigint_ge(x, y));
    assert(bigint_lt(x, y));
    assert(!bigint_gt(x, y));
    bigint_delete(x);
    bigint_delete(y);

    x = bigint_from_int(101);
    y = bigint_from_int(100);
    assert(!bigint_eq(x, y));
    assert(!bigint_le(x, y));
    assert(bigint_ge(x, y));
    assert(!bigint_lt(x, y));
    assert(bigint_gt(x, y));
    bigint_delete(x);
    bigint_delete(y);

    // Test the bigint_add function
    x = bigint_from_int(100);
    y = bigint_from_int(200);
    bigint z = bigint_add(x, y);
    bigint tmp = bigint_from_int(300);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);

    // Test the bigint_sub function
    x = bigint_from_int(200);
    y = bigint_from_int(100);
    z = bigint_sub(x, y);
    tmp = bigint_from_int(100);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);

    // Test the bigint_mul function
    x = bigint_from_int(100);
    y = bigint_from_int(200);
    z = bigint_mul(x, y);
    tmp = bigint_from_int(20000);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);

    // Test the bigint_div function
    x = bigint_from_int(200);
    y = bigint_from_int(100);
    z = bigint_div(x, y);
    tmp = bigint_from_int(2);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);

    // Test the bigint_mod function
    x = bigint_from_int(200);
    y = bigint_from_int(100);
    z = bigint_mod(x, y);
    tmp = bigint_from_int(0);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);

    x = bigint_from_int(201);
    y = bigint_from_int(100);
    z = bigint_mod(x, y);
    tmp = bigint_from_int(1);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);

    // Test the bigint_pow function
    x = bigint_from_int(2);
    y = bigint_from_int(10);
    z = bigint_pow(x, y);
    tmp = bigint_from_int(1024);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);

    // Test mod inverse
    bigint a = bigint_from_int(17);
    bigint m = bigint_from_int(43);
    z = bigint_modinv(a, m);
    tmp = bigint_from_int(1);
    // Do the mod to check
    bigint t = bigint_mul(a, z);
    bigint r = bigint_mod(t, m);
    assert(bigint_eq(r, tmp));
    bigint_delete(a);
    bigint_delete(m);
    bigint_delete(z);
    bigint_delete(tmp);
    bigint_delete(t);
    bigint_delete(r);


    // Test sqrt
    x = bigint_from_int(100);
    z = bigint_sqrt(x);
    tmp = bigint_from_int(10);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(z);
    bigint_delete(tmp);

    x = bigint_from_int(101);
    z = bigint_sqrt(x);
    tmp = bigint_from_int(11);
    assert(bigint_eq(z, tmp));
    bigint_delete(x);
    bigint_delete(z);
    bigint_delete(tmp);

    // Test bigint is prime
    x = bigint_from_int(17);
    assert(bigint_is_prime(x));
    bigint_delete(x);

    x = bigint_from_int(18);
    assert(!bigint_is_prime(x));
    bigint_delete(x);


    // Test fast modular exponentiation
    x = bigint_from_int(745232);
    y = bigint_from_int(67121);
    z = bigint_from_int(1022117);
    tmp = bigint_fast_pow(x, y, z);
    t = bigint_from_int(97);
    assert(bigint_eq(tmp, t));
    bigint_delete(x);
    bigint_delete(y);
    bigint_delete(z);
    bigint_delete(tmp);
    bigint_delete(t);

    printf("Test passed\n");
    
    return 0;
}
