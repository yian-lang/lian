#include "../src/bigint.h"
#include <assert.h>
#include <stdio.h>

bigint factorial(bigint n) {
    bigint tmp1, tmp2;
    bigint result = bigint_from_int(1);
    bigint i = bigint_from_int(1);
    while (bigint_le(i, n)) {
        tmp1 = result;
        result = bigint_mul(result, i);
        bigint_delete(tmp1);

        tmp1 = bigint_from_int(1);
        tmp2 = i;
        i = bigint_add(i, tmp1);
        bigint_delete(tmp1);
        bigint_delete(tmp2);
    }
    bigint_delete(i);
    return result;
}

int main() {
    bigint n = bigint_from_int(100);
    bigint result = factorial(n);
    bigint_print(n);
    printf("! = ");
    bigint_print(result);
    printf("\n");
    bigint_delete(n);

    bigint tmp = bigint_from_string("93326215443944152681699238856266700490715968264381621468592963895217599993229915608941463976156518286253697920827223758251185210916864000000000000000000000000");
    assert(bigint_eq(result, tmp));
    bigint_delete(result);
    bigint_delete(tmp);
    printf("Test passed\n");

    return 0;
}
