/*
 * Adam's Big Integer Library
 * Version 1.0
 */
#ifndef bigint_H
#define bigint_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct {
    bool is_negative;
    int64_t *digits;
    size_t size;
} bigint;

void bigint_delete(bigint n);

bigint bigint_zero() {
    bigint result;
    result.is_negative = false;
    result.size = 1;
    result.digits = malloc(sizeof(int64_t));
    result.digits[0] = 0;
    return result;
}

void bigint_print(bigint n);

bool bigint_is_64_bit(bigint n) {
    if (n.is_negative) {
        if (n.size > 10) {
            return false;
        }
        if (n.size < 10) {
            return true;
        }
    } else {
        if (n.size > 10) {
            return false;
        }
        if (n.size < 10) {
            return true;
        }
    }
    return false;
}

void bigint_remove_leading_zeros(bigint *n) {
    size_t leading_zeros = 0;
    for (size_t i = 0; i < n->size; i++) {
        if (n->digits[i] == 0) {
            leading_zeros++;
        } else {
            break;
        }
    }

    // If there are leading zeros, memmove the digits
    if (leading_zeros > 0) {
        if (leading_zeros >= n->size) {
            n->size = 1;
            n->digits[0] = 0;
            return;
        }
        n->size -= leading_zeros;
        memmove(n->digits, n->digits + leading_zeros, n->size * sizeof(int64_t));
    }
}

bigint bigint_from_int(int64_t n) {
    bigint result;
    if (n < 0) {
        result.is_negative = true;
        n = -n;
    } else {
        result.is_negative = false;
    }
    result.size = 1;
    int64_t m = n;
    while (m > 0) {
        m /= 10;
        result.size++;
    }
    result.digits = malloc(result.size * sizeof(int64_t));
    m = n;
    for (size_t i = 0; i < result.size; i++) {
        result.digits[result.size - i - 1] = m % 10;
        m /= 10;
    }
    bigint_remove_leading_zeros(&result);
    return result;
}

int64_t bigint_to_int(bigint n) {
    int64_t result = 0;
    for (size_t i = 0; i < n.size; i++) {
        result *= 10;
        result += n.digits[i];
    }
    if (n.is_negative) {
        result = -result;
    }
    return result;
}

/* Create a new bigint from an integer 
* @param n The integer to create a bigint from
* @return A new bigint with the value of n
*/
bigint bigint_from_string(const char *n) {
    bigint result;
    
    // Determine if the number is negative
    if (n[0] == '-') {
        result.is_negative = true;
        n++;
    } else {
        result.is_negative = false;
    }

    // Determine the size of the number
    result.size = strlen(n);

    // Allocate memory for the digits
    result.digits = malloc(result.size * sizeof(int64_t));
    
    // Copy the digits into the bigint
    for (size_t i = 0; i < result.size; i++) {
        result.digits[i] = n[i] - '0';
    }
    
    return result;
}


bigint bigint_copy(bigint n) {
    bigint result;
    result.is_negative = n.is_negative;
    result.size = n.size;
    result.digits = malloc(result.size * sizeof(int64_t));
    memcpy(result.digits, n.digits, result.size * sizeof(int64_t));
    return result;
}

/* Print a bigint
* @param n The bigint to print
*/
void bigint_print(bigint n) {
    if (n.is_negative) {
        printf("-");
    }
    for (size_t i = 0; i < n.size; i++) {
        assert(n.digits[i] >= 0 && n.digits[i] <= 9);
        printf("%lld", n.digits[i]);
    }
}


bool bigint_gt(bigint a, bigint b) {
    bigint_remove_leading_zeros(&a);
    bigint_remove_leading_zeros(&b);
    if (a.size > b.size) {
        return !a.is_negative;
    }
    if (a.size < b.size) {
        return a.is_negative;
    }
    for (size_t i = 0; i < a.size; i++) {
        if (a.digits[i] > b.digits[i]) {
            return !a.is_negative;
        }
        if (a.digits[i] < b.digits[i]) {
            return a.is_negative;
        }
    }
    return false;
}

bool bigint_eq(bigint a, bigint b) {
    bigint_remove_leading_zeros(&a);
    bigint_remove_leading_zeros(&b);
    if (a.size != b.size) {
        return false;
    }
    if (a.is_negative != b.is_negative) {
        return false;
    }
    for (size_t i = 0; i < a.size; i++) {
        if (a.digits[i] != b.digits[i]) {
            return false;
        }
    }
    return true;
}

bool bigint_eqzero(bigint n) {
    bigint_remove_leading_zeros(&n);
    if (n.size == 1 && n.digits[0] == 0) {
        return true;
    }
    return false;
}

bool bigint_ltzero(bigint n) {
    bigint_remove_leading_zeros(&n);
    if (n.size == 1 && n.digits[0] == 0) {
        return false;
    }
    return n.is_negative;
}
bool bigint_gtzero(bigint n) {
    bigint_remove_leading_zeros(&n);
    if (n.size == 1 && n.digits[0] == 0) {
        return false;
    }
    return !n.is_negative;
}

bool bigint_lezero(bigint n) {
    bigint_remove_leading_zeros(&n);
    if (n.size == 1 && n.digits[0] == 0) {
        return true;
    }
    return n.is_negative;
}

bool bigint_gezero(bigint n) {
    bigint_remove_leading_zeros(&n);
    if (n.size == 1 && n.digits[0] == 0) {
        return true;
    }
    return !n.is_negative;
}

bigint bigint_abs(bigint n) {
    n.is_negative = false;
    return n;
}

bool bigint_ge(bigint a, bigint b) {
    return bigint_gt(a, b) || bigint_eq(a, b);
}

bool bigint_lt(bigint a, bigint b) {
    return !bigint_ge(a, b);
}

bool bigint_le(bigint a, bigint b) {
    return !bigint_gt(a, b);
}


bigint bigint_add(bigint a, bigint b);

/* Subtract two bigints
* @param a The first bigint
* @param b The second bigint
* @return The difference of a and b
*/
bigint bigint_sub(bigint a, bigint b) {
    bigint result;
    if (a.is_negative && b.is_negative) {
        a.is_negative = false;
        b.is_negative = false;
        result = bigint_add(b, a);
        result.is_negative = true;
        return result;
    }
    
    if (a.is_negative) {
        // -a - b = -(a + b)
        b.is_negative = true;
        result = bigint_add(a, b);
        return result;
    }

    if (b.is_negative) {
        // a - (-b) = a + b
        b.is_negative = false;
        result = bigint_add(a, b);
        return result;
    }

    result.size = a.size > b.size ? a.size : b.size;
    result.digits = malloc(result.size * sizeof(int64_t));
    
    bool is_negative = bigint_lt(a, b);


    // Subtract the digits
    int64_t carry = 0;
    bigint larger = bigint_gt(a, b) ? a : b;
    bigint smaller = bigint_gt(a, b) ? b : a;

    for (size_t i = 0; i < result.size; i++) {
        int64_t diff = carry;
        if (i < larger.size) {
            diff += larger.digits[larger.size - i - 1];
        }
        if (i < smaller.size) {
            diff -= smaller.digits[smaller.size - i - 1];
        }
        if (diff < 0) {
            diff += 10;
            carry = -1;
        } else {
            carry = 0;
        }
        result.digits[result.size - i - 1] = diff;
    }
    
    bigint_remove_leading_zeros(&result);

    result.is_negative = is_negative;

    return result;
}

/* Add two bigints
* @param a The first bigint
* @param b The second bigint
* @return The sum of a and b
*/
bigint bigint_add(bigint a, bigint b) {
    bigint result;
    if (a.is_negative && b.is_negative) {
        result.is_negative = true;
    } else if (a.is_negative) {
        a.is_negative = false;
        result = bigint_sub(b, a);
        return result;
    } else if (b.is_negative) {
        b.is_negative = false;
        result = bigint_sub(a, b);
        return result;
    } else {
        result.is_negative = false;
    }
    result.size = a.size > b.size ? a.size : b.size;
    result.digits = malloc(result.size * sizeof(int64_t));
    

    
    // Add the digits
    int64_t carry = 0;
    for (size_t i = 0; i < result.size; i++) {
        int64_t sum = carry;
        if (i < a.size) {
            sum += a.digits[a.size - i - 1];
        }
        if (i < b.size) {
            sum += b.digits[b.size - i - 1];
        }
        result.digits[result.size - i - 1] = sum % 10;
        carry = sum / 10;
    }
    
    // If there is a carry, add another digit
    if (carry > 0) {
        result.size++;
        result.digits = realloc(result.digits, result.size * sizeof(int64_t));
        for (size_t i = result.size - 1; i > 0; i--) {
            result.digits[i] = result.digits[i - 1];
        }
        result.digits[0] = carry;
    }
    bigint_remove_leading_zeros(&result);
    
    return result;
}


bigint bigint_inc(bigint *n) {
    bigint one = bigint_from_string("1"), tmp;
    tmp = *n;
    *n = bigint_add(*n, one);
    bigint_delete(tmp);
    bigint_delete(one);
    return *n;
}

bigint bigint_dec(bigint *n) {
    bigint one = bigint_from_string("1"), tmp;
    tmp = *n;
    *n = bigint_sub(*n, one);
    bigint_delete(tmp);
    bigint_delete(one);
    return *n;
}

bigint bigint_mul(bigint a, bigint b) {
    if (bigint_is_64_bit(a) && bigint_is_64_bit(b)) {
        return bigint_from_int(bigint_to_int(a) * bigint_to_int(b));
    }


    bigint result;
    result.size = a.size + b.size;
    result.digits = malloc(result.size * sizeof(int64_t));
    
    // Multiply the digits
    for (size_t i = 0; i < result.size; i++) {
        result.digits[i] = 0;
    }
    for (size_t i = 0; i < a.size; i++) {
        for (size_t j = 0; j < b.size; j++) {
            result.digits[result.size - i - j - 1] += a.digits[a.size - i - 1] * b.digits[b.size - j - 1];
        }
    }

    // Normalize the result
    int64_t carry = 0;
    for (size_t i = 0; i < result.size; i++) {
        int64_t sum = result.digits[result.size - i - 1] + carry;
        result.digits[result.size - i - 1] = sum % 10;
        carry = sum / 10;
    }

    // If there is a carry, add another digit
    if (carry > 0) {
        result.size++;
        result.digits = realloc(result.digits, result.size * sizeof(int64_t));
        for (size_t i = result.size - 1; i > 0; i--) {
            result.digits[i] = result.digits[i - 1];
        }
        result.digits[0] = carry;
    }
    
    bigint_remove_leading_zeros(&result);
    
    // Check negative
    result.is_negative = a.is_negative != b.is_negative;
    
    return result;
}


bigint bigint_divmod(bigint numerator, bigint denominator, bigint *remainder) {
    if (bigint_is_64_bit(numerator) && bigint_is_64_bit(denominator)) {
        int64_t quotient = bigint_to_int(numerator) / bigint_to_int(denominator);
        int64_t rem = bigint_to_int(numerator) % bigint_to_int(denominator);
        *remainder = bigint_from_int(rem);
        return bigint_from_int(quotient);
    }

    bigint quotient = bigint_from_string("0");
    
    bool negative = numerator.is_negative != denominator.is_negative;
    numerator.is_negative = false;
    denominator.is_negative = false;
    
    bigint tmp1, tmp2;
    numerator = bigint_copy(numerator);

    // Divide the numerator by the denominator
    // This is a very slow algorithm
    // It works by subtracting the denominator from the numerator until the numerator is less than the denominator
    // The number of times the denominator is subtracted is the quotient
    // The remainder is the numerator after the last subtraction
    while (bigint_gtzero(numerator)) {
        tmp1 = numerator;
        numerator = bigint_sub(numerator, denominator);
        bigint_delete(tmp1);
        if (bigint_ltzero(numerator)) {
            break;
        }
        bigint_inc(&quotient);
    }
    if (bigint_ltzero(numerator)) {
        tmp1 = numerator;
        numerator = bigint_add(numerator, denominator);
        bigint_delete(tmp1);
    }

    // Set the remainder
    *remainder = numerator;

    bigint_remove_leading_zeros(&quotient);

    if (negative) {
        quotient.is_negative = true;
        remainder->is_negative = true;
    }

    return quotient;
}

bigint bigint_div(bigint a, bigint b) {
    if (bigint_is_64_bit(a) && bigint_is_64_bit(b)) {
        return bigint_from_int(bigint_to_int(a) / bigint_to_int(b));
    }

    bigint remainder;
    bigint result = bigint_divmod(a, b, &remainder);
    bigint_delete(remainder);
    return result;
}

bigint bigint_mod(bigint a, bigint b) {
    if (bigint_is_64_bit(a) && bigint_is_64_bit(b)) {
        bigint result = bigint_from_int(bigint_to_int(a) % bigint_to_int(b));
        // printf("Computing %lld %% %lld = %lld\n", bigint_to_int(a), bigint_to_int(b), bigint_to_int(result));
        return result;
    }

    bigint remainder;
    bigint_delete(bigint_divmod(a, b, &remainder));
    return remainder;
}

bigint bigint_pow(bigint a, bigint b) {
    bigint result, tmp;
    if (b.is_negative) {
        result = bigint_from_string("0");
        return result;
    }
    result = bigint_from_string("1");
    if (bigint_eqzero(b)) {
        return result;
    }
    b = bigint_copy(b);
    while (!bigint_eqzero(b)) {
        tmp = result;
        result = bigint_mul(result, a);
        bigint_delete(tmp);
        bigint_dec(&b);
    }
    bigint_delete(b);
    return result;
}

bool bigint_is_odd(bigint n);
bool bigint_is_even(bigint n);

bigint bigint_fast_pow(bigint a, bigint b, bigint m) {
    if (bigint_is_64_bit(a) && bigint_is_64_bit(b) && bigint_is_64_bit(m)) {
        int64_t result = 1;
        int64_t base = bigint_to_int(a);
        int64_t exp = bigint_to_int(b);
        int64_t mod = bigint_to_int(m);
        base %= mod;
        while (exp > 0) {
            if (exp % 2 == 1) {
                result = (result * base) % mod;
            }
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return bigint_from_int(result);
    }
    
    bigint result;

    if (b.is_negative) {
        result = bigint_from_string("0");
        return result;
    }
    if (bigint_eqzero(b)) {
        result = bigint_from_string("1");
        return result;
    }

    bigint tmp1, tmp2;
    // printf("Computing %lld ^ %lld mod %lld\n", bigint_to_int(a), bigint_to_int(b), bigint_to_int(m));
    b = bigint_copy(b);
    a = bigint_mod(a, m);
    result = bigint_copy(a);
    bigint b_save = bigint_copy(b);
    bigint_dec(&b);

    bigint pow = bigint_from_string("1");
    while (true) {
        tmp1 = bigint_from_string("2");
        tmp2 = bigint_div(b, tmp1);
        bigint_delete(tmp1);
        if (!bigint_gtzero(tmp2)) {
            bigint_delete(tmp2);
            break;
        }
        bigint_delete(tmp2);

        tmp1 = bigint_mul(result, result);
        tmp2 = result;
        result = bigint_mod(tmp1, m);
        bigint_delete(tmp1);
        bigint_delete(tmp2);

        // Halve b
        tmp1 = b;
        tmp2 = bigint_from_string("2");
        
        b = bigint_div(b, tmp2);
        bigint_delete(tmp1);
        bigint_delete(tmp2);
        
        tmp1 = pow;
        pow = bigint_add(pow, pow);
        bigint_delete(tmp1);
    }
    
    tmp1 = b_save;
    b_save = bigint_sub(b_save, pow);
    bigint_delete(tmp1);

    if (bigint_is_odd(b_save)) {
        tmp1 = result;
        tmp2 = bigint_mul(result, a);
        result = bigint_mod(tmp2, m);
        bigint_delete(tmp1);
        bigint_delete(tmp2);
        bigint_dec(&b_save);
        bigint_inc(&pow);
    }

    if (bigint_lt(b_save, bigint_from_int(5))) {
        while (!bigint_eqzero(b_save)) {
            tmp1 = result;
            tmp2 = bigint_mul(result, a);
            result = bigint_mod(tmp2, m);
            bigint_delete(tmp1);
            bigint_delete(tmp2);
            bigint_dec(&b_save);
            bigint_inc(&pow);
        }

        bigint_delete(b_save);
        bigint_delete(pow);

        return result;
    }

    // Do the same halving powers for the subpart
    bigint subpart = bigint_fast_pow(a, b_save, m);

    tmp1 = result;
    tmp2 = subpart;
    result = bigint_mul(result, subpart);
    bigint_delete(tmp1);
    bigint_delete(tmp2);

    tmp1 = result;
    result = bigint_mod(result, m);
    bigint_delete(tmp1);

    bigint_delete(b_save);
    bigint_delete(pow);
    
    return result;
}

bigint bigint_modinv(bigint a, bigint m) {
    bigint m0 = bigint_copy(m);
    bigint y = bigint_from_string("0");
    bigint x = bigint_from_string("1");
    bigint q = bigint_from_string("0");
    bigint t = bigint_from_string("0");
    bigint temp = bigint_from_string("0");
    bigint one = bigint_from_string("1");
    a = bigint_copy(a);
    m = bigint_copy(m);

    bigint tmp1, tmp2;
    while (!bigint_eqzero(a)) {
        tmp1 = q;
        q = bigint_div(m, a);
        bigint_delete(tmp1);

        tmp1 = t;
        tmp2 = bigint_mul(q, a);
        t = bigint_sub(m, tmp2);
        bigint_delete(tmp1);
        bigint_delete(tmp2);

        tmp1 = m, tmp2 = a;
        m = bigint_copy(a);
        a = bigint_copy(t);
        bigint_delete(tmp1);
        bigint_delete(tmp2);

        tmp1 = t;
        tmp2 = bigint_mul(q, x);
        t = bigint_sub(y, tmp2);
        bigint_delete(tmp1);
        bigint_delete(tmp2);

        tmp1 = y, tmp2 = x;
        y = bigint_copy(x);
        x = bigint_copy(t);
        bigint_delete(tmp1);
        bigint_delete(tmp2);
    }
    if (bigint_ltzero(m)) {
        tmp1 = m;
        m = bigint_add(m, m0);
        bigint_delete(tmp1);
    }

    if (bigint_eq(m, one)) {
        bigint result = bigint_mod(y, m0);
        if (bigint_ltzero(result)) {
            tmp1 = result;
            result = bigint_add(result, m0);
            bigint_delete(tmp1);
        }
        bigint_delete(a);
        bigint_delete(m);
        bigint_delete(m0);
        bigint_delete(y);
        bigint_delete(x);
        bigint_delete(q);
        bigint_delete(t);
        bigint_delete(temp);
        bigint_delete(one);
        return result;
    }
    bigint_delete(a);
    bigint_delete(m);
    bigint_delete(m0);
    bigint_delete(y);
    bigint_delete(x);
    bigint_delete(q);
    bigint_delete(t);
    bigint_delete(temp);
    bigint_delete(one);
    return bigint_from_int(0);
}

bigint bigint_sqrt(bigint n) {
    bigint one = bigint_from_string("1");
    bigint two = bigint_from_string("2");
    bigint low = bigint_from_string("0");
    bigint high = bigint_copy(n);
    bigint mid = bigint_from_string("0");
    while (bigint_lt(low, high)) {
        bigint tmp1 = bigint_add(low, high);
        bigint tmp2 = mid;
        mid = bigint_div(tmp1, two);
        bigint_delete(tmp1);
        bigint_delete(tmp2);
        tmp1 = bigint_mul(mid, mid);
        if (bigint_lt(tmp1, n)) {
            tmp2 = low;
            low = bigint_add(mid, one);
            bigint_delete(tmp2);
        } else {
            tmp2 = high;
            high = bigint_copy(mid);
            bigint_delete(tmp2);
        }
        bigint_delete(tmp1);
    }

    bigint_delete(one);
    bigint_delete(two);
    bigint_delete(mid);
    bigint_delete(high);

    return low;
}

bool bigint_is_even(bigint n) {
    return n.digits[n.size - 1] % 2 == 0;
}

bool bigint_is_odd(bigint n) {
    return n.digits[n.size - 1] % 2 == 1;
}

bool bigint_is_prime(bigint n) {
    bigint tmp1, tmp2;
    // Check if the number is even
    if (bigint_is_even(n)) {
        return false;
    }

    // If the last digit is a 5 or 0, the number is divisible by 5
    if (n.size > 1 && (n.digits[n.size - 1] == 5 || n.digits[n.size - 1] == 0)) {
        return false;
    }
    // Check if the sum of the digits is divisible by 3
    bigint sum = bigint_from_string("0");
    for (size_t i = 0; i < n.size; i++) {
        tmp1 = bigint_from_int(n.digits[i]);
        tmp2 = sum;
        sum = bigint_add(sum, tmp1);
        bigint_delete(tmp1);
        bigint_delete(tmp2);
    }

    tmp1 = bigint_from_string("3");
    tmp2 = bigint_mod(sum, tmp1);
    if (bigint_eqzero(tmp2)) {
        bigint_delete(tmp1);
        bigint_delete(tmp2);
        bigint_delete(sum);
        return false;
    }
    bigint_delete(tmp1);
    bigint_delete(tmp2);
    bigint_delete(sum);

    bigint sqrt_n = bigint_sqrt(n);
    
    for (tmp1 = bigint_from_string("2"); bigint_le(tmp1, sqrt_n); bigint_inc(&tmp1)) {
        tmp2 = bigint_mod(n, tmp1);
        if (bigint_eqzero(tmp2)) {
            bigint_delete(tmp1);
            bigint_delete(tmp2);
            bigint_delete(sqrt_n);
            return false;
        }
        bigint_delete(tmp2);
    }
    bigint_delete(tmp1);
    bigint_delete(sqrt_n);
    return true;
}

/* Delete a bigint
* @param n The bigint to delete
*/
#include <execinfo.h>
void bigint_delete(bigint n) {
    free(n.digits);
    n.digits = NULL;
    n.is_negative = false;
    n.size = 0;
}

#endif