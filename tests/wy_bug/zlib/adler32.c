#include "zutil.h"








uLong adler32_z(uLong adler, const Bytef *buf, z_size_t len) {
    unsigned long sum2;
    unsigned n;


    sum2 = (adler >> 16) & 0xffff;
    adler &= 0xffff;


    if (len == 1) {
        adler += buf[0];
        if (adler >= 65521U)
            adler -= 65521U;
        sum2 += adler;
        if (sum2 >= 65521U)
            sum2 -= 65521U;
        return adler | (sum2 << 16);
    }


    if (buf == 0)
        return 1L;


    if (len < 16) {
        while (len--) {
            adler += *buf++;
            sum2 += adler;
        }
        if (adler >= 65521U)
            adler -= 65521U;
        sum2 %= 65521U;
        return adler | (sum2 << 16);
    }


    while (len >= 5552) {
        len -= 5552;
        n = 5552 / 16;
        do {
            {adler += (buf)[0]; sum2 += adler;}; {adler += (buf)[0 +1]; sum2 += adler;};; {adler += (buf)[0 +2]; sum2 += adler;}; {adler += (buf)[0 +2 +1]; sum2 += adler;};;; {adler += (buf)[0 +4]; sum2 += adler;}; {adler += (buf)[0 +4 +1]; sum2 += adler;};; {adler += (buf)[0 +4 +2]; sum2 += adler;}; {adler += (buf)[0 +4 +2 +1]; sum2 += adler;};;;; {adler += (buf)[8]; sum2 += adler;}; {adler += (buf)[8 +1]; sum2 += adler;};; {adler += (buf)[8 +2]; sum2 += adler;}; {adler += (buf)[8 +2 +1]; sum2 += adler;};;; {adler += (buf)[8 +4]; sum2 += adler;}; {adler += (buf)[8 +4 +1]; sum2 += adler;};; {adler += (buf)[8 +4 +2]; sum2 += adler;}; {adler += (buf)[8 +4 +2 +1]; sum2 += adler;};;;;;
            buf += 16;
        } while (--n);
        adler %= 65521U;
        sum2 %= 65521U;
    }


    if (len) {
        while (len >= 16) {
            len -= 16;
            {adler += (buf)[0]; sum2 += adler;}; {adler += (buf)[0 +1]; sum2 += adler;};; {adler += (buf)[0 +2]; sum2 += adler;}; {adler += (buf)[0 +2 +1]; sum2 += adler;};;; {adler += (buf)[0 +4]; sum2 += adler;}; {adler += (buf)[0 +4 +1]; sum2 += adler;};; {adler += (buf)[0 +4 +2]; sum2 += adler;}; {adler += (buf)[0 +4 +2 +1]; sum2 += adler;};;;; {adler += (buf)[8]; sum2 += adler;}; {adler += (buf)[8 +1]; sum2 += adler;};; {adler += (buf)[8 +2]; sum2 += adler;}; {adler += (buf)[8 +2 +1]; sum2 += adler;};;; {adler += (buf)[8 +4]; sum2 += adler;}; {adler += (buf)[8 +4 +1]; sum2 += adler;};; {adler += (buf)[8 +4 +2]; sum2 += adler;}; {adler += (buf)[8 +4 +2 +1]; sum2 += adler;};;;;;
            buf += 16;
        }
        while (len--) {
            adler += *buf++;
            sum2 += adler;
        }
        adler %= 65521U;
        sum2 %= 65521U;
    }


    return adler | (sum2 << 16);
}


uLong adler32(uLong adler, const Bytef *buf, uInt len) {
    return adler32_z(adler, buf, len);
}


static uLong adler32_combine_(uLong adler1, uLong adler2, long long len2) {
    unsigned long sum1;
    unsigned long sum2;
    unsigned rem;


    if (len2 < 0)
        return 0xffffffffUL;


    len2 %= 65521U;
    rem = (unsigned)len2;
    sum1 = adler1 & 0xffff;
    sum2 = rem * sum1;
    sum2 %= 65521U;
    sum1 += (adler2 & 0xffff) + 65521U - 1;
    sum2 += ((adler1 >> 16) & 0xffff) + ((adler2 >> 16) & 0xffff) + 65521U - rem;
    if (sum1 >= 65521U) sum1 -= 65521U;
    if (sum1 >= 65521U) sum1 -= 65521U;
    if (sum2 >= ((unsigned long)65521U << 1)) sum2 -= ((unsigned long)65521U << 1);
    if (sum2 >= 65521U) sum2 -= 65521U;
    return sum1 | (sum2 << 16);
}


uLong adler32_combine(uLong adler1, uLong adler2, long long len2) {
    return adler32_combine_(adler1, adler2, len2);
}

uLong adler32_combine64(uLong adler1, uLong adler2, long long len2) {
    return adler32_combine_(adler1, adler2, len2);
}
