#  include <stdio.h>
#include "zutil.h"      /* for Z_U4, Z_U8, z_crc_t, and FAR definitions */
#  include "contrib/crc32vx/crc32_vx_hooks.h"
#  include "crc32.h"

     typedef unsigned long z_word_t;
static z_word_t byte_swap(z_word_t word) {

    return
        (word & 0xff00000000000000) >> 56 |
        (word & 0xff000000000000) >> 40 |
        (word & 0xff0000000000) >> 24 |
        (word & 0xff00000000) >> 8 |
        (word & 0xff000000) << 8 |
        (word & 0xff0000) << 24 |
        (word & 0xff00) << 40 |
        (word & 0xff) << 56;







}
static uLong multmodp(uLong a, uLong b) {
    uLong m, p;

    m = (uLong)1 << 31;
    p = 0;
    for (;;) {
        if (a & m) {
            p ^= b;
            if ((a & (m - 1)) == 0)
                break;
        }
        m >>= 1;
        b = b & 1 ? (b >> 1) ^ 0xedb88320 : b >> 1;
    }
    return p;
}





static uLong x2nmodp(long long n, unsigned k) {
    uLong p;

    p = (uLong)1 << 31;
    while (n) {
        if (n & 1)
            p = multmodp(x2n_table[k & 31], p);
        n >>= 1;
        k++;
    }
    return p;
}
const z_crc_t * get_crc_table(void) {



    return (const z_crc_t *)crc_table;
}
static z_crc_t crc_word(z_word_t data) {
    int k;
    for (k = 0; k < 8; k++)
        data = (data >> 8) ^ crc_table[data & 0xff];
    return (z_crc_t)data;
}

static z_word_t crc_word_big(z_word_t data) {
    int k;
    for (k = 0; k < 8; k++)
        data = (data << 8) ^
            crc_big_table[(data >> ((8 - 1) << 3)) & 0xff];
    return data;
}




uLong crc32_z(uLong crc, const unsigned char *buf, z_size_t len) {

    if (buf == 0) return 0;






    crc = (~crc) & 0xffffffff;




    if (len >= 5 * 8 + 8 - 1) {
        z_size_t blks;
        z_word_t const *words;
        unsigned endian;
        int k;


        while (len && ((z_size_t)buf & (8 - 1)) != 0) {
            len--;
            crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        }


        blks = len / (5 * 8);
        len -= blks * 5 * 8;
        words = (z_word_t const *)buf;





        endian = 1;
        if (*(unsigned char *)&endian) {


            z_crc_t crc0;
            z_word_t word0;

            z_crc_t crc1;
            z_word_t word1;

            z_crc_t crc2;
            z_word_t word2;

            z_crc_t crc3;
            z_word_t word3;

            z_crc_t crc4;
            z_word_t word4;
            crc0 = crc;

            crc1 = 0;

            crc2 = 0;

            crc3 = 0;

            crc4 = 0;
            while (--blks) {

                word0 = crc0 ^ words[0];

                word1 = crc1 ^ words[1];

                word2 = crc2 ^ words[2];

                word3 = crc3 ^ words[3];

                word4 = crc4 ^ words[4];







                words += 5;



                crc0 = crc_braid_table[0][word0 & 0xff];

                crc1 = crc_braid_table[0][word1 & 0xff];

                crc2 = crc_braid_table[0][word2 & 0xff];

                crc3 = crc_braid_table[0][word3 & 0xff];

                crc4 = crc_braid_table[0][word4 & 0xff];







                for (k = 1; k < 8; k++) {
                    crc0 ^= crc_braid_table[k][(word0 >> (k << 3)) & 0xff];

                    crc1 ^= crc_braid_table[k][(word1 >> (k << 3)) & 0xff];

                    crc2 ^= crc_braid_table[k][(word2 >> (k << 3)) & 0xff];

                    crc3 ^= crc_braid_table[k][(word3 >> (k << 3)) & 0xff];

                    crc4 ^= crc_braid_table[k][(word4 >> (k << 3)) & 0xff];







                }
            }





            crc = crc_word(crc0 ^ words[0]);

            crc = crc_word(crc1 ^ words[1] ^ crc);

            crc = crc_word(crc2 ^ words[2] ^ crc);

            crc = crc_word(crc3 ^ words[3] ^ crc);

            crc = crc_word(crc4 ^ words[4] ^ crc);







            words += 5;
        }
        else {


            z_word_t crc0, word0, comb;

            z_word_t crc1, word1;

            z_word_t crc2, word2;

            z_word_t crc3, word3;

            z_word_t crc4, word4;
            crc0 = byte_swap(crc);

            crc1 = 0;

            crc2 = 0;

            crc3 = 0;

            crc4 = 0;
            while (--blks) {

                word0 = crc0 ^ words[0];

                word1 = crc1 ^ words[1];

                word2 = crc2 ^ words[2];

                word3 = crc3 ^ words[3];

                word4 = crc4 ^ words[4];







                words += 5;



                crc0 = crc_braid_big_table[0][word0 & 0xff];

                crc1 = crc_braid_big_table[0][word1 & 0xff];

                crc2 = crc_braid_big_table[0][word2 & 0xff];

                crc3 = crc_braid_big_table[0][word3 & 0xff];

                crc4 = crc_braid_big_table[0][word4 & 0xff];







                for (k = 1; k < 8; k++) {
                    crc0 ^= crc_braid_big_table[k][(word0 >> (k << 3)) & 0xff];

                    crc1 ^= crc_braid_big_table[k][(word1 >> (k << 3)) & 0xff];

                    crc2 ^= crc_braid_big_table[k][(word2 >> (k << 3)) & 0xff];

                    crc3 ^= crc_braid_big_table[k][(word3 >> (k << 3)) & 0xff];

                    crc4 ^= crc_braid_big_table[k][(word4 >> (k << 3)) & 0xff];







                }
            }





            comb = crc_word_big(crc0 ^ words[0]);

            comb = crc_word_big(crc1 ^ words[1] ^ comb);

            comb = crc_word_big(crc2 ^ words[2] ^ comb);

            comb = crc_word_big(crc3 ^ words[3] ^ comb);

            comb = crc_word_big(crc4 ^ words[4] ^ comb);







            words += 5;
            crc = byte_swap(comb);
        }




        buf = (unsigned char const *)words;
    }




    while (len >= 8) {
        len -= 8;
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
    }
    while (len) {
        len--;
        crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
    }


    return crc ^ 0xffffffff;
}




uLong crc32(uLong crc, const unsigned char *buf, uInt len) {



    return crc32_z(crc, buf, len);
}


uLong crc32_combine_gen64(long long len2) {
    if (len2 < 0)
        return 0;



    return x2nmodp(len2, 3);
}


uLong crc32_combine_gen(long long len2) {
    return crc32_combine_gen64((long long)len2);
}


uLong crc32_combine_op(uLong crc1, uLong crc2, uLong op) {
    if (op == 0)
        return 0;
    return multmodp(op, crc1 & 0xffffffff) ^ (crc2 & 0xffffffff);
}


uLong crc32_combine64(uLong crc1, uLong crc2, long long len2) {
    return crc32_combine_op(crc1, crc2, crc32_combine_gen64(len2));
}


uLong crc32_combine(uLong crc1, uLong crc2, long long len2) {
    return crc32_combine64(crc1, crc2, (long long)len2);
}
