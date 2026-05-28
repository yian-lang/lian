#include "deflate.h"
#  include <ctype.h>
#  include "trees.h"
#    include <stdio.h>
#  include <stdio.h>

static const int extra_lbits[29]
   = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};

static const int extra_dbits[30]
   = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

static const int extra_blbits[19]
   = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,3,7};

static const uch bl_order[19]
   = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};


struct static_tree_desc_s {
    const ct_data *static_tree;
    const intf *extra_bits;
    int extra_base;
    int elems;
    int max_length;
};







static const static_tree_desc static_l_desc =
{static_ltree, extra_lbits, 256 +1, (256 +1+29), 15};

static const static_tree_desc static_d_desc =
{static_dtree, extra_dbits, 0, 30, 15};

static const static_tree_desc static_bl_desc =
{(const ct_data *)0, extra_blbits, 0, 19, 7};
static unsigned bi_reverse(unsigned code, int len) {
    unsigned res = 0;
    do {
        res |= code & 1;
        code >>= 1, res <<= 1;
    } while (--len > 0);
    return res >> 1;
}




static void bi_flush(deflate_state *s) {
    if (s->bi_valid == 16) {
        { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; };
        s->bi_buf = 0;
        s->bi_valid = 0;
    } else if (s->bi_valid >= 8) {
        {s->pending_buf[s->pending++] = (Bytef)((Byte)s->bi_buf);};
        s->bi_buf >>= 8;
        s->bi_valid -= 8;
    }
}




static void bi_windup(deflate_state *s) {
    if (s->bi_valid > 8) {
        { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; };
    } else if (s->bi_valid > 0) {
        {s->pending_buf[s->pending++] = (Bytef)((Byte)s->bi_buf);};
    }
    s->bi_used = ((s->bi_valid - 1) & 7) + 1;
    s->bi_buf = 0;
    s->bi_valid = 0;



}
static void gen_codes(ct_data *tree, int max_code, ushf *bl_count) {
    ush next_code[15 +1];
    unsigned code = 0;
    int bits;
    int n;




    for (bits = 1; bits <= 15; bits++) {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = (ush)code;
    }




                                      ;
                                                          ;

    for (n = 0; n <= max_code; n++) {
        int len = tree[n].dl.len;
        if (len == 0) continue;

        tree[n].fc.code = (ush)bi_reverse(next_code[len]++, len);


                                                                              ;
    }
}
static void tr_static_init(void) {
}
static void init_block(deflate_state *s) {
    int n;


    for (n = 0; n < (256 +1+29); n++) s->dyn_ltree[n].fc.freq = 0;
    for (n = 0; n < 30; n++) s->dyn_dtree[n].fc.freq = 0;
    for (n = 0; n < 19; n++) s->bl_tree[n].fc.freq = 0;

    s->dyn_ltree[256].fc.freq = 1;
    s->opt_len = s->static_len = 0L;
    s->sym_next = s->matches = 0;
}




void _tr_init(deflate_state *s) {
    tr_static_init();

    s->l_desc.dyn_tree = s->dyn_ltree;
    s->l_desc.stat_desc = &static_l_desc;

    s->d_desc.dyn_tree = s->dyn_dtree;
    s->d_desc.stat_desc = &static_d_desc;

    s->bl_desc.dyn_tree = s->bl_tree;
    s->bl_desc.stat_desc = &static_bl_desc;

    s->bi_buf = 0;
    s->bi_valid = 0;
    s->bi_used = 0;






    init_block(s);
}
static void pqdownheap(deflate_state *s, ct_data *tree, int k) {
    int v = s->heap[k];
    int j = k << 1;
    while (j <= s->heap_len) {

        if (j < s->heap_len &&
            (tree[s->heap[j + 1]].fc.freq < tree[s->heap[j]].fc.freq || (tree[s->heap[j + 1]].fc.freq == tree[s->heap[j]].fc.freq && s->depth[s->heap[j + 1]] <= s->depth[s->heap[j]]))) {
            j++;
        }

        if ((tree[v].fc.freq < tree[s->heap[j]].fc.freq || (tree[v].fc.freq == tree[s->heap[j]].fc.freq && s->depth[v] <= s->depth[s->heap[j]]))) break;


        s->heap[k] = s->heap[j]; k = j;


        j <<= 1;
    }
    s->heap[k] = v;
}
static void gen_bitlen(deflate_state *s, tree_desc *desc) {
    ct_data *tree = desc->dyn_tree;
    int max_code = desc->max_code;
    const ct_data *stree = desc->stat_desc->static_tree;
    const intf *extra = desc->stat_desc->extra_bits;
    int base = desc->stat_desc->extra_base;
    int max_length = desc->stat_desc->max_length;
    int h;
    int n, m;
    int bits;
    int xbits;
    ush f;
    int overflow = 0;

    for (bits = 0; bits <= 15; bits++) s->bl_count[bits] = 0;




    tree[s->heap[s->heap_max]].dl.len = 0;

    for (h = s->heap_max + 1; h < (2*(256 +1+29)+1); h++) {
        n = s->heap[h];
        bits = tree[tree[n].dl.dad].dl.len + 1;
        if (bits > max_length) bits = max_length, overflow++;
        tree[n].dl.len = (ush)bits;


        if (n > max_code) continue;

        s->bl_count[bits]++;
        xbits = 0;
        if (n >= base) xbits = extra[n - base];
        f = tree[n].fc.freq;
        s->opt_len += (ulg)f * (unsigned)(bits + xbits);
        if (stree) s->static_len += (ulg)f * (unsigned)(stree[n].dl.len + xbits);
    }
    if (overflow == 0) return;

                                              ;



    do {
        bits = max_length - 1;
        while (s->bl_count[bits] == 0) bits--;
        s->bl_count[bits]--;
        s->bl_count[bits + 1] += 2;
        s->bl_count[max_length]--;



        overflow -= 2;
    } while (overflow > 0);






    for (bits = max_length; bits != 0; bits--) {
        n = s->bl_count[bits];
        while (n != 0) {
            m = s->heap[--h];
            if (m > max_code) continue;
            if ((unsigned) tree[m].dl.len != (unsigned) bits) {
                                                                              ;
                s->opt_len += ((ulg)bits - tree[m].dl.len) * tree[m].fc.freq;
                tree[m].dl.len = (ush)bits;
            }
            n--;
        }
    }
}
static void build_tree(deflate_state *s, tree_desc *desc) {
    ct_data *tree = desc->dyn_tree;
    const ct_data *stree = desc->stat_desc->static_tree;
    int elems = desc->stat_desc->elems;
    int n, m;
    int max_code = -1;
    int node;





    s->heap_len = 0, s->heap_max = (2*(256 +1+29)+1);

    for (n = 0; n < elems; n++) {
        if (tree[n].fc.freq != 0) {
            s->heap[++(s->heap_len)] = max_code = n;
            s->depth[n] = 0;
        } else {
            tree[n].dl.len = 0;
        }
    }






    while (s->heap_len < 2) {
        node = s->heap[++(s->heap_len)] = (max_code < 2 ? ++max_code : 0);
        tree[node].fc.freq = 1;
        s->depth[node] = 0;
        s->opt_len--; if (stree) s->static_len -= stree[node].dl.len;

    }
    desc->max_code = max_code;




    for (n = s->heap_len/2; n >= 1; n--) pqdownheap(s, tree, n);




    node = elems;
    do {
        { n = s->heap[1]; s->heap[1] = s->heap[s->heap_len--]; pqdownheap(s, tree, 1); };
        m = s->heap[1];

        s->heap[--(s->heap_max)] = n;
        s->heap[--(s->heap_max)] = m;


        tree[node].fc.freq = tree[n].fc.freq + tree[m].fc.freq;
        s->depth[node] = (uch)((s->depth[n] >= s->depth[m] ?
                                s->depth[n] : s->depth[m]) + 1);
        tree[n].dl.dad = tree[m].dl.dad = (ush)node;







        s->heap[1] = node++;
        pqdownheap(s, tree, 1);

    } while (s->heap_len >= 2);

    s->heap[--(s->heap_max)] = s->heap[1];




    gen_bitlen(s, (tree_desc *)desc);


    gen_codes ((ct_data *)tree, max_code, s->bl_count);
}





static void scan_tree(deflate_state *s, ct_data *tree, int max_code) {
    int n;
    int prevlen = -1;
    int curlen;
    int nextlen = tree[0].dl.len;
    int count = 0;
    int max_count = 7;
    int min_count = 4;

    if (nextlen == 0) max_count = 138, min_count = 3;
    tree[max_code + 1].dl.len = (ush)0xffff;

    for (n = 0; n <= max_code; n++) {
        curlen = nextlen; nextlen = tree[n + 1].dl.len;
        if (++count < max_count && curlen == nextlen) {
            continue;
        } else if (count < min_count) {
            s->bl_tree[curlen].fc.freq += (ush)count;
        } else if (curlen != 0) {
            if (curlen != prevlen) s->bl_tree[curlen].fc.freq++;
            s->bl_tree[16].fc.freq++;
        } else if (count <= 10) {
            s->bl_tree[17].fc.freq++;
        } else {
            s->bl_tree[18].fc.freq++;
        }
        count = 0; prevlen = curlen;
        if (nextlen == 0) {
            max_count = 138, min_count = 3;
        } else if (curlen == nextlen) {
            max_count = 6, min_count = 3;
        } else {
            max_count = 7, min_count = 4;
        }
    }
}





static void send_tree(deflate_state *s, ct_data *tree, int max_code) {
    int n;
    int prevlen = -1;
    int curlen;
    int nextlen = tree[0].dl.len;
    int count = 0;
    int max_count = 7;
    int min_count = 4;


    if (nextlen == 0) max_count = 138, min_count = 3;

    for (n = 0; n <= max_code; n++) {
        curlen = nextlen; nextlen = tree[n + 1].dl.len;
        if (++count < max_count && curlen == nextlen) {
            continue;
        } else if (count < min_count) {
            do { { int len = s->bl_tree[curlen].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)s->bl_tree[curlen].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(s->bl_tree[curlen].fc.code) << s->bi_valid; s->bi_valid += len; }}; } while (--count != 0);

        } else if (curlen != 0) {
            if (curlen != prevlen) {
                { int len = s->bl_tree[curlen].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)s->bl_tree[curlen].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(s->bl_tree[curlen].fc.code) << s->bi_valid; s->bi_valid += len; }}; count--;
            }
                                                     ;
            { int len = s->bl_tree[16].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)s->bl_tree[16].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(s->bl_tree[16].fc.code) << s->bi_valid; s->bi_valid += len; }}; { int len = 2; if (s->bi_valid > (int)16 - len) { int val = (int)count - 3; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(count - 3) << s->bi_valid; s->bi_valid += len; }};

        } else if (count <= 10) {
            { int len = s->bl_tree[17].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)s->bl_tree[17].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(s->bl_tree[17].fc.code) << s->bi_valid; s->bi_valid += len; }}; { int len = 3; if (s->bi_valid > (int)16 - len) { int val = (int)count - 3; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(count - 3) << s->bi_valid; s->bi_valid += len; }};

        } else {
            { int len = s->bl_tree[18].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)s->bl_tree[18].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(s->bl_tree[18].fc.code) << s->bi_valid; s->bi_valid += len; }}; { int len = 7; if (s->bi_valid > (int)16 - len) { int val = (int)count - 11; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(count - 11) << s->bi_valid; s->bi_valid += len; }};
        }
        count = 0; prevlen = curlen;
        if (nextlen == 0) {
            max_count = 138, min_count = 3;
        } else if (curlen == nextlen) {
            max_count = 6, min_count = 3;
        } else {
            max_count = 7, min_count = 4;
        }
    }
}





static int build_bl_tree(deflate_state *s) {
    int max_blindex;


    scan_tree(s, (ct_data *)s->dyn_ltree, s->l_desc.max_code);
    scan_tree(s, (ct_data *)s->dyn_dtree, s->d_desc.max_code);


    build_tree(s, (tree_desc *)(&(s->bl_desc)));
    for (max_blindex = 19 -1; max_blindex >= 3; max_blindex--) {
        if (s->bl_tree[bl_order[max_blindex]].dl.len != 0) break;
    }

    s->opt_len += 3*((ulg)max_blindex + 1) + 5 + 5 + 4;

                                       ;

    return max_blindex;
}






static void send_all_trees(deflate_state *s, int lcodes, int dcodes,
                          int blcodes) {
    int rank;

                                                                             ;

                             ;
                                     ;
    { int len = 5; if (s->bi_valid > (int)16 - len) { int val = (int)lcodes - 257; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(lcodes - 257) << s->bi_valid; s->bi_valid += len; }};
    { int len = 5; if (s->bi_valid > (int)16 - len) { int val = (int)dcodes - 1; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(dcodes - 1) << s->bi_valid; s->bi_valid += len; }};
    { int len = 4; if (s->bi_valid > (int)16 - len) { int val = (int)blcodes - 4; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(blcodes - 4) << s->bi_valid; s->bi_valid += len; }};
    for (rank = 0; rank < blcodes; rank++) {
                                                          ;
        { int len = 3; if (s->bi_valid > (int)16 - len) { int val = (int)s->bl_tree[bl_order[rank]].dl.len; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(s->bl_tree[bl_order[rank]].dl.len) << s->bi_valid; s->bi_valid += len; }};
    }
                                                         ;

    send_tree(s, (ct_data *)s->dyn_ltree, lcodes - 1);
                                                          ;

    send_tree(s, (ct_data *)s->dyn_dtree, dcodes - 1);
                                                           ;
}




void _tr_stored_block(deflate_state *s, charf *buf,
                                    ulg stored_len, int last) {
    { int len = 3; if (s->bi_valid > (int)16 - len) { int val = (int)(0<<1) + last; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)((0<<1) + last) << s->bi_valid; s->bi_valid += len; }};
    bi_windup(s);
    { {s->pending_buf[s->pending++] = (Bytef)((uch)(((ush)stored_len) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)((ush)stored_len) >> 8));}; };
    { {s->pending_buf[s->pending++] = (Bytef)((uch)(((ush)~stored_len) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)((ush)~stored_len) >> 8));}; };
    if (stored_len)
        memcpy(s->pending_buf + s->pending, (Bytef *)buf, stored_len);
    s->pending += stored_len;






}




void _tr_flush_bits(deflate_state *s) {
    bi_flush(s);
}





void _tr_align(deflate_state *s) {
    { int len = 3; if (s->bi_valid > (int)16 - len) { int val = (int)1<<1; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(1<<1) << s->bi_valid; s->bi_valid += len; }};
    { int len = static_ltree[256].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)static_ltree[256].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(static_ltree[256].fc.code) << s->bi_valid; s->bi_valid += len; }};



    bi_flush(s);
}




static void compress_block(deflate_state *s, const ct_data *ltree,
                          const ct_data *dtree) {
    unsigned dist;
    int lc;
    unsigned sx = 0;
    unsigned code;
    int extra;

    if (s->sym_next != 0) do {




        dist = s->sym_buf[sx++] & 0xff;
        dist += (unsigned)(s->sym_buf[sx++] & 0xff) << 8;
        lc = s->sym_buf[sx++];

        if (dist == 0) {
            { int len = ltree[lc].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)ltree[lc].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(ltree[lc].fc.code) << s->bi_valid; s->bi_valid += len; }};
                                                       ;
        } else {

            code = _length_code[lc];
            { int len = ltree[code + 256 + 1].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)ltree[code + 256 + 1].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(ltree[code + 256 + 1].fc.code) << s->bi_valid; s->bi_valid += len; }};
            extra = extra_lbits[code];
            if (extra != 0) {
                lc -= base_length[code];
                { int len = extra; if (s->bi_valid > (int)16 - len) { int val = (int)lc; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(lc) << s->bi_valid; s->bi_valid += len; }};
            }
            dist--;
            code = ((dist) < 256 ? _dist_code[dist] : _dist_code[256+((dist)>>7)]);
                                                 ;

            { int len = dtree[code].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)dtree[code].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(dtree[code].fc.code) << s->bi_valid; s->bi_valid += len; }};
            extra = extra_dbits[code];
            if (extra != 0) {
                dist -= (unsigned)base_dist[code];
                { int len = extra; if (s->bi_valid > (int)16 - len) { int val = (int)(int)dist; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)((int)dist) << s->bi_valid; s->bi_valid += len; }};
            }
        }





                                                                       ;


    } while (sx < s->sym_next);

    { int len = ltree[256].dl.len; if (s->bi_valid > (int)16 - len) { int val = (int)ltree[256].fc.code; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)(ltree[256].fc.code) << s->bi_valid; s->bi_valid += len; }};
}
static int detect_data_type(deflate_state *s) {




    unsigned long block_mask = 0xf3ffc07fUL;
    int n;


    for (n = 0; n <= 31; n++, block_mask >>= 1)
        if ((block_mask & 1) && (s->dyn_ltree[n].fc.freq != 0))
            return 0;


    if (s->dyn_ltree[9].fc.freq != 0 || s->dyn_ltree[10].fc.freq != 0
            || s->dyn_ltree[13].fc.freq != 0)
        return 1;
    for (n = 32; n < 256; n++)
        if (s->dyn_ltree[n].fc.freq != 0)
            return 1;




    return 0;
}





void _tr_flush_block(deflate_state *s, charf *buf,
                                   ulg stored_len, int last) {
    ulg opt_lenb, static_lenb;
    int max_blindex = 0;


    if (s->level > 0) {


        if (s->strm->data_type == 2)
            s->strm->data_type = detect_data_type(s);


        build_tree(s, (tree_desc *)(&(s->l_desc)));

                               ;

        build_tree(s, (tree_desc *)(&(s->d_desc)));

                               ;







        max_blindex = build_bl_tree(s);


        opt_lenb = (s->opt_len + 3 + 7) >> 3;
        static_lenb = (s->static_len + 3 + 7) >> 3;



                                 ;


        if (static_lenb <= opt_lenb || s->strategy == 4)

            opt_lenb = static_lenb;

    } else {
                                           ;
        opt_lenb = static_lenb = stored_len + 5;
    }




    if (stored_len + 4 <= opt_lenb && buf != (char*)0) {
        _tr_stored_block(s, buf, stored_len, last);

    } else if (static_lenb == opt_lenb) {
        { int len = 3; if (s->bi_valid > (int)16 - len) { int val = (int)(1<<1) + last; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)((1<<1) + last) << s->bi_valid; s->bi_valid += len; }};
        compress_block(s, (const ct_data *)static_ltree,
                       (const ct_data *)static_dtree);



    } else {
        { int len = 3; if (s->bi_valid > (int)16 - len) { int val = (int)(2<<1) + last; s->bi_buf |= (ush)val << s->bi_valid; { {s->pending_buf[s->pending++] = (Bytef)((uch)((s->bi_buf) & 0xff));}; {s->pending_buf[s->pending++] = (Bytef)((uch)((ush)(s->bi_buf) >> 8));}; }; s->bi_buf = (ush)val >> (16 - s->bi_valid); s->bi_valid += len - 16; } else { s->bi_buf |= (ush)((2<<1) + last) << s->bi_valid; s->bi_valid += len; }};
        send_all_trees(s, s->l_desc.max_code + 1, s->d_desc.max_code + 1,
                       max_blindex + 1);
        compress_block(s, (const ct_data *)s->dyn_ltree,
                       (const ct_data *)s->dyn_dtree);



    }
                                                                     ;



    init_block(s);

    if (last) {
        bi_windup(s);



    }

                                            ;
}





int _tr_tally(deflate_state *s, unsigned dist, unsigned lc) {




    s->sym_buf[s->sym_next++] = (uch)dist;
    s->sym_buf[s->sym_next++] = (uch)(dist >> 8);
    s->sym_buf[s->sym_next++] = (uch)lc;

    if (dist == 0) {

        s->dyn_ltree[lc].fc.freq++;
    } else {
        s->matches++;

        dist--;


                                                                         ;

        s->dyn_ltree[_length_code[lc] + 256 + 1].fc.freq++;
        s->dyn_dtree[((dist) < 256 ? _dist_code[dist] : _dist_code[256+((dist)>>7)])].fc.freq++;
    }
    return (s->sym_next == s->sym_end);
}
