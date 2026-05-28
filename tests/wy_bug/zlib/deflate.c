#include "deflate.h"


const char deflate_copyright[] =
   " deflate 1.3.2.1 Copyright 1995-2026 Jean-loup Gailly and Mark Adler ";







typedef enum {
    need_more,
    block_done,
    finish_started,
    finish_done
} block_state;

typedef block_state (*compress_func)(deflate_state *s, int flush);


static block_state deflate_stored(deflate_state *s, int flush);
static block_state deflate_fast(deflate_state *s, int flush);

static block_state deflate_slow(deflate_state *s, int flush);

static block_state deflate_rle(deflate_state *s, int flush);
static block_state deflate_huff(deflate_state *s, int flush);
typedef struct config_s {
   ush good_length;
   ush max_lazy;
   ush nice_length;
   ush max_chain;
   compress_func func;
} config;







static const config configuration_table[10] = {

        {0, 0, 0, 0, deflate_stored},
        {4, 4, 8, 4, deflate_fast},
        {4, 5, 16, 8, deflate_fast},
        {4, 6, 32, 32, deflate_fast},

        {4, 4, 16, 16, deflate_slow},
        {8, 16, 32, 32, deflate_slow},
        {8, 16, 128, 128, deflate_slow},
        {8, 32, 128, 256, deflate_slow},
        {32, 128, 258, 1024, deflate_slow},
        {32, 258, 258, 4096, deflate_slow}};
static void slide_hash(deflate_state *s) {
    unsigned n, m;
    Posf *p;
    uInt wsize = s->w_size;

    n = s->hash_size;
    p = &s->head[n];
    do {
        m = *--p;
        *p = (Pos)(m >= wsize ? m - wsize : 0);
    } while (--n);

    n = wsize;
    p = &s->prev[n];
    do {
        m = *--p;
        *p = (Pos)(m >= wsize ? m - wsize : 0);



    } while (--n);

    s->slid = 1;
}
static unsigned read_buf(z_streamp strm, Bytef *buf, unsigned size) {
    unsigned len = strm->avail_in;

    if (len > size) len = size;
    if (len == 0) return 0;

    strm->avail_in -= len;

    memcpy(buf, strm->next_in, len);
    if (strm->state->wrap == 1) {
        strm->adler = adler32(strm->adler, buf, len);
    }

    else if (strm->state->wrap == 2) {
        strm->adler = crc32(strm->adler, buf, len);
    }

    strm->next_in += len;
    strm->total_in += len;

    return len;
}
static void fill_window(deflate_state *s) {
    unsigned n;
    unsigned more;
    uInt wsize = s->w_size;

                                                                    ;

    do {
        more = (unsigned)(s->window_size -(ulg)s->lookahead -(ulg)s->strstart);






        if (sizeof(int) <= 2) {



            if (more == 0 && s->strstart == 0 && s->lookahead == 0) {
                more = wsize;

            } else if (more == (unsigned)(-1)) {



                more--;
            }
        }




        if (s->strstart >= wsize + ((s)->w_size-(258 +3 +1))) {

            memcpy(s->window, s->window + wsize, (unsigned)wsize - more);
            s->match_start -= wsize;
            s->strstart -= wsize;
            s->block_start -= (long) wsize;
            if (s->insert > s->strstart)
                s->insert = s->strstart;
            slide_hash(s);
            more += wsize;
        }
        if (s->strm->avail_in == 0) break;
                                     ;

        n = read_buf(s->strm, s->window + s->strstart + s->lookahead, more);
        s->lookahead += n;


        if (s->lookahead + s->insert >= 3) {
            uInt str = s->strstart - s->insert;
            s->ins_h = s->window[str];
            (s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[str + 1])) & s->hash_mask);



            while (s->insert) {
                (s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[str + 3 -1])) & s->hash_mask);

                s->prev[str & s->w_mask] = s->head[s->ins_h];

                s->head[s->ins_h] = (Pos)str;
                str++;
                s->insert--;
                if (s->lookahead + s->insert < 3)
                    break;
            }
        }




    } while (s->lookahead < (258 +3 +1) && s->strm->avail_in != 0);
    if (s->high_water < s->window_size) {
        ulg curr = s->strstart + (ulg)(s->lookahead);
        ulg init;

        if (s->high_water < curr) {



            init = s->window_size - curr;
            if (init > 258)
                init = 258;
            memset(s->window + curr, 0, (unsigned)init);
            s->high_water = curr + init;
        }
        else if (s->high_water < (ulg)curr + 258) {




            init = (ulg)curr + 258 - s->high_water;
            if (init > s->window_size - s->high_water)
                init = s->window_size - s->high_water;
            memset(s->window + s->high_water, 0, (unsigned)init);
            s->high_water += init;
        }
    }


                                        ;
}


int deflateInit_(z_streamp strm, int level, const char *version,
                         int stream_size) {
    return deflateInit2_(strm, level, 8, 15, 8,
                         0, version, stream_size);

}


int deflateInit2_(z_streamp strm, int level, int method,
                          int windowBits, int memLevel, int strategy,
                          const char *version, int stream_size) {
    deflate_state *s;
    int wrap = 1;
    static const char my_version[] = "1.3.2.1-motley";

    if (version == 0 || version[0] != my_version[0] ||
        stream_size != sizeof(z_stream)) {
        return (-6);
    }
    if (strm == 0) return (-2);

    strm->msg = 0;
    if (strm->zalloc == (alloc_func)0) {



        strm->zalloc = zcalloc;
        strm->opaque = (voidpf)0;

    }
    if (strm->zfree == (free_func)0)



        strm->zfree = zcfree;





    if (level == (-1)) level = 6;


    if (windowBits < 0) {
        wrap = 0;
        if (windowBits < -15)
            return (-2);
        windowBits = -windowBits;
    }

    else if (windowBits > 15) {
        wrap = 2;
        windowBits -= 16;
    }

    if (memLevel < 1 || memLevel > 9 || method != 8 ||
        windowBits < 8 || windowBits > 15 || level < 0 || level > 9 ||
        strategy < 0 || strategy > 4 || (windowBits == 8 && wrap != 1)) {
        return (-2);
    }
    if (windowBits == 8) windowBits = 9;
    s = (deflate_state *) (*((strm)->zalloc))((strm)->opaque, (1), (sizeof(deflate_state)));
    if (s == 0) return (-4);
    memset(s, 0, sizeof(deflate_state));
    strm->state = (struct internal_state *)s;
    s->strm = strm;
    s->status = 42;

    s->wrap = wrap;
    s->gzhead = 0;
    s->w_bits = (uInt)windowBits;
    s->w_size = 1 << s->w_bits;
    s->w_mask = s->w_size - 1;

    s->hash_bits = (uInt)memLevel + 7;
    s->hash_size = 1 << s->hash_bits;
    s->hash_mask = s->hash_size - 1;
    s->hash_shift = ((s->hash_bits + 3 -1) / 3);

    s->window = (Bytef *) (*((strm)->zalloc))((strm)->opaque, (s->w_size), (2*sizeof(Byte)));
    s->prev = (Posf *) (*((strm)->zalloc))((strm)->opaque, (s->w_size), (sizeof(Pos)));
    s->head = (Posf *) (*((strm)->zalloc))((strm)->opaque, (s->hash_size), (sizeof(Pos)));

    s->high_water = 0;

    s->lit_bufsize = 1 << (memLevel + 6);
    s->pending_buf = (uchf *) (*((strm)->zalloc))((strm)->opaque, (s->lit_bufsize), (4));
    s->pending_buf_size = (ulg)s->lit_bufsize * 4;

    if (s->window == 0 || s->prev == 0 || s->head == 0 ||
        s->pending_buf == 0) {
        s->status = 666;
        strm->msg = z_errmsg[((-4)) < -6 || ((-4)) > 2 ? 9 : 2 - ((-4))];
        deflateEnd (strm);
        return (-4);
    }





    s->sym_buf = s->pending_buf + s->lit_bufsize;
    s->sym_end = (s->lit_bufsize - 1) * 3;






    s->level = level;
    s->strategy = strategy;
    s->method = (Byte)method;

    return deflateReset(strm);
}




static int deflateStateCheck(z_streamp strm) {
    deflate_state *s;
    if (strm == 0 ||
        strm->zalloc == (alloc_func)0 || strm->zfree == (free_func)0)
        return 1;
    s = strm->state;
    if (s == 0 || s->strm != strm || (s->status != 42 &&

                                           s->status != 57 &&

                                           s->status != 69 &&
                                           s->status != 73 &&
                                           s->status != 91 &&
                                           s->status != 103 &&
                                           s->status != 113 &&
                                           s->status != 666))
        return 1;
    return 0;
}


int deflateSetDictionary(z_streamp strm, const Bytef *dictionary,
                                 uInt dictLength) {
    deflate_state *s;
    uInt str, n;
    int wrap;
    unsigned avail;
            unsigned char *next;

    if (deflateStateCheck(strm) || dictionary == 0)
        return (-2);
    s = strm->state;
    wrap = s->wrap;
    if (wrap == 2 || (wrap == 1 && s->status != 42) || s->lookahead)
        return (-2);


    if (wrap == 1)
        strm->adler = adler32(strm->adler, dictionary, dictLength);
    s->wrap = 0;


    if (dictLength >= s->w_size) {
        if (wrap == 0) {
            do { s->head[s->hash_size - 1] = 0; memset(s->head, 0, (unsigned)(s->hash_size - 1)*sizeof(*s->head)); s->slid = 0; } while (0);
            s->strstart = 0;
            s->block_start = 0L;
            s->insert = 0;
        }
        dictionary += dictLength - s->w_size;
        dictLength = s->w_size;
    }


    avail = strm->avail_in;
    next = strm->next_in;
    strm->avail_in = dictLength;
    strm->next_in = ( Bytef *)dictionary;
    fill_window(s);
    while (s->lookahead >= 3) {
        str = s->strstart;
        n = s->lookahead - (3 -1);
        do {
            (s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[str + 3 -1])) & s->hash_mask);

            s->prev[str & s->w_mask] = s->head[s->ins_h];

            s->head[s->ins_h] = (Pos)str;
            str++;
        } while (--n);
        s->strstart = str;
        s->lookahead = 3 -1;
        fill_window(s);
    }
    s->strstart += s->lookahead;
    s->block_start = (long)s->strstart;
    s->insert = s->lookahead;
    s->lookahead = 0;
    s->match_length = s->prev_length = 3 -1;
    s->match_available = 0;
    strm->next_in = next;
    strm->avail_in = avail;
    s->wrap = wrap;
    return 0;
}


int deflateGetDictionary(z_streamp strm, Bytef *dictionary,
                                 uInt *dictLength) {
    deflate_state *s;
    uInt len;

    if (deflateStateCheck(strm))
        return (-2);
    s = strm->state;
    len = s->strstart + s->lookahead;
    if (len > s->w_size)
        len = s->w_size;
    if (dictionary != 0 && len)
        memcpy(dictionary, s->window + s->strstart + s->lookahead - len, len);
    if (dictLength != 0)
        *dictLength = len;
    return 0;
}


int deflateResetKeep(z_streamp strm) {
    deflate_state *s;

    if (deflateStateCheck(strm)) {
        return (-2);
    }

    strm->total_in = strm->total_out = 0;
    strm->msg = 0;
    strm->data_type = 2;

    s = (deflate_state *)strm->state;
    s->pending = 0;
    s->pending_out = s->pending_buf;

    if (s->wrap < 0) {
        s->wrap = -s->wrap;
    }
    s->status =

        s->wrap == 2 ? 57 :

        42;
    strm->adler =

        s->wrap == 2 ? crc32(0L, 0, 0) :

        adler32(0L, 0, 0);
    s->last_flush = -2;

    _tr_init(s);

    return 0;
}




static void lm_init(deflate_state *s) {
    s->window_size = (ulg)2L*s->w_size;

    do { s->head[s->hash_size - 1] = 0; memset(s->head, 0, (unsigned)(s->hash_size - 1)*sizeof(*s->head)); s->slid = 0; } while (0);



    s->max_lazy_match = configuration_table[s->level].max_lazy;
    s->good_match = configuration_table[s->level].good_length;
    s->nice_match = configuration_table[s->level].nice_length;
    s->max_chain_length = configuration_table[s->level].max_chain;

    s->strstart = 0;
    s->block_start = 0L;
    s->lookahead = 0;
    s->insert = 0;
    s->match_length = s->prev_length = 3 -1;
    s->match_available = 0;
    s->ins_h = 0;
}


int deflateReset(z_streamp strm) {
    int ret;

    ret = deflateResetKeep(strm);
    if (ret == 0)
        lm_init(strm->state);
    return ret;
}


int deflateSetHeader(z_streamp strm, gz_headerp head) {
    if (deflateStateCheck(strm) || strm->state->wrap != 2)
        return (-2);
    strm->state->gzhead = head;
    return 0;
}


int deflatePending(z_streamp strm, unsigned *pending, int *bits) {
    if (deflateStateCheck(strm)) return (-2);
    if (bits != 0)
        *bits = strm->state->bi_valid;
    if (pending != 0) {
        *pending = (unsigned)strm->state->pending;
        if (*pending != strm->state->pending) {
            *pending = (unsigned)-1;
            return (-5);
        }
    }
    return 0;
}


int deflateUsed(z_streamp strm, int *bits) {
    if (deflateStateCheck(strm)) return (-2);
    if (bits != 0)
        *bits = strm->state->bi_used;
    return 0;
}


int deflatePrime(z_streamp strm, int bits, int value) {
    deflate_state *s;
    int put;

    if (deflateStateCheck(strm)) return (-2);
    s = strm->state;





    if (bits < 0 || bits > 16 ||
        s->sym_buf < s->pending_out + ((16 + 7) >> 3))
        return (-5);

    do {
        put = 16 - s->bi_valid;
        if (put > bits)
            put = bits;
        s->bi_buf |= (ush)((value & ((1 << put) - 1)) << s->bi_valid);
        s->bi_valid += put;
        _tr_flush_bits(s);
        value >>= put;
        bits -= put;
    } while (bits);
    return 0;
}


int deflateParams(z_streamp strm, int level, int strategy) {
    deflate_state *s;
    compress_func func;

    if (deflateStateCheck(strm)) return (-2);
    s = strm->state;




    if (level == (-1)) level = 6;

    if (level < 0 || level > 9 || strategy < 0 || strategy > 4) {
        return (-2);
    }
    func = configuration_table[s->level].func;

    if ((strategy != s->strategy || func != configuration_table[level].func) &&
        s->last_flush != -2) {

        int err = deflate(strm, 5);
        if (err == (-2))
            return err;
        if (strm->avail_in || (s->strstart - s->block_start) + s->lookahead)
            return (-5);
    }
    if (s->level != level) {
        if (s->level == 0 && s->matches != 0) {
            if (s->matches == 1)
                slide_hash(s);
            else
                do { s->head[s->hash_size - 1] = 0; memset(s->head, 0, (unsigned)(s->hash_size - 1)*sizeof(*s->head)); s->slid = 0; } while (0);
            s->matches = 0;
        }
        s->level = level;
        s->max_lazy_match = configuration_table[level].max_lazy;
        s->good_match = configuration_table[level].good_length;
        s->nice_match = configuration_table[level].nice_length;
        s->max_chain_length = configuration_table[level].max_chain;
    }
    s->strategy = strategy;
    return 0;
}


int deflateTune(z_streamp strm, int good_length, int max_lazy,
                        int nice_length, int max_chain) {
    deflate_state *s;

    if (deflateStateCheck(strm)) return (-2);
    s = strm->state;
    s->good_match = (uInt)good_length;
    s->max_lazy_match = (uInt)max_lazy;
    s->nice_match = nice_length;
    s->max_chain_length = (uInt)max_chain;
    return 0;
}
z_size_t deflateBound_z(z_streamp strm, z_size_t sourceLen) {
    deflate_state *s;
    z_size_t fixedlen, storelen, wraplen, bound;




    fixedlen = sourceLen + (sourceLen >> 3) + (sourceLen >> 8) +
               (sourceLen >> 9) + 4;
    if (fixedlen < sourceLen)
        fixedlen = (z_size_t)-1;



    storelen = sourceLen + (sourceLen >> 5) + (sourceLen >> 7) +
               (sourceLen >> 11) + 7;
    if (storelen < sourceLen)
        storelen = (z_size_t)-1;


    if (deflateStateCheck(strm)) {
        bound = fixedlen > storelen ? fixedlen : storelen;
        return bound + 18 < bound ? (z_size_t)-1 : bound + 18;
    }


    s = strm->state;
    switch (s->wrap < 0 ? -s->wrap : s->wrap) {
    case 0:
        wraplen = 0;
        break;
    case 1:
        wraplen = 6 + (s->strstart ? 4 : 0);
        break;

    case 2:
        wraplen = 18;
        if (s->gzhead != 0) {
            Bytef *str;
            if (s->gzhead->extra != 0)
                wraplen += 2 + s->gzhead->extra_len;
            str = s->gzhead->name;
            if (str != 0)
                do {
                    wraplen++;
                } while (*str++);
            str = s->gzhead->comment;
            if (str != 0)
                do {
                    wraplen++;
                } while (*str++);
            if (s->gzhead->hcrc)
                wraplen += 2;
        }
        break;

    default:
        wraplen = 18;
    }


    if (s->w_bits != 15 || s->hash_bits != 8 + 7) {
        bound = s->w_bits <= s->hash_bits && s->level ? fixedlen :
                                                        storelen;
        return bound + wraplen < bound ? (z_size_t)-1 : bound + wraplen;
    }



    bound = sourceLen + (sourceLen >> 12) + (sourceLen >> 14) +
            (sourceLen >> 25) + 13 - 6 + wraplen;
    return bound < sourceLen ? (z_size_t)-1 : bound;
}
uLong deflateBound(z_streamp strm, uLong sourceLen) {
    z_size_t bound = deflateBound_z(strm, sourceLen);
    return (uLong)bound != bound ? (uLong)-1 : (uLong)bound;
}






static void putShortMSB(deflate_state *s, uInt b) {
    {s->pending_buf[s->pending++] = (Bytef)((Byte)(b >> 8));};
    {s->pending_buf[s->pending++] = (Bytef)((Byte)(b & 0xff));};
}







static void flush_pending(z_streamp strm) {
    unsigned len;
    deflate_state *s = strm->state;

    _tr_flush_bits(s);
    len = s->pending > strm->avail_out ? strm->avail_out :
                                         (unsigned)s->pending;
    if (len == 0) return;

    memcpy(strm->next_out, s->pending_out, len);
    strm->next_out += len;
    s->pending_out += len;
    strm->total_out += len;
    strm->avail_out -= len;
    s->pending -= len;
    if (s->pending == 0) {
        s->pending_out = s->pending_buf;
    }
}
int deflate(z_streamp strm, int flush) {
    int old_flush;
    deflate_state *s;

    if (deflateStateCheck(strm) || flush > 5 || flush < 0) {
        return (-2);
    }
    s = strm->state;

    if (strm->next_out == 0 ||
        (strm->avail_in != 0 && strm->next_in == 0) ||
        (s->status == 666 && flush != 4)) {
        return (strm->msg = z_errmsg[((-2)) < -6 || ((-2)) > 2 ? 9 : 2 - ((-2))], ((-2)));
    }
    if (strm->avail_out == 0) return (strm->msg = z_errmsg[((-5)) < -6 || ((-5)) > 2 ? 9 : 2 - ((-5))], ((-5)));

    old_flush = s->last_flush;
    s->last_flush = flush;


    if (s->pending != 0) {
        flush_pending(strm);
        if (strm->avail_out == 0) {






            s->last_flush = -1;
            return 0;
        }





    } else if (strm->avail_in == 0 && (((flush) * 2) - ((flush) > 4 ? 9 : 0)) <= (((old_flush) * 2) - ((old_flush) > 4 ? 9 : 0)) &&
               flush != 4) {
        return (strm->msg = z_errmsg[((-5)) < -6 || ((-5)) > 2 ? 9 : 2 - ((-5))], ((-5)));
    }


    if (s->status == 666 && strm->avail_in != 0) {
        return (strm->msg = z_errmsg[((-5)) < -6 || ((-5)) > 2 ? 9 : 2 - ((-5))], ((-5)));
    }


    if (s->status == 42 && s->wrap == 0)
        s->status = 113;
    if (s->status == 42) {

        uInt header = (8 + ((s->w_bits - 8) << 4)) << 8;
        uInt level_flags;

        if (s->strategy >= 2 || s->level < 2)
            level_flags = 0;
        else if (s->level < 6)
            level_flags = 1;
        else if (s->level == 6)
            level_flags = 2;
        else
            level_flags = 3;
        header |= (level_flags << 6);
        if (s->strstart != 0) header |= 0x20;
        header += 31 - (header % 31);

        putShortMSB(s, header);


        if (s->strstart != 0) {
            putShortMSB(s, (uInt)(strm->adler >> 16));
            putShortMSB(s, (uInt)(strm->adler & 0xffff));
        }
        strm->adler = adler32(0L, 0, 0);
        s->status = 113;


        flush_pending(strm);
        if (s->pending != 0) {
            s->last_flush = -1;
            return 0;
        }
    }

    if (s->status == 57) {

        strm->adler = crc32(0L, 0, 0);
        {s->pending_buf[s->pending++] = (Bytef)(31);};
        {s->pending_buf[s->pending++] = (Bytef)(139);};
        {s->pending_buf[s->pending++] = (Bytef)(8);};
        if (s->gzhead == 0) {
            {s->pending_buf[s->pending++] = (Bytef)(0);};
            {s->pending_buf[s->pending++] = (Bytef)(0);};
            {s->pending_buf[s->pending++] = (Bytef)(0);};
            {s->pending_buf[s->pending++] = (Bytef)(0);};
            {s->pending_buf[s->pending++] = (Bytef)(0);};
            {s->pending_buf[s->pending++] = (Bytef)(s->level == 9 ? 2 : (s->strategy >= 2 || s->level < 2 ? 4 : 0));};


            {s->pending_buf[s->pending++] = (Bytef)(3);};
            s->status = 113;


            flush_pending(strm);
            if (s->pending != 0) {
                s->last_flush = -1;
                return 0;
            }
        }
        else {
            {s->pending_buf[s->pending++] = (Bytef)((s->gzhead->text ? 1 : 0) + (s->gzhead->hcrc ? 2 : 0) + (s->gzhead->extra == 0 ? 0 : 4) + (s->gzhead->name == 0 ? 0 : 8) + (s->gzhead->comment == 0 ? 0 : 16));};





            {s->pending_buf[s->pending++] = (Bytef)((Byte)(s->gzhead->time & 0xff));};
            {s->pending_buf[s->pending++] = (Bytef)((Byte)((s->gzhead->time >> 8) & 0xff));};
            {s->pending_buf[s->pending++] = (Bytef)((Byte)((s->gzhead->time >> 16) & 0xff));};
            {s->pending_buf[s->pending++] = (Bytef)((Byte)((s->gzhead->time >> 24) & 0xff));};
            {s->pending_buf[s->pending++] = (Bytef)(s->level == 9 ? 2 : (s->strategy >= 2 || s->level < 2 ? 4 : 0));};


            {s->pending_buf[s->pending++] = (Bytef)(s->gzhead->os & 0xff);};
            if (s->gzhead->extra != 0) {
                {s->pending_buf[s->pending++] = (Bytef)(s->gzhead->extra_len & 0xff);};
                {s->pending_buf[s->pending++] = (Bytef)((s->gzhead->extra_len >> 8) & 0xff);};
            }
            if (s->gzhead->hcrc)
                strm->adler = crc32_z(strm->adler, s->pending_buf,
                                      s->pending);
            s->gzindex = 0;
            s->status = 69;
        }
    }
    if (s->status == 69) {
        if (s->gzhead->extra != 0) {
            ulg beg = s->pending;
            ulg left = (s->gzhead->extra_len & 0xffff) - s->gzindex;
            while (s->pending + left > s->pending_buf_size) {
                ulg copy = s->pending_buf_size - s->pending;
                memcpy(s->pending_buf + s->pending,
                        s->gzhead->extra + s->gzindex, copy);
                s->pending = s->pending_buf_size;
                do { if (s->gzhead->hcrc && s->pending > (beg)) strm->adler = crc32_z(strm->adler, s->pending_buf + (beg), s->pending - (beg)); } while (0);
                s->gzindex += copy;
                flush_pending(strm);
                if (s->pending != 0) {
                    s->last_flush = -1;
                    return 0;
                }
                beg = 0;
                left -= copy;
            }
            memcpy(s->pending_buf + s->pending,
                    s->gzhead->extra + s->gzindex, left);
            s->pending += left;
            do { if (s->gzhead->hcrc && s->pending > (beg)) strm->adler = crc32_z(strm->adler, s->pending_buf + (beg), s->pending - (beg)); } while (0);
            s->gzindex = 0;
        }
        s->status = 73;
    }
    if (s->status == 73) {
        if (s->gzhead->name != 0) {
            ulg beg = s->pending;
            int val;
            do {
                if (s->pending == s->pending_buf_size) {
                    do { if (s->gzhead->hcrc && s->pending > (beg)) strm->adler = crc32_z(strm->adler, s->pending_buf + (beg), s->pending - (beg)); } while (0);
                    flush_pending(strm);
                    if (s->pending != 0) {
                        s->last_flush = -1;
                        return 0;
                    }
                    beg = 0;
                }
                val = s->gzhead->name[s->gzindex++];
                {s->pending_buf[s->pending++] = (Bytef)(val);};
            } while (val != 0);
            do { if (s->gzhead->hcrc && s->pending > (beg)) strm->adler = crc32_z(strm->adler, s->pending_buf + (beg), s->pending - (beg)); } while (0);
            s->gzindex = 0;
        }
        s->status = 91;
    }
    if (s->status == 91) {
        if (s->gzhead->comment != 0) {
            ulg beg = s->pending;
            int val;
            do {
                if (s->pending == s->pending_buf_size) {
                    do { if (s->gzhead->hcrc && s->pending > (beg)) strm->adler = crc32_z(strm->adler, s->pending_buf + (beg), s->pending - (beg)); } while (0);
                    flush_pending(strm);
                    if (s->pending != 0) {
                        s->last_flush = -1;
                        return 0;
                    }
                    beg = 0;
                }
                val = s->gzhead->comment[s->gzindex++];
                {s->pending_buf[s->pending++] = (Bytef)(val);};
            } while (val != 0);
            do { if (s->gzhead->hcrc && s->pending > (beg)) strm->adler = crc32_z(strm->adler, s->pending_buf + (beg), s->pending - (beg)); } while (0);
        }
        s->status = 103;
    }
    if (s->status == 103) {
        if (s->gzhead->hcrc) {
            if (s->pending + 2 > s->pending_buf_size) {
                flush_pending(strm);
                if (s->pending != 0) {
                    s->last_flush = -1;
                    return 0;
                }
            }
            {s->pending_buf[s->pending++] = (Bytef)((Byte)(strm->adler & 0xff));};
            {s->pending_buf[s->pending++] = (Bytef)((Byte)((strm->adler >> 8) & 0xff));};
            strm->adler = crc32(0L, 0, 0);
        }
        s->status = 113;


        flush_pending(strm);
        if (s->pending != 0) {
            s->last_flush = -1;
            return 0;
        }
    }




    if (strm->avail_in != 0 || s->lookahead != 0 ||
        (flush != 0 && s->status != 666)) {
        block_state bstate;

        bstate = s->level == 0 ? deflate_stored(s, flush) :
                 s->strategy == 2 ? deflate_huff(s, flush) :
                 s->strategy == 3 ? deflate_rle(s, flush) :
                 (*(configuration_table[s->level].func))(s, flush);

        if (bstate == finish_started || bstate == finish_done) {
            s->status = 666;
        }
        if (bstate == need_more || bstate == finish_started) {
            if (strm->avail_out == 0) {
                s->last_flush = -1;
            }
            return 0;







        }
        if (bstate == block_done) {
            if (flush == 1) {
                _tr_align(s);
            } else if (flush != 5) {
                _tr_stored_block(s, (char*)0, 0L, 0);



                if (flush == 3) {
                    do { s->head[s->hash_size - 1] = 0; memset(s->head, 0, (unsigned)(s->hash_size - 1)*sizeof(*s->head)); s->slid = 0; } while (0);
                    if (s->lookahead == 0) {
                        s->strstart = 0;
                        s->block_start = 0L;
                        s->insert = 0;
                    }
                }
            }
            flush_pending(strm);
            if (strm->avail_out == 0) {
              s->last_flush = -1;
              return 0;
            }
        }
    }

    if (flush != 4) return 0;
    if (s->wrap <= 0) return 1;



    if (s->wrap == 2) {
        {s->pending_buf[s->pending++] = (Bytef)((Byte)(strm->adler & 0xff));};
        {s->pending_buf[s->pending++] = (Bytef)((Byte)((strm->adler >> 8) & 0xff));};
        {s->pending_buf[s->pending++] = (Bytef)((Byte)((strm->adler >> 16) & 0xff));};
        {s->pending_buf[s->pending++] = (Bytef)((Byte)((strm->adler >> 24) & 0xff));};
        {s->pending_buf[s->pending++] = (Bytef)((Byte)(strm->total_in & 0xff));};
        {s->pending_buf[s->pending++] = (Bytef)((Byte)((strm->total_in >> 8) & 0xff));};
        {s->pending_buf[s->pending++] = (Bytef)((Byte)((strm->total_in >> 16) & 0xff));};
        {s->pending_buf[s->pending++] = (Bytef)((Byte)((strm->total_in >> 24) & 0xff));};
    }
    else

    {
        putShortMSB(s, (uInt)(strm->adler >> 16));
        putShortMSB(s, (uInt)(strm->adler & 0xffff));
    }
    flush_pending(strm);



    if (s->wrap > 0) s->wrap = -s->wrap;
    return s->pending != 0 ? 0 : 1;
}


int deflateEnd(z_streamp strm) {
    int status;

    if (deflateStateCheck(strm)) return (-2);

    status = strm->state->status;


    {if (strm->state->pending_buf) (*((strm)->zfree))((strm)->opaque, (voidpf)(strm->state->pending_buf));};
    {if (strm->state->head) (*((strm)->zfree))((strm)->opaque, (voidpf)(strm->state->head));};
    {if (strm->state->prev) (*((strm)->zfree))((strm)->opaque, (voidpf)(strm->state->prev));};
    {if (strm->state->window) (*((strm)->zfree))((strm)->opaque, (voidpf)(strm->state->window));};

    (*((strm)->zfree))((strm)->opaque, (voidpf)(strm->state));
    strm->state = 0;

    return status == 113 ? (-3) : 0;
}






int deflateCopy(z_streamp dest, z_streamp source) {





    deflate_state *ds;
    deflate_state *ss;


    if (deflateStateCheck(source) || dest == 0) {
        return (-2);
    }

    ss = source->state;

    memcpy(dest, source, sizeof(z_stream));

    ds = (deflate_state *) (*((dest)->zalloc))((dest)->opaque, (1), (sizeof(deflate_state)));
    if (ds == 0) return (-4);
    memset(ds, 0, sizeof(deflate_state));
    dest->state = (struct internal_state *) ds;
    memcpy(ds, ss, sizeof(deflate_state));
    ds->strm = dest;

    ds->window = (Bytef *) (*((dest)->zalloc))((dest)->opaque, (ds->w_size), (2*sizeof(Byte)));
    ds->prev = (Posf *) (*((dest)->zalloc))((dest)->opaque, (ds->w_size), (sizeof(Pos)));
    ds->head = (Posf *) (*((dest)->zalloc))((dest)->opaque, (ds->hash_size), (sizeof(Pos)));
    ds->pending_buf = (uchf *) (*((dest)->zalloc))((dest)->opaque, (ds->lit_bufsize), (4));

    if (ds->window == 0 || ds->prev == 0 || ds->head == 0 ||
        ds->pending_buf == 0) {
        deflateEnd (dest);
        return (-4);
    }

    memcpy(ds->window, ss->window, ss->high_water);
    memcpy(ds->prev, ss->prev,
            (ss->slid || ss->strstart - ss->insert > ds->w_size ? ds->w_size :
                ss->strstart - ss->insert) * sizeof(Pos));
    memcpy(ds->head, ss->head, ds->hash_size * sizeof(Pos));

    ds->pending_out = ds->pending_buf + (ss->pending_out - ss->pending_buf);
    memcpy(ds->pending_out, ss->pending_out, ss->pending);






    ds->sym_buf = ds->pending_buf + ds->lit_bufsize;
    memcpy(ds->sym_buf, ss->sym_buf, ss->sym_next);


    ds->l_desc.dyn_tree = ds->dyn_ltree;
    ds->d_desc.dyn_tree = ds->dyn_dtree;
    ds->bl_desc.dyn_tree = ds->bl_tree;

    return 0;

}
static uInt longest_match(deflate_state *s, IPos cur_match) {
    unsigned chain_length = s->max_chain_length;
    Bytef *scan = s->window + s->strstart;
    Bytef *match;
    int len;
    int best_len = (int)s->prev_length;
    int nice_match = s->nice_match;
    IPos limit = s->strstart > (IPos)((s)->w_size-(258 +3 +1)) ?
        s->strstart - (IPos)((s)->w_size-(258 +3 +1)) : 0;



    Posf *prev = s->prev;
    uInt wmask = s->w_mask;
    Bytef *strend = s->window + s->strstart + 258;
    Byte scan_end1 = scan[best_len - 1];
    Byte scan_end = scan[best_len];





                                                                    ;


    if (s->prev_length >= s->good_match) {
        chain_length >>= 2;
    }



    if ((uInt)nice_match > s->lookahead) nice_match = (int)s->lookahead;


                            ;

    do {
                                                    ;
        match = s->window + cur_match;
        if (match[best_len] != scan_end ||
            match[best_len - 1] != scan_end1 ||
            *match != *scan ||
            *++match != scan[1]) continue;







        scan += 2, match++;
                                            ;




        do {
        } while (*++scan == *++match && *++scan == *++match &&
                 *++scan == *++match && *++scan == *++match &&
                 *++scan == *++match && *++scan == *++match &&
                 *++scan == *++match && *++scan == *++match &&
                 scan < strend);


                           ;

        len = 258 - (int)(strend - scan);
        scan = strend - 258;



        if (len > best_len) {
            s->match_start = cur_match;
            best_len = len;
            if (len >= nice_match) break;



            scan_end1 = scan[best_len - 1];
            scan_end = scan[best_len];

        }
    } while ((cur_match = prev[cur_match & wmask]) > limit
             && --chain_length != 0);

    if ((uInt)best_len <= s->lookahead) return (uInt)best_len;
    return s->lookahead;
}
static block_state deflate_stored(deflate_state *s, int flush) {




    unsigned min_block = (unsigned)(((s->pending_buf_size - 5) > (s->w_size) ? (s->w_size) : (s->pending_buf_size - 5)));





    int last = 0;
    unsigned len, left, have;
    unsigned used = s->strm->avail_in;
    do {




        len = 65535;
        have = ((unsigned)s->bi_valid + 42) >> 3;
        if (s->strm->avail_out < have)
            break;

        have = s->strm->avail_out - have;
        left = (unsigned)(s->strstart - s->block_start);
        if (len > (ulg)left + s->strm->avail_in)
            len = left + s->strm->avail_in;
        if (len > have)
            len = have;






        if (len < min_block && ((len == 0 && flush != 4) ||
                                flush == 0 ||
                                len != left + s->strm->avail_in))
            break;




        last = flush == 4 && len == left + s->strm->avail_in ? 1 : 0;
        _tr_stored_block(s, (char *)0, 0L, last);


        s->pending_buf[s->pending - 4] = (Bytef)len;
        s->pending_buf[s->pending - 3] = (Bytef)(len >> 8);
        s->pending_buf[s->pending - 2] = (Bytef)~len;
        s->pending_buf[s->pending - 1] = (Bytef)(~len >> 8);


        flush_pending(s->strm);
        if (left) {
            if (left > len)
                left = len;
            memcpy(s->strm->next_out, s->window + s->block_start, left);
            s->strm->next_out += left;
            s->strm->avail_out -= left;
            s->strm->total_out += left;
            s->block_start += left;
            len -= left;
        }




        if (len) {
            read_buf(s->strm, s->strm->next_out, len);
            s->strm->next_out += len;
            s->strm->avail_out -= len;
            s->strm->total_out += len;
        }
    } while (last == 0);







    used -= s->strm->avail_in;
    if (used) {



        if (used >= s->w_size) {
            s->matches = 2;
            memcpy(s->window, s->strm->next_in - s->w_size, s->w_size);
            s->strstart = s->w_size;
            s->insert = s->strstart;
        }
        else {
            if (s->window_size - s->strstart <= used) {

                s->strstart -= s->w_size;
                memcpy(s->window, s->window + s->w_size, s->strstart);
                if (s->matches < 2)
                    s->matches++;
                if (s->insert > s->strstart)
                    s->insert = s->strstart;
            }
            memcpy(s->window + s->strstart, s->strm->next_in - used, used);
            s->strstart += used;
            s->insert += ((used) > (s->w_size - s->insert) ? (s->w_size - s->insert) : (used));
        }
        s->block_start = s->strstart;
    }
    if (s->high_water < s->strstart)
        s->high_water = s->strstart;


    if (last) {
        s->bi_used = 8;
        return finish_done;
    }


    if (flush != 0 && flush != 4 &&
        s->strm->avail_in == 0 && (long)s->strstart == s->block_start)
        return block_done;


    have = (unsigned)(s->window_size - s->strstart);
    if (s->strm->avail_in > have && s->block_start >= (long)s->w_size) {

        s->block_start -= s->w_size;
        s->strstart -= s->w_size;
        memcpy(s->window, s->window + s->w_size, s->strstart);
        if (s->matches < 2)
            s->matches++;
        have += s->w_size;
        if (s->insert > s->strstart)
            s->insert = s->strstart;
    }
    if (have > s->strm->avail_in)
        have = s->strm->avail_in;
    if (have) {
        read_buf(s->strm, s->window + s->strstart, have);
        s->strstart += have;
        s->insert += ((have) > (s->w_size - s->insert) ? (s->w_size - s->insert) : (have));
    }
    if (s->high_water < s->strstart)
        s->high_water = s->strstart;






    have = ((unsigned)s->bi_valid + 42) >> 3;

    have = (unsigned)((s->pending_buf_size - have) > (65535) ? (65535) : (s->pending_buf_size - have));
    min_block = ((have) > (s->w_size) ? (s->w_size) : (have));
    left = (unsigned)(s->strstart - s->block_start);
    if (left >= min_block ||
        ((left || flush == 4) && flush != 0 &&
         s->strm->avail_in == 0 && left <= have)) {
        len = ((left) > (have) ? (have) : (left));
        last = flush == 4 && s->strm->avail_in == 0 &&
               len == left ? 1 : 0;
        _tr_stored_block(s, (charf *)s->window + s->block_start, len, last);
        s->block_start += len;
        flush_pending(s->strm);
    }


    if (last)
        s->bi_used = 8;
    return last ? finish_started : need_more;
}
static block_state deflate_fast(deflate_state *s, int flush) {
    IPos hash_head;
    int bflush;

    for (;;) {





        if (s->lookahead < (258 +3 +1)) {
            fill_window(s);
            if (s->lookahead < (258 +3 +1) && flush == 0) {
                return need_more;
            }
            if (s->lookahead == 0) break;
        }




        hash_head = 0;
        if (s->lookahead >= 3) {
            ((s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[(s->strstart) + (3 -1)])) & s->hash_mask), hash_head = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h], s->head[s->ins_h] = (Pos)(s->strstart));
        }




        if (hash_head != 0 && s->strstart - hash_head <= ((s)->w_size-(258 +3 +1))) {




            s->match_length = longest_match (s, hash_head);

        }
        if (s->match_length >= 3) {
                                                                             ;

            { uch len = (uch)(s->match_length - 3); ush dist = (ush)(s->strstart - s->match_start); s->sym_buf[s->sym_next++] = (uch)dist; s->sym_buf[s->sym_next++] = (uch)(dist >> 8); s->sym_buf[s->sym_next++] = len; dist--; s->dyn_ltree[_length_code[len]+256 +1].fc.freq++; s->dyn_dtree[((dist) < 256 ? _dist_code[dist] : _dist_code[256+((dist)>>7)])].fc.freq++; bflush = (s->sym_next == s->sym_end); };


            s->lookahead -= s->match_length;





            if (s->match_length <= s->max_lazy_match &&
                s->lookahead >= 3) {
                s->match_length--;
                do {
                    s->strstart++;
                    ((s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[(s->strstart) + (3 -1)])) & s->hash_mask), hash_head = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h], s->head[s->ins_h] = (Pos)(s->strstart));



                } while (--s->match_length != 0);
                s->strstart++;
            } else

            {
                s->strstart += s->match_length;
                s->match_length = 0;
                s->ins_h = s->window[s->strstart];
                (s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[s->strstart + 1])) & s->hash_mask);






            }
        } else {

                                                          ;
            { uch cc = (s->window[s->strstart]); s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = cc; s->dyn_ltree[cc].fc.freq++; bflush = (s->sym_next == s->sym_end); };
            s->lookahead--;
            s->strstart++;
        }
        if (bflush) { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };
    }
    s->insert = s->strstart < 3 -1 ? s->strstart : 3 -1;
    if (flush == 4) {
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (1)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (1) ? finish_started : need_more; };
        return finish_done;
    }
    if (s->sym_next)
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };
    return block_done;
}







static block_state deflate_slow(deflate_state *s, int flush) {
    IPos hash_head;
    int bflush;


    for (;;) {





        if (s->lookahead < (258 +3 +1)) {
            fill_window(s);
            if (s->lookahead < (258 +3 +1) && flush == 0) {
                return need_more;
            }
            if (s->lookahead == 0) break;
        }




        hash_head = 0;
        if (s->lookahead >= 3) {
            ((s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[(s->strstart) + (3 -1)])) & s->hash_mask), hash_head = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h], s->head[s->ins_h] = (Pos)(s->strstart));
        }



        s->prev_length = s->match_length, s->prev_match = s->match_start;
        s->match_length = 3 -1;

        if (hash_head != 0 && s->prev_length < s->max_lazy_match &&
            s->strstart - hash_head <= ((s)->w_size-(258 +3 +1))) {




            s->match_length = longest_match (s, hash_head);


            if (s->match_length <= 5 && (s->strategy == 1

                || (s->match_length == 3 &&
                    s->strstart - s->match_start > 4096)

                )) {




                s->match_length = 3 -1;
            }
        }



        if (s->prev_length >= 3 && s->match_length <= s->prev_length) {
            uInt max_insert = s->strstart + s->lookahead - 3;


                                                                               ;

            { uch len = (uch)(s->prev_length - 3); ush dist = (ush)(s->strstart - 1 - s->prev_match); s->sym_buf[s->sym_next++] = (uch)dist; s->sym_buf[s->sym_next++] = (uch)(dist >> 8); s->sym_buf[s->sym_next++] = len; dist--; s->dyn_ltree[_length_code[len]+256 +1].fc.freq++; s->dyn_dtree[((dist) < 256 ? _dist_code[dist] : _dist_code[256+((dist)>>7)])].fc.freq++; bflush = (s->sym_next == s->sym_end); };







            s->lookahead -= s->prev_length - 1;
            s->prev_length -= 2;
            do {
                if (++s->strstart <= max_insert) {
                    ((s->ins_h = (((s->ins_h) << s->hash_shift) ^ (s->window[(s->strstart) + (3 -1)])) & s->hash_mask), hash_head = s->prev[(s->strstart) & s->w_mask] = s->head[s->ins_h], s->head[s->ins_h] = (Pos)(s->strstart));
                }
            } while (--s->prev_length != 0);
            s->match_available = 0;
            s->match_length = 3 -1;
            s->strstart++;

            if (bflush) { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };

        } else if (s->match_available) {




                                                              ;
            { uch cc = (s->window[s->strstart - 1]); s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = cc; s->dyn_ltree[cc].fc.freq++; bflush = (s->sym_next == s->sym_end); };
            if (bflush) {
                { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; };
            }
            s->strstart++;
            s->lookahead--;
            if (s->strm->avail_out == 0) return need_more;
        } else {



            s->match_available = 1;
            s->strstart++;
            s->lookahead--;
        }
    }
                                             ;
    if (s->match_available) {
                                                          ;
        { uch cc = (s->window[s->strstart - 1]); s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = cc; s->dyn_ltree[cc].fc.freq++; bflush = (s->sym_next == s->sym_end); };
        s->match_available = 0;
    }
    s->insert = s->strstart < 3 -1 ? s->strstart : 3 -1;
    if (flush == 4) {
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (1)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (1) ? finish_started : need_more; };
        return finish_done;
    }
    if (s->sym_next)
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };
    return block_done;
}







static block_state deflate_rle(deflate_state *s, int flush) {
    int bflush;
    uInt prev;
    Bytef *scan, *strend;

    for (;;) {




        if (s->lookahead <= 258) {
            fill_window(s);
            if (s->lookahead <= 258 && flush == 0) {
                return need_more;
            }
            if (s->lookahead == 0) break;
        }


        s->match_length = 0;
        if (s->lookahead >= 3 && s->strstart > 0) {
            scan = s->window + s->strstart - 1;
            prev = *scan;
            if (prev == *++scan && prev == *++scan && prev == *++scan) {
                strend = s->window + s->strstart + 258;
                do {
                } while (prev == *++scan && prev == *++scan &&
                         prev == *++scan && prev == *++scan &&
                         prev == *++scan && prev == *++scan &&
                         prev == *++scan && prev == *++scan &&
                         scan < strend);
                s->match_length = 258 - (uInt)(strend - scan);
                if (s->match_length > s->lookahead)
                    s->match_length = s->lookahead;
            }

                               ;
        }


        if (s->match_length >= 3) {
                                                                              ;

            { uch len = (uch)(s->match_length - 3); ush dist = (ush)(1); s->sym_buf[s->sym_next++] = (uch)dist; s->sym_buf[s->sym_next++] = (uch)(dist >> 8); s->sym_buf[s->sym_next++] = len; dist--; s->dyn_ltree[_length_code[len]+256 +1].fc.freq++; s->dyn_dtree[((dist) < 256 ? _dist_code[dist] : _dist_code[256+((dist)>>7)])].fc.freq++; bflush = (s->sym_next == s->sym_end); };

            s->lookahead -= s->match_length;
            s->strstart += s->match_length;
            s->match_length = 0;
        } else {

                                                          ;
            { uch cc = (s->window[s->strstart]); s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = cc; s->dyn_ltree[cc].fc.freq++; bflush = (s->sym_next == s->sym_end); };
            s->lookahead--;
            s->strstart++;
        }
        if (bflush) { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };
    }
    s->insert = 0;
    if (flush == 4) {
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (1)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (1) ? finish_started : need_more; };
        return finish_done;
    }
    if (s->sym_next)
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };
    return block_done;
}





static block_state deflate_huff(deflate_state *s, int flush) {
    int bflush;

    for (;;) {

        if (s->lookahead == 0) {
            fill_window(s);
            if (s->lookahead == 0) {
                if (flush == 0)
                    return need_more;
                break;
            }
        }


        s->match_length = 0;
                                                      ;
        { uch cc = (s->window[s->strstart]); s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = 0; s->sym_buf[s->sym_next++] = cc; s->dyn_ltree[cc].fc.freq++; bflush = (s->sym_next == s->sym_end); };
        s->lookahead--;
        s->strstart++;
        if (bflush) { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };
    }
    s->insert = 0;
    if (flush == 4) {
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (1)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (1) ? finish_started : need_more; };
        return finish_done;
    }
    if (s->sym_next)
        { { _tr_flush_block(s, (s->block_start >= 0L ? (charf *)&s->window[(unsigned)s->block_start] : (charf *)0), (ulg)((long)s->strstart - s->block_start), (0)); s->block_start = s->strstart; flush_pending(s->strm); ; }; if (s->strm->avail_out == 0) return (0) ? finish_started : need_more; };
    return block_done;
}
