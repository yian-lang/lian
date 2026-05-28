#include "zutil.h"
#include "inftrees.h"
#include "inflate.h"
#include "inffast.h"


static int inflateStateCheck(z_streamp strm) {
    struct inflate_state *state;
    if (strm == 0 ||
        strm->zalloc == (alloc_func)0 || strm->zfree == (free_func)0)
        return 1;
    state = (struct inflate_state *)strm->state;
    if (state == 0 || state->strm != strm ||
        state->mode < HEAD || state->mode > SYNC)
        return 1;
    return 0;
}

int inflateResetKeep(z_streamp strm) {
    struct inflate_state *state;

    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;
    strm->total_in = strm->total_out = state->total = 0;
    strm->msg = 0;
    strm->data_type = 0;
    if (state->wrap)
        strm->adler = state->wrap & 1;
    state->mode = HEAD;
    state->last = 0;
    state->havedict = 0;
    state->flags = -1;
    state->dmax = 32768U;
    state->head = 0;
    state->hold = 0;
    state->bits = 0;
    state->lencode = state->distcode = state->next = state->codes;
    state->sane = 1;
    state->back = -1;
                                        ;
    return 0;
}

int inflateReset(z_streamp strm) {
    struct inflate_state *state;

    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;
    state->wsize = 0;
    state->whave = 0;
    state->wnext = 0;
    return inflateResetKeep(strm);
}

int inflateReset2(z_streamp strm, int windowBits) {
    int wrap;
    struct inflate_state *state;


    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;


    if (windowBits < 0) {
        if (windowBits < -15)
            return (-2);
        wrap = 0;
        windowBits = -windowBits;
    }
    else {
        wrap = (windowBits >> 4) + 5;

        if (windowBits < 48)
            windowBits &= 15;

    }


    if (windowBits && (windowBits < 8 || windowBits > 15))
        return (-2);
    if (state->window != 0 && state->wbits != (unsigned)windowBits) {
        (*((strm)->zfree))((strm)->opaque, (voidpf)(state->window));
        state->window = 0;
    }


    state->wrap = wrap;
    state->wbits = (unsigned)windowBits;
    return inflateReset(strm);
}

int inflateInit2_(z_streamp strm, int windowBits,
                          const char *version, int stream_size) {
    int ret;
    struct inflate_state *state;

    if (version == 0 || version[0] != "1.3.2.1-motley"[0] ||
        stream_size != (int)(sizeof(z_stream)))
        return (-6);
    if (strm == 0) return (-2);
    strm->msg = 0;
    if (strm->zalloc == (alloc_func)0) {



        strm->zalloc = zcalloc;
        strm->opaque = (voidpf)0;

    }
    if (strm->zfree == (free_func)0)



        strm->zfree = zcfree;

    state = (struct inflate_state *)
            (*((strm)->zalloc))((strm)->opaque, (1), (sizeof(struct inflate_state)));
    if (state == 0) return (-4);
    memset(state, 0, sizeof(struct inflate_state));
                                            ;
    strm->state = (struct internal_state *)state;
    state->strm = strm;
    state->window = 0;
    state->mode = HEAD;
    ret = inflateReset2(strm, windowBits);
    if (ret != 0) {
        (*((strm)->zfree))((strm)->opaque, (voidpf)(state));
        strm->state = 0;
    }
    return ret;
}

int inflateInit_(z_streamp strm, const char *version,
                         int stream_size) {
    return inflateInit2_(strm, 15, version, stream_size);
}

int inflatePrime(z_streamp strm, int bits, int value) {
    struct inflate_state *state;

    if (inflateStateCheck(strm)) return (-2);
    if (bits == 0)
        return 0;
    state = (struct inflate_state *)strm->state;
    if (bits < 0) {
        state->hold = 0;
        state->bits = 0;
        return 0;
    }
    if (bits > 16 || state->bits + (uInt)bits > 32) return (-2);
    value &= (1L << bits) - 1;
    state->hold += (unsigned long)value << state->bits;
    state->bits += (uInt)bits;
    return 0;
}
static int updatewindow(z_streamp strm, const Bytef *end, unsigned copy) {
    struct inflate_state *state;
    unsigned dist;

    state = (struct inflate_state *)strm->state;


    if (state->window == 0) {
        state->window = (unsigned char *)
                        (*((strm)->zalloc))((strm)->opaque, (1U << state->wbits), (sizeof(unsigned char)));

        if (state->window == 0) return 1;
    }


    if (state->wsize == 0) {
        state->wsize = 1U << state->wbits;
        state->wnext = 0;
        state->whave = 0;
    }


    if (copy >= state->wsize) {
        memcpy(state->window, end - state->wsize, state->wsize);
        state->wnext = 0;
        state->whave = state->wsize;
    }
    else {
        dist = state->wsize - state->wnext;
        if (dist > copy) dist = copy;
        memcpy(state->window + state->wnext, end - copy, dist);
        copy -= dist;
        if (copy) {
            memcpy(state->window, end - copy, copy);
            state->wnext = copy;
            state->whave = state->wsize;
        }
        else {
            state->wnext += dist;
            if (state->wnext == state->wsize) state->wnext = 0;
            if (state->whave < state->wsize) state->whave += dist;
        }
    }
    return 0;
}
int inflate(z_streamp strm, int flush) {
    struct inflate_state *state;
            unsigned char *next;
    unsigned char *put;
    unsigned have, left;
    unsigned long hold;
    unsigned bits;
    unsigned in, out;
    unsigned copy;
    unsigned char *from;
    code here;
    code last;
    unsigned len;
    int ret;

    unsigned char hbuf[4];

    static const unsigned short order[19] =
        {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

    if (inflateStateCheck(strm) || strm->next_out == 0 ||
        (strm->next_in == 0 && strm->avail_in != 0))
        return (-2);

    state = (struct inflate_state *)strm->state;
    if (state->mode == TYPE) state->mode = TYPEDO;
    do { put = strm->next_out; left = strm->avail_out; next = strm->next_in; have = strm->avail_in; hold = state->hold; bits = state->bits; } while (0);
    in = have;
    out = left;
    ret = 0;
    for (;;)
        switch (state->mode) {
        case HEAD:
            if (state->wrap == 0) {
                state->mode = TYPEDO;
                break;
            }
            do { while (bits < (unsigned)(16)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);

            if ((state->wrap & 2) && hold == 0x8b1f) {
                if (state->wbits == 0)
                    state->wbits = 15;
                state->check = crc32(0L, 0, 0);
                do { hbuf[0] = (unsigned char)(hold); hbuf[1] = (unsigned char)((hold) >> 8); state->check = crc32(state->check, hbuf, 2); } while (0);
                do { hold = 0; bits = 0; } while (0);
                state->mode = FLAGS;
                break;
            }
            if (state->head != 0)
                state->head->done = -1;
            if (!(state->wrap & 1) ||



                ((((unsigned)hold & ((1U << (8)) - 1)) << 8) + (hold >> 8)) % 31) {
                strm->msg = ( char *)"incorrect header check";
                state->mode = BAD;
                break;
            }
            if (((unsigned)hold & ((1U << (4)) - 1)) != 8) {
                strm->msg = ( char *)"unknown compression method";
                state->mode = BAD;
                break;
            }
            do { hold >>= (4); bits -= (unsigned)(4); } while (0);
            len = ((unsigned)hold & ((1U << (4)) - 1)) + 8;
            if (state->wbits == 0)
                state->wbits = len;
            if (len > 15 || len > state->wbits) {
                strm->msg = ( char *)"invalid window size";
                state->mode = BAD;
                break;
            }
            state->dmax = 1U << len;
            state->flags = 0;
                                                           ;
            strm->adler = state->check = adler32(0L, 0, 0);
            state->mode = hold & 0x200 ? DICTID : TYPE;
            do { hold = 0; bits = 0; } while (0);
            break;

        case FLAGS:
            do { while (bits < (unsigned)(16)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            state->flags = (int)(hold);
            if ((state->flags & 0xff) != 8) {
                strm->msg = ( char *)"unknown compression method";
                state->mode = BAD;
                break;
            }
            if (state->flags & 0xe000) {
                strm->msg = ( char *)"unknown header flags set";
                state->mode = BAD;
                break;
            }
            if (state->head != 0)
                state->head->text = (int)((hold >> 8) & 1);
            if ((state->flags & 0x0200) && (state->wrap & 4))
                do { hbuf[0] = (unsigned char)(hold); hbuf[1] = (unsigned char)((hold) >> 8); state->check = crc32(state->check, hbuf, 2); } while (0);
            do { hold = 0; bits = 0; } while (0);
            state->mode = TIME;

        case TIME:
            do { while (bits < (unsigned)(32)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            if (state->head != 0)
                state->head->time = hold;
            if ((state->flags & 0x0200) && (state->wrap & 4))
                do { hbuf[0] = (unsigned char)(hold); hbuf[1] = (unsigned char)((hold) >> 8); hbuf[2] = (unsigned char)((hold) >> 16); hbuf[3] = (unsigned char)((hold) >> 24); state->check = crc32(state->check, hbuf, 4); } while (0);
            do { hold = 0; bits = 0; } while (0);
            state->mode = OS;

        case OS:
            do { while (bits < (unsigned)(16)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            if (state->head != 0) {
                state->head->xflags = (int)(hold & 0xff);
                state->head->os = (int)(hold >> 8);
            }
            if ((state->flags & 0x0200) && (state->wrap & 4))
                do { hbuf[0] = (unsigned char)(hold); hbuf[1] = (unsigned char)((hold) >> 8); state->check = crc32(state->check, hbuf, 2); } while (0);
            do { hold = 0; bits = 0; } while (0);
            state->mode = EXLEN;

        case EXLEN:
            if (state->flags & 0x0400) {
                do { while (bits < (unsigned)(16)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                state->length = (unsigned)(hold);
                if (state->head != 0)
                    state->head->extra_len = (unsigned)hold;
                if ((state->flags & 0x0200) && (state->wrap & 4))
                    do { hbuf[0] = (unsigned char)(hold); hbuf[1] = (unsigned char)((hold) >> 8); state->check = crc32(state->check, hbuf, 2); } while (0);
                do { hold = 0; bits = 0; } while (0);
            }
            else if (state->head != 0)
                state->head->extra = 0;
            state->mode = EXTRA;

        case EXTRA:
            if (state->flags & 0x0400) {
                copy = state->length;
                if (copy > have) copy = have;
                if (copy) {
                    if (state->head != 0 &&
                        state->head->extra != 0 &&
                        (len = state->head->extra_len - state->length) <
                            state->head->extra_max) {
                        memcpy(state->head->extra + len, next,
                                len + copy > state->head->extra_max ?
                                state->head->extra_max - len : copy);
                    }
                    if ((state->flags & 0x0200) && (state->wrap & 4))
                        state->check = crc32(state->check, next, copy);
                    have -= copy;
                    next += copy;
                    state->length -= copy;
                }
                if (state->length) goto inf_leave;
            }
            state->length = 0;
            state->mode = NAME;

        case NAME:
            if (state->flags & 0x0800) {
                if (have == 0) goto inf_leave;
                copy = 0;
                do {
                    len = (unsigned)(next[copy++]);
                    if (state->head != 0 &&
                            state->head->name != 0 &&
                            state->length < state->head->name_max)
                        state->head->name[state->length++] = (Bytef)len;
                } while (len && copy < have);
                if ((state->flags & 0x0200) && (state->wrap & 4))
                    state->check = crc32(state->check, next, copy);
                have -= copy;
                next += copy;
                if (len) goto inf_leave;
            }
            else if (state->head != 0)
                state->head->name = 0;
            state->length = 0;
            state->mode = COMMENT;

        case COMMENT:
            if (state->flags & 0x1000) {
                if (have == 0) goto inf_leave;
                copy = 0;
                do {
                    len = (unsigned)(next[copy++]);
                    if (state->head != 0 &&
                            state->head->comment != 0 &&
                            state->length < state->head->comm_max)
                        state->head->comment[state->length++] = (Bytef)len;
                } while (len && copy < have);
                if ((state->flags & 0x0200) && (state->wrap & 4))
                    state->check = crc32(state->check, next, copy);
                have -= copy;
                next += copy;
                if (len) goto inf_leave;
            }
            else if (state->head != 0)
                state->head->comment = 0;
            state->mode = HCRC;

        case HCRC:
            if (state->flags & 0x0200) {
                do { while (bits < (unsigned)(16)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                if ((state->wrap & 4) && hold != (state->check & 0xffff)) {
                    strm->msg = ( char *)"header crc mismatch";
                    state->mode = BAD;
                    break;
                }
                do { hold = 0; bits = 0; } while (0);
            }
            if (state->head != 0) {
                state->head->hcrc = (int)((state->flags >> 9) & 1);
                state->head->done = 1;
            }
            strm->adler = state->check = crc32(0L, 0, 0);
            state->mode = TYPE;
            break;

        case DICTID:
            do { while (bits < (unsigned)(32)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            strm->adler = state->check = ((((hold) >> 24) & 0xff) + (((hold) >> 8) & 0xff00) + (((hold) & 0xff00) << 8) + (((hold) & 0xff) << 24));
            do { hold = 0; bits = 0; } while (0);
            state->mode = DICT;

        case DICT:
            if (state->havedict == 0) {
                do { strm->next_out = put; strm->avail_out = left; strm->next_in = next; strm->avail_in = have; state->hold = hold; state->bits = bits; } while (0);
                return 2;
            }
            strm->adler = state->check = adler32(0L, 0, 0);
            state->mode = TYPE;

        case TYPE:
            if (flush == 5 || flush == 6) goto inf_leave;

        case TYPEDO:
            if (state->last) {
                do { hold >>= bits & 7; bits -= bits & 7; } while (0);
                state->mode = CHECK;
                break;
            }
            do { while (bits < (unsigned)(3)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            state->last = ((unsigned)hold & ((1U << (1)) - 1));
            do { hold >>= (1); bits -= (unsigned)(1); } while (0);
            switch (((unsigned)hold & ((1U << (2)) - 1))) {
            case 0:

                                                      ;
                state->mode = STORED;
                break;
            case 1:
                inflate_fixed(state);

                                                      ;
                state->mode = LEN_;
                if (flush == 6) {
                    do { hold >>= (2); bits -= (unsigned)(2); } while (0);
                    goto inf_leave;
                }
                break;
            case 2:

                                                      ;
                state->mode = TABLE;
                break;
            default:
                strm->msg = ( char *)"invalid block type";
                state->mode = BAD;
            }
            do { hold >>= (2); bits -= (unsigned)(2); } while (0);
            break;
        case STORED:
            do { hold >>= bits & 7; bits -= bits & 7; } while (0);
            do { while (bits < (unsigned)(32)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            if ((hold & 0xffff) != ((hold >> 16) ^ 0xffff)) {
                strm->msg = ( char *)"invalid stored block lengths";
                state->mode = BAD;
                break;
            }
            state->length = (unsigned)hold & 0xffff;

                                   ;
            do { hold = 0; bits = 0; } while (0);
            state->mode = COPY_;
            if (flush == 6) goto inf_leave;

        case COPY_:
            state->mode = COPY;

        case COPY:
            copy = state->length;
            if (copy) {
                if (copy > have) copy = have;
                if (copy > left) copy = left;
                if (copy == 0) goto inf_leave;
                memcpy(put, next, copy);
                have -= copy;
                next += copy;
                left -= copy;
                put += copy;
                state->length -= copy;
                break;
            }
                                                           ;
            state->mode = TYPE;
            break;
        case TABLE:
            do { while (bits < (unsigned)(14)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            state->nlen = ((unsigned)hold & ((1U << (5)) - 1)) + 257;
            do { hold >>= (5); bits -= (unsigned)(5); } while (0);
            state->ndist = ((unsigned)hold & ((1U << (5)) - 1)) + 1;
            do { hold >>= (5); bits -= (unsigned)(5); } while (0);
            state->ncode = ((unsigned)hold & ((1U << (4)) - 1)) + 4;
            do { hold >>= (4); bits -= (unsigned)(4); } while (0);

            if (state->nlen > 286 || state->ndist > 30) {
                strm->msg = ( char *)
                    "too many length or distance symbols";
                state->mode = BAD;
                break;
            }

                                                               ;
            state->have = 0;
            state->mode = LENLENS;

        case LENLENS:
            while (state->have < state->ncode) {
                do { while (bits < (unsigned)(3)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                state->lens[order[state->have++]] = (unsigned short)((unsigned)hold & ((1U << (3)) - 1));
                do { hold >>= (3); bits -= (unsigned)(3); } while (0);
            }
            while (state->have < 19)
                state->lens[order[state->have++]] = 0;
            state->next = state->codes;
            state->lencode = state->distcode = (const code *)(state->next);
            state->lenbits = 7;
            ret = inflate_table(CODES, state->lens, 19, &(state->next),
                                &(state->lenbits), state->work);
            if (ret) {
                strm->msg = ( char *)"invalid code lengths set";
                state->mode = BAD;
                break;
            }
                                                                ;
            state->have = 0;
            state->mode = CODELENS;

        case CODELENS:
            while (state->have < state->nlen + state->ndist) {
                for (;;) {
                    here = state->lencode[((unsigned)hold & ((1U << (state->lenbits)) - 1))];
                    if ((unsigned)(here.bits) <= bits) break;
                    do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
                }
                if (here.val < 16) {
                    do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
                    state->lens[state->have++] = here.val;
                }
                else {
                    if (here.val == 16) {
                        do { while (bits < (unsigned)(here.bits + 2)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                        do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
                        if (state->have == 0) {
                            strm->msg = ( char *)
                                "invalid bit length repeat";
                            state->mode = BAD;
                            break;
                        }
                        len = state->lens[state->have - 1];
                        copy = 3 + ((unsigned)hold & ((1U << (2)) - 1));
                        do { hold >>= (2); bits -= (unsigned)(2); } while (0);
                    }
                    else if (here.val == 17) {
                        do { while (bits < (unsigned)(here.bits + 3)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                        do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
                        len = 0;
                        copy = 3 + ((unsigned)hold & ((1U << (3)) - 1));
                        do { hold >>= (3); bits -= (unsigned)(3); } while (0);
                    }
                    else {
                        do { while (bits < (unsigned)(here.bits + 7)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                        do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
                        len = 0;
                        copy = 11 + ((unsigned)hold & ((1U << (7)) - 1));
                        do { hold >>= (7); bits -= (unsigned)(7); } while (0);
                    }
                    if (state->have + copy > state->nlen + state->ndist) {
                        strm->msg = ( char *)
                            "invalid bit length repeat";
                        state->mode = BAD;
                        break;
                    }
                    while (copy--)
                        state->lens[state->have++] = (unsigned short)len;
                }
            }


            if (state->mode == BAD) break;


            if (state->lens[256] == 0) {
                strm->msg = ( char *)
                    "invalid code -- missing end-of-block";
                state->mode = BAD;
                break;
            }




            state->next = state->codes;
            state->lencode = (const code *)(state->next);
            state->lenbits = 9;
            ret = inflate_table(LENS, state->lens, state->nlen, &(state->next),
                                &(state->lenbits), state->work);
            if (ret) {
                strm->msg = ( char *)"invalid literal/lengths set";
                state->mode = BAD;
                break;
            }
            state->distcode = (const code *)(state->next);
            state->distbits = 6;
            ret = inflate_table(DISTS, state->lens + state->nlen, state->ndist,
                            &(state->next), &(state->distbits), state->work);
            if (ret) {
                strm->msg = ( char *)"invalid distances set";
                state->mode = BAD;
                break;
            }
                                                         ;
            state->mode = LEN_;
            if (flush == 6) goto inf_leave;

        case LEN_:
            state->mode = LEN;

        case LEN:
            if (have >= 6 && left >= 258) {
                do { strm->next_out = put; strm->avail_out = left; strm->next_in = next; strm->avail_in = have; state->hold = hold; state->bits = bits; } while (0);
                inflate_fast(strm, out);
                do { put = strm->next_out; left = strm->avail_out; next = strm->next_in; have = strm->avail_in; hold = state->hold; bits = state->bits; } while (0);
                if (state->mode == TYPE)
                    state->back = -1;
                break;
            }
            state->back = 0;
            for (;;) {
                here = state->lencode[((unsigned)hold & ((1U << (state->lenbits)) - 1))];
                if ((unsigned)(here.bits) <= bits) break;
                do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
            }
            if (here.op && (here.op & 0xf0) == 0) {
                last = here;
                for (;;) {
                    here = state->lencode[last.val +
                            (((unsigned)hold & ((1U << (last.bits + last.op)) - 1)) >> last.bits)];
                    if ((unsigned)(last.bits + here.bits) <= bits) break;
                    do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
                }
                do { hold >>= (last.bits); bits -= (unsigned)(last.bits); } while (0);
                state->back += last.bits;
            }
            do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
            state->back += here.bits;
            state->length = (unsigned)here.val;
            if ((int)(here.op) == 0) {


                                                                       ;
                state->mode = LIT;
                break;
            }
            if (here.op & 32) {
                                                                    ;
                state->back = -1;
                state->mode = TYPE;
                break;
            }
            if (here.op & 64) {
                strm->msg = ( char *)"invalid literal/length code";
                state->mode = BAD;
                break;
            }
            state->extra = (unsigned)(here.op) & 15;
            state->mode = LENEXT;

        case LENEXT:
            if (state->extra) {
                do { while (bits < (unsigned)(state->extra)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                state->length += ((unsigned)hold & ((1U << (state->extra)) - 1));
                do { hold >>= (state->extra); bits -= (unsigned)(state->extra); } while (0);
                state->back += state->extra;
            }
                                                                            ;
            state->was = state->length;
            state->mode = DIST;

        case DIST:
            for (;;) {
                here = state->distcode[((unsigned)hold & ((1U << (state->distbits)) - 1))];
                if ((unsigned)(here.bits) <= bits) break;
                do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
            }
            if ((here.op & 0xf0) == 0) {
                last = here;
                for (;;) {
                    here = state->distcode[last.val +
                            (((unsigned)hold & ((1U << (last.bits + last.op)) - 1)) >> last.bits)];
                    if ((unsigned)(last.bits + here.bits) <= bits) break;
                    do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
                }
                do { hold >>= (last.bits); bits -= (unsigned)(last.bits); } while (0);
                state->back += last.bits;
            }
            do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
            state->back += here.bits;
            if (here.op & 64) {
                strm->msg = ( char *)"invalid distance code";
                state->mode = BAD;
                break;
            }
            state->offset = (unsigned)here.val;
            state->extra = (unsigned)(here.op) & 15;
            state->mode = DISTEXT;

        case DISTEXT:
            if (state->extra) {
                do { while (bits < (unsigned)(state->extra)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                state->offset += ((unsigned)hold & ((1U << (state->extra)) - 1));
                do { hold >>= (state->extra); bits -= (unsigned)(state->extra); } while (0);
                state->back += state->extra;
            }







                                                                              ;
            state->mode = MATCH;

        case MATCH:
            if (left == 0) goto inf_leave;
            copy = out - left;
            if (state->offset > copy) {
                copy = state->offset - copy;
                if (copy > state->whave) {
                    if (state->sane) {
                        strm->msg = ( char *)
                            "invalid distance too far back";
                        state->mode = BAD;
                        break;
                    }
                }
                if (copy > state->wnext) {
                    copy -= state->wnext;
                    from = state->window + (state->wsize - copy);
                }
                else
                    from = state->window + (state->wnext - copy);
                if (copy > state->length) copy = state->length;
            }
            else {
                from = put - state->offset;
                copy = state->length;
            }
            if (copy > left) copy = left;
            left -= copy;
            state->length -= copy;
            do {
                *put++ = *from++;
            } while (--copy);
            if (state->length == 0) state->mode = LEN;
            break;
        case LIT:
            if (left == 0) goto inf_leave;
            *put++ = (unsigned char)(state->length);
            left--;
            state->mode = LEN;
            break;
        case CHECK:
            if (state->wrap) {
                do { while (bits < (unsigned)(32)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                out -= left;
                strm->total_out += out;
                state->total += out;
                if ((state->wrap & 4) && out)
                    strm->adler = state->check =
                        (state->flags ? crc32(state->check, put - out, out) : adler32(state->check, put - out, out));
                out = left;
                if ((state->wrap & 4) && (

                     state->flags ? hold :

                     ((((hold) >> 24) & 0xff) + (((hold) >> 8) & 0xff00) + (((hold) & 0xff00) << 8) + (((hold) & 0xff) << 24))) != state->check) {
                    strm->msg = ( char *)"incorrect data check";
                    state->mode = BAD;
                    break;
                }
                do { hold = 0; bits = 0; } while (0);
                                                                      ;
            }

            state->mode = LENGTH;

        case LENGTH:
            if (state->wrap && state->flags) {
                do { while (bits < (unsigned)(32)) do { if (have == 0) goto inf_leave; have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                if ((state->wrap & 4) && hold != (state->total & 0xffffffff)) {
                    strm->msg = ( char *)"incorrect length check";
                    state->mode = BAD;
                    break;
                }
                do { hold = 0; bits = 0; } while (0);
                                                                       ;
            }

            state->mode = DONE;

        case DONE:
            ret = 1;
            goto inf_leave;
        case BAD:
            ret = (-3);
            goto inf_leave;
        case MEM:
            return (-4);
        case SYNC:

        default:
            return (-2);
        }







  inf_leave:
    do { strm->next_out = put; strm->avail_out = left; strm->next_in = next; strm->avail_in = have; state->hold = hold; state->bits = bits; } while (0);
    if (state->wsize || (out != strm->avail_out && state->mode < BAD &&
            (state->mode < CHECK || flush != 4)))
        if (updatewindow(strm, strm->next_out, out - strm->avail_out)) {
            state->mode = MEM;
            return (-4);
        }
    in -= strm->avail_in;
    out -= strm->avail_out;
    strm->total_in += in;
    strm->total_out += out;
    state->total += out;
    if ((state->wrap & 4) && out)
        strm->adler = state->check =
            (state->flags ? crc32(state->check, strm->next_out - out, out) : adler32(state->check, strm->next_out - out, out));
    strm->data_type = (int)state->bits + (state->last ? 64 : 0) +
                      (state->mode == TYPE ? 128 : 0) +
                      (state->mode == LEN_ || state->mode == COPY_ ? 256 : 0);
    if (((in == 0 && out == 0) || flush == 4) && ret == 0)
        ret = (-5);
    return ret;
}

int inflateEnd(z_streamp strm) {
    struct inflate_state *state;
    if (inflateStateCheck(strm))
        return (-2);
    state = (struct inflate_state *)strm->state;
    if (state->window != 0) (*((strm)->zfree))((strm)->opaque, (voidpf)(state->window));
    (*((strm)->zfree))((strm)->opaque, (voidpf)(strm->state));
    strm->state = 0;
                                      ;
    return 0;
}

int inflateGetDictionary(z_streamp strm, Bytef *dictionary,
                                 uInt *dictLength) {
    struct inflate_state *state;


    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;


    if (state->whave && dictionary != 0) {
        memcpy(dictionary, state->window + state->wnext,
                state->whave - state->wnext);
        memcpy(dictionary + state->whave - state->wnext,
                state->window, state->wnext);
    }
    if (dictLength != 0)
        *dictLength = state->whave;
    return 0;
}

int inflateSetDictionary(z_streamp strm, const Bytef *dictionary,
                                 uInt dictLength) {
    struct inflate_state *state;
    unsigned long dictid;
    int ret;


    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;
    if (state->wrap != 0 && state->mode != DICT)
        return (-2);


    if (state->mode == DICT) {
        dictid = adler32(0L, 0, 0);
        dictid = adler32(dictid, dictionary, dictLength);
        if (dictid != state->check)
            return (-3);
    }



    ret = updatewindow(strm, dictionary + dictLength, dictLength);
    if (ret) {
        state->mode = MEM;
        return (-4);
    }
    state->havedict = 1;
                                                   ;
    return 0;
}

int inflateGetHeader(z_streamp strm, gz_headerp head) {
    struct inflate_state *state;


    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;
    if ((state->wrap & 2) == 0) return (-2);


    state->head = head;
    head->done = 0;
    return 0;
}
static unsigned syncsearch(unsigned *have, const unsigned char *buf,
                          unsigned len) {
    unsigned got;
    unsigned next;

    got = *have;
    next = 0;
    while (next < len && got < 4) {
        if ((int)(buf[next]) == (got < 2 ? 0 : 0xff))
            got++;
        else if (buf[next])
            got = 0;
        else
            got = 4 - got;
        next++;
    }
    *have = got;
    return next;
}

int inflateSync(z_streamp strm) {
    unsigned len;
    int flags;
    unsigned long in, out;
    unsigned char buf[4];
    struct inflate_state *state;


    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;
    if (strm->avail_in == 0 && state->bits < 8) return (-5);


    if (state->mode != SYNC) {
        state->mode = SYNC;
        state->hold >>= state->bits & 7;
        state->bits -= state->bits & 7;
        len = 0;
        while (state->bits >= 8) {
            buf[len++] = (unsigned char)(state->hold);
            state->hold >>= 8;
            state->bits -= 8;
        }
        state->have = 0;
        syncsearch(&(state->have), buf, len);
    }


    len = syncsearch(&(state->have), strm->next_in, strm->avail_in);
    strm->avail_in -= len;
    strm->next_in += len;
    strm->total_in += len;


    if (state->have != 4) return (-3);
    if (state->flags == -1)
        state->wrap = 0;
    else
        state->wrap &= ~4;
    flags = state->flags;
    in = strm->total_in; out = strm->total_out;
    inflateReset(strm);
    strm->total_in = in; strm->total_out = out;
    state->flags = flags;
    state->mode = TYPE;
    return 0;
}
int inflateSyncPoint(z_streamp strm) {
    struct inflate_state *state;

    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;
    return state->mode == STORED && state->bits == 0;
}

int inflateCopy(z_streamp dest, z_streamp source) {
    struct inflate_state *state;
    struct inflate_state *copy;
    unsigned char *window;


    if (inflateStateCheck(source) || dest == 0)
        return (-2);
    state = (struct inflate_state *)source->state;


    copy = (struct inflate_state *)
           (*((source)->zalloc))((source)->opaque, (1), (sizeof(struct inflate_state)));
    if (copy == 0) return (-4);
    memset(copy, 0, sizeof(struct inflate_state));
    window = 0;
    if (state->window != 0) {
        window = (unsigned char *)
                 (*((source)->zalloc))((source)->opaque, (1U << state->wbits), (sizeof(unsigned char)));
        if (window == 0) {
            (*((source)->zfree))((source)->opaque, (voidpf)(copy));
            return (-4);
        }
    }


    memcpy(dest, source, sizeof(z_stream));
    memcpy(copy, state, sizeof(struct inflate_state));
    copy->strm = dest;
    if (state->lencode >= state->codes &&
        state->lencode <= state->codes + (852 +592) - 1) {
        copy->lencode = copy->codes + (state->lencode - state->codes);
        copy->distcode = copy->codes + (state->distcode - state->codes);
    }
    copy->next = copy->codes + (state->next - state->codes);
    if (window != 0)
        memcpy(window, state->window, state->whave);
    copy->window = window;
    dest->state = (struct internal_state *)copy;
    return 0;
}

int inflateUndermine(z_streamp strm, int subvert) {
    struct inflate_state *state;

    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;




    (void)subvert;
    state->sane = 1;
    return (-3);

}

int inflateValidate(z_streamp strm, int check) {
    struct inflate_state *state;

    if (inflateStateCheck(strm)) return (-2);
    state = (struct inflate_state *)strm->state;
    if (check && state->wrap)
        state->wrap |= 4;
    else
        state->wrap &= ~4;
    return 0;
}

long inflateMark(z_streamp strm) {
    struct inflate_state *state;

    if (inflateStateCheck(strm))
        return -(1L << 16);
    state = (struct inflate_state *)strm->state;
    return (long)(((unsigned long)((long)state->back)) << 16) +
        (state->mode == COPY ? state->length :
            (state->mode == MATCH ? state->was - state->length : 0));
}

unsigned long inflateCodesUsed(z_streamp strm) {
    struct inflate_state *state;
    if (inflateStateCheck(strm)) return (unsigned long)-1;
    state = (struct inflate_state *)strm->state;
    return (unsigned long)(state->next - state->codes);
}
