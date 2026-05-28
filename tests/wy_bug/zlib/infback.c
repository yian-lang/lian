#include "zutil.h"
#include "inftrees.h"
#include "inflate.h"
#include "inffast.h"









int inflateBackInit_(z_streamp strm, int windowBits,
                             unsigned char *window, const char *version,
                             int stream_size) {
    struct inflate_state *state;

    if (version == 0 || version[0] != "1.3.2.1-motley"[0] ||
        stream_size != (int)(sizeof(z_stream)))
        return (-6);
    if (strm == 0 || window == 0 ||
        windowBits < 8 || windowBits > 15)
        return (-2);
    strm->msg = 0;
    if (strm->zalloc == (alloc_func)0) {



        strm->zalloc = zcalloc;
        strm->opaque = (voidpf)0;

    }
    if (strm->zfree == (free_func)0)



        strm->zfree = zcfree;

    state = (struct inflate_state *)(*((strm)->zalloc))((strm)->opaque, (1), (sizeof(struct inflate_state)));

    if (state == 0) return (-4);
                                            ;
    strm->state = (struct internal_state *)state;
    state->dmax = 32768U;
    state->wbits = (uInt)windowBits;
    state->wsize = 1U << windowBits;
    state->window = window;
    state->wnext = 0;
    state->whave = 0;
    state->sane = 1;
    return 0;
}
int inflateBack(z_streamp strm, in_func in, void *in_desc,
                        out_func out, void *out_desc) {
    struct inflate_state *state;
            unsigned char *next;
    unsigned char *put;
    unsigned have, left;
    unsigned long hold;
    unsigned bits;
    unsigned copy;
    unsigned char *from;
    code here;
    code last;
    unsigned len;
    int ret;
    static const unsigned short order[19] =
        {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};


    if (strm == 0 || strm->state == 0)
        return (-2);
    state = (struct inflate_state *)strm->state;


    strm->msg = 0;
    state->mode = TYPE;
    state->last = 0;
    state->whave = 0;
    next = strm->next_in;
    have = next != 0 ? strm->avail_in : 0;
    hold = 0;
    bits = 0;
    put = state->window;
    left = state->wsize;


    for (;;)
        switch (state->mode) {
        case TYPE:

            if (state->last) {
                do { hold >>= bits & 7; bits -= bits & 7; } while (0);
                state->mode = DONE;
                break;
            }
            do { while (bits < (unsigned)(3)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
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
                state->mode = LEN;
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
            do { while (bits < (unsigned)(32)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
            if ((hold & 0xffff) != ((hold >> 16) ^ 0xffff)) {
                strm->msg = ( char *)"invalid stored block lengths";
                state->mode = BAD;
                break;
            }
            state->length = (unsigned)hold & 0xffff;

                                   ;
            do { hold = 0; bits = 0; } while (0);


            while (state->length != 0) {
                copy = state->length;
                do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0);
                do { if (left == 0) { put = state->window; left = state->wsize; state->whave = left; if (out(out_desc, put, left)) { ret = (-5); goto inf_leave; } } } while (0);
                if (copy > have) copy = have;
                if (copy > left) copy = left;
                memcpy(put, next, copy);
                have -= copy;
                next += copy;
                left -= copy;
                put += copy;
                state->length -= copy;
            }
                                                           ;
            state->mode = TYPE;
            break;

        case TABLE:

            do { while (bits < (unsigned)(14)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
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
            while (state->have < state->ncode) {
                do { while (bits < (unsigned)(3)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                state->lens[order[state->have++]] = (unsigned short)((unsigned)hold & ((1U << (3)) - 1));
                do { hold >>= (3); bits -= (unsigned)(3); } while (0);
            }
            while (state->have < 19)
                state->lens[order[state->have++]] = 0;
            state->next = state->codes;
            state->lencode = (code const *)(state->next);
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
            while (state->have < state->nlen + state->ndist) {
                for (;;) {
                    here = state->lencode[((unsigned)hold & ((1U << (state->lenbits)) - 1))];
                    if ((unsigned)(here.bits) <= bits) break;
                    do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
                }
                if (here.val < 16) {
                    do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
                    state->lens[state->have++] = here.val;
                }
                else {
                    if (here.val == 16) {
                        do { while (bits < (unsigned)(here.bits + 2)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                        do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
                        if (state->have == 0) {
                            strm->msg = ( char *)
                                "invalid bit length repeat";
                            state->mode = BAD;
                            break;
                        }
                        len = (unsigned)(state->lens[state->have - 1]);
                        copy = 3 + ((unsigned)hold & ((1U << (2)) - 1));
                        do { hold >>= (2); bits -= (unsigned)(2); } while (0);
                    }
                    else if (here.val == 17) {
                        do { while (bits < (unsigned)(here.bits + 3)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                        do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
                        len = 0;
                        copy = 3 + ((unsigned)hold & ((1U << (3)) - 1));
                        do { hold >>= (3); bits -= (unsigned)(3); } while (0);
                    }
                    else {
                        do { while (bits < (unsigned)(here.bits + 7)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
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
            state->lencode = (code const *)(state->next);
            state->lenbits = 9;
            ret = inflate_table(LENS, state->lens, state->nlen, &(state->next),
                                &(state->lenbits), state->work);
            if (ret) {
                strm->msg = ( char *)"invalid literal/lengths set";
                state->mode = BAD;
                break;
            }
            state->distcode = (code const *)(state->next);
            state->distbits = 6;
            ret = inflate_table(DISTS, state->lens + state->nlen, state->ndist,
                            &(state->next), &(state->distbits), state->work);
            if (ret) {
                strm->msg = ( char *)"invalid distances set";
                state->mode = BAD;
                break;
            }
                                                         ;
            state->mode = LEN;


        case LEN:

            if (have >= 6 && left >= 258) {
                do { strm->next_out = put; strm->avail_out = left; strm->next_in = next; strm->avail_in = have; state->hold = hold; state->bits = bits; } while (0);
                inflate_fast(strm, state->wsize);
                do { put = strm->next_out; left = strm->avail_out; next = strm->next_in; have = strm->avail_in; hold = state->hold; bits = state->bits; } while (0);
                break;
            }


            for (;;) {
                here = state->lencode[((unsigned)hold & ((1U << (state->lenbits)) - 1))];
                if ((unsigned)(here.bits) <= bits) break;
                do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
            }
            if (here.op && (here.op & 0xf0) == 0) {
                last = here;
                for (;;) {
                    here = state->lencode[last.val +
                            (((unsigned)hold & ((1U << (last.bits + last.op)) - 1)) >> last.bits)];
                    if ((unsigned)(last.bits + here.bits) <= bits) break;
                    do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
                }
                do { hold >>= (last.bits); bits -= (unsigned)(last.bits); } while (0);
            }
            do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
            state->length = (unsigned)here.val;


            if (here.op == 0) {


                                                                       ;
                do { if (left == 0) { put = state->window; left = state->wsize; state->whave = left; if (out(out_desc, put, left)) { ret = (-5); goto inf_leave; } } } while (0);
                *put++ = (unsigned char)(state->length);
                left--;
                state->mode = LEN;
                break;
            }


            if (here.op & 32) {
                                                                    ;
                state->mode = TYPE;
                break;
            }


            if (here.op & 64) {
                strm->msg = ( char *)"invalid literal/length code";
                state->mode = BAD;
                break;
            }


            state->extra = (unsigned)(here.op) & 15;
            if (state->extra != 0) {
                do { while (bits < (unsigned)(state->extra)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                state->length += ((unsigned)hold & ((1U << (state->extra)) - 1));
                do { hold >>= (state->extra); bits -= (unsigned)(state->extra); } while (0);
            }
                                                                            ;


            for (;;) {
                here = state->distcode[((unsigned)hold & ((1U << (state->distbits)) - 1))];
                if ((unsigned)(here.bits) <= bits) break;
                do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
            }
            if ((here.op & 0xf0) == 0) {
                last = here;
                for (;;) {
                    here = state->distcode[last.val +
                            (((unsigned)hold & ((1U << (last.bits + last.op)) - 1)) >> last.bits)];
                    if ((unsigned)(last.bits + here.bits) <= bits) break;
                    do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0);
                }
                do { hold >>= (last.bits); bits -= (unsigned)(last.bits); } while (0);
            }
            do { hold >>= (here.bits); bits -= (unsigned)(here.bits); } while (0);
            if (here.op & 64) {
                strm->msg = ( char *)"invalid distance code";
                state->mode = BAD;
                break;
            }
            state->offset = (unsigned)here.val;


            state->extra = (unsigned)(here.op) & 15;
            if (state->extra != 0) {
                do { while (bits < (unsigned)(state->extra)) do { do { if (have == 0) { have = in(in_desc, &next); if (have == 0) { next = 0; ret = (-5); goto inf_leave; } } } while (0); have--; hold += (unsigned long)(*next++) << bits; bits += 8; } while (0); } while (0);
                state->offset += ((unsigned)hold & ((1U << (state->extra)) - 1));
                do { hold >>= (state->extra); bits -= (unsigned)(state->extra); } while (0);
            }
            if (state->offset > state->wsize - (state->whave < state->wsize ?
                                                left : 0)) {
                strm->msg = ( char *)"invalid distance too far back";
                state->mode = BAD;
                break;
            }
                                                                              ;


            do {
                do { if (left == 0) { put = state->window; left = state->wsize; state->whave = left; if (out(out_desc, put, left)) { ret = (-5); goto inf_leave; } } } while (0);
                copy = state->wsize - state->offset;
                if (copy < left) {
                    from = put + copy;
                    copy = left - copy;
                }
                else {
                    from = put - state->offset;
                    copy = left;
                }
                if (copy > state->length) copy = state->length;
                state->length -= copy;
                left -= copy;
                do {
                    *put++ = *from++;
                } while (--copy);
            } while (state->length != 0);
            break;

        case DONE:

            ret = 1;
            goto inf_leave;

        case BAD:
            ret = (-3);
            goto inf_leave;

        default:

            ret = (-2);
            goto inf_leave;
        }


  inf_leave:
    if (left < state->wsize) {
        if (out(out_desc, state->window, state->wsize - left) &&
            ret == 1)
            ret = (-5);
    }
    strm->next_in = next;
    strm->avail_in = have;
    return ret;
}

int inflateBackEnd(z_streamp strm) {
    if (strm == 0 || strm->state == 0 || strm->zfree == (free_func)0)
        return (-2);
    (*((strm)->zfree))((strm)->opaque, (voidpf)(strm->state));
    strm->state = 0;
                                      ;
    return 0;
}
