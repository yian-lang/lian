#include "gzguts.h"
#include <stdarg.h>










static int gz_init(gz_statep state) {
    int ret;
    z_streamp strm = &(state->strm);


    state->in = (unsigned char *)malloc(state->want << 1);
    if (state->in == ((void*)0)) {
        gz_error(state, (-4), "out of memory");
        return -1;
    }


    if (!state->direct) {

        state->out = (unsigned char *)malloc(state->want);
        if (state->out == ((void*)0)) {
            free(state->in);
            gz_error(state, (-4), "out of memory");
            return -1;
        }


        strm->zalloc = 0;
        strm->zfree = 0;
        strm->opaque = 0;
        ret = deflateInit2_((strm),(state->level),(8),(15 + 16),(8), (state->strategy), "1.3.2.1-motley", (int)sizeof(z_stream));

        if (ret != 0) {
            free(state->out);
            free(state->in);
            gz_error(state, (-4), "out of memory");
            return -1;
        }
        strm->next_in = ((void*)0);
    }


    state->size = state->want;


    if (!state->direct) {
        strm->avail_out = state->size;
        strm->next_out = state->out;
        state->x.next = strm->next_out;
    }
    return 0;
}







static int gz_comp(gz_statep state, int flush) {
    int ret, writ;
    unsigned have, put, max = ((unsigned)-1 >> 2) + 1;
    z_streamp strm = &(state->strm);


    if (state->size == 0 && gz_init(state) == -1)
        return -1;


    if (state->direct) {
        while (strm->avail_in) {
            (*__errno_location ()) = 0;
            state->again = 0;
            put = strm->avail_in > max ? max : strm->avail_in;
            writ = (int)write(state->fd, strm->next_in, put);
            if (writ < 0) {
                if ((*__errno_location ()) == 11 || (*__errno_location ()) == 11)
                    state->again = 1;
                gz_error(state, (-1), strerror((*__errno_location ())));
                return -1;
            }
            strm->avail_in -= (unsigned)writ;
            strm->next_in += writ;
        }
        return 0;
    }


    if (state->reset) {


        if (strm->avail_in == 0 && flush == 0)
            return 0;
        deflateReset(strm);
        state->reset = 0;
    }


    ret = 0;
    do {


        if (strm->avail_out == 0 || (flush != 0 &&
            (flush != 4 || ret == 1))) {
            while (strm->next_out > state->x.next) {
                (*__errno_location ()) = 0;
                state->again = 0;
                put = strm->next_out - state->x.next > (int)max ? max :
                      (unsigned)(strm->next_out - state->x.next);
                writ = (int)write(state->fd, state->x.next, put);
                if (writ < 0) {
                    if ((*__errno_location ()) == 11 || (*__errno_location ()) == 11)
                        state->again = 1;
                    gz_error(state, (-1), strerror((*__errno_location ())));
                    return -1;
                }
                state->x.next += writ;
            }
            if (strm->avail_out == 0) {
                strm->avail_out = state->size;
                strm->next_out = state->out;
                state->x.next = state->out;
            }
        }


        have = strm->avail_out;
        ret = deflate(strm, flush);
        if (ret == (-2)) {
            gz_error(state, (-2),
                      "internal error: deflate stream corrupt");
            return -1;
        }
        have -= strm->avail_out;
    } while (have);


    if (flush == 4)
        state->reset = 1;


    return 0;
}





static int gz_zero(gz_statep state) {
    int first, ret;
    unsigned n;
    z_streamp strm = &(state->strm);


    if (strm->avail_in && gz_comp(state, 0) == -1)
        return -1;


    first = 1;
    do {
        n = (sizeof(int) == sizeof(long long) && (state->size) > gz_intmax()) || (long long)state->size > state->skip ?
            (unsigned)state->skip : state->size;
        if (first) {
            memset(state->in, 0, n);
            first = 0;
        }
        strm->avail_in = n;
        strm->next_in = state->in;
        ret = gz_comp(state, 0);
        n -= strm->avail_in;
        state->x.pos += n;
        state->skip -= n;
        if (ret == -1)
            return -1;
    } while (state->skip);
    return 0;
}





static z_size_t gz_write(gz_statep state, voidpc buf, z_size_t len) {
    z_size_t put = len;
    int ret;


    if (len == 0)
        return 0;


    if (state->size == 0 && gz_init(state) == -1)
        return 0;


    if (state->skip && gz_zero(state) == -1)
        return 0;


    if (len < state->size) {

        for (;;) {
            unsigned have, copy;

            if (state->strm.avail_in == 0)
                state->strm.next_in = state->in;
            have = (unsigned)((state->strm.next_in + state->strm.avail_in) -
                              state->in);
            copy = state->size - have;
            if (copy > len)
                copy = (unsigned)len;
            memcpy(state->in + have, buf, copy);
            state->strm.avail_in += copy;
            state->x.pos += copy;
            buf = (const char *)buf + copy;
            len -= copy;
            if (len == 0)
                break;
            if (gz_comp(state, 0) == -1)
                return state->again ? put - len : 0;
        }
    }
    else {

        if (state->strm.avail_in && gz_comp(state, 0) == -1)
            return 0;


        state->strm.next_in = ( Bytef *)buf;
        do {
            unsigned n = (unsigned)-1;

            if (n > len)
                n = (unsigned)len;
            state->strm.avail_in = n;
            ret = gz_comp(state, 0);
            n -= state->strm.avail_in;
            state->x.pos += n;
            len -= n;
            if (ret == -1)
                return state->again ? put - len : 0;
        } while (len);
    }


    return put;
}


int gzwrite(gzFile file, voidpc buf, unsigned len) {
    gz_statep state;


    if (file == ((void*)0))
        return 0;
    state = (gz_statep)file;


    if (state->mode != 31153 || (state->err != 0 && !state->again))
        return 0;
    gz_error(state, 0, ((void*)0));



    if ((int)len < 0) {
        gz_error(state, (-3), "requested length does not fit in int");
        return 0;
    }


    return (int)gz_write(state, buf, len);
}


z_size_t gzfwrite(voidpc buf, z_size_t size, z_size_t nitems,
                          gzFile file) {
    z_size_t len;
    gz_statep state;


    if (file == ((void*)0))
        return 0;
    state = (gz_statep)file;


    if (state->mode != 31153 || (state->err != 0 && !state->again))
        return 0;
    gz_error(state, 0, ((void*)0));


    len = nitems * size;
    if (size && len / size != nitems) {
        gz_error(state, (-2), "request does not fit in a size_t");
        return 0;
    }


    return len ? gz_write(state, buf, len) / size : 0;
}


int gzputc(gzFile file, int c) {
    unsigned have;
    unsigned char buf[1];
    gz_statep state;
    z_streamp strm;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    strm = &(state->strm);


    if (state->mode != 31153 || (state->err != 0 && !state->again))
        return -1;
    gz_error(state, 0, ((void*)0));


    if (state->skip && gz_zero(state) == -1)
        return -1;



    if (state->size) {
        if (strm->avail_in == 0)
            strm->next_in = state->in;
        have = (unsigned)((strm->next_in + strm->avail_in) - state->in);
        if (have < state->size) {
            state->in[have] = (unsigned char)c;
            strm->avail_in++;
            state->x.pos++;
            return c & 0xff;
        }
    }


    buf[0] = (unsigned char)c;
    if (gz_write(state, buf, 1) != 1)
        return -1;
    return c & 0xff;
}


int gzputs(gzFile file, const char *s) {
    z_size_t len, put;
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;


    if (state->mode != 31153 || (state->err != 0 && !state->again))
        return -1;
    gz_error(state, 0, ((void*)0));


    len = strlen(s);
    if ((int)len < 0 || (unsigned)len != len) {
        gz_error(state, (-2), "string length does not fit in int");
        return -1;
    }
    put = gz_write(state, s, len);
    return len && put == 0 ? -1 : (int)put;
}
static int gz_vacate(gz_statep state) {
    z_streamp strm;

    strm = &(state->strm);
    if (strm->next_in + strm->avail_in <= state->in + state->size)
        return 0;
    (void)gz_comp(state, 0);
    if (strm->avail_in == 0) {
        strm->next_in = state->in;
        return 0;
    }
    memmove(state->in, strm->next_in, strm->avail_in);
    strm->next_in = state->in;
    return strm->avail_in > state->size;
}





int gzvprintf(gzFile file, const char *format, va_list va) {







    int len, ret;
    char *next;
    gz_statep state;
    z_streamp strm;


    if (file == ((void*)0))
        return (-2);
    state = (gz_statep)file;
    strm = &(state->strm);


    if (state->mode != 31153 || (state->err != 0 && !state->again))
        return (-2);
    gz_error(state, 0, ((void*)0));


    if (state->size == 0 && gz_init(state) == -1)
        return state->err;


    if (state->skip && gz_zero(state) == -1)
        return state->err;




    ret = gz_vacate(state);
    if (state->err) {
        if (ret && state->again) {




            gz_error(state, (-5), "stalled write on gzprintf");
        }
        if (!state->again)
            return state->err;
    }
    if (strm->avail_in == 0)
        strm->next_in = state->in;
    next = (char *)(state->in + (strm->next_in - state->in) + strm->avail_in);
    next[state->size - 1] = 0;
    len = vsnprintf(next, state->size, format, va);




    if (len == 0 || (unsigned)len >= state->size || next[state->size - 1] != 0)
        return 0;


    strm->avail_in += (unsigned)len;
    state->x.pos += len;


    ret = gz_vacate(state);
    if (state->err && !state->again)
        return state->err;
    return len;

}

int gzprintf(gzFile file, const char *format, ...) {
    va_list va;
    int ret;

    __builtin_va_start(va, format);
    ret = gzvprintf(file, format, va);
    __builtin_va_end(va);
    return ret;
}
int gzflush(gzFile file, int flush) {
    gz_statep state;


    if (file == ((void*)0))
        return (-2);
    state = (gz_statep)file;


    if (state->mode != 31153 || (state->err != 0 && !state->again))
        return (-2);
    gz_error(state, 0, ((void*)0));


    if (flush < 0 || flush > 4)
        return (-2);


    if (state->skip && gz_zero(state) == -1)
        return state->err;


    (void)gz_comp(state, flush);
    return state->err;
}


int gzsetparams(gzFile file, int level, int strategy) {
    gz_statep state;
    z_streamp strm;


    if (file == ((void*)0))
        return (-2);
    state = (gz_statep)file;
    strm = &(state->strm);


    if (state->mode != 31153 || (state->err != 0 && !state->again) ||
            state->direct)
        return (-2);
    gz_error(state, 0, ((void*)0));


    if (level == state->level && strategy == state->strategy)
        return 0;


    if (state->skip && gz_zero(state) == -1)
        return state->err;


    if (state->size) {

        if (strm->avail_in && gz_comp(state, 5) == -1)
            return state->err;
        deflateParams(strm, level, strategy);
    }
    state->level = level;
    state->strategy = strategy;
    return 0;
}


int gzclose_w(gzFile file) {
    int ret = 0;
    gz_statep state;


    if (file == ((void*)0))
        return (-2);
    state = (gz_statep)file;


    if (state->mode != 31153)
        return (-2);


    if (state->skip && gz_zero(state) == -1)
        ret = state->err;


    if (gz_comp(state, 4) == -1)
        ret = state->err;
    if (state->size) {
        if (!state->direct) {
            (void)deflateEnd(&(state->strm));
            free(state->out);
        }
        free(state->in);
    }
    gz_error(state, 0, ((void*)0));
    free(state->path);
    if (close(state->fd) == -1)
        ret = (-1);
    free(state);
    return ret;
}
