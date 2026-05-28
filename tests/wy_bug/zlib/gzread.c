#include "gzguts.h"






static int gz_load(gz_statep state, unsigned char *buf, unsigned len,
                  unsigned *have) {
    int ret;
    unsigned get, max = ((unsigned)-1 >> 2) + 1;

    state->again = 0;
    (*__errno_location ()) = 0;
    *have = 0;
    do {
        get = len - *have;
        if (get > max)
            get = max;
        ret = (int)read(state->fd, buf + *have, get);
        if (ret <= 0)
            break;
        *have += (unsigned)ret;
    } while (*have < len);
    if (ret < 0) {
        if ((*__errno_location ()) == 11 || (*__errno_location ()) == 11) {
            state->again = 1;
            if (*have != 0)
                return 0;
        }
        gz_error(state, (-1), strerror((*__errno_location ())));
        return -1;
    }
    if (ret == 0)
        state->eof = 1;
    return 0;
}
static int gz_avail(gz_statep state) {
    unsigned got;
    z_streamp strm = &(state->strm);

    if (state->err != 0 && state->err != (-5))
        return -1;
    if (state->eof == 0) {
        if (strm->avail_in) {
            unsigned char *p = state->in;
            unsigned const char *q = strm->next_in;

            if (q != p) {
                unsigned n = strm->avail_in;

                do {
                    *p++ = *q++;
                } while (--n);
            }
        }
        if (gz_load(state, state->in + strm->avail_in,
                    state->size - strm->avail_in, &got) == -1)
            return -1;
        strm->avail_in += got;
        strm->next_in = state->in;
    }
    return 0;
}
static int gz_look(gz_statep state) {
    z_streamp strm = &(state->strm);


    if (state->size == 0) {

        state->in = (unsigned char *)malloc(state->want);
        state->out = (unsigned char *)malloc(state->want << 1);
        if (state->in == ((void*)0) || state->out == ((void*)0)) {
            free(state->out);
            free(state->in);
            gz_error(state, (-4), "out of memory");
            return -1;
        }
        state->size = state->want;


        state->strm.zalloc = 0;
        state->strm.zfree = 0;
        state->strm.opaque = 0;
        state->strm.avail_in = 0;
        state->strm.next_in = 0;
        if (inflateInit2_((&(state->strm)), (15 + 16), "1.3.2.1-motley", (int)sizeof(z_stream)) != 0) {
            free(state->out);
            free(state->in);
            state->size = 0;
            gz_error(state, (-4), "out of memory");
            return -1;
        }
    }




    if (state->direct == -1 || state->junk == 0) {
        inflateReset(strm);
        state->how = 2;
        state->junk = state->junk != -1;
        state->direct = 0;
        return 0;
    }







    if (gz_avail(state) == -1)
        return -1;
    if (strm->avail_in == 0 || (state->again && strm->avail_in < 4))


        return 0;




    if (strm->avail_in > 3 &&
            strm->next_in[0] == 31 && strm->next_in[1] == 139 &&
            strm->next_in[2] == 8 && strm->next_in[3] < 32) {
        inflateReset(strm);
        state->how = 2;
        state->junk = 1;
        state->direct = 0;
        return 0;
    }




    state->x.next = state->out;
    memcpy(state->x.next, strm->next_in, strm->avail_in);
    state->x.have = strm->avail_in;
    strm->avail_in = 0;
    state->how = 1;
    return 0;
}
static int gz_decomp(gz_statep state) {
    int ret = 0;
    unsigned had;
    z_streamp strm = &(state->strm);


    had = strm->avail_out;
    do {

        if (strm->avail_in == 0 && gz_avail(state) == -1) {
            ret = state->err;
            break;
        }
        if (strm->avail_in == 0) {
            if (!state->again)
                gz_error(state, (-5), "unexpected end of file");
            break;
        }


        ret = inflate(strm, 0);
        if (strm->avail_out < had)

            state->junk = 0;
        if (ret == (-2) || ret == 2) {
            gz_error(state, (-2),
                     "internal error: inflate stream corrupt");
            break;
        }
        if (ret == (-4)) {
            gz_error(state, (-4), "out of memory");
            break;
        }
        if (ret == (-3)) {
            if (state->junk == 1) {
                strm->avail_in = 0;
                state->eof = 1;
                state->how = 0;
                ret = 0;
                break;
            }
            gz_error(state, (-3),
                     strm->msg == ((void*)0) ? "compressed data error" : strm->msg);
            break;
        }
    } while (strm->avail_out && ret != 1);


    state->x.have = had - strm->avail_out;
    state->x.next = strm->next_out - state->x.have;


    if (ret == 1) {
        state->junk = 0;
        state->how = 0;
        return 0;
    }


    return ret != 0 ? -1 : 0;
}







static int gz_fetch(gz_statep state) {
    z_streamp strm = &(state->strm);

    do {
        switch(state->how) {
        case 0:
            if (gz_look(state) == -1)
                return -1;
            if (state->how == 0)
                return 0;
            break;
        case 1:
            if (gz_load(state, state->out, state->size << 1, &(state->x.have))
                    == -1)
                return -1;
            state->x.next = state->out;
            return 0;
        case 2:
            strm->avail_out = state->size << 1;
            strm->next_out = state->out;
            if (gz_decomp(state) == -1)
                return -1;
            break;
        default:
            gz_error(state, (-2), "state corrupt");
            return -1;
        }
    } while (state->x.have == 0 && (!state->eof || strm->avail_in));
    return 0;
}



static int gz_skip(gz_statep state) {
    unsigned n;


    do {

        if (state->x.have) {
            n = (sizeof(int) == sizeof(long long) && (state->x.have) > gz_intmax()) ||
                (long long)state->x.have > state->skip ?
                (unsigned)state->skip : state->x.have;
            state->x.have -= n;
            state->x.next += n;
            state->x.pos += n;
            state->skip -= n;
        }


        else if (state->eof && state->strm.avail_in == 0)
            break;


        else {

            if (gz_fetch(state) == -1)
                return -1;
        }
    } while (state->skip);
    return 0;
}







static z_size_t gz_read(gz_statep state, voidp buf, z_size_t len) {
    z_size_t got;
    unsigned n;
    int err;


    if (len == 0)
        return 0;


    if (state->skip && gz_skip(state) == -1)
        return 0;


    got = 0;
    err = 0;
    do {

        n = (unsigned)-1;
        if (n > len)
            n = (unsigned)len;


        if (state->x.have) {
            if (state->x.have < n)
                n = state->x.have;
            memcpy(buf, state->x.next, n);
            state->x.next += n;
            state->x.have -= n;
            if (state->err != 0)

                err = -1;
        }


        else if (state->eof && state->strm.avail_in == 0)
            break;



        else if (state->how == 0 || n < (state->size << 1)) {

            if (gz_fetch(state) == -1 && state->x.have == 0)

                err = -1;
            continue;


        }


        else if (state->how == 1)
            err = gz_load(state, (unsigned char *)buf, n, &n);


        else {
            state->strm.avail_out = n;
            state->strm.next_out = (unsigned char *)buf;
            err = gz_decomp(state);
            n = state->x.have;
            state->x.have = 0;
        }


        len -= n;
        buf = (char *)buf + n;
        got += n;
        state->x.pos += n;
    } while (len && !err);


    if (len && state->eof)
        state->past = 1;


    return got;
}


int gzread(gzFile file, voidp buf, unsigned len) {
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    if (state->mode != 7247)
        return -1;


    if (state->err != 0 && state->err != (-5) && !state->again)
        return -1;
    gz_error(state, 0, ((void*)0));



    if ((int)len < 0) {
        gz_error(state, (-2), "request does not fit in an int");
        return -1;
    }


    len = (unsigned)gz_read(state, buf, len);


    if (len == 0) {
        if (state->err != 0 && state->err != (-5))
            return -1;
        if (state->again) {



            gz_error(state, (-1), strerror((*__errno_location ())));
            return -1;
        }
    }


    return (int)len;
}


z_size_t gzfread(voidp buf, z_size_t size, z_size_t nitems,
                         gzFile file) {
    z_size_t len;
    gz_statep state;


    if (file == ((void*)0))
        return 0;
    state = (gz_statep)file;
    if (state->mode != 7247)
        return 0;


    if (state->err != 0 && state->err != (-5) && !state->again)
        return 0;
    gz_error(state, 0, ((void*)0));


    len = nitems * size;
    if (size && len / size != nitems) {
        gz_error(state, (-2), "request does not fit in a size_t");
        return 0;
    }


    return len ? gz_read(state, buf, len) / size : 0;
}







int gzgetc(gzFile file) {
    unsigned char buf[1];
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    if (state->mode != 7247)
        return -1;


    if (state->err != 0 && state->err != (-5) && !state->again)
        return -1;
    gz_error(state, 0, ((void*)0));


    if (state->x.have) {
        state->x.have--;
        state->x.pos++;
        return *(state->x.next)++;
    }


    return gz_read(state, buf, 1) < 1 ? -1 : buf[0];
}

int gzgetc_(gzFile file) {
    return gzgetc(file);
}


int gzungetc(int c, gzFile file) {
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    if (state->mode != 7247)
        return -1;


    if (state->how == 0 && state->x.have == 0)
        (void)gz_look(state);


    if (state->err != 0 && state->err != (-5) && !state->again)
        return -1;
    gz_error(state, 0, ((void*)0));


    if (state->skip && gz_skip(state) == -1)
        return -1;


    if (c < 0)
        return -1;


    if (state->x.have == 0) {
        state->x.have = 1;
        state->x.next = state->out + (state->size << 1) - 1;
        state->x.next[0] = (unsigned char)c;
        state->x.pos--;
        state->past = 0;
        return c;
    }


    if (state->x.have == (state->size << 1)) {
        gz_error(state, (-3), "out of room to push characters");
        return -1;
    }


    if (state->x.next == state->out) {
        unsigned char *src = state->out + state->x.have;
        unsigned char *dest = state->out + (state->size << 1);

        while (src > state->out)
            *--dest = *--src;
        state->x.next = dest;
    }
    state->x.have++;
    state->x.next--;
    state->x.next[0] = (unsigned char)c;
    state->x.pos--;
    state->past = 0;
    return c;
}


char * gzgets(gzFile file, char *buf, int len) {
    unsigned left, n;
    char *str;
    unsigned char *eol;
    gz_statep state;



    if (file == ((void*)0) || buf == ((void*)0) || len < 1)
        return ((void*)0);
    state = (gz_statep)file;
    if (state->mode != 7247)
        return ((void*)0);


    if (state->err != 0 && state->err != (-5) && !state->again)
        return ((void*)0);
    gz_error(state, 0, ((void*)0));


    if (state->skip && gz_skip(state) == -1)
        return ((void*)0);



    str = buf;
    left = (unsigned)len - 1;
    if (left) do {

        if (state->x.have == 0 && gz_fetch(state) == -1)
            break;
        if (state->x.have == 0) {
            state->past = 1;
            break;
        }


        n = state->x.have > left ? left : state->x.have;
        eol = (unsigned char *)memchr(state->x.next, '\n', n);
        if (eol != ((void*)0))
            n = (unsigned)(eol - state->x.next) + 1;


        memcpy(buf, state->x.next, n);
        state->x.have -= n;
        state->x.next += n;
        state->x.pos += n;
        left -= n;
        buf += n;
    } while (left && eol == ((void*)0));




    if (buf == str)
        return ((void*)0);
    buf[0] = 0;
    return str;
}


int gzdirect(gzFile file) {
    gz_statep state;


    if (file == ((void*)0))
        return 0;
    state = (gz_statep)file;



    if (state->mode == 7247 && state->how == 0 && state->x.have == 0)
        (void)gz_look(state);


    return state->direct == 1;
}


int gzclose_r(gzFile file) {
    int ret, err;
    gz_statep state;


    if (file == ((void*)0))
        return (-2);
    state = (gz_statep)file;
    if (state->mode != 7247)
        return (-2);


    if (state->size) {
        inflateEnd(&(state->strm));
        free(state->out);
        free(state->in);
    }
    err = state->err == (-5) ? (-5) : 0;
    gz_error(state, 0, ((void*)0));
    free(state->path);
    ret = close(state->fd);
    free(state);
    return ret ? (-1) : err;
}
