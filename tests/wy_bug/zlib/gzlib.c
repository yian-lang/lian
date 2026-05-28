#include "gzguts.h"






static void gz_reset(gz_statep state) {
    state->x.have = 0;
    if (state->mode == 7247) {
        state->eof = 0;
        state->past = 0;
        state->how = 0;
        state->junk = -1;
    }
    else
        state->reset = 0;
    state->again = 0;
    state->skip = 0;
    gz_error(state, 0, ((void*)0));
    state->x.pos = 0;
    state->strm.avail_in = 0;
}


static gzFile gz_open(const void *path, int fd, const char *mode) {
    gz_statep state;
    z_size_t len;
    int oflag = 0;

    int exclusive = 0;



    if (path == ((void*)0) || mode == ((void*)0))
        return ((void*)0);


    state = (gz_statep)malloc(sizeof(gz_state));
    if (state == ((void*)0))
        return ((void*)0);
    state->size = 0;
    state->want = 8192;
    state->err = 0;
    state->msg = ((void*)0);


    state->mode = 0;
    state->level = (-1);
    state->strategy = 0;
    state->direct = 0;
    while (*mode) {
        if (*mode >= '0' && *mode <= '9')
            state->level = *mode - '0';
        else
            switch (*mode) {
            case 'r':
                state->mode = 7247;
                break;

            case 'w':
                state->mode = 31153;
                break;
            case 'a':
                state->mode = 1;
                break;

            case '+':
                free(state);
                return ((void*)0);
            case 'b':
                break;

            case 'e':
                oflag |= 02000000;
                break;


            case 'x':
                exclusive = 1;
                break;

            case 'f':
                state->strategy = 1;
                break;
            case 'h':
                state->strategy = 2;
                break;
            case 'R':
                state->strategy = 3;
                break;
            case 'F':
                state->strategy = 4;
                break;
            case 'G':
                state->direct = -1;
                break;

            case 'N':
                oflag |= 04000;
                break;

            case 'T':
                state->direct = 1;
                break;
            default:
                ;
            }
        mode++;
    }


    if (state->mode == 0) {
        free(state);
        return ((void*)0);
    }


    if (state->mode == 7247) {
        if (state->direct == 1) {

            free(state);
            return ((void*)0);
        }
        if (state->direct == 0)


            state->direct = 1;
    }
    else if (state->direct == -1) {

        free(state);
        return ((void*)0);
    }
        len = strlen((const char *)path);
    state->path = (char *)malloc(len + 1);
    if (state->path == ((void*)0)) {
        free(state);
        return ((void*)0);
    }
    {

        (void)snprintf(state->path, len + 1, "%s", (const char *)path);



    }


    oflag |=






        (state->mode == 7247 ?
         00 :
         (01 | 0100 |

          (exclusive ? 0200 : 0) |

          (state->mode == 31153 ?
           01000 :
           02000)));


    if (fd == -1)
        state->fd = open((const char *)path, oflag, 0666);




    else {

        if (oflag & 04000)
            fcntl(fd, 4, fcntl(fd, 3) | 04000);


        if (oflag & 02000000)
            fcntl(fd, 2, fcntl(fd, 1) | 02000000);

        state->fd = fd;
    }
    if (state->fd == -1) {
        free(state->path);
        free(state);
        return ((void*)0);
    }
    if (state->mode == 1) {
        lseek(state->fd, 0, 2);
        state->mode = 31153;
    }


    if (state->mode == 7247) {
        state->start = lseek(state->fd, 0, 1);
        if (state->start == -1) state->start = 0;
    }


    gz_reset(state);


    return (gzFile)state;
}


gzFile gzopen(const char *path, const char *mode) {
    return gz_open(path, -1, mode);
}


gzFile gzopen64(const char *path, const char *mode) {
    return gz_open(path, -1, mode);
}


gzFile gzdopen(int fd, const char *mode) {
    char *path;
    gzFile gz;

    if (fd == -1 || (path = (char *)malloc(7 + 3 * sizeof(int))) == ((void*)0))
        return ((void*)0);

    (void)snprintf(path, 7 + 3 * sizeof(int), "<fd:%d>", fd);



    gz = gz_open(path, fd, mode);
    free(path);
    return gz;
}
int gzbuffer(gzFile file, unsigned size) {
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    if (state->mode != 7247 && state->mode != 31153)
        return -1;


    if (state->size != 0)
        return -1;


    if ((size << 1) < size)
        return -1;
    if (size < 8)
        size = 8;
    state->want = size;
    return 0;
}


int gzrewind(gzFile file) {
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;


    if (state->mode != 7247 ||
            (state->err != 0 && state->err != (-5)))
        return -1;


    if (lseek(state->fd, state->start, 0) == -1)
        return -1;
    gz_reset(state);
    return 0;
}


long long gzseek64(gzFile file, long long offset, int whence) {
    unsigned n;
    long long ret;
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    if (state->mode != 7247 && state->mode != 31153)
        return -1;


    if (state->err != 0 && state->err != (-5))
        return -1;


    if (whence != 0 && whence != 1)
        return -1;


    if (whence == 0)
        offset -= state->x.pos;
    else {
        offset += state->past ? 0 : state->skip;
        state->skip = 0;
    }


    if (state->mode == 7247 && state->how == 1 &&
            state->x.pos + offset >= 0) {
        ret = lseek(state->fd, offset - (long long)state->x.have, 1);
        if (ret == -1)
            return -1;
        state->x.have = 0;
        state->eof = 0;
        state->past = 0;
        state->skip = 0;
        gz_error(state, 0, ((void*)0));
        state->strm.avail_in = 0;
        state->x.pos += offset;
        return state->x.pos;
    }


    if (offset < 0) {
        if (state->mode != 7247)
            return -1;
        offset += state->x.pos;
        if (offset < 0)
            return -1;
        if (gzrewind(file) == -1)
            return -1;
    }


    if (state->mode == 7247) {
        n = (sizeof(int) == sizeof(long long) && (state->x.have) > gz_intmax()) || (long long)state->x.have > offset ?
            (unsigned)offset : state->x.have;
        state->x.have -= n;
        state->x.next += n;
        state->x.pos += n;
        offset -= n;
    }


    state->skip = offset;
    return state->x.pos + offset;
}


long long gzseek(gzFile file, long long offset, int whence) {
    long long ret;

    ret = gzseek64(file, (long long)offset, whence);
    return ret == (long long)ret ? (long long)ret : -1;
}


long long gztell64(gzFile file) {
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    if (state->mode != 7247 && state->mode != 31153)
        return -1;


    return state->x.pos + (state->past ? 0 : state->skip);
}


long long gztell(gzFile file) {
    long long ret;

    ret = gztell64(file);
    return ret == (long long)ret ? (long long)ret : -1;
}


long long gzoffset64(gzFile file) {
    long long offset;
    gz_statep state;


    if (file == ((void*)0))
        return -1;
    state = (gz_statep)file;
    if (state->mode != 7247 && state->mode != 31153)
        return -1;


    offset = lseek(state->fd, 0, 1);
    if (offset == -1)
        return -1;
    if (state->mode == 7247)
        offset -= state->strm.avail_in;
    return offset;
}


long long gzoffset(gzFile file) {
    long long ret;

    ret = gzoffset64(file);
    return ret == (long long)ret ? (long long)ret : -1;
}


int gzeof(gzFile file) {
    gz_statep state;


    if (file == ((void*)0))
        return 0;
    state = (gz_statep)file;
    if (state->mode != 7247 && state->mode != 31153)
        return 0;


    return state->mode == 7247 ? state->past : 0;
}


const char * gzerror(gzFile file, int *errnum) {
    gz_statep state;


    if (file == ((void*)0))
        return ((void*)0);
    state = (gz_statep)file;
    if (state->mode != 7247 && state->mode != 31153)
        return ((void*)0);


    if (errnum != ((void*)0))
        *errnum = state->err;
    return state->err == (-4) ? "out of memory" :
                                       (state->msg == ((void*)0) ? "" : state->msg);
}


void gzclearerr(gzFile file) {
    gz_statep state;


    if (file == ((void*)0))
        return;
    state = (gz_statep)file;
    if (state->mode != 7247 && state->mode != 31153)
        return;


    if (state->mode == 7247) {
        state->eof = 0;
        state->past = 0;
    }
    gz_error(state, 0, ((void*)0));
}







void gz_error(gz_statep state, int err, const char *msg) {

    if (state->msg != ((void*)0)) {
        if (state->err != (-4))
            free(state->msg);
        state->msg = ((void*)0);
    }


    if (err != 0 && err != (-5) && !state->again)
        state->x.have = 0;


    state->err = err;
    if (msg == ((void*)0))
        return;


    if (err == (-4))
        return;


    if ((state->msg = (char *)malloc(strlen(state->path) + strlen(msg) + 3)) ==
            ((void*)0)) {
        state->err = (-4);
        return;
    }

    (void)snprintf(state->msg, strlen(state->path) + strlen(msg) + 3,
                   "%s%s%s", state->path, ": ", msg);





}





unsigned gz_intmax(void) {

    return 2147483647;
}
