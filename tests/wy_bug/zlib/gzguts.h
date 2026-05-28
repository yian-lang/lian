#include <stdio.h>
#include "zlib.h"
#  include <string.h>
#  include <stdlib.h>
#  include <limits.h>
#include <fcntl.h>
#  include <stddef.h>
#  include <io.h>
#  include <sys/stat.h>
#  include <windows.h>
#    include <errno.h>















    extern gzFile gzopen64(const char *, const char *);
    extern long long gzseek64(gzFile, long long, int);
    extern long long gztell64(gzFile);
    extern long long gzoffset64(gzFile);
typedef struct {

    struct gzFile_s x;




    int mode;
    int fd;
    char *path;
    unsigned size;
    unsigned want;
    unsigned char *in;
    unsigned char *out;
    int direct;

    int junk;
    int how;
    int again;
    long long start;
    int eof;
    int past;

    int level;
    int strategy;
    int reset;

    long long skip;

    int err;
    char *msg;

    z_stream strm;
} gz_state;
typedef gz_state *gz_statep;


void gz_error(gz_statep, int, const char *);







unsigned gz_intmax(void);
