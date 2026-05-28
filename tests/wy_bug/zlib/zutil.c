#include "zutil.h"
#  include "gzguts.h"
#include <stdlib.h>











        char * const z_errmsg[10] = {
    ( char *)"need dictionary",
    ( char *)"stream end",
    ( char *)"",
    ( char *)"file error",
    ( char *)"stream error",
    ( char *)"data error",
    ( char *)"insufficient memory",
    ( char *)"buffer error",
    ( char *)"incompatible version",
    ( char *)""
};


const char * zlibVersion(void) {
    return "1.3.2.1-motley";
}

uLong zlibCompileFlags(void) {
    uLong flags;

    flags = 0;
    switch ((int)(sizeof(uInt))) {
    case 2: break;
    case 4: flags += 1; break;
    case 8: flags += 2; break;
    default: flags += 3;
    }
    switch ((int)(sizeof(uLong))) {
    case 2: break;
    case 4: flags += 1 << 2; break;
    case 8: flags += 2 << 2; break;
    default: flags += 3 << 2;
    }
    switch ((int)(sizeof(voidpf))) {
    case 2: break;
    case 4: flags += 1 << 4; break;
    case 8: flags += 2 << 4; break;
    default: flags += 3 << 4;
    }
    switch ((int)(sizeof(long long))) {
    case 2: break;
    case 4: flags += 1 << 6; break;
    case 8: flags += 2 << 6; break;
    default: flags += 3 << 6;
    }
    return flags;
}
const char * zError(int err) {
    return z_errmsg[(err) < -6 || (err) > 2 ? 9 : 2 - (err)];
}
voidpf zcalloc(voidpf opaque, unsigned items, unsigned size) {
    (void)opaque;
    return sizeof(uInt) > 2 ? (voidpf)malloc(items * size) :
                              (voidpf)calloc(items, size);
}

void zcfree(voidpf opaque, voidpf ptr) {
    (void)opaque;
    free(ptr);
}
