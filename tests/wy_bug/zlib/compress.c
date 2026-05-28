#include "zlib.h"









int compress2_z(Bytef *dest, z_size_t *destLen, const Bytef *source,
                        z_size_t sourceLen, int level) {
    z_stream stream;
    int err;
    const uInt max = (uInt)-1;
    z_size_t left;

    if ((sourceLen > 0 && source == ((void*)0)) ||
        destLen == ((void*)0) || (*destLen > 0 && dest == ((void*)0)))
        return (-2);

    left = *destLen;
    *destLen = 0;

    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;
    stream.opaque = (voidpf)0;

    err = deflateInit_((&stream), (level), "1.3.2.1-motley", (int)sizeof(z_stream));
    if (err != 0) return err;

    stream.next_out = dest;
    stream.avail_out = 0;
    stream.next_in = ( Bytef *)source;
    stream.avail_in = 0;

    do {
        if (stream.avail_out == 0) {
            stream.avail_out = left > (z_size_t)max ? max : (uInt)left;
            left -= stream.avail_out;
        }
        if (stream.avail_in == 0) {
            stream.avail_in = sourceLen > (z_size_t)max ? max :
                                                          (uInt)sourceLen;
            sourceLen -= stream.avail_in;
        }
        err = deflate(&stream, sourceLen ? 0 : 4);
    } while (err == 0);

    *destLen = (z_size_t)(stream.next_out - dest);
    deflateEnd(&stream);
    return err == 1 ? 0 : err;
}
int compress2(Bytef *dest, uLongf *destLen, const Bytef *source,
                      uLong sourceLen, int level) {
    int ret;
    z_size_t got = *destLen;
    ret = compress2_z(dest, &got, source, sourceLen, level);
    *destLen = (uLong)got;
    return ret;
}


int compress_z(Bytef *dest, z_size_t *destLen, const Bytef *source,
                       z_size_t sourceLen) {
    return compress2_z(dest, destLen, source, sourceLen,
                       (-1));
}
int compress(Bytef *dest, uLongf *destLen, const Bytef *source,
                     uLong sourceLen) {
    return compress2(dest, destLen, source, sourceLen, (-1));
}





z_size_t compressBound_z(z_size_t sourceLen) {
    z_size_t bound = sourceLen + (sourceLen >> 12) + (sourceLen >> 14) +
                     (sourceLen >> 25) + 13;
    return bound < sourceLen ? (z_size_t)-1 : bound;
}
uLong compressBound(uLong sourceLen) {
    z_size_t bound = compressBound_z(sourceLen);
    return (uLong)bound != bound ? (uLong)-1 : (uLong)bound;
}
