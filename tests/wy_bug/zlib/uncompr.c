#include "zlib.h"









int uncompress2_z(Bytef *dest, z_size_t *destLen, const Bytef *source,
                          z_size_t *sourceLen) {
    z_stream stream;
    int err;
    const uInt max = (uInt)-1;
    z_size_t len, left;

    if (sourceLen == ((void*)0) || (*sourceLen > 0 && source == ((void*)0)) ||
        destLen == ((void*)0) || (*destLen > 0 && dest == ((void*)0)))
        return (-2);

    len = *sourceLen;
    left = *destLen;
    if (left == 0 && dest == 0)
        dest = (Bytef *)&stream.reserved;

    stream.next_in = ( Bytef *)source;
    stream.avail_in = 0;
    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;
    stream.opaque = (voidpf)0;

    err = inflateInit_((&stream), "1.3.2.1-motley", (int)sizeof(z_stream));
    if (err != 0) return err;

    stream.next_out = dest;
    stream.avail_out = 0;

    do {
        if (stream.avail_out == 0) {
            stream.avail_out = left > (z_size_t)max ? max : (uInt)left;
            left -= stream.avail_out;
        }
        if (stream.avail_in == 0) {
            stream.avail_in = len > (z_size_t)max ? max : (uInt)len;
            len -= stream.avail_in;
        }
        err = inflate(&stream, 0);
    } while (err == 0);




    len += stream.avail_in;
    left += stream.avail_out;
    *sourceLen -= len;
    *destLen -= left;

    inflateEnd(&stream);
    return err == 1 ? 0 :
           err == 2 ? (-3) :
           err == (-5) && len == 0 ? (-3) :
           err;
}
int uncompress2(Bytef *dest, uLongf *destLen, const Bytef *source,
                        uLong *sourceLen) {
    int ret;
    z_size_t got = *destLen, used = *sourceLen;
    ret = uncompress2_z(dest, &got, source, &used);
    *sourceLen = (uLong)used;
    *destLen = (uLong)got;
    return ret;
}
int uncompress_z(Bytef *dest, z_size_t *destLen, const Bytef *source,
                         z_size_t sourceLen) {
    z_size_t used = sourceLen;
    return uncompress2_z(dest, destLen, source, &used);
}
int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source,
                       uLong sourceLen) {
    uLong used = sourceLen;
    return uncompress2(dest, destLen, source, &used);
}
