#  include <zconf.h>
# include "zconf.h"

typedef voidpf (*alloc_func)(voidpf opaque, uInt items, uInt size);
typedef void (*free_func)(voidpf opaque, voidpf address);

struct internal_state;

typedef struct z_stream_s {
            Bytef *next_in;
    uInt avail_in;
    uLong total_in;

    Bytef *next_out;
    uInt avail_out;
    uLong total_out;

            char *msg;
    struct internal_state *state;

    alloc_func zalloc;
    free_func zfree;
    voidpf opaque;

    int data_type;

    uLong adler;
    uLong reserved;
} z_stream;

typedef z_stream *z_streamp;





typedef struct gz_header_s {
    int text;
    uLong time;
    int xflags;
    int os;
    Bytef *extra;
    uInt extra_len;
    uInt extra_max;
    Bytef *name;
    uInt name_max;
    Bytef *comment;
    uInt comm_max;
    int hcrc;
    int done;

} gz_header;

typedef gz_header *gz_headerp;
extern const char * zlibVersion(void);
extern int deflate(z_streamp strm, int flush);
extern int deflateEnd(z_streamp strm);
extern int inflate(z_streamp strm, int flush);
extern int inflateEnd(z_streamp strm);
extern int deflateSetDictionary(z_streamp strm,
                                         const Bytef *dictionary,
                                         uInt dictLength);
extern int deflateGetDictionary(z_streamp strm,
                                         Bytef *dictionary,
                                         uInt *dictLength);
extern int deflateCopy(z_streamp dest,
                                z_streamp source);
extern int deflateReset(z_streamp strm);
extern int deflateParams(z_streamp strm,
                                  int level,
                                  int strategy);
extern int deflateTune(z_streamp strm,
                                int good_length,
                                int max_lazy,
                                int nice_length,
                                int max_chain);
extern uLong deflateBound(z_streamp strm, uLong sourceLen);
extern z_size_t deflateBound_z(z_streamp strm, z_size_t sourceLen);
extern int deflatePending(z_streamp strm,
                                   unsigned *pending,
                                   int *bits);
extern int deflateUsed(z_streamp strm,
                                int *bits);
extern int deflatePrime(z_streamp strm,
                                 int bits,
                                 int value);
extern int deflateSetHeader(z_streamp strm,
                                     gz_headerp head);
extern int inflateSetDictionary(z_streamp strm,
                                         const Bytef *dictionary,
                                         uInt dictLength);
extern int inflateGetDictionary(z_streamp strm,
                                         Bytef *dictionary,
                                         uInt *dictLength);
extern int inflateSync(z_streamp strm);
extern int inflateCopy(z_streamp dest,
                                z_streamp source);
extern int inflateReset(z_streamp strm);
extern int inflateReset2(z_streamp strm,
                                  int windowBits);
extern int inflatePrime(z_streamp strm,
                                 int bits,
                                 int value);
extern long inflateMark(z_streamp strm);
extern int inflateGetHeader(z_streamp strm,
                                     gz_headerp head);
typedef unsigned (*in_func)(void *,
                                    unsigned char * *);
typedef int (*out_func)(void *, unsigned char *, unsigned);

extern int inflateBack(z_streamp strm,
                                in_func in, void *in_desc,
                                out_func out, void *out_desc);
extern int inflateBackEnd(z_streamp strm);







extern uLong zlibCompileFlags(void);
extern int compress(Bytef *dest, uLongf *destLen,
                             const Bytef *source, uLong sourceLen);
extern int compress_z(Bytef *dest, z_size_t *destLen,
                               const Bytef *source, z_size_t sourceLen);
extern int compress2(Bytef *dest, uLongf *destLen,
                              const Bytef *source, uLong sourceLen,
                              int level);
extern int compress2_z(Bytef *dest, z_size_t *destLen,
                                const Bytef *source, z_size_t sourceLen,
                                int level);
extern uLong compressBound(uLong sourceLen);
extern z_size_t compressBound_z(z_size_t sourceLen);






extern int uncompress(Bytef *dest, uLongf *destLen,
                               const Bytef *source, uLong sourceLen);
extern int uncompress_z(Bytef *dest, z_size_t *destLen,
                                 const Bytef *source, z_size_t sourceLen);
extern int uncompress2(Bytef *dest, uLongf *destLen,
                                const Bytef *source, uLong *sourceLen);
extern int uncompress2_z(Bytef *dest, z_size_t *destLen,
                                  const Bytef *source, z_size_t *sourceLen);
typedef struct gzFile_s *gzFile;
extern gzFile gzdopen(int fd, const char *mode);
extern int gzbuffer(gzFile file, unsigned size);
extern int gzsetparams(gzFile file, int level, int strategy);
extern int gzread(gzFile file, voidp buf, unsigned len);
extern z_size_t gzfread(voidp buf, z_size_t size, z_size_t nitems,
                                 gzFile file);
extern int gzwrite(gzFile file, voidpc buf, unsigned len);
extern z_size_t gzfwrite(voidpc buf, z_size_t size,
                                  z_size_t nitems, gzFile file);
extern int gzprintf(gzFile file, const char *format, ...);
extern int gzputs(gzFile file, const char *s);
extern char * gzgets(gzFile file, char *buf, int len);
extern int gzputc(gzFile file, int c);





extern int gzgetc(gzFile file);
extern int gzungetc(int c, gzFile file);
extern int gzflush(gzFile file, int flush);
extern int gzrewind(gzFile file);
extern int gzeof(gzFile file);
extern int gzdirect(gzFile file);
extern int gzclose(gzFile file);
extern int gzclose_r(gzFile file);
extern int gzclose_w(gzFile file);
extern const char * gzerror(gzFile file, int *errnum);
extern void gzclearerr(gzFile file);
extern uLong adler32(uLong adler, const Bytef *buf, uInt len);
extern uLong adler32_z(uLong adler, const Bytef *buf,
                                z_size_t len);
extern uLong crc32(uLong crc, const Bytef *buf, uInt len);
extern uLong crc32_z(uLong crc, const Bytef *buf,
                              z_size_t len);
extern uLong crc32_combine_op(uLong crc1, uLong crc2, uLong op);
extern int deflateInit_(z_streamp strm, int level,
                                 const char *version, int stream_size);
extern int inflateInit_(z_streamp strm,
                                 const char *version, int stream_size);
extern int deflateInit2_(z_streamp strm, int level, int method,
                                  int windowBits, int memLevel,
                                  int strategy, const char *version,
                                  int stream_size);
extern int inflateInit2_(z_streamp strm, int windowBits,
                                  const char *version, int stream_size);
extern int inflateBackInit_(z_streamp strm, int windowBits,
                                     unsigned char *window,
                                     const char *version,
                                     int stream_size);
struct gzFile_s {
    unsigned have;
    unsigned char *next;
    long long pos;
};
extern int gzgetc_(gzFile file);
   extern gzFile gzopen(const char *, const char *);
   extern long long gzseek(gzFile, long long, int);
   extern long long gztell(gzFile);
   extern long long gzoffset(gzFile);
   extern uLong adler32_combine(uLong, uLong, long long);
   extern uLong crc32_combine(uLong, uLong, long long);
   extern uLong crc32_combine_gen(long long);
extern const char * zError(int);
extern int inflateSyncPoint(z_streamp);
extern const z_crc_t * get_crc_table(void);
extern int inflateUndermine(z_streamp, int);
extern int inflateValidate(z_streamp, int);
extern unsigned long inflateCodesUsed(z_streamp);
extern int inflateResetKeep(z_streamp);
extern int deflateResetKeep(z_streamp);






extern int gzvprintf(gzFile file,
                                           const char *format,
                                           va_list va);
