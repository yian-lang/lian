#include "zlib.h"
#    include <stddef.h>
#  include <string.h>
#  include <stdlib.h>
#  include <limits.h>
#        include <alloc.h>
#      include <malloc.h>
#    include <malloc.h>
#  include <stdio.h>
#include <stdatomic.h>





extern const char deflate_copyright[];
extern const char inflate_copyright[];
extern const char inflate9_copyright[];

typedef unsigned char uch;
typedef uch uchf;
typedef unsigned short ush;
typedef ush ushf;
typedef unsigned long ulg;


extern char * const z_errmsg[10];
   extern uLong adler32_combine64(uLong, uLong, long long);
   extern uLong crc32_combine64(uLong, uLong, long long);
   extern uLong crc32_combine_gen64(long long);
   voidpf zcalloc(voidpf opaque, unsigned items,
                                unsigned size);
   void zcfree(voidpf opaque, voidpf ptr);
