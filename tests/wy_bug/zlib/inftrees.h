
typedef struct {
    unsigned char op;
    unsigned char bits;
    unsigned short val;
} code;
typedef enum {
    CODES,
    LENS,
    DISTS
} codetype;

int ZLIB_INTERNAL inflate_table(codetype type, unsigned short FAR *lens,
                                unsigned codes, code FAR * FAR *table,
                                unsigned FAR *bits, unsigned short FAR *work);
struct inflate_state;
void ZLIB_INTERNAL inflate_fixed(struct inflate_state FAR *state);
