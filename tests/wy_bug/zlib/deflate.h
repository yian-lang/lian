#include "zutil.h"

typedef struct ct_data_s {
    union {
        ush freq;
        ush code;
    } fc;
    union {
        ush dad;
        ush len;
    } dl;
} ct_data;






typedef struct static_tree_desc_s static_tree_desc;

typedef struct tree_desc_s {
    ct_data *dyn_tree;
    int max_code;
    const static_tree_desc *stat_desc;
} tree_desc;

typedef ush Pos;
typedef Pos Posf;
typedef unsigned IPos;





typedef struct internal_state {
    z_streamp strm;
    int status;
    Bytef *pending_buf;
    ulg pending_buf_size;
    Bytef *pending_out;
    ulg pending;
    int wrap;
    gz_headerp gzhead;
    ulg gzindex;
    Byte method;
    int last_flush;



    uInt w_size;
    uInt w_bits;
    uInt w_mask;

    Bytef *window;
    ulg window_size;




    Posf *prev;





    Posf *head;

    uInt ins_h;
    uInt hash_size;
    uInt hash_bits;
    uInt hash_mask;

    uInt hash_shift;






    long block_start;




    uInt match_length;
    IPos prev_match;
    int match_available;
    uInt strstart;
    uInt match_start;
    uInt lookahead;

    uInt prev_length;




    uInt max_chain_length;





    uInt max_lazy_match;
    int level;
    int strategy;

    uInt good_match;


    int nice_match;



    struct ct_data_s dyn_ltree[(2*(256 +1+29)+1)];
    struct ct_data_s dyn_dtree[2*30 +1];
    struct ct_data_s bl_tree[2*19 +1];

    struct tree_desc_s l_desc;
    struct tree_desc_s d_desc;
    struct tree_desc_s bl_desc;

    ush bl_count[15 +1];


    int heap[2*(256 +1+29)+1];
    int heap_len;
    int heap_max;




    uch depth[2*(256 +1+29)+1];
    uchf *sym_buf;


    uInt lit_bufsize;
    uInt sym_next;
    uInt sym_end;

    ulg opt_len;
    ulg static_len;
    uInt matches;
    uInt insert;






    ush bi_buf;



    int bi_valid;



    int bi_used;



    ulg high_water;






    int slid;


} deflate_state;
void _tr_init(deflate_state *s);
int _tr_tally(deflate_state *s, unsigned dist, unsigned lc);
void _tr_flush_block(deflate_state *s, charf *buf,
                                   ulg stored_len, int last);
void _tr_flush_bits(deflate_state *s);
void _tr_align(deflate_state *s);
void _tr_stored_block(deflate_state *s, charf *buf,
                                    ulg stored_len, int last);
  extern const uch _length_code[];
  extern const uch _dist_code[];
