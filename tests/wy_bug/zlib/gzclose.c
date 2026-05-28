#include "gzguts.h"










int gzclose(gzFile file) {

    gz_statep state;

    if (file == ((void*)0))
        return (-2);
    state = (gz_statep)file;

    return state->mode == 7247 ? gzclose_r(file) : gzclose_w(file);



}
