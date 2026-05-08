#include "xalloc.h"

#ifndef DYNAMICARR_H
#define DYNAMICARR_H

#define DA_BUFFER_SIZE 16
#define DA_NULL .items = NULL, .position = 0, .bufsize = 0

#define da_append(l, x) \
	do {\
		if ((l)->position >= (l)->bufsize) {\
			if ((l)->bufsize == 0) (l)->bufsize = DA_BUFFER_SIZE;\
			else (l)->bufsize *= 2;\
			(l)->items = xrealloc((l)->items, ((l)->bufsize)*sizeof(*(l)->items));\
		}\
		(l)->items[(l)->position++] = x;\
	} while(0)

typedef struct str {
	char* items;
	size_t position;
	size_t bufsize;
} str;

char* get_string(str* s);

typedef struct arg_list {
	char** items;
	size_t position;
	size_t bufsize;
} arg_list;

char** get_args(arg_list* l);
void destroy_args(char** args);

#endif
