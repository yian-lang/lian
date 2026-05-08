#include <string.h>

#include "include/dynamicarr.h"
#include "include/xalloc.h"
//
char* get_string(str* s) {
	da_append(s, '\0');
	char* string = xmalloc(sizeof(char) * (s->position));
	memcpy(string, s->items, sizeof(char) * s->position);
	free(s->items);
	s->position = 0; s->items = NULL; s->bufsize = 0;
	return string;
}


void destroy_args(char** args) {
	if (!args) return;
	size_t i = 0;
	while(args[i] != NULL) {
		free(args[i]);
		i++;
	}
}

char** get_args(arg_list* l) {
	if (l->position == 0) {
		return NULL;
	}
	da_append(l, NULL);
	char** args = xmalloc(sizeof(char*) * (l->position));
	for (size_t i = 0; i < l->position - 1; i++) {
		size_t length = strlen(l->items[i]);
		args[i] = xmalloc(sizeof(char) * (length + 1));
		memcpy(args[i], l->items[i], length + 1);
	}
	args[l->position - 1] = NULL;
	return args;
}
