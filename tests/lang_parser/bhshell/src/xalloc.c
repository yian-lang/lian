#include <stdlib.h>
#include <stdio.h>

#include "include/xalloc.h"

void* xmalloc(size_t size) {
	void* ptr = malloc(size);
	if (!ptr) {
		fprintf(stderr, "bhshell: allocation error\n");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

void* xrealloc(void* ptr, size_t size) {
	ptr = realloc(ptr, size);
	if (!ptr) {
		fprintf(stderr, "bhshell: allocation error\n");
		exit(EXIT_FAILURE);
	}
	return ptr;
}
