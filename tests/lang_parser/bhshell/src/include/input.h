#include <stdlib.h>

#ifndef INPUT_H
#define INPUT_H

#define FREE_ON_INVALID(ARGS, PIPE_ARGS, REDIRECT) \
	do {\
		if ((ARGS).position > 0) destroy_args(args.items);\
		if ((PIPE_ARGS).position > 0) destroy_args(pipe_args.items);\
		if ((REDIRECT)!= NULL) free(redirect);\
	} while(0)

typedef struct command {
	char** args;
	char** pipe_args;
	char* redirect_file_name;
} command;

char* bhshell_read_line();
command* bhshell_parse(char* line);
void destroy_command(command* cmd);
command* new_command();
#endif
