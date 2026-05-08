#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "include/input.h"
#include "include/dynamicarr.h"
#include "include/xalloc.h"

enum ARG_TYPE {
	ARG,
	PIPE_ARG,
	REDIRECT
};

char* bhshell_read_line() {
	str s = { DA_NULL };
	while(1) {
		int c = getchar();
		if (c == '\n' || c == EOF) {
			char* string = get_string(&s);
			return string;
		} else {
			da_append(&s, c);
		}
	}
}

command* bhshell_parse(char* line) {
	size_t length = strlen(line);
	arg_list args = { DA_NULL };
	arg_list pipe_args = { DA_NULL };
	str s = { DA_NULL };
	char* redirect = NULL;
	enum ARG_TYPE current = ARG;
	command* cmd = new_command();

	for (size_t i = 0; i < length; i++) {
		if (line[i] == '\n' || line[i] == '\t' || line[i] == ' ') {
			if (s.position > 0) {
				char* string = get_string(&s);
				if (current == ARG) {
					da_append(&args, string);
				} else if (current == PIPE_ARG) {
					da_append(&pipe_args, string);
				} else {
					redirect = string;	
				}
			} 
			continue;
		} else if (line[i] == '|') {
			if (s.position > 0) {
				char* string = get_string(&s);
				if (current == ARG) {
					da_append(&args, string);
					da_append(&args, NULL);
				} else {
					FREE_ON_INVALID(args, pipe_args, redirect);
					return NULL;
				}
			}
			if (i + 1 < length && line[i] == '>') {
				FREE_ON_INVALID(args, pipe_args, redirect);
				return NULL;
			}
			current = PIPE_ARG;
		} else if (line[i] == '>') {
			if (s.position > 0) {
				char* string = get_string(&s);
				if (current == ARG) {
					da_append(&args, string);
					da_append(&args, NULL);
				} else if (current == PIPE_ARG) {
					da_append(&pipe_args, string);
					da_append(&pipe_args, NULL);
				}
			}
			current = REDIRECT;
		} else {
			da_append(&s, line[i]);
		}
	}
	if (s.position == 0) {
		FREE_ON_INVALID(args, pipe_args, redirect);
		return NULL;
	}
	if (s.position > 0) {
		char* string = get_string(&s);
		if (current == ARG) {
			da_append(&args, string);
			da_append(&args, NULL);
		} else if (current == PIPE_ARG) {
			da_append(&pipe_args, string);
			da_append(&pipe_args, NULL);
		} else {
			redirect = string;
		}
	} 
	if (args.position == 0) {
		FREE_ON_INVALID(args, pipe_args, redirect);
		return NULL;
	}
	cmd->args = args.items;
	if (pipe_args.position > 0) {
		cmd->pipe_args = pipe_args.items;
	}
	if (redirect != NULL) {
		cmd->redirect_file_name = redirect;
	}
	return cmd;
}

command* new_command() {
	command* cmd = xmalloc(sizeof(command));
	
	cmd->args = NULL;
	cmd->pipe_args = NULL;
	cmd->redirect_file_name = NULL;
	return cmd;
}

void destroy_command(command* cmd) {
	destroy_args(cmd->args);
	destroy_args(cmd->pipe_args);
	free(cmd->redirect_file_name);
	free(cmd);
}
