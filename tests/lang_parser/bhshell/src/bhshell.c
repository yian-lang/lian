#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdbool.h>

#include "include/dynamicarr.h"
#include "include/input.h"
#include "include/bhshell.h"
#include "include/xalloc.h"

#define BUF_SIZE 64

char* bhshell_builtin_str[] = {
	"cd",
	"help",
	"exit",
};

int (*bhshell_builtin_func[]) (char**) = {
	&bhshell_cd,
	&bhshell_help,
	&bhshell_exit,
};

void bhshell_loop() {
	char** args; 
	int status = 1;

	do {
		char* dir = getcwd(NULL, 0);
		if (!dir) exit(EXIT_FAILURE);

		printf("[%s] $ ", dir);

		char* line = bhshell_read_line();
		command* cmd = bhshell_parse(line);
		if (cmd == NULL) {
			printf("Invalid Command\n");
			continue;
		}

		status = bhshell_execute(cmd); 
		
		free(dir);
		free(line);
		destroy_command(cmd);
	} while(status); 
}

int bhshell_execute(command* cmd) {
	if (cmd->args[0] == NULL) {
		return 1;
	}

	for (int i = 0; i < bhshell_num_builtins(); i++) {
		if (strcmp(cmd->args[0], bhshell_builtin_str[i]) == 0) {
			return (*bhshell_builtin_func[i])(cmd->args);
		}
	}
	return bhshell_launch(cmd);
}

int bhshell_launch(command* cmd) {
	pid_t pid;
	int status;

	int redirect_fd[2];
	if (cmd->redirect_file_name != NULL) {
		if (pipe(redirect_fd) == -1) {
			exit(EXIT_FAILURE);
		}
	}
	
	int pipe_fd[2];
	if (cmd->pipe_args != NULL) {
		if (pipe(pipe_fd) == -1) {
			exit(EXIT_FAILURE);
		}
	}

	pid = fork();
	if (pid == 0) {
		if (cmd->pipe_args != NULL) {
			close(pipe_fd[0]);
			if (dup2(pipe_fd[1], STDOUT_FILENO) == -1) {
				fprintf(stderr, "bhshell: Could not redirect stdout\n");
				exit(EXIT_FAILURE);
			}
			close(pipe_fd[1]);
			if (cmd->redirect_file_name != NULL) {
				close(redirect_fd[0]);
				close(redirect_fd[1]);
			}
		}
		if (cmd->pipe_args == NULL && cmd->redirect_file_name != NULL) {
			close(redirect_fd[0]);
			if (dup2(redirect_fd[1], STDOUT_FILENO) == -1) {
				fprintf(stderr, "bhshell: Could not redirect stdout to file\n");
				exit(EXIT_FAILURE);
			}
			close(redirect_fd[1]);
		} 
		
		if (execvp(cmd->args[0], cmd->args) == -1) {
			perror("bhshell");
		}
		// execvp takes over the entire process
		// so if return backs to the child process
		exit(EXIT_FAILURE);

	} else if (pid < 0) {
		// error forking
		perror("bhshell: Could not create child process");
		exit(EXIT_FAILURE);
	} 
	// Main process
	if (cmd->pipe_args != NULL) {
		pid_t pid_pipe = fork();
		int pipe_status;
		if (pid_pipe == 0) {
			if (cmd->redirect_file_name != NULL) {
				close(redirect_fd[0]);
				if (dup2(redirect_fd[1], STDOUT_FILENO) == -1) {
					fprintf(stderr, "bhshell: Could not redirect stdout to file\n");
					exit(EXIT_FAILURE);
				}
				close(redirect_fd[1]);
			}

			close(pipe_fd[1]);
			if (dup2(pipe_fd[0], STDIN_FILENO) == -1) {
				fprintf(stderr, "bhshell: Could not redirect stdin\n");
				exit(EXIT_FAILURE);
			}
			close(pipe_fd[0]);


			if (execvp(cmd->pipe_args[0], cmd->pipe_args) == -1) {
				perror("bhshell");
			}
			exit(EXIT_FAILURE);
		} else if (pid_pipe < 0) {
			perror("bhshell: Could not create child process");
			exit(EXIT_FAILURE);
		}
		close(pipe_fd[0]);
		close(pipe_fd[1]);
		if (cmd->redirect_file_name != NULL) {
			write_to_redirect(redirect_fd, cmd);
		}
		do {
			waitpid(pid_pipe, &pipe_status, WUNTRACED);
			waitpid(pid, &status, WUNTRACED);
		} while(!WIFEXITED(status) && !WIFSIGNALED(status) && !WIFEXITED(pipe_status) && !WIFSIGNALED(pipe_status));
	
		return 1;
	} else if (cmd->redirect_file_name != NULL) {
		write_to_redirect(redirect_fd, cmd);
	}
	do {
		waitpid(pid, &status, WUNTRACED);
	} while(!WIFEXITED(status) && !WIFSIGNALED(status));
	return 1;
}

int bhshell_cd(char** args) {
	if (args[1] == NULL) {
		fprintf(stderr, "bhshell: expected argument to \"cd\" into\n");
	} else {
		if (chdir(args[1]) != 0) {
			perror("bhshell");
		}
	}
	return 1;
}

int bhshell_help(char** args) {
	printf("A simple shell built to understand how processes work.\n");
	printf("The following functions are builtin:\n");

	int count = bhshell_num_builtins();
	for (int i = 0; i < count; i++) {
		printf("\t %d. %s\n", i + 1, bhshell_builtin_str[i]);
	}
	return 1;
}

int bhshell_exit(char** args) {
	return 0;
}

int bhshell_num_builtins() {
	return sizeof(bhshell_builtin_str) / sizeof(char*);
}

void write_to_redirect(int redirect_fd[2], command* cmd) {
	str s = { DA_NULL };

	char temp;
	
	close(redirect_fd[1]);
	int finished = read(redirect_fd[0], &temp, sizeof(char));
	if (finished == -1) {
		close(redirect_fd[0]);
		close(redirect_fd[1]);
		free(s.items);
		exit(EXIT_FAILURE);
	}
	while (finished != 0) {
		da_append(&s, temp);

		finished = read(redirect_fd[0], &temp, sizeof(char));
	}
	char* string = get_string(&s);
	
	close(redirect_fd[0]);

	FILE* f = fopen(cmd->redirect_file_name, "w");
	if (!f) {
		fprintf(stderr, "Could not open file\n");
		free(s.items);
		exit(EXIT_FAILURE);
	}
	size_t written = fwrite(string, strlen(string), 1, f);
	if (written == 0) {
		fprintf(stderr, "Could not write to file\n");
		free(string);
		exit(EXIT_FAILURE);
	}
	free(string); 
	fclose(f);
}
