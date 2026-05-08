#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

#include "include/bhshell.h"
#include "include/input.h"

int main(void) {
	bhshell_loop();	
	return EXIT_SUCCESS;
}
