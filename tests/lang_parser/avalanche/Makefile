.PHONY: all clean

# Compiler settings
CC ?= gcc  # Default to gcc, but allow override
CFLAGS = -Wall -Wextra -g -fprofile-arcs -ftest-coverage -I$(abspath src) -fPIC
LDFLAGS = -fprofile-arcs -ftest-coverage
RM = rm -f

# Directories
SRC_DIR = src

# Sources and Headers
SOURCES = avalanche.c  # Compiled in current directory
HEADERS = $(SRC_DIR)/avalanche.h

TEST_SOURCES = src/matrix_test.c
TEST_OBJECTS = $(notdir $(TEST_SOURCES:.c=.o))  # Compiled in current directory

# Targets
all: matrix_test fnv_32 fnv_mw
	./matrix_test
	./fnv_32 ./data/fnv_32.txt
	./fnv_mw ./data/fnv_mw.txt

# Ensure avalanche.c is compiled in the current directory
avalanche.o: $(SRC_DIR)/avalanche.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Test binary (Coverage stats in the current directory)
matrix_test: $(TEST_OBJECTS) avalanche.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST_OBJECTS) avalanche.o

# Rule to compile test source file in the current directory
matrix_test.o: src/matrix_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

# FNV-1a Binaries (Coverage stats in the current directory)
fnv_32: src/fnv_1a.c avalanche.o $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $< avalanche.o

fnv_mw: src/fnv_1a.c avalanche.o $(HEADERS)
	$(CC) $(CFLAGS) -DMULTI_WORD -o $@ $< avalanche.o

# Clean rule
clean:
	$(RM) $(TEST_OBJECTS) matrix_test fnv_32 fnv_mw *.gcda *.gcno *.gcov
	$(RM) avalanche.o
