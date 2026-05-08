CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -fprofile-arcs -ftest-coverage -fPIC
LDFLAGS = -lgcov --coverage

SRC = src/bhshell.c src/dynamicarr.c src/input.c src/main.c src/xalloc.c
TEST_SRC = src/dynamicarr.c src/input.c src/xalloc.c tests/test.c
OBJ = $(SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)

all: bhshell

bhshell: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o bhshell $(LDFLAGS)

test: $(TEST_SRC)
	$(CC) $(CFLAGS) $(TEST_SRC) -o test_1 $(LDFLAGS)
	./test_1

coverage: test
	@gcov -b -c $(SRC)

clean:
	rm -rf test_1 bhshell
	rm -rf **/*.gcno **/*.gcda **/*.gcov
	rm -rf *.gcno *.gcda *.gcov
	rm -rf src/*.o tests/*.o

.PHONY: all clean test coverage
