CFLAGS = -Wall -Wextra -Wpedantic -Werror -g
CC = clang

.PHONY: clean

all: main

clean:
	rm -rf main main.dSYM
