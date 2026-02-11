CC      := gcc
CFLAGS  := -O3 -march=native -flto -fomit-frame-pointer -pipe \
           -Wall -Wextra -Wpedantic -Wno-unused-parameter      \
           -Iinclude
LDFLAGS := -O3 -flto -s

SRC     := $(wildcard src/*.c)
OBJ     := $(SRC:src/%.c=build/%.o)
BIN     := elfparse

.PHONY: all clean

all: build $(BIN)

build:
	@mkdir -p build

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf build $(BIN)
