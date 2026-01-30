CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/local/include/libr -I../radare2/libr/include $(shell pkg-config --cflags r_core) -g
LDFLAGS = $(shell pkg-config --libs r_core) -Wl,-rpath,/usr/local/lib -g

TARGET = blutter_r2
SOURCES = main.c dart_app.c dart_dumper.c dart_pool_parse.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

fmt:
	clang-format-radare2 *.c

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

test-r2r:
	r2r -t 30 test/db

test: $(TARGET)
	@echo "Running custom Python testsuite"
	@python3 scripts/run_tests.py

.PHONY: all clean test
