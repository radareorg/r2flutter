CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/local/include/libr -I../radare2/libr/include $(shell pkg-config --cflags r_core)
LDFLAGS = $(shell pkg-config --libs r_core) -Wl,-rpath,/usr/local/lib

TARGET = blutter_r2
SOURCES = main.c dart_app.c dart_dumper.c dart_pool_parse.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
