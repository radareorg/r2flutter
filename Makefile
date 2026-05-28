CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -fPIC
CFLAGS += -Iinclude
CFLAGS += $(shell pkg-config --cflags r_core 2>/dev/null || echo "-I/usr/local/include/libr")
LDFLAGS += $(shell pkg-config --libs r_core 2>/dev/null || echo "-L/usr/local/lib -lr_core -lr_util -ldl")
DEPFLAGS = -MMD -MP

# Directories
SRC_DIR = src/lib
BUILD_DIR = build
BIN_DIR = bin

# Source files
LIB_SRC = $(SRC_DIR)/dart_app.c $(SRC_DIR)/dart_dumper.c $(SRC_DIR)/dart_pool_snapshot.c $(SRC_DIR)/dart_pool_discovery.c $(SRC_DIR)/dart_pool_names.c $(SRC_DIR)/dart_pool_strings.c $(SRC_DIR)/dart_pool_data_image.c $(SRC_DIR)/dart_pool_it.c $(SRC_DIR)/dart_pool_xrefs.c $(SRC_DIR)/dart_pool_clusters.c $(SRC_DIR)/dart_pool_classes.c $(SRC_DIR)/dart_pool_parse.c $(SRC_DIR)/dart_pool_modern.c $(SRC_DIR)/dart_version.c $(SRC_DIR)/dart_obf.c
MAIN_SRC = src/tool/main.c

# Object files
LIB_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC))
MAIN_OBJ = $(BUILD_DIR)/main.o
DEP_FILES = $(LIB_OBJ:.o=.d) $(MAIN_OBJ:.o=.d)

# Artifacts
BIN_FILE = $(BIN_DIR)/r2flutter
STATIC_LIB = $(BUILD_DIR)/libr2flutter.a

all: $(BIN_FILE)

$(STATIC_LIB): $(LIB_OBJ)
	ar rcs $@ $^

$(BIN_FILE): $(STATIC_LIB) $(MAIN_OBJ) | $(shell mkdir -p $(BIN_DIR))
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) -L$(BUILD_DIR) -lr2flutter $(LDFLAGS) -Wl,-rpath,/usr/local/lib -g

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -g -c $< -o $@

$(MAIN_OBJ): $(MAIN_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -g -c $< -o $@

r2:
	$(MAKE) $(STATIC_LIB)
	$(MAKE) -C src/r2
	$(MAKE) -C src/r2 user-install

user-install user-uninstall:
	$(MAKE) $(STATIC_LIB)
	$(MAKE) -C src/r2
	$(MAKE) -C src/r2 $@

fmt indent format:
	clang-format-radare2 $(shell find src include -name '*.[ch]')

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)/r2flutter
	$(MAKE) -C src/r2 clean

test-r2r: $(BIN_FILE)
	$(MAKE) -C src/r2
	r2r -u -t 30 test/db

test: $(BIN_FILE)
	@$(MAKE) -C src/r2
	@echo "Running custom testsuite"
	@python3 scripts/run_tests.py

.PHONY: all clean test test-r2r r2 user-install user-uninstall fmt indent format

-include $(DEP_FILES)
