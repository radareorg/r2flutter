CC ?= gcc
R2_CFLAGS  ?= $(shell r2 -H R2_CFLAGS)
R2_LDFLAGS ?= $(shell r2 -H R2_LDFLAGS)
CFLAGS ?= -Wall -Wextra -O2 -fPIC
CFLAGS += -Iinclude -Iinclude/r2flutter
CFLAGS += $(R2_CFLAGS)
LDFLAGS += $(R2_LDFLAGS)
DEPFLAGS = -MMD -MP
R2R_JOBS ?= 1
R2R_TIMEOUT ?= 30
R2_LIBR_PLUGINS=$(shell r2 -H R2_LIBR_PLUGINS 2> /dev/null)
R2_LIBEXT=$(shell r2 -H R2_LIBEXT 2> /dev/null)
-include config.mk
PREFIX?=/usr/local

# Directories
SRC_DIR = src/lib
BUILD_DIR = build
BIN_DIR = bin

# Source files
LIB_SRC = $(SRC_DIR)/dart_app.c $(SRC_DIR)/dart_dumper.c $(SRC_DIR)/dart_pool_snapshot.c $(SRC_DIR)/dart_pool_discovery.c $(SRC_DIR)/dart_pool_names.c $(SRC_DIR)/dart_pool_strings.c $(SRC_DIR)/dart_pool_data_image.c $(SRC_DIR)/dart_pool_it.c $(SRC_DIR)/dart_pool_xrefs.c $(SRC_DIR)/dart_object.c $(SRC_DIR)/dart_sbom.c $(SRC_DIR)/dart_pool_clusters.c $(SRC_DIR)/dart_pool_classes.c $(SRC_DIR)/dart_pool_model.c $(SRC_DIR)/dart_pool_parse.c $(SRC_DIR)/dart_pool_modern.c $(SRC_DIR)/dart_version.c $(SRC_DIR)/dart_cid.c $(SRC_DIR)/dart_obf.c
MAIN_SRC = src/tool/main.c
ANALYSIS_SRC = src/r2/flutter_analysis.c

# Object files
LIB_OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRC))
MAIN_OBJ = $(BUILD_DIR)/main.o
ANALYSIS_OBJ = $(BUILD_DIR)/flutter_analysis.o
DEP_FILES = $(LIB_OBJ:.o=.d) $(MAIN_OBJ:.o=.d) $(ANALYSIS_OBJ:.o=.d)

# Artifacts
BIN_FILE = $(BIN_DIR)/r2flutter
STATIC_LIB = $(BUILD_DIR)/libr2flutter.a
INC_VER = $(SRC_DIR)/../include/r2flutter/r2flutter_version.h

all: $(BIN_FILE) $(INC_VER)

$(INC_VER):
	./configure

$(STATIC_LIB): $(LIB_OBJ)
	ar rcs $@ $^

$(BIN_FILE): $(STATIC_LIB) $(MAIN_OBJ) $(ANALYSIS_OBJ) | $(shell mkdir -p $(BIN_DIR))
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) $(ANALYSIS_OBJ) -L$(BUILD_DIR) -lr2flutter $(LDFLAGS) -Wl,-rpath,$(PREFIX)/lib -g

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -g -c $< -o $@

$(MAIN_OBJ): $(MAIN_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -g -c $< -o $@

$(ANALYSIS_OBJ): $(ANALYSIS_SRC) src/r2/flutter_analysis.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -g -c $< -o $@

r2 plugin:
	$(MAKE) $(STATIC_LIB)
	$(MAKE) -C src/r2
	$(MAKE) -C src/r2 user-install

user-install user-uninstall:
	$(MAKE) $(STATIC_LIB)
	$(MAKE) -C src/r2
	$(MAKE) -C src/r2 $@

install: uninstall
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	cp -f bin/r2flutter "$(DESTDIR)$(PREFIX)/bin/r2flutter"
	mkdir -p "$(DESTDIR)$(R2_LIBR_PLUGINS)"
	cp -f src/r2/core_flutter.$(R2_LIBEXT) "$(DESTDIR)$(R2_LIBR_PLUGINS)"/core_flutter.$(R2_LIBEXT)

symstall: uninstall
	mkdir -p "$(DESTDIR)$(PREFIX)/bin"
	ln -fs $(shell pwd)/bin/r2flutter "$(DESTDIR)$(PREFIX)/bin/r2flutter"
	mkdir -p "$(DESTDIR)$(R2_LIBR_PLUGINS)"
	ln -fs $(shell pwd)/src/r2/core_flutter.$(R2_LIBEXT) "$(DESTDIR)$(R2_LIBR_PLUGINS)"/core_flutter.$(R2_LIBEXT)

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/r2flutter"
	rm -f $(DESTDIR)$(R2_LIBR_PLUGINS)/core_flutter.$(R2_LIBEXT)

fmt indent format:
	clang-format-radare2 $(shell find src include -name '*.[ch]')

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)/r2flutter
	$(MAKE) -C src/r2 clean

test-r2r: $(BIN_FILE)
	$(MAKE) -C src/r2
	r2r -u -j$(R2R_JOBS) -t $(R2R_TIMEOUT) test/db

test: $(BIN_FILE)
	@$(MAKE) -C src/r2
	@echo "Running custom testsuite"
	@python3 scripts/run_tests.py

.PHONY: all clean test test-r2r r2 plugin user-install user-uninstall fmt indent format

-include $(DEP_FILES)
