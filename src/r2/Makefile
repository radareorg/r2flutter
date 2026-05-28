CC ?= gcc
CFLAGS += -Wall -Wextra -O2 -fPIC
CFLAGS += -I../../include
CFLAGS += $(shell pkg-config --cflags r_core 2>/dev/null || echo "-I/usr/local/include/libr")
R2_PLUGDIR ?= $(shell r2 -H R2_USER_PLUGINS)
LDFLAGS += $(shell pkg-config --libs r_core 2>/dev/null || echo "-L/usr/local/lib -lr_core -lr_util -ldl")
DEPFLAGS = -MMD -MP

# Detect platform for shared library extension
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	EXT_SO = dylib
	LDFLAGS += -dynamiclib -undefined dynamic_lookup
else
	EXT_SO = so
	LDFLAGS += -shared
endif

# Source and objects
CORE_SRC = core_flutter.c flutter_analysis.c
CORE_OBJ = core_flutter.o flutter_analysis.o
CORE_DEP = $(CORE_OBJ:.o=.d)
CORE_PLUGIN = core_flutter.$(EXT_SO)

# Library
R2FLUTTER_LIB_DIR = ../../build
R2FLUTTER_LIB = $(R2FLUTTER_LIB_DIR)/libr2flutter.a

all: $(CORE_PLUGIN)

$(CORE_PLUGIN): $(CORE_OBJ) $(R2FLUTTER_LIB)
	$(CC) $(LDFLAGS) -o $@ $(CORE_OBJ) $(R2FLUTTER_LIB)

core_flutter.o: core_flutter.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

flutter_analysis.o: flutter_analysis.c flutter_analysis.h
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(R2FLUTTER_LIB):
	$(MAKE) -C ../.. $(R2FLUTTER_LIB_DIR)/libr2flutter.a

user-install: $(CORE_PLUGIN)
	mkdir -p $(R2_PLUGDIR)
	cp -f $(CORE_PLUGIN) $(R2_PLUGDIR)/

user-uninstall:
	rm -f $(R2_PLUGDIR)/$(CORE_PLUGIN)

clean:
	rm -f $(CORE_OBJ) $(CORE_DEP) $(CORE_PLUGIN)

.PHONY: all clean user-install user-uninstall

-include $(CORE_DEP)
