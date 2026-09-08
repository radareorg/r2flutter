ROOT := $(CURDIR)/r2flutter-macos
ARCHIVE := $(CURDIR)/r2flutter-macos.tar.gz
STRIP ?= strip

all:
	rm -rf $(ROOT) $(ARCHIVE)
	mkdir -p $(ROOT)/bin $(ROOT)/plugins
	cp ../../bin/r2flutter $(ROOT)/bin/
	cp ../../src/r2/core_flutter.dylib $(ROOT)/plugins/
	cp ../README.md $(ROOT)/
	$(STRIP) -x $(ROOT)/bin/r2flutter
	$(STRIP) -x $(ROOT)/plugins/core_flutter.dylib
	codesign -f -s - $(ROOT)/bin/r2flutter
	codesign -f -s - $(ROOT)/plugins/core_flutter.dylib
	tar -C $(CURDIR) -czf $(ARCHIVE) r2flutter-macos

clean:
	rm -rf $(ROOT) $(ARCHIVE)

.PHONY: all clean
