ROOT := $(CURDIR)/r2flutter-macos
ARCHIVE := $(CURDIR)/r2flutter-macos.tar.gz

all:
	rm -rf $(ROOT) $(ARCHIVE)
	mkdir -p $(ROOT)/bin $(ROOT)/plugins
	cp ../../bin/r2flutter $(ROOT)/bin/
	cp ../../src/r2/core_flutter.dylib $(ROOT)/plugins/
	tar -C $(CURDIR) -czf $(ARCHIVE) r2flutter-macos

clean:
	rm -rf $(ROOT) $(ARCHIVE)

.PHONY: all clean
