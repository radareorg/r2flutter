ROOT := $(CURDIR)/r2flutter-linux-x86_64
ARCHIVE := $(CURDIR)/r2flutter-linux-x86_64.tar.gz
STRIP ?= strip

all:
	rm -rf $(ROOT) $(ARCHIVE)
	mkdir -p $(ROOT)/bin $(ROOT)/plugins
	cp ../../bin/r2flutter $(ROOT)/bin/
	cp ../../src/r2/core_flutter.so $(ROOT)/plugins/
	cp ../README.md $(ROOT)/
	$(STRIP) --strip-all $(ROOT)/bin/r2flutter
	$(STRIP) --strip-unneeded $(ROOT)/plugins/core_flutter.so
	tar -C $(CURDIR) -czf $(ARCHIVE) r2flutter-linux-x86_64

clean:
	rm -rf $(ROOT) $(ARCHIVE)

.PHONY: all clean
