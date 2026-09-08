include ./CONFIG

PWD=$(shell pwd)

all: deb

deb:
	$(MAKE) root
	$(MAKE) build

root:
	rm -rf root
	$(MAKE) -C ../.. install DESTDIR=$(PWD)/root

build:
	mkdir -p root/DEBIAN
	echo "Package: $(PACKAGE)" > root/DEBIAN/control
	echo "Version: $(VERSION)" >> root/DEBIAN/control
	echo "Section: $(SECTION)" >> root/DEBIAN/control
	echo "Priority: $(PRIORITY)" >> root/DEBIAN/control
	echo "Architecture: $(ARCH)" >> root/DEBIAN/control
	echo "Depends: $(DEPENDS)" >> root/DEBIAN/control
	echo "Maintainer: $(MAINTAINER)" >> root/DEBIAN/control
	echo "Description: r2flutter plugin for radare2" >> root/DEBIAN/control
	dpkg-deb --build root $(PACKAGE)_$(VERSION)_$(ARCH).deb

clean:
	rm -rf root *.deb

.PHONY: all deb root build clean
