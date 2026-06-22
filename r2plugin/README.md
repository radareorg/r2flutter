# r2plugin

This directory contains the Make and Meson files required to link r2flutter
inside radare2 through `libr/xps`.

```console
cd radare2
cp ../r2flutter/r2plugin/config.mk libr/xps/config.mk
git clone ../r2flutter libr/xps/p/r2flutter
make -C libr/xps
./configure
make
```
