# r2flutter binary release

This package contains:

* `bin/r2flutter` — the standalone command line tool
* `plugins/core_flutter.{so,dylib,dll}` — the radare2 core plugin

## Installing

Copy the tool anywhere in your `$PATH` and drop the plugin into the radare2
plugin directory reported by r2:

```sh
r2 -H R2_USER_PLUGINS   # per user, no root needed
r2 -H R2_LIBR_PLUGINS   # system wide
```

For example:

```sh
mkdir -p "$(r2 -H R2_USER_PLUGINS)"
cp plugins/core_flutter.* "$(r2 -H R2_USER_PLUGINS)"
cp bin/r2flutter /usr/local/bin
```

On Windows the plugin directory is usually `%HOMEPATH%\.local\share\radare2\plugins`.

## Checking the installation

```sh
r2 -qc 'Lc~r2flutter' --
r2flutter -V
```

The plugin must match the radare2 version it was built against, otherwise r2
refuses to load it.
