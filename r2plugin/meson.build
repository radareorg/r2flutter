# r2flutter XPS integration for radare2.
# Included from libr/xps/meson.build when r2flutter sources live under
# libr/xps/p/r2flutter/. Appends sources and include paths to the r_core
# aggregate so the static plugin is linked into libr_core.

core_plugins += ['r2flutter']

r_core_additional_inc += include_directories(join_paths('..', 'include'))

r_core_additional_sources += files(
  '../src/lib/dart_app.c',
  '../src/lib/dart_dumper.c',
  '../src/lib/dart_pool_snapshot.c',
  '../src/lib/dart_pool_discovery.c',
  '../src/lib/dart_pool_names.c',
  '../src/lib/dart_pool_strings.c',
  '../src/lib/dart_pool_data_image.c',
  '../src/lib/dart_pool_it.c',
  '../src/lib/dart_pool_xrefs.c',
  '../src/lib/dart_object.c',
  '../src/lib/dart_sbom.c',
  '../src/lib/dart_pool_clusters.c',
  '../src/lib/dart_pool_classes.c',
  '../src/lib/dart_pool_model.c',
  '../src/lib/dart_pool_parse.c',
  '../src/lib/dart_pool_modern.c',
  '../src/lib/dart_version.c',
  '../src/lib/dart_cid.c',
  '../src/lib/dart_obf.c',
  '../src/r2/flutter_analysis.c',
  '../src/r2/core_flutter.c',
)
