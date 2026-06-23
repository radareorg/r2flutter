project('r2flutter', 'c',
  version: '0.1.0',
  meson_version: '>=0.53.0',
  default_options: [
    'warning_level=2',
    'werror=false',
  ],
)

r_core_dep = dependency('r_core', method: 'pkg-config')
r2flutter_inc = include_directories('include')

r2flutter_sources = files(
  'src/lib/dart_app.c',
  'src/lib/dart_dumper.c',
  'src/lib/dart_pool_snapshot.c',
  'src/lib/dart_pool_discovery.c',
  'src/lib/dart_pool_names.c',
  'src/lib/dart_pool_strings.c',
  'src/lib/dart_pool_data_image.c',
  'src/lib/dart_pool_it.c',
  'src/lib/dart_pool_xrefs.c',
  'src/lib/dart_object.c',
  'src/lib/dart_sbom.c',
  'src/lib/dart_pool_clusters.c',
  'src/lib/dart_pool_classes.c',
  'src/lib/dart_pool_model.c',
  'src/lib/dart_pool_parse.c',
  'src/lib/dart_pool_modern.c',
  'src/lib/dart_version.c',
  'src/lib/dart_cid.c',
  'src/lib/dart_obf.c',
)

r2flutter_static = static_library(
  'r2flutter',
  r2flutter_sources,
  include_directories: r2flutter_inc,
  dependencies: r_core_dep,
)

linux_link_args = []
if host_machine.system() == 'linux'
  linux_link_args += ['-Wl,-rpath,/usr/local/lib']
endif

r2flutter_cli = executable(
  'r2flutter',
  'src/tool/main.c',
  'src/r2/flutter_analysis.c',
  include_directories: r2flutter_inc,
  link_with: r2flutter_static,
  dependencies: r_core_dep,
  link_args: linux_link_args,
  install: true,
)

test('r2flutter-version', r2flutter_cli, args: ['-V'])
