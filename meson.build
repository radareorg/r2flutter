project(
  'r2flutter',
  'c',
  version : '0.3.6',
  meson_version : '>=0.56.0',
  default_options : ['warning_level=2', 'werror=false']
)

cc = meson.get_compiler('c')

r2 = find_program('r2', required: true)
r2_cflags_res = run_command(r2, '-H', 'R2_CFLAGS', check: true)
r2_ldflags_res = run_command(r2, '-H', 'R2_LDFLAGS', check: true)
r2_libs_res = run_command(r2, '-H', 'R2_LIBS', check: true)
r2_plugdir_res = run_command(r2, '-H', 'R2_LIBR_PLUGINS', check: false)

r2_compile_args = r2_cflags_res.stdout().strip().split()
r2_link_args = r2_ldflags_res.stdout().strip().split() + r2_libs_res.stdout().strip().split()

r2_plugdir = r2_plugdir_res.stdout().strip()
if r2_plugdir == ''
  r2_plugdir = join_paths(get_option('prefix'), get_option('libdir'), 'radare2', 'last')
endif

# r2 -H always reports gcc style flags, msvc needs its own spelling for them
if cc.get_argument_syntax() == 'msvc'
  msvc_link_args = []
  foreach flag : r2_link_args
    if flag.startswith('-L')
      msvc_link_args += '/LIBPATH:' + flag.substring(2)
    elif flag.startswith('-l')
      msvc_link_args += flag.substring(2) + '.lib'
    else
      msvc_link_args += flag
    endif
  endforeach
  r2_link_args = msvc_link_args
  # posix names like strdup are available, just noisy without this
  r2_compile_args += ['-D_CRT_SECURE_NO_WARNINGS', '-D_CRT_NONSTDC_NO_DEPRECATE']
endif

r_core_dep = declare_dependency(
  compile_args: r2_compile_args,
  link_args: r2_link_args,
)
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

# The radare2 core plugin, loaded by r2 as core_flutter.{so,dylib,dll}
core_flutter = shared_module(
  'core_flutter',
  'src/r2/core_flutter.c',
  'src/r2/flutter_analysis.c',
  name_prefix: '',
  include_directories: r2flutter_inc,
  link_with: r2flutter_static,
  dependencies: r_core_dep,
  install: true,
  install_dir: r2_plugdir,
)

test('r2flutter-version', r2flutter_cli, args: ['-V'])
