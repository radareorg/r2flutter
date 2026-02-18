#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <r_core.h>
#include <r_flag.h>
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_pool_parse.h"

static bool is_library(const char *name) {
	return r_str_endswith (name, ".so") || r_str_endswith (name, ".dylib") || r_str_endswith (name, ".aot") || r_str_endswith (name, ".bin") || r_str_startswith (name, "lib");
}

static char *find_lib_in_dir(const char *dir) {
	if (!dir) {
		return NULL;
	}
	DIR *d = opendir (dir);
	if (!d) {
		return NULL;
	}
	struct dirent *ent;
	// Prefer libapp.so explicitly if present
	char *preferred = NULL;

	// iOS .app bundle support: look for App.framework/App inside Frameworks
	if (r_str_endswith (dir, ".app")) {
		char *path = r_str_newf ("%s/Frameworks/App.framework/App", dir);
		struct stat st;
		if (path && stat (path, &st) == 0 && S_ISREG (st.st_mode)) {
			closedir (d);
			return path;
		}
		free (path);
	}
	while ((ent = readdir (d)) != NULL) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		char *full = r_str_newf ("%s/%s", dir, ent->d_name);
		struct stat st;
		if (stat (full, &st) == 0 && S_ISREG (st.st_mode)) {
			if (!strcmp (ent->d_name, "libapp.so")) {
				closedir (d);
				return full;
			}
			if (!preferred && is_library (ent->d_name)) {
				preferred = full;
				full = NULL;
			}
		}
		free (full);
	}
	closedir (d);
	return preferred;
}

static void print_usage(const char *argv0) {
	printf ("Usage: %s [options] <libapp_path_or_dir>\n", argv0);
	printf ("Options:\n");
	printf ("  -h, --help                 Show help\n");
	printf ("  -V, --version              Show version\n");
	printf ("  -v                         Verbose (stderr info)\n");
	printf ("  -vv                        More verbose (dump headers)\n");
	printf ("  --no-stubs                 Do not emit ELF/r2 stub functions\n");
	printf ("  --dump-snapshot-json       Print snapshot header as a single JSON line\n");
	printf ("  --dump-it                  Print instruction table entry addresses to stderr\n");
	printf ("  --quiet                    Suppress non-essential stdout (only JSON if requested)\n");
	printf ("  --no-dump                  Do not emit radare2 flags/script to stdout\n");
	printf ("  --dump-fns N               Print first N functions (addr name) to stdout\n");
	printf ("  --use-name-pool            Assign names from data image strings when unknown\n");
	printf ("  --dump-classes             Print extracted class information as JSON\n");
	printf ("  --dump-classes-r2          Print class info as r2 type definition commands\n");
	printf ("  --dump-fields              Include field details in class output\n");
	printf ("  --dump-types               Print string-based type names as JSON array\n");
}

int main(int argc, char **argv) {
	if (argc < 2) {
		print_usage (argv[0]);
		return 1;
	}

	const char *libapp_path_in = NULL;
	int opt_quiet = 0;
	int opt_no_dump = 0;
	// Parse flags, keep last non-flag as path
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!a) {
			continue;
		}
		if (a[0] == '-') {
			if (!strcmp (a, "-h") || !strcmp (a, "--help")) {
				print_usage (argv[0]);
				return 0;
			} else if (!strcmp (a, "-V") || !strcmp (a, "--version")) {
				printf ("r2flutter 0.1\n");
				return 0;
			} else if (!strcmp (a, "-v")) {
				dart_pool_set_verbose (1);
			} else if (!strcmp (a, "-vv")) {
				dart_pool_set_verbose (2);
			} else if (!strcmp (a, "--no-stubs")) {
				dart_pool_set_no_stubs (1);
			} else if (!strcmp (a, "--dump-snapshot-json")) {
				dart_pool_set_dump_snapshot_json (1);
			} else if (!strcmp (a, "--dump-it")) {
				dart_pool_set_dump_it (1);
			} else if (!strcmp (a, "--quiet")) {
				opt_quiet = 1;
				dart_pool_set_quiet (1);
			} else if (!strcmp (a, "--no-dump")) {
				opt_no_dump = 1;
			} else if (!strcmp (a, "--use-name-pool")) {
				dart_pool_set_use_name_pool (1);
			} else if (!strcmp (a, "--dump-classes")) {
				dart_pool_set_dump_classes (1);
			} else if (!strcmp (a, "--dump-classes-r2")) {
				dart_pool_set_dump_classes (2);
			} else if (!strcmp (a, "--dump-fields")) {
				dart_pool_set_dump_fields (1);
			} else if (!strcmp (a, "--dump-types")) {
				dart_pool_set_dump_classes (3);
			} else if (!strncmp (a, "--dump-fns=", 11)) {
				int n = atoi (a + 11);
				if (n > 0) {
					dart_pool_set_dump_fns (n);
				}
			} else if (!strcmp (a, "--dump-fns")) {
				if (i + 1 < argc) {
					int n = atoi (argv[i + 1]);
					if (n > 0) {
						dart_pool_set_dump_fns (n);
					}
					i++;
				}
			} else {
				// Unknown flag, ignore to be lenient
			}
		} else {
			libapp_path_in = a;
		}
	}
	if (!libapp_path_in) {
		print_usage (argv[0]);
		return 1;
	}

	char *libapp_path = NULL;
	struct stat st;
	if (stat (libapp_path_in, &st) == 0) {
		if (S_ISDIR (st.st_mode)) {
			// Prefer libapp.so explicitly if present in dir
			char *candidate = r_str_newf ("%s/%s", libapp_path_in, "libapp.so");
			struct stat st2;
			if (candidate && stat (candidate, &st2) == 0 && S_ISREG (st2.st_mode)) {
				libapp_path = candidate;
			} else {
				free (candidate);
				libapp_path = find_lib_in_dir (libapp_path_in);
			}
			if (!libapp_path) {
				eprintf ("No suitable library file found in directory: %s\n", libapp_path_in);
				return 1;
			}
		} else if (S_ISREG (st.st_mode)) {
			libapp_path = strdup (libapp_path_in);
		} else {
			eprintf ("Not a regular file or directory: %s\n", libapp_path_in);
			return 1;
		}
	} else {
		eprintf ("File or directory does not exist: %s\n", libapp_path_in);
		return 1;
	}

	RCore *core = r_core_new ();
	if (!core) {
		eprintf ("Failed to create radare2 core\n");
		free (libapp_path);
		return 1;
	}

	if (!r_core_file_open (core, libapp_path, 0, 0)) {
		fprintf (stderr, "Failed to open file: %s\n", libapp_path);
		r_core_free (core);
		free (libapp_path);
		return 1;
	}
	// Ensure binary info/symbols are loaded for queries like `isj`
	r_core_bin_load (core, NULL, 0);

	DartApp *app = dart_app_new (libapp_path);
	if (!app) {
		eprintf ("Failed to create DartApp\n");
		r_core_free (core);
		free (libapp_path);
		return 1;
	}

	app->core = core;
	app->base_addr = r_bin_get_baddr (core->bin);
	if (app->base_addr == (ut64)-1) {
		app->base_addr = 0;
	}
	app->heap_base = 0;

	if (!opt_quiet) {
		fprintf (stderr, "libapp is loaded at 0x%" PFMT64x "\n", app->base_addr);
		fprintf (stderr, "Dart heap at 0x%" PFMT64x "\n", app->heap_base);
		fprintf (stderr, "app->file_path = %s\n", app->file_path? app->file_path: "(null)");
	}

	int dump_classes_mode = dart_pool_get_dump_classes ();
	if (dump_classes_mode > 0) {
		if (dump_classes_mode == 2) {
			char *r2out = dart_pool_dump_classes_r2 (core);
			if (r2out) {
				printf ("%s", r2out);
				free (r2out);
			}
		} else if (dump_classes_mode == 3) {
			char *json = dart_pool_dump_classes_json (core);
			if (json) {
				printf ("%s\n", json);
				free (json);
			}
		} else {
			char *json = dart_pool_dump_classes_json (core);
			if (json) {
				printf ("%s\n", json);
				free (json);
			}
		}
		dart_app_free (app);
		r_core_free (core);
		free (libapp_path);
		return 0;
	}

	dart_app_load_info (app);

	if (dart_pool_get_dump_fns () > 0) {
		int limit = dart_pool_get_dump_fns ();
		int count = 0;
		if (app->functions) {
			RListIter *it;
			DartFunction *fn;
			r_list_foreach (app->functions, it, fn) {
				if (!fn || !fn->name) {
					continue;
				}
				printf ("0x%" PFMT64x " %s\n", (uint64_t)fn->addr, fn->name);
				if (++count >= limit) {
					break;
				}
			}
		}
	}

	if (!opt_no_dump && !opt_quiet) {
		printf ("Dumping for radare2\n");
		char *s = dart_dumper_dump4radare2 (app);
		printf ("%s\n", s);
		free (s);
	}

	dart_app_free (app);
	r_core_free (core);
	free (libapp_path);

	return 0;
}
