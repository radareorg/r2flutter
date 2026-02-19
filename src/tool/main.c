/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

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
#include "../../include/r2flutter/version.h"

static bool is_library (const char *name) {
	return r_str_endswith (name, ".so") || r_str_endswith (name, ".dylib") || r_str_endswith (name, ".aot") || r_str_endswith (name, ".bin") || r_str_startswith (name, "lib");
}

static char *find_lib_in_dir (const char *dir) {
	if (!dir) {
		return NULL;
	}
	DIR *d = opendir (dir);
	if (!d) {
		return NULL;
	}
	struct dirent *ent;
	char *preferred = NULL;

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

typedef enum {
	ACTION_NONE = 0,
	ACTION_DUMP_STRINGS,
	ACTION_DUMP_CLASSES,
	ACTION_DUMP_TYPES,
	ACTION_DUMP_HEADER,
	ACTION_DUMP_FNS,
	ACTION_DUMP_IT,
} DumpAction;

static void print_usage (const char *argv0) {
	printf ("Usage: %s [options] <libapp_path_or_dir>\n", argv0);
	printf ("Modifiers:\n");
	printf ("  -h, --help       Show help\n");
	printf ("  -V, --version    Show version\n");
	printf ("  -v               Verbose (stderr info)\n");
	printf ("  -vv              More verbose (dump headers)\n");
	printf ("  -j               Output in JSON format\n");
	printf ("  -r               Output in radare2 format\n");
	printf ("  -q               Quiet mode (suppress non-essential output)\n");
	printf ("  -n               Do not emit radare2 flags/script to stdout\n");
	printf ("Actions:\n");
	printf ("  --dump-strings   Print all extracted strings\n");
	printf ("  --dump-classes   Print extracted class information\n");
	printf ("  --dump-types     Print string-based type names\n");
	printf ("  --dump-header    Print Dart AOT snapshot header info\n");
	printf ("  --dump-fns N     Print first N functions (addr name)\n");
	printf ("  --dump-it        Print instruction table entry addresses to stderr\n");
	printf ("Options:\n");
	printf ("  --no-stubs       Do not emit ELF/r2 stub functions\n");
	printf ("  --use-name-pool  Assign names from data image strings when unknown\n");
	printf ("  --dump-fields    Include field details in class output\n");
}

int main (int argc, char **argv) {
	if (argc < 2) {
		print_usage (argv[0]);
		return 1;
	}

	const char *libapp_path_in = NULL;
	int opt_quiet = 0;
	int opt_no_dump = 0;
	int opt_r2 = 0;
	int opt_json = 0;
	int dump_fns_count = 0;
	DumpAction action = ACTION_NONE;
	DartCtx dctx = { 0 };

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
				printf ("r2flutter %s\n", R2FLUTTER_VERSION);
				return 0;
			} else if (!strcmp (a, "-v")) {
				dctx.verbose = 1;
			} else if (!strcmp (a, "-vv")) {
				dctx.verbose = 2;
			} else if (!strcmp (a, "-j")) {
				opt_r2 = 0;
				opt_json = 1;
			} else if (!strcmp (a, "-r")) {
				opt_r2 = 1;
				opt_json = 0;
			} else if (!strcmp (a, "-q")) {
				opt_quiet = 1;
				dctx.quiet = 1;
			} else if (!strcmp (a, "-n")) {
				opt_no_dump = 1;
			} else if (!strcmp (a, "--dump-strings")) {
				action = ACTION_DUMP_STRINGS;
			} else if (!strcmp (a, "--dump-classes")) {
				action = ACTION_DUMP_CLASSES;
			} else if (!strcmp (a, "--dump-types")) {
				action = ACTION_DUMP_TYPES;
			} else if (!strcmp (a, "--dump-header")) {
				action = ACTION_DUMP_HEADER;
			} else if (!strcmp (a, "--dump-it")) {
				action = ACTION_DUMP_IT;
				dctx.dump_it = 1;
			} else if (!strncmp (a, "--dump-fns=", 11)) {
				action = ACTION_DUMP_FNS;
				dump_fns_count = atoi (a + 11);
			} else if (!strcmp (a, "--dump-fns")) {
				action = ACTION_DUMP_FNS;
				if (i + 1 < argc) {
					dump_fns_count = atoi (argv[++i]);
				}
			} else if (!strcmp (a, "--no-stubs")) {
				dctx.no_stubs = 1;
			} else if (!strcmp (a, "--use-name-pool")) {
				dctx.use_name_pool = 1;
			} else if (!strcmp (a, "--dump-fields")) {
				dctx.dump_fields = 1;
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
	r_core_bin_load (core, NULL, 0);

	dctx.core = core;

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
	memcpy (&app->dctx, &dctx, sizeof (DartCtx));

	if (!opt_quiet) {
		fprintf (stderr, "libapp is loaded at 0x%" PFMT64x "\n", app->base_addr);
		fprintf (stderr, "Dart heap at 0x%" PFMT64x "\n", app->heap_base);
		fprintf (stderr, "app->file_path = %s\n", app->file_path? app->file_path: "(null)");
	}

	int ret = 0;
	char *output = NULL;

	switch (action) {
	case ACTION_DUMP_STRINGS:
		if (opt_r2) {
			output = dart_pool_dump_strings_r2 (&dctx);
		} else {
			output = dart_pool_dump_strings_json (&dctx);
		}
		break;
	case ACTION_DUMP_CLASSES:
		dctx.dump_classes = 1;
		if (opt_r2) {
			output = dart_pool_dump_classes_r2 (&dctx);
		} else {
			output = dart_pool_dump_classes_json (&dctx);
		}
		break;
	case ACTION_DUMP_TYPES:
		dctx.dump_classes = 3;
		if (opt_r2) {
			output = dart_pool_dump_classes_r2 (&dctx);
		} else {
			output = dart_pool_dump_classes_json (&dctx);
		}
		break;
	case ACTION_DUMP_HEADER:
		app->dctx.dump_header = 1;
		app->dctx.dump_header_json = opt_r2 ? 0 : opt_json;
		output = dart_pool_dump_header (&app->dctx);
		break;
	case ACTION_DUMP_FNS:
		dart_app_load_info (app);
		if (app->functions && dump_fns_count > 0) {
			RListIter *it;
			DartFunction *fn;
			int count = 0;
			r_list_foreach (app->functions, it, fn) {
				if (!fn || !fn->name) {
					continue;
				}
				printf ("0x%" PFMT64x " %s\n", (uint64_t)fn->addr, fn->name);
				if (++count >= dump_fns_count) {
					break;
				}
			}
		}
		break;
	case ACTION_DUMP_IT:
		dart_app_load_info (app);
		break;
	case ACTION_NONE:
	default:
		dart_app_load_info (app);
		if (!opt_no_dump && !opt_quiet) {
			printf ("Dumping for radare2\n");
			char *s = dart_dumper_dump4radare2 (app);
			printf ("%s\n", s);
			free (s);
		}
		break;
	}

	if (output) {
		printf ("%s\n", output);
		free (output);
	}

	dart_app_free (app);
	r_core_free (core);
	free (libapp_path);

	return ret;
}
