/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <r_core.h>
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_pool_parse.h"
#include "../../include/r2flutter/version.h"

typedef enum {
	ACTION_NONE = 0,
	ACTION_DUMP_STRINGS,
	ACTION_DUMP_CLASSES,
	ACTION_DUMP_TYPES,
	ACTION_DUMP_HEADER,
	ACTION_DUMP_FUNCS,
	ACTION_DUMP_IT,
	ACTION_DUMP_R2SCRIPT,
} DumpAction;

static const char usage_text[] =
	"Usage: %s [options] <libapp_path_or_dir>\n"
	"Modifiers:\n"
	"  -h, --help            Show help\n"
	"  -j                    Output in JSON format\n"
	"  -r                    Format output for r2 commands\n"
	"  -V, --version         Show version\n"
	"  -v                    Verbose (stderr debug info)\n"
	"  -vv                   More verbose (dump headers)\n"
	"Actions:\n"
	"  --dump-classes        Print extracted class information\n"
	"  --dump-funcs          Print all extracted functions (addr name)\n"
	"  --dump-header         Print Dart AOT snapshot header info\n"
	"  --dump-it             Print instruction table entry addresses to stderr\n"
	"  --dump-r2script       Print radare2 script for snapshot analysis\n"
	"  --dump-strings        Print all extracted strings\n"
	"  --dump-types          Print string-based type names\n"
	"Options:\n"
	"  --no-stubs            Do not emit ELF/r2 stub functions\n"
	"  --limit <N>           Limit output to N items (applies to dump-funcs, etc.)\n"
	"  --use-name-pool       Assign names from data image strings when unknown\n";

static void print_usage(const char *argv0) {
	printf (usage_text, argv0);
}

static char *find_libapp(const char *s) {
	if (r_file_is_directory (s)) {
		char *candidate = r_str_newf ("%s/libapp.so", s); // Android
		if (r_file_exists (candidate)) {
			return candidate;
		}
		free (candidate);
		candidate = r_str_newf ("%s/Frameworks/App.framework/App", s); // iOS
		if (r_file_exists (candidate)) {
			return candidate;
		}
	} else if (r_file_exists (s)) {
		return strdup (s);
	}
	return NULL;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		print_usage (argv[0]);
		return 1;
	}

	const char *libapp_path_in = NULL;
	bool opt_json = false;
	bool opt_r2 = false;
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
			}
			if (!strcmp (a, "-V") || !strcmp (a, "--version")) {
				printf ("r2flutter %s\n", R2FLUTTER_VERSION);
				return 0;
			}
			if (!strcmp (a, "-v")) {
				dctx.verbose = 1;
			} else if (!strcmp (a, "-vv")) {
				dctx.verbose = 2;
			} else if (!strcmp (a, "-j")) {
				opt_json = true;
			} else if (!strcmp (a, "-r")) {
				opt_r2 = true;
			} else if (!strcmp (a, "--dump-strings")) {
				action = ACTION_DUMP_STRINGS;
			} else if (!strcmp (a, "--dump-classes")) {
				action = ACTION_DUMP_CLASSES;
			} else if (!strcmp (a, "--dump-types")) {
				action = ACTION_DUMP_TYPES;
			} else if (!strcmp (a, "--dump-header")) {
				action = ACTION_DUMP_HEADER;
			} else if (!strcmp (a, "--dump-funcs")) {
				action = ACTION_DUMP_FUNCS;
			} else if (!strcmp (a, "--limit")) {
				if (i + 1 < argc) {
					dctx.dump_fns_limit = atoi (argv[i + 1]);
					i++;
				}
			} else if (!strcmp (a, "--dump-it")) {
				action = ACTION_DUMP_IT;
				dctx.dump_it = true;
			} else if (!strcmp (a, "--dump-r2script")) {
				action = ACTION_DUMP_R2SCRIPT;
			} else if (!strcmp (a, "--no-stubs")) {
				dctx.no_stubs = true;
			} else if (!strcmp (a, "--use-name-pool")) {
				dctx.use_name_pool = true;
			}
		} else {
			libapp_path_in = a;
		}
	}
	if (!libapp_path_in) {
		print_usage (argv[0]);
		return 1;
	}

	char *libapp_path = find_libapp (libapp_path_in);
	if (!libapp_path) {
		R_LOG_ERROR ("File or directory does not exist: %s", libapp_path_in);
		return 1;
	}

	RCore *core = r_core_new ();
	if (!core) {
		R_LOG_ERROR ("Failed to create radare2 core");
		free (libapp_path);
		return 1;
	}

	if (!r_core_file_open (core, libapp_path, 0, 0)) {
		R_LOG_ERROR ("Failed to open file: %s", libapp_path);
		r_core_free (core);
		free (libapp_path);
		return 1;
	}
	r_core_bin_load (core, NULL, 0);

	dctx.core = core;

	DartApp *app = dart_app_new (libapp_path);
	if (!app) {
		R_LOG_ERROR ("Failed to create DartApp");
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

	if (dctx.verbose) {
		fprintf (stderr, "libapp is loaded at 0x%" PFMT64x "\n", app->base_addr);
		fprintf (stderr, "Dart heap at 0x%" PFMT64x "\n", app->heap_base);
		fprintf (stderr, "app->file_path = %s\n", app->file_path? app->file_path: "(null)");
	}

	int ret = 0;
	char *output = NULL;

	switch (action) {
	case ACTION_DUMP_STRINGS:
		if (opt_json) {
			output = dart_pool_dump_strings_json (&dctx);
		} else if (opt_r2) {
			output = dart_pool_dump_strings_r2 (&dctx);
		} else {
			output = dart_pool_dump_strings (&dctx);
		}
		break;
	case ACTION_DUMP_CLASSES:
		dctx.dump_classes = 1;
		dctx.dump_fields = 1;
		if (opt_json) {
			output = dart_pool_dump_classes_json (&dctx);
		} else {
			output = dart_pool_dump_classes_r2 (&dctx);
		}
		break;
	case ACTION_DUMP_TYPES:
		dctx.dump_classes = 3;
		if (opt_json) {
			output = dart_pool_dump_classes_json (&dctx);
		} else {
			output = dart_pool_dump_classes_r2 (&dctx);
		}
		break;
	case ACTION_DUMP_HEADER:
		app->dctx.dump_header = 1;
		app->dctx.dump_header_json = opt_json;
		output = dart_pool_dump_header (&app->dctx);
		break;
	case ACTION_DUMP_FUNCS:
		dart_app_load_info (app);
		if (opt_json) {
			output = dart_dumper_dump_funcs_json (app);
		} else {
			if (app->functions) {
				RListIter *it;
				DartFunction *fn;
				int count = 0;
				int limit = dctx.dump_fns_limit? dctx.dump_fns_limit: -1;
				r_list_foreach (app->functions, it, fn) {
					if (!fn || !fn->name) {
						continue;
					}
					if (limit > 0 && count >= limit) {
						break;
					}
					printf ("0x%" PFMT64x " %s\n", (uint64_t)fn->addr, fn->name);
					count++;
				}
			}
		}
		break;
	case ACTION_DUMP_IT:
		dart_app_load_info (app);
		break;
	case ACTION_DUMP_R2SCRIPT:
		dart_app_load_info (app);
		if (dctx.verbose) {
			R_LOG_ERROR ("Dumping radare2 script");
		}
		char *s = dart_dumper_dump4radare2 (app);
		printf ("%s\n", s);
		free (s);
		break;
	case ACTION_NONE:
	default:
		R_LOG_ERROR ("no action specified. Use --help for available actions");
		ret = 1;
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
