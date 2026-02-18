/* radare2 - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <r_core.h>
#include <r_cons.h>
#include <r_lib.h>
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_pool_parse.h"

static void r2flutter_help(RCore *core) {
	r_cons_printf (core->cons, "Usage: r2flutter [-jifqsncFSt] [args]\n");
	r_cons_printf (core->cons, "| r2flutter          analyze dart snapshot and apply flags/comments\n");
	r_cons_printf (core->cons, "| r2flutter -j       dump snapshot header as JSON\n");
	r_cons_printf (core->cons, "| r2flutter -i       dump instruction table entries to output\n");
	r_cons_printf (core->cons, "| r2flutter -f [n]   list first N discovered functions (default 20)\n");
	r_cons_printf (core->cons, "| r2flutter -q       analyze quietly (no extra output)\n");
	r_cons_printf (core->cons, "| r2flutter -s       include ELF/r2 stub symbols\n");
	r_cons_printf (core->cons, "| r2flutter -n       use name pool for unknown function names\n");
	r_cons_printf (core->cons, "| r2flutter -c       dump classes as JSON\n");
	r_cons_printf (core->cons, "| r2flutter -C       dump classes as r2 type definitions\n");
	r_cons_printf (core->cons, "| r2flutter -F       include field info in class output\n");
	r_cons_printf (core->cons, "| r2flutter -S       dump all strings as JSON\n");
	r_cons_printf (core->cons, "| r2flutter -t       dump strings as r2 comments\n");
}

static bool r2flutter_analyze(RCore *core, int quiet) {
	const char *filepath = core->bin && core->bin->cur
		? core->bin->cur->file
		: NULL;
	if (!filepath) {
		R_LOG_ERROR ("r2flutter: no file loaded");
		return false;
	}
	DartApp *app = dart_app_new (filepath);
	if (!app) {
		R_LOG_ERROR ("r2flutter: failed to create DartApp");
		return false;
	}
	app->core = core;
	app->base_addr = r_bin_get_baddr (core->bin);
	if (app->base_addr == UT64_MAX) {
		app->base_addr = 0;
	}
	app->heap_base = 0;

	dart_app_load_info (app);

	if (!quiet) {
		r_cons_printf (core->cons, "r2flutter: loaded %d functions from Dart snapshot\n", app->functions? r_list_length (app->functions): 0);
	}

	dart_dumper_apply_to_core (app);

	dart_app_free (app);
	return true;
}

static bool r_cmd_r2flutter_call(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (!core) {
		return false;
	}
	if (!r_str_startswith (input, "r2flutter")) {
		return false;
	}
	const char *args = input + 9;

	// Reset state for each invocation
	dart_pool_set_verbose (0);
	dart_pool_set_no_stubs (1);
	dart_pool_set_dump_snapshot_json (0);
	dart_pool_set_dump_it (0);
	dart_pool_set_quiet (0);
	dart_pool_set_dump_fns (0);
	dart_pool_set_use_name_pool (0);

	// Skip leading spaces
	while (*args == ' ') {
		args++;
	}

	if (!*args) {
		// "r2flutter" - main analysis
		r2flutter_analyze (core, 0);
		return true;
	}

	if (*args == '?') {
		r2flutter_help (core);
		return true;
	}

	// Parse -flags
	if (*args != '-') {
		r2flutter_help (core);
		return true;
	}
	char flag = args[1];
	const char *rest = args + 2;
	while (*rest == ' ') {
		rest++;
	}

	switch (flag) {
	case 'j':
		// "r2flutter -j" - dump snapshot JSON
		dart_pool_set_dump_snapshot_json (1);
		dart_pool_set_quiet (1);
		r2flutter_analyze (core, 1);
		return true;
	case 'i':
		// "r2flutter -i" - dump instruction table
		dart_pool_set_dump_it (1);
		r2flutter_analyze (core, 1);
		return true;
	case 'f':
		{
			// "r2flutter -f [N]" - list functions
			int n = 20;
			if (*rest) {
				int v = atoi (rest);
				if (v > 0) {
					n = v;
				}
			}
			dart_pool_set_quiet (1);
			dart_pool_set_dump_fns (n);
		const char *filepath = core->bin && core->bin->cur
			? core->bin->cur->file
			: NULL;
			if (!filepath) {
				R_LOG_ERROR ("r2flutter: no file loaded");
				return true;
			}
			DartApp *app = dart_app_new (filepath);
			if (!app) {
				return true;
			}
			app->core = core;
			app->base_addr = r_bin_get_baddr (core->bin);
			if (app->base_addr == UT64_MAX) {
				app->base_addr = 0;
			}
			app->heap_base = 0;
			dart_app_load_info (app);
			int count = 0;
			if (app->functions) {
				RListIter *it;
				DartFunction *fn;
				r_list_foreach (app->functions, it, fn) {
				if (!fn || !fn->name) {
						continue;
					}
					r_cons_printf (core->cons, "0x%08" PFMT64x " %s\n", fn->addr, fn->name);
					if (++count >= n) {
						break;
					}
				}
			}
			dart_app_free (app);
			return true;
		}
	case 'q':
		// "r2flutter -q" - quiet analyze
		dart_pool_set_quiet (1);
		r2flutter_analyze (core, 1);
		return true;
	case 's':
		// "r2flutter -s" - include stubs
		dart_pool_set_no_stubs (0);
		r2flutter_analyze (core, 0);
		return true;
	case 'n':
		// "r2flutter -n" - use name pool
		dart_pool_set_use_name_pool (1);
		r2flutter_analyze (core, 0);
		return true;
	case 'c':
		// "r2flutter -c" - dump classes as JSON
		{
			char *json = dart_pool_dump_classes_json (core);
			if (json) {
				r_cons_printf (core->cons, "%s\n", json);
				free (json);
			}
		}
		return true;
	case 'C':
		// "r2flutter -C" - dump classes as r2 type definitions
		{
			char *r2out = dart_pool_dump_classes_r2 (core);
			if (r2out) {
				r_cons_printf (core->cons, "%s", r2out);
				free (r2out);
			}
		}
		return true;
	case 'F':
		// "r2flutter -F" - include field info
		dart_pool_set_dump_fields (1);
		r2flutter_analyze (core, 0);
		return true;
	case 'S':
		// "r2flutter -S" - dump strings as JSON
		{
			char *json = dart_pool_dump_strings_json (core);
			if (json) {
				r_cons_printf (core->cons, "%s\n", json);
				free (json);
			}
		}
		return true;
	case 't':
		// "r2flutter -t" - dump strings as r2 comments
		{
			char *r2out = dart_pool_dump_strings_r2 (core);
			if (r2out) {
				r_cons_printf (core->cons, "%s", r2out);
				free (r2out);
			}
		}
		return true;
	default:
		r2flutter_help (core);
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_flutter = {
	.meta = {
		.name = "r2flutter",
		.desc = "Dart/Flutter AOT snapshot analyzer",
		.author = "pancake, Ahmeth4n",
		.license = "LGPL-3.0",
		.version = "0.1.0",
	},
	.call = r_cmd_r2flutter_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_flutter,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
