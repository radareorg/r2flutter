/* radare2 - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <r_core.h>
#include "../../include/r2flutter/version.h"
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_pool_parse.h"

static void r2flutter_help(RCore *core) {
	r_cons_printf (core->cons,
		"Usage: r2flutter [-jirfqncFstxH] [args]\n"
		"| r2flutter          analyze dart snapshot and apply flags/comments\n"
		"| r2flutter -c       dump classes as JSON\n"
		"| r2flutter -C       dump classes as r2 type definitions\n"
		"| r2flutter -F       include field info in class output\n"
		"| r2flutter -f [n]   list first N discovered functions (default 20)\n"
		"| r2flutter -H       dump Dart AOT snapshot header info\n"
		"| r2flutter -i       dump instruction table entries to output\n"
		"| r2flutter -j       dump snapshot header as JSON\n"
		"| r2flutter -n       use heuristic name-pool fallback; names may be wrong\n"
		"| r2flutter -q       analyze quietly (no extra output)\n"
		"| r2flutter -r       output r2 script (like rabin2 -r)\n"
		"| r2flutter -s       dump all strings as JSON\n"
		"| r2flutter -t       dump strings as r2 comments\n"
		"| r2flutter -x       dump metadata/data-image xrefs\n");
}

static bool r2flutter_analyze(RCore *core, DartCtx *dctx, int quiet) {
	const char *filepath = R_UNWRAP4 (core, bin, cur, file);
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
	memcpy (&app->dctx, dctx, sizeof (DartCtx));
	app->dctx.core = core;

	dart_app_load_info (app);

	if (!quiet) {
		size_t count = app->functions? r_list_length (app->functions): 0;
		R_LOG_INFO ("Loaded %d functions from Dart snapshot", count);
	}

	dart_dumper_apply_to_core (app);

	dart_app_free (app);
	return true;
}

static bool r2flutter_dump_r2script(RCore *core, DartCtx *dctx) {
	const char *filepath = R_UNWRAP4 (core, bin, cur, file);
	if (!filepath) {
		R_LOG_ERROR ("r2flutter: no file loaded");
		return false;
	}
	DartApp *app = dart_app_new (filepath);
	if (!app) {
		return false;
	}
	app->core = core;
	app->base_addr = r_bin_get_baddr (core->bin);
	if (app->base_addr == UT64_MAX) {
		app->base_addr = 0;
	}
	app->heap_base = 0;
	memcpy (&app->dctx, dctx, sizeof (DartCtx));
	app->dctx.core = core;
	dart_app_load_info (app);
	char *script = dart_dumper_dump4radare2 (app);
	if (script) {
		r_cons_printf (core->cons, "%s", script);
		free (script);
	}
	dart_app_free (app);
	return true;
}

static bool r_cmd_r2flutter_call(RCorePluginSession *cps, const char *input) {
	R_RETURN_VAL_IF_FAIL (cps && cps->core, false);
	RCore *core = cps->core;
	if (!r_str_startswith (input, "r2flutter")) {
		return false;
	}
	const char *args = r_str_trim_head_ro (input + strlen ("r2flutter"));
	DartCtx dctx = {
		.core = core,
		.no_stubs = true
	};

	if (!*args) {
		r2flutter_analyze (core, &dctx, 0);
		return true;
	}

	if (*args == '?') {
		r2flutter_help (core);
		return true;
	}

	if (*args != '-') {
		r2flutter_analyze (core, &dctx, 0);
		return true;
	}
	char flag = args[1];
	const char *rest = args + 2;
	while (*rest == ' ') {
		rest++;
	}

	switch (flag) {
	case 'H':
		{
			char *hdr = dart_pool_dump_header (&dctx, 0);
			if (hdr) {
				r_cons_printf (core->cons, "%s", hdr);
				free (hdr);
			}
		}
		return true;
	case 'j':
		dctx.dump_snapshot_json = 1;
		dctx.quiet = 1;
		r2flutter_analyze (core, &dctx, 1);
		return true;
	case 'i':
		{
			char *out = dart_pool_dump_it (&dctx, 0);
			if (out) {
				r_cons_printf (core->cons, "%s", out);
				free (out);
			}
		}
		return true;
	case 'r':
		r2flutter_dump_r2script (core, &dctx);
		return true;
	case 'f':
		{
			int n = 20;
			if (*rest) {
				int v = atoi (rest);
				if (v > 0) {
					n = v;
				}
			}
			dctx.quiet = 1;
			const char *filepath = R_UNWRAP4 (core, bin, cur, file);
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
			memcpy (&app->dctx, &dctx, sizeof (DartCtx));
			app->dctx.core = core;
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
		dctx.quiet = 1;
		r2flutter_analyze (core, &dctx, 1);
		return true;
	case 'n':
		dctx.use_name_pool = true;
		r2flutter_analyze (core, &dctx, 0);
		return true;
	case 'c':
		{
			char *json = dart_pool_dump_classes (&dctx, 'j');
			if (json) {
				r_cons_printf (core->cons, "%s\n", json);
				free (json);
			}
		}
		return true;
	case 'C':
		{
			char *r2out = dart_pool_dump_classes (&dctx, 'r');
			if (r2out) {
				r_cons_printf (core->cons, "%s", r2out);
				free (r2out);
			}
		}
		return true;
	case 'F':
		dctx.dump_fields = 1;
		r2flutter_analyze (core, &dctx, 0);
		return true;
	case 's':
		{
			char *json = dart_pool_dump_strings (&dctx, 'j');
			if (json) {
				r_cons_printf (core->cons, "%s\n", json);
				free (json);
			}
		}
		return true;
	case 't':
		{
			char *r2out = dart_pool_dump_strings (&dctx, 'r');
			if (r2out) {
				r_cons_printf (core->cons, "%s", r2out);
				free (r2out);
			}
		}
		return true;
	case 'x':
		{
			char *out = dart_pool_dump_xrefs (&dctx, 0);
			if (out) {
				r_cons_printf (core->cons, "%s\n", out);
				free (out);
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
		.version = R2FLUTTER_VERSION,
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
