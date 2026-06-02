/* radare2 - MIT - Copyright 2026 - pancake */

#include <r_core.h>
#include "../../include/r2flutter/version.h"
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_pool_parse.h"
#include "flutter_analysis.h"

#define R2FLUTTER_CFG_MAPFILE "r2flutter.mapfile"
#define R2FLUTTER_CFG_NAMEPOOL "r2flutter.namepool"

static bool r2flutter_core_init(RCorePluginSession *cps) {
	RConfig *cfg = cps->core->config;
	r_config_lock (cfg, false);
	RConfigNode *node = r_config_set (cfg, R2FLUTTER_CFG_MAPFILE, "");
	r_config_node_desc (node, "Flutter obfuscation map JSON path");
	node = r_config_set_b (cfg, R2FLUTTER_CFG_NAMEPOOL, false);
	r_config_node_desc (node, "Enable heuristic name-pool fallback resolution");
	r_config_lock (cfg, true);
	return true;
}

static bool r2flutter_core_fini(RCorePluginSession *cps) {
	RConfig *cfg = cps->core->config;
	r_config_lock (cfg, false);
	r_config_rm (cfg, R2FLUTTER_CFG_MAPFILE);
	r_config_rm (cfg, R2FLUTTER_CFG_NAMEPOOL);
	r_config_lock (cfg, true);
	return true;
}

static void r2flutter_apply_config(RCore *core, DartCtx *dctx) {
	dctx->obf_map_path = r_config_get (core->config, R2FLUTTER_CFG_MAPFILE);
	dctx->use_name_pool = r_config_get_b (core->config, R2FLUTTER_CFG_NAMEPOOL);
}

static void r2flutter_help(RCore *core) {
	r_cons_printf (core->cons,
		"Usage: r2flutter [-ajirfqncFstxH] [args]\n"
		"| r2flutter          analyze dart snapshot and apply flags/comments\n"
		"| r2flutter -a       run Dart-aware code analysis and recover code refs\n"
		"| r2flutter -c       dump classes as JSON\n"
		"| r2flutter -C       apply Dart classes, fields, methods and types\n"
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
	DartApp *app = dart_app_new_from_core (core, dctx);
	if (!app) {
		return false;
	}
	dart_app_load_info (app);

	if (!quiet && app->functions) {
		size_t count = RVecDartFunction_length (app->functions);
		if (count > 0) {
			R_LOG_INFO ("Loaded %zu functions from Dart snapshot", count);
		}
	}

	dart_dumper_apply_to_core (app);

	dart_app_free (app);
	return true;
}

static bool r2flutter_dump_r2script(RCore *core, DartCtx *dctx) {
	DartApp *app = dart_app_new_from_core (core, dctx);
	if (!app) {
		return false;
	}
	dart_app_load_info (app);
	char *script = dart_dumper_dump4radare2 (app);
	if (script) {
		r_cons_print (core->cons, script);
		free (script);
	}
	dart_app_free (app);
	return true;
}

static char *r2flutter_dump_functions(RCore *core, DartCtx *dctx, const char *args) {
	int n = 20;
	if (*args) {
		int v = atoi (args);
		if (v > 0) {
			n = v;
		}
	}
	dctx->quiet = 1;
	DartApp *app = dart_app_new_from_core (core, dctx);
	if (!app) {
		return NULL;
	}
	dart_app_load_info (app);
	RStrBuf *sb = r_strbuf_new ("");
	int count = 0;
	if (app->functions) {
		DartFunction *fn;
		R_VEC_FOREACH (app->functions, fn) {
			r_strbuf_appendf (sb, "0x%08" PFMT64x " %s\n", fn->addr, fn->name);
			count++;
			if (count >= n) {
				break;
			}
		}
	}
	dart_app_free (app);
	return r_strbuf_drain (sb);
}

static bool r2flutter_handle_option(RCore *core, DartCtx *dctx, const char *args) {
	R_RETURN_VAL_IF_FAIL (core && dctx && args && *args == '-', false);

	const char flag = args[1];
	const char *rest = flag? r_str_trim_head_ro (args + 2): "";
	char *out = NULL;

	switch (flag) {
	case 'a':
		r2flutter_analysis_run (core, dctx, dctx->quiet);
		return true;
	case 'H':
		out = dart_pool_dump_header (dctx, 0);
		break;
	case 'j':
		dctx->dump_snapshot_json = 1;
		dctx->quiet = 1;
		r2flutter_analyze (core, dctx, 1);
		return true;
	case 'i':
		out = dart_pool_dump_it (dctx, 0);
		break;
	case 'r':
		r2flutter_dump_r2script (core, dctx);
		return true;
	case 'f':
		out = r2flutter_dump_functions (core, dctx, rest);
		break;
	case 'q':
		dctx->quiet = 1;
		r2flutter_analyze (core, dctx, 1);
		return true;
	case 'n':
		dctx->use_name_pool = true;
		r2flutter_analyze (core, dctx, 0);
		return true;
	case 'c':
		out = dart_pool_dump_classes (dctx, 'j');
		break;
	case 'C':
		dctx->dump_classes = 1;
		dctx->dump_fields = 1;
		dart_pool_apply_classes_to_core (dctx);
		return true;
	case 'F':
		dctx->dump_fields = 1;
		r2flutter_analyze (core, dctx, 0);
		return true;
	case 's':
		out = dart_pool_dump_strings (dctx, 'j');
		break;
	case 't':
		out = dart_pool_dump_strings (dctx, 'r');
		break;
	case 'x':
		out = dart_pool_dump_xrefs (dctx, 0);
		break;
	default:
		r2flutter_help (core);
		return true;
	}
	if (out) {
		r_cons_println (core->cons, out);
		free (out);
	}
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
	r2flutter_apply_config (core, &dctx);

	const char ch0 = *args;
	if (!ch0) {
		r2flutter_analyze (core, &dctx, 0);
		return true;
	}

	if (ch0 == '?') {
		r2flutter_help (core);
		return true;
	}

	if (ch0 == '-') {
		return r2flutter_handle_option (core, &dctx, args);
	}
	r2flutter_analyze (core, &dctx, 0);
	return true;
}

RCorePlugin r_core_plugin_flutter = {
	.meta = {
		.name = "r2flutter",
		.desc = "Dart/Flutter AOT snapshot analyzer",
		.author = "pancake, Ahmeth4n",
		.license = "MIT",
		.version = R2FLUTTER_VERSION,
	},
	.init = r2flutter_core_init,
	.fini = r2flutter_core_fini,
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
