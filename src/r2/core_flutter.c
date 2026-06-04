/* radare2 - MIT - Copyright 2026 - pancake */

#include <ctype.h>
#include <r_core.h>
#include "../../include/r2flutter/version.h"
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_pool_parse.h"
#include "flutter_analysis.h"

#define R2FLUTTER_CFG_MAPFILE "r2flutter.mapfile"
#define R2FLUTTER_CFG_NAMEPOOL "r2flutter.namepool"

typedef struct {
	char action;
	int fmt;
	int analysis_depth;
	int header_depth;
	int string_depth;
	bool string_refs;
	bool help;
	char *obf_map_path;
} R2FlutterCmd;

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
		"Usage: r2flutter [-jqrnv] [-l N] [-m file] <action>\n"
		"| r2flutter          show this help\n"
		"| r2flutter -j <act> output JSON for dump actions\n"
		"| r2flutter -q <act> compact output; quiet analysis logs\n"
		"| r2flutter -r <act> output r2 commands for dump actions\n"
		"| r2flutter -n       use heuristic name-pool fallback; names may be wrong\n"
		"| r2flutter -v       increase parser verbosity\n"
		"| r2flutter -l N     limit function/instruction-table/xref output\n"
		"| r2flutter -m file  load Flutter obfuscation map JSON\n"
		"| r2flutter -A       analyze dart snapshot and apply flags/comments\n"
		"| r2flutter -AA      analyze with field extraction enabled\n"
		"| r2flutter -AAA     run Dart-aware code analysis and recover code refs\n"
		"| r2flutter -c       dump classes\n"
		"| r2flutter -C       apply Dart classes, fields, methods and types\n"
		"| r2flutter -f       dump recovered functions\n"
		"| r2flutter -H       dump Dart AOT snapshot header info\n"
		"| r2flutter -HH      dump Dart AOT snapshot header and cluster layout\n"
		"| r2flutter -HHH     decode selected cluster payloads for diagnostics\n"
		"| r2flutter -h       show this help\n"
		"| r2flutter -i       dump instruction table entries\n"
		"| r2flutter -p       print reconstructed ObjectPool PP value\n"
		"| r2flutter -R       dump full radare2 script (like standalone -R)\n"
		"| r2flutter -T       dump string-based type names\n"
		"| r2flutter -V       show version\n"
		"| r2flutter -x       dump metadata/data-image xrefs; combine with -z to show string refs\n"
		"| r2flutter -z       dump reliable ObjectPool-referenced strings (-q prints values only)\n"
		"| r2flutter -zz      dump all fuzzy/carved strings (-xzz includes refs)\n");
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

static char *r2flutter_dump_functions(RCore *core, DartCtx *dctx, int fmt) {
	DartApp *app = dart_app_new_from_core (core, dctx);
	if (!app) {
		return NULL;
	}
	dart_app_load_info (app);
	char *out = dart_dumper_dump_funcs (app, fmt);
	dart_app_free (app);
	return out;
}

static bool r2flutter_is_number(const char *s) {
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	const char *p = s;
	if (*p == '-') {
		p++;
	}
	for (; *p; p++) {
		if (!isdigit ((ut8)*p)) {
			return false;
		}
	}
	return true;
}

static const char *r2flutter_opt_arg(const char *tail, char **words, int nwords, int *word_index) {
	if (R_STR_ISNOTEMPTY (tail)) {
		return tail;
	}
	if (*word_index + 1 >= nwords) {
		return NULL;
	}
	(*word_index)++;
	return words[*word_index];
}

static bool r2flutter_parse_cmd(const char *args, DartCtx *dctx, R2FlutterCmd *cmd) {
	cmd->action = 0;
	cmd->fmt = 0;
	cmd->analysis_depth = 0;
	cmd->header_depth = 0;
	cmd->string_depth = 0;
	cmd->string_refs = false;
	cmd->help = false;
	cmd->obf_map_path = NULL;
	char *dup = strdup (args);
	int nwords = r_str_word_set0 (dup);
	char **words = R_NEWS0 (char *, nwords);
	for (int i = 0; i < nwords; i++) {
		words[i] = (char *)r_str_word_get0 (dup, i);
	}
	for (int i = 0; i < nwords; i++) {
		char *word = words[i];
		if (R_STR_ISEMPTY (word)) {
			continue;
		}
		if (word[0] != '-') {
			continue;
		}
		const char *flags = word + 1;
		for (int j = 0; flags[j]; j++) {
			const char flag = flags[j];
			const char *tail = flags + j + 1;
			switch (flag) {
			case 'A':
				cmd->action = flag;
				cmd->analysis_depth++;
				break;
			case 'c':
				cmd->action = flag;
				break;
			case 'C':
				cmd->action = flag;
				break;
			case 'f':
				cmd->action = flag;
				if (r2flutter_is_number (tail)) {
					dctx->dump_fns_limit = atoi (tail);
					j += strlen (tail);
				} else if (!tail[0] && i + 1 < nwords && r2flutter_is_number (words[i + 1])) {
					i++;
					dctx->dump_fns_limit = atoi (words[i]);
				}
				break;
			case 'H':
				cmd->action = flag;
				cmd->header_depth++;
				break;
			case 'h':
				cmd->help = true;
				break;
			case 'i':
				dctx->dump_it = true;
				cmd->action = flag;
				break;
			case 'p':
				cmd->action = flag;
				break;
			case 'j':
				cmd->fmt = 'j';
				break;
			case 'l':
				{
					const char *arg = r2flutter_opt_arg (tail, words, nwords, &i);
					if (!arg) {
						cmd->help = true;
						break;
					}
					dctx->dump_fns_limit = atoi (arg);
					j += strlen (tail);
					break;
				}
			case 'n':
				dctx->use_name_pool = true;
				break;
			case 'm':
				{
					const char *arg = r2flutter_opt_arg (tail, words, nwords, &i);
					if (!arg) {
						cmd->help = true;
						break;
					}
					free (cmd->obf_map_path);
					cmd->obf_map_path = strdup (arg);
					dctx->obf_map_path = cmd->obf_map_path;
					j += strlen (tail);
					break;
				}
			case 'q':
				dctx->quiet = 1;
				break;
			case 'r':
				cmd->fmt = 'r';
				break;
			case 'R':
				cmd->action = flag;
				break;
			case 'T':
				cmd->action = flag;
				break;
			case 'V':
				cmd->action = flag;
				break;
			case 'v':
				dctx->verbose++;
				break;
			case 'x':
				cmd->string_refs = true;
				dctx->dump_string_refs = true;
				if (cmd->action != 'z') {
					cmd->action = flag;
				}
				break;
			case 'z':
				if (cmd->action == 'x') {
					cmd->string_refs = true;
					dctx->dump_string_refs = true;
				}
				cmd->action = flag;
				cmd->string_depth++;
				break;
			default:
				cmd->help = true;
				break;
			}
			if (cmd->help || (R_STR_ISNOTEMPTY (tail) && (flag == 'l' || flag == 'm'))) {
				break;
			}
		}
		if (cmd->help) {
			break;
		}
	}
	free (words);
	free (dup);
	return !cmd->help;
}

static bool r2flutter_run_cmd(RCore *core, DartCtx *dctx, const R2FlutterCmd *cmd) {
	char *out = NULL;
	dctx->dump_string_refs = cmd->string_refs;

	switch (cmd->action) {
	case 0:
		r2flutter_help (core);
		return true;
	case 'A':
		if (cmd->analysis_depth >= 2) {
			dctx->dump_fields = 1;
		}
		if (cmd->analysis_depth >= 3) {
			r2flutter_analysis_run (core, dctx, dctx->quiet);
		} else {
			r2flutter_analyze (core, dctx, dctx->quiet);
		}
		return true;
	case 'C':
		dctx->dump_classes = 1;
		dctx->dump_fields = 1;
		dart_pool_apply_classes_to_core (dctx);
		return true;
	case 'c':
		dctx->dump_classes = 1;
		dctx->dump_fields = 1;
		out = dart_pool_dump_classes (dctx, cmd->fmt);
		break;
	case 'f':
		out = r2flutter_dump_functions (core, dctx, cmd->fmt);
		break;
	case 'H':
		out = cmd->header_depth >= 3? dart_pool_dump_header_deep (dctx, cmd->fmt): cmd->header_depth >= 2? dart_pool_dump_header_ext (dctx, cmd->fmt)
														: dart_pool_dump_header (dctx, cmd->fmt);
		break;
	case 'i':
		out = dart_pool_dump_it (dctx, cmd->fmt);
		break;
	case 'p':
		out = dart_pool_dump_pp (dctx, cmd->fmt);
		break;
	case 'R':
		r2flutter_dump_r2script (core, dctx);
		return true;
	case 'z':
		out = cmd->string_depth >= 2? dart_pool_dump_strings_fuzzy (dctx, cmd->fmt): dart_pool_dump_strings (dctx, cmd->fmt);
		break;
	case 'T':
		dctx->dump_classes = 3;
		out = dart_pool_dump_classes (dctx, cmd->fmt);
		break;
	case 'V':
		r_cons_printf (core->cons, "r2flutter %s\n", R2FLUTTER_VERSION);
		return true;
	case 'x':
		out = dart_pool_dump_xrefs (dctx, cmd->fmt);
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
		r2flutter_help (core);
		return true;
	}

	if (ch0 == '?') {
		r2flutter_help (core);
		return true;
	}

	if (ch0 == '-') {
		R2FlutterCmd cmd;
		if (!r2flutter_parse_cmd (args, &dctx, &cmd) || cmd.help) {
			free (cmd.obf_map_path);
			r2flutter_help (core);
			return true;
		}
		bool ret = r2flutter_run_cmd (core, &dctx, &cmd);
		free (cmd.obf_map_path);
		return ret;
	}
	r2flutter_help (core);
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
