/* r2flutter - MIT - Copyright 2026 - pancake */

#include "../../include/r2flutter/dart_dumper.h"

R_VEC_TYPE(RVecDartOffset, ut64);

static bool vec_contains_offset(RVecDartOffset *list, ut64 off) {
	ut64 *p;
	R_VEC_FOREACH (list, p) {
		if (*p == off) {
			return true;
		}
	}
	return false;
}

static void collect_pool_offsets_from_fn(RCore *core, ut64 addr, RVecDartOffset *offsets) {
	if (!core || !offsets) {
		return;
	}
	r_strf_var (cmd, 128, "pdj 96 @ 0x%" PFMT64x, addr);
	char *s = r_core_cmd_str (core, cmd);
	if (!s) {
		return;
	}
	RJson *j = r_json_parse (s);
	if (!j) {
		free (s);
		return;
	}
	const RJson *ops = r_json_get (j, "ops");
	const RJson *arr = ops? ops: j;
	size_t i;
	for (i = 0;; i++) {
		const RJson *item = r_json_item (arr, i);
		if (!item) {
			break;
		}
		const char *opstr = r_json_get_str (item, "opstr");
		if (R_STR_ISEMPTY (opstr)) {
			opstr = r_json_get_str (item, "opcode");
		}
		if (R_STR_ISEMPTY (opstr)) {
			continue;
		}
		// search for pattern like: ldr x0, [x27, 0x123]; also match wX, qX
		const char *b = strstr (opstr, "[x27");
		if (!b) {
			continue;
		}
		const char *comma = strchr (b, ',');
		if (!comma) {
			continue;
		}
		const char *p = comma + 1;
		while (*p == ' ' || *p == '#') {
			p++;
		}
		const char *q = p;
		bool is_hex = r_str_startswith (p, "0x") || r_str_startswith (p, "0X");
		if (is_hex) {
			q = p + 2;
			while (isxdigit ((ut8)*q)) {
				q++;
			}
			if (q == p + 2) {
				continue;
			}
		} else {
			while (isdigit ((ut8)*q)) {
				q++;
			}
			if (q == p) {
				continue;
			}
		}
		ut64 val = strtoull (p, NULL, is_hex? 16: 10);
		if (!vec_contains_offset (offsets, val)) {
			RVecDartOffset_push_back (offsets, &val);
		}
	}
	r_json_free (j);
	free (s);
}

static void dump_pool_offsets_flags(DartApp *app, RStrBuf *sb, bool quiet) {
	if (!app || !app->core || !app->functions) {
		return;
	}
	if (!app->dctx.verbose) {
		if (!quiet) {
			r_strbuf_append (sb, "# PP offset scan skipped by default; use xrefs/analysis for pool-slot refs\n");
		}
		return;
	}
	RVecDartOffset offsets;
	RVecDartOffset_init (&offsets);
	DartFunction *fn;
	R_VEC_FOREACH (app->functions, fn) {
		if (fn->name && r_str_startswith (fn->name, "sym.imp.")) {
			continue;
		}
		collect_pool_offsets_from_fn (app->core, fn->addr, &offsets);
	}
	ut64 *offp;
	R_VEC_FOREACH (&offsets, offp) {
		r_strbuf_appendf (sb, "f pp.off_0x%" PFMT64x "=PP+0x%" PFMT64x "\n", (uint64_t)*offp, (uint64_t)*offp);
		if (!quiet) {
			r_strbuf_appendf (sb, "'@PP+0x%" PFMT64x "'CC pool_entry_%" PFMT64x "\n", (uint64_t)*offp, (uint64_t)*offp);
		}
	}
	RVecDartOffset_fini (&offsets);
}

// Build a "method.xxx" flag name, avoiding double "method." prefix
static char *make_method_flagname(const char *name) {
	char *safe = strdup (name);
	r_name_filter (safe, 0);
	if (r_str_startswith (safe, "method.")) {
		return safe;
	}
	char *flagname = r_str_newf ("method.%s", safe);
	free (safe);
	return flagname;
}

static void dump_func_r2(RStrBuf *sb, const DartFunction *fn, bool quiet) {
	char *flagname = make_method_flagname (fn->name);
	r_strbuf_appendf (sb, "f %s = 0x%" PFMT64x "\n", flagname, (uint64_t)fn->addr);
	if (!quiet) {
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC %s\n", (uint64_t)fn->addr, fn->name);
	}
	free (flagname);
}

char *dart_dumper_dump_r2(DartApp *app) {
	RStrBuf *sb = r_strbuf_new ("");
	const bool quiet = app && app->dctx.quiet;

	if (!quiet) {
		r_strbuf_append (sb, "# create flags for libraries, classes and methods\n");
	}
	r_strbuf_append (sb, "e emu.str=true\n");
	r_strbuf_appendf (sb, "f app.base = 0x%" PFMT64x "\n", (uint64_t)app->base_addr);
	r_strbuf_appendf (sb, "f app.heap_base = 0x%" PFMT64x "\n", (uint64_t)app->heap_base);

	if (app->functions) {
		DartFunction *fn;
		R_VEC_FOREACH (app->functions, fn) {
			if (!fn->name) {
				continue;
			}
			dump_func_r2 (sb, fn, quiet);
		}
	}

	r_strbuf_append (sb, "dr x27=`e anal.gp`\n");
	r_strbuf_append (sb, "'f PP=x27\n");

	dump_pool_offsets_flags (app, sb, quiet);

	return r_strbuf_drain (sb);
}

static int dump_funcs_limit(const DartApp *app) {
	return app->dctx.dump_fns_limit? app->dctx.dump_fns_limit: -1;
}

static char *drain_trimmed_strbuf(RStrBuf *sb) {
	char *out = r_strbuf_drain (sb);
	size_t len = strlen (out);
	if (len > 0 && out[len - 1] == '\n') {
		out[len - 1] = '\0';
	}
	return out;
}

static void dump_func_json(PJ *pj, const DartFunction *fn) {
	pj_o (pj);
	pj_kn (pj, "addr", fn->addr);
	pj_ks (pj, "name", fn->name);
	if (fn->size) {
		pj_kn (pj, "size", fn->size);
	}
	if (R_STR_ISNOTEMPTY (fn->signature)) {
		pj_ks (pj, "signature", fn->signature);
	}
	pj_end (pj);
}

static void dump_func_text(RStrBuf *sb, const DartFunction *fn) {
	r_strbuf_appendf (sb, "0x%" PFMT64x " %s\n", (uint64_t)fn->addr, fn->name);
}

char *dart_dumper_dump_funcs(DartApp *app, int fmt) {
	if (!app || !app->functions || RVecDartFunction_length (app->functions) == 0) {
		return fmt == 'j'? strdup ("[]"): strdup ("");
	}

	DartFunction *fn;
	int count = 0;
	int limit = dump_funcs_limit (app);

	if (fmt == 'j') {
		PJ *pj = pj_new ();
		pj_a (pj);
		R_VEC_FOREACH (app->functions, fn) {
			if (!fn->name) {
				continue;
			}
			if (limit > 0 && count >= limit) {
				break;
			}
			dump_func_json (pj, fn);
			count++;
		}
		pj_end (pj);
		return pj_drain (pj);
	}

	RStrBuf *sb = r_strbuf_new ("");
	R_VEC_FOREACH (app->functions, fn) {
		if (!fn->name) {
			continue;
		}
		if (limit > 0 && count >= limit) {
			break;
		}
		if (fmt == 'r') {
			dump_func_r2 (sb, fn, app->dctx.quiet);
		} else {
			dump_func_text (sb, fn);
		}
		count++;
	}
	return drain_trimmed_strbuf (sb);
}

// Map a single Dart type token to a C-ish spelling radare2's `afs` accepts.
static void dart_type_to_c(RStrBuf *sb, const char *tok) {
	if (R_STR_ISEMPTY (tok) || !strcmp (tok, "dynamic")) {
		r_strbuf_append (sb, "void *");
	} else if (!strcmp (tok, "void")) {
		r_strbuf_append (sb, "void");
	} else if (!strcmp (tok, "int")) {
		r_strbuf_append (sb, "int64_t");
	} else if (!strcmp (tok, "double")) {
		r_strbuf_append (sb, "double");
	} else if (!strcmp (tok, "bool")) {
		r_strbuf_append (sb, "bool");
	} else if (!strcmp (tok, "String")) {
		r_strbuf_append (sb, "char *");
	} else {
		// Object / user-class type: an opaque pointer named after the class.
		char *safe = strdup (tok);
		r_name_filter (safe, 0);
		r_strbuf_appendf (sb, "%s *", R_STR_ISNOTEMPTY (safe)? safe: "void");
		free (safe);
	}
}

// Turn a recovered Dart signature "RET(T,T,...)" into a radare2 `afs` prototype
// and return it, or NULL if the signature is not in that canonical form.
static char *dart_signature_to_afs_proto(const char *fname, const char *sig) {
	if (R_STR_ISEMPTY (sig) || strchr (sig, ' ') || strchr (sig, '=')) {
		return NULL; // not our canonical "RET(T,...)" form
	}
	const char *lp = strchr (sig, '(');
	if (!lp) {
		return NULL;
	}
	char *ret = r_str_ndup (sig, (int)(lp - sig));
	if (R_STR_ISEMPTY (ret)) {
		free (ret);
		return NULL;
	}
	char *inside = strdup (lp + 1);
	char *rp = strrchr (inside, ')');
	if (rp) {
		*rp = '\0';
	}
	char *safe_name = strdup (fname);
	r_name_filter (safe_name, 0);
	RStrBuf *sb = r_strbuf_new ("");
	dart_type_to_c (sb, ret);
	r_strbuf_appendf (sb, " %s(", R_STR_ISNOTEMPTY (safe_name)? safe_name: "fcn");
	int argc = 0;
	if (R_STR_ISNOTEMPTY (inside)) {
		RList *args = r_str_split_list (inside, ",", 0);
		RListIter *it;
		char *a;
		r_list_foreach (args, it, a) {
			if (argc > 0) {
				r_strbuf_append (sb, ", ");
			}
			dart_type_to_c (sb, r_str_trim_head_ro (a));
			// The first parameter of an instance method is the receiver.
			if (argc == 0) {
				r_strbuf_append (sb, " this");
			} else {
				r_strbuf_appendf (sb, " arg%d", argc);
			}
			argc++;
		}
		r_list_free (args);
	}
	r_strbuf_append (sb, ")");
	free (ret);
	free (inside);
	free (safe_name);
	return r_strbuf_drain (sb);
}

static int dart_fn_addr_desc(const void *a, const void *b) {
	const DartFunction *fa = *(const DartFunction *const *)a;
	const DartFunction *fb = *(const DartFunction *const *)b;
	if (fa->addr < fb->addr) {
		return 1;
	}
	if (fa->addr > fb->addr) {
		return -1;
	}
	return 0;
}

// Define a function at `addr` if needed and set its recovered signature so that
// `afsj`/`afcrj` report real parameter and return types. Functions are analysed
// in descending address order: a Dart function whose analysis overruns into the
// next one then stops at the already-defined higher function instead of merging.
void dart_dumper_apply_signatures(DartApp *app) {
	if (!app || !app->core || !app->functions) {
		return;
	}
	RCore *core = app->core;
	size_t total = RVecDartFunction_length (app->functions);
	if (!total) {
		return;
	}
	DartFunction **order = (DartFunction **)malloc (total * sizeof (DartFunction *));
	if (!order) {
		return;
	}
	size_t n = 0;
	DartFunction *fn;
	R_VEC_FOREACH (app->functions, fn) {
		if (fn->addr && R_STR_ISNOTEMPTY (fn->signature)) {
			order[n++] = fn;
		}
	}
	qsort (order, n, sizeof (DartFunction *), dart_fn_addr_desc);
	// Keep the analysis local to each function start; the surrounding pass owns
	// broader discovery. String ESIL emulation is very slow and irrelevant to
	// prototypes, so disable it for the duration of this pass.
	int prev_hasnext = r_config_get_i (core->config, "anal.hasnext");
	int prev_emustr = r_config_get_i (core->config, "emu.str");
	r_config_set_i (core->config, "anal.hasnext", 0);
	r_config_set_i (core->config, "emu.str", 0);
	for (size_t i = 0; i < n; i++) {
		fn = order[i];
		char *proto = dart_signature_to_afs_proto (fn->name? fn->name: "fcn", fn->signature);
		if (!proto) {
			continue;
		}
		if (!r_anal_get_function_at (core->anal, fn->addr)) {
			r_core_cmdf (core, "af @ 0x%" PFMT64x, fn->addr);
		}
		if (r_anal_get_function_at (core->anal, fn->addr)) {
			r_core_cmdf (core, "\"afs %s\" @ 0x%" PFMT64x, proto, fn->addr);
		}
		free (proto);
	}
	r_config_set_i (core->config, "anal.hasnext", prev_hasnext);
	r_config_set_i (core->config, "emu.str", prev_emustr);
	free (order);
}

void dart_dumper_apply_to_core(DartApp *app, bool apply_signatures) {
	if (!app || !app->core) {
		return;
	}
	RCore *core = app->core;

	r_flag_set (core->flags, "app.base", app->base_addr, 0);
	if (app->heap_base) {
		r_flag_set (core->flags, "app.heap_base", app->heap_base, 0);
	}

	if (app->functions) {
		DartFunction *fn;
		R_VEC_FOREACH (app->functions, fn) {
			if (!fn->name) {
				continue;
			}
			char *flagname = make_method_flagname (fn->name);
			r_flag_set (core->flags, flagname, fn->addr, fn->size);
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, fn->addr, fn->name);
			free (flagname);
		}
	}

	r_core_cmd0 (core, "e emu.str=true");
	// Applying signatures forces analysis (af) of every typed function, which is
	// slow on a large snapshot; only do it at the deepest level (-AAA). Lighter
	// consumers (e.g. the reflow decompiler) read per-function signatures from
	// the fast `-fj` dump instead.
	if (apply_signatures) {
		dart_dumper_apply_signatures (app);
	}
}
