/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_core.h>
#include <r_list.h>
#include <r_util/r_name.h>
#include <r_util/r_str.h>
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_obf.h"
#include "../../include/r2flutter/dart_pool_parse.h"

extern int dart_pool_enumerate(DartCtx *ctx, const char *libapp_path, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user, unsigned long long *out_base, unsigned long long *out_heap_base);

typedef unsigned long long ull;

enum {
	DART_FN_KIND_REGULAR = 0,
	DART_FN_KIND_CLOSURE = 1,
	DART_FN_KIND_IMPLICIT_CLOSURE = 2,
	DART_FN_KIND_GETTER = 3,
	DART_FN_KIND_SETTER = 4,
	DART_FN_KIND_CONSTRUCTOR = 5,
	DART_FN_KIND_IMPLICIT_GETTER = 6,
	DART_FN_KIND_IMPLICIT_SETTER = 7,
	DART_FN_KIND_IMPLICIT_STATIC_GETTER = 8,
};

typedef struct {
	const char *op;
	const char *name;
} DartOpNameMap;

static const DartOpNameMap op_name_map[] = {
	{ "==", "eq" },
	{ "<", "lt" },
	{ ">", "gt" },
	{ "<=", "lte" },
	{ ">=", "gte" },
	{ "=", "assign" },
	{ "[]", "at" },
	{ "[]=", "at_assign" },
	{ "++", "increment" },
	{ "--", "decrement" },
	{ "+", "add" },
	{ "-", "sub" },
	{ "*", "mul" },
	{ "~/", "div" },
	{ "/", "divf" },
	{ "%", "mod" },
	{ "&", "LAnd" },
	{ "|", "LOr" },
	{ "^", "xor" },
	{ "~", "not" },
	{ ">>", "shr" },
	{ "<<", "shal" },
	{ NULL, NULL }
};

static void free_dart_function(void *p) {
	DartFunction *fn = (DartFunction *)p;
	if (!fn) {
		return;
	}
	free (fn->name);
	free (fn);
}

static ut64 dart_normalize_code_addr(ut64 addr) {
	return (addr & 1ULL)? addr - 1: addr;
}

static int dart_function_cmp(const void *a, const void *b) {
	const DartFunction *fa = (const DartFunction *)a;
	const DartFunction *fb = (const DartFunction *)b;
	if (!fa && !fb) {
		return 0;
	}
	if (!fa) {
		return 1;
	}
	if (!fb) {
		return -1;
	}
	if (fa->addr < fb->addr) {
		return -1;
	}
	if (fa->addr > fb->addr) {
		return 1;
	}
	if (fa->quality > fb->quality) {
		return -1;
	}
	if (fa->quality < fb->quality) {
		return 1;
	}
	return 0;
}

static int dart_function_name_quality(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return 0;
	}
	if (r_str_startswith (name, "method.fn_") || r_str_startswith (name, "func.")) {
		return 10;
	}
	if (r_str_startswith (name, "method.")) {
		int dots = 0;
		for (const char *p = name; *p; p++) {
			if (*p == '.') {
				dots++;
			}
		}
		return dots >= 3? 100: 80;
	}
	if (strchr (name, '.')) {
		return 60;
	}
	return 40;
}

static char *dart_strdup_filtered(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	char *dup = strdup (name);
	r_name_filter (dup, 0);
	return dup;
}

static void dart_app_add_or_update_fn(DartApp *app, const char *name, ut64 addr, ut64 size, int quality) {
	if (!app || !app->functions || !addr) {
		return;
	}
	char *filtered = dart_strdup_filtered (name);
	if (filtered) {
		char *resolved = dart_obf_resolve (&app->dctx, filtered);
		free (filtered);
		filtered = resolved;
	}
	RListIter *it;
	DartFunction *fn;
	r_list_foreach (app->functions, it, fn) {
		if (!fn || fn->addr != addr) {
			continue;
		}
		if (size > fn->size) {
			fn->size = size;
		}
		if (quality > fn->quality || (!fn->name && filtered)) {
			free (fn->name);
			fn->name = filtered;
			fn->quality = quality;
			filtered = NULL;
		} else if (quality == fn->quality && filtered && fn->name && strlen (filtered) > strlen (fn->name)) {
			free (fn->name);
			fn->name = filtered;
			filtered = NULL;
		}
		free (filtered);
		return;
	}
	DartFunction *newfn = (DartFunction *)calloc (1, sizeof (DartFunction));
	if (!newfn) {
		free (filtered);
		return;
	}
	newfn->addr = addr;
	newfn->size = size;
	newfn->quality = quality;
	if (filtered) {
		newfn->name = filtered;
	} else {
		char buf[64];
		snprintf (buf, sizeof (buf), "func_%llx", (unsigned long long)addr);
		newfn->name = strdup (buf);
		newfn->quality = 0;
	}
	r_list_append (app->functions, newfn);
}

static char *dart_sanitize_component(const char *input, bool strip_package_prefix) {
	if (R_STR_ISEMPTY (input)) {
		return strdup ("");
	}
	const char *src = input;
	if (strip_package_prefix && r_str_startswith (src, "package:")) {
		src += strlen ("package:");
	}
	char *dup = strdup (src);
	size_t len = strlen (dup);
	if (len > 5 && !strcmp (dup + len - 5, ".dart")) {
		dup[len - 5] = '\0';
	}
	char *out = (char *)calloc (strlen (dup) + 2, 1);
	int j = 0;
	bool last_sep = false;
	for (size_t i = 0; dup[i]; i++) {
		ut8 ch = (ut8)dup[i];
		if (isalpha (ch) || isdigit (ch) || ch == '_') {
			out[j++] = dup[i];
			last_sep = false;
		} else {
			if (!last_sep) {
				out[j++] = '_';
				last_sep = true;
			}
		}
	}
	while (j > 0 && out[j - 1] == '_') {
		out[--j] = '\0';
	}
	free (dup);
	return out;
}

static const char *dart_lookup_operator_name(const char *name) {
	for (int i = 0; op_name_map[i].op; i++) {
		if (!strcmp (name, op_name_map[i].op)) {
			return op_name_map[i].name;
		}
	}
	return NULL;
}

static char *dart_format_method_leaf_name(const char *owner_name, const DartMethodInfo *mi) {
	if (!mi || R_STR_ISEMPTY (mi->name)) {
		return NULL;
	}
	const ut32 kind = mi->kind_tag & 0x1f;
	char *fn_name = strdup (mi->name);
	char *prefix = strdup ("");
	if ((kind == DART_FN_KIND_CLOSURE || kind == DART_FN_KIND_IMPLICIT_CLOSURE) && !strcmp (fn_name, "<anonymous closure>")) {
		free (prefix);
		free (fn_name);
		return strdup ("_anon_closure");
	}
	const char *dot = strchr (fn_name, '.');
	if (kind == DART_FN_KIND_REGULAR && dot && dot != fn_name) {
		free (prefix);
		prefix = r_str_ndup (fn_name, (int) (dot - fn_name) + 1);
		for (char *p = prefix; *p; p++) {
			if (*p == '#') {
				*p = '@';
			}
		}
		char *tail = strdup (dot + 1);
		free (fn_name);
		fn_name = tail;
	}
	const char *op_name = dart_lookup_operator_name (fn_name);
	if (op_name) {
		char *out = r_str_newf ("%sop_%s", prefix, op_name);
		free (prefix);
		free (fn_name);
		return out;
	}
	size_t len = strlen (fn_name);
	if (len > 0 && fn_name[len - 1] == '=') {
		fn_name[len - 1] = '\0';
		char *out = r_str_newf ("%s%s_assign", prefix, fn_name);
		free (prefix);
		free (fn_name);
		return out;
	}
	if (len > 0 && fn_name[len - 1] == '-') {
		fn_name[len - 1] = '\0';
		char *out = r_str_newf ("%s%s_neg", prefix, fn_name);
		free (prefix);
		free (fn_name);
		return out;
	}
	if (len > 0 && fn_name[len - 1] == '!') {
		fn_name[len - 1] = '\0';
		char *out = r_str_newf ("%s%s_not", prefix, fn_name);
		free (prefix);
		free (fn_name);
		return out;
	}
	if (kind == DART_FN_KIND_CONSTRUCTOR) {
		char *out = NULL;
		if (R_STR_ISNOTEMPTY (owner_name) && r_str_startswith (fn_name, owner_name) && fn_name[strlen (owner_name)] == '.') {
			out = r_str_newf ("ctor_%s", fn_name + strlen (owner_name) + 1);
		} else {
			out = strdup ("ctor");
		}
		free (prefix);
		free (fn_name);
		return out;
	}
	if (kind == DART_FN_KIND_SETTER || kind == DART_FN_KIND_IMPLICIT_SETTER) {
		char *out = r_str_newf ("set_%s", fn_name);
		free (prefix);
		free (fn_name);
		return out;
	}
	if (kind == DART_FN_KIND_GETTER || kind == DART_FN_KIND_IMPLICIT_GETTER || kind == DART_FN_KIND_IMPLICIT_STATIC_GETTER) {
		char *out = r_str_newf ("get_%s", fn_name);
		free (prefix);
		free (fn_name);
		return out;
	}
	char *out = r_str_newf ("%s%s", prefix, fn_name);
	free (prefix);
	free (fn_name);
	return out;
}

static char *dart_format_method_full_name(const DartClassInfo *ci, const DartMethodInfo *mi) {
	if (!mi || R_STR_ISEMPTY (mi->name)) {
		return NULL;
	}
	char *lib = dart_sanitize_component (ci && ci->library_name? ci->library_name: "app", true);
	char *owner = dart_sanitize_component (ci && ci->name? ci->name: mi->owner_name, false);
	char *leaf = dart_format_method_leaf_name (ci? ci->name: mi->owner_name, mi);
	char *out = NULL;
	if (R_STR_ISNOTEMPTY (owner)) {
		out = r_str_newf ("method.%s.%s.%s", lib, owner, leaf? leaf: mi->name);
	} else {
		out = r_str_newf ("method.%s..%s", lib, leaf? leaf: mi->name);
	}
	r_name_filter (out, 0);
	free (lib);
	free (owner);
	free (leaf);
	return out;
}

static void dart_app_load_it_functions(DartApp *app) {
	RList *entries = dart_pool_extract_instruction_table (&app->dctx);
	if (!entries) {
		return;
	}
	RListIter *it;
	DartInstructionTableEntry *entry;
	r_list_foreach (entries, it, entry) {
		if (!entry || !entry->has_code || !entry->address) {
			continue;
		}
		dart_app_add_or_update_fn (app,
			entry->name? entry->name: "method.unknown",
			dart_normalize_code_addr (entry->address),
			0,
			dart_function_name_quality (entry->name));
	}
	dart_instruction_table_list_free (entries);
}

static void dart_app_merge_class_methods(DartApp *app) {
	DartCtx ctx = app->dctx;
	ctx.core = app->core;
	ctx.dump_fields = 1;
	RList *classes = dart_pool_extract_classes (&ctx);
	if (!classes) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (classes, it, ci) {
		if (!ci || !ci->methods) {
			continue;
		}
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			if (!mi || !mi->entry_point || R_STR_ISEMPTY (mi->name)) {
				continue;
			}
			char *fullname = dart_format_method_full_name (ci, mi);
			dart_app_add_or_update_fn (app,
				fullname? fullname: mi->name,
				dart_normalize_code_addr (mi->entry_point),
				0,
				dart_function_name_quality (fullname? fullname: mi->name));
			free (fullname);
		}
	}
	dart_class_list_free (classes);
}

DartApp *dart_app_new(const char *path) {
	DartApp *app = (DartApp *)calloc (1, sizeof (DartApp));
	if (!app) {
		return NULL;
	}
	app->file_path = path? strdup (path): NULL;
	app->functions = r_list_newf (free_dart_function);
	return app;
}

DartApp *dart_app_new_from_core(RCore *core, DartCtx *dctx) {
	const char *filepath = R_UNWRAP4 (core, bin, cur, file);
	if (!filepath) {
		return NULL;
	}
	DartApp *app = dart_app_new (filepath);
	if (!app) {
		return NULL;
	}
	app->core = core;
	app->base_addr = r_bin_get_baddr (core->bin);
	if (app->base_addr == UT64_MAX) {
		app->base_addr = 0;
	}
	app->heap_base = 0;
	memcpy (&app->dctx, dctx, sizeof (DartCtx));
	app->dctx.core = core;
	return app;
}

void dart_app_free(DartApp *app) {
	if (!app) {
		return;
	}
	dart_obf_fini (&app->dctx);
	r_list_free (app->functions);
	free (app->file_path);
	free (app);
}

static void add_fn_cb(const char *name, unsigned long long addr, unsigned long long size, void *user) {
	DartApp *app = (DartApp *)user;
	dart_app_add_or_update_fn (app,
		name,
		dart_normalize_code_addr ((ut64)addr),
		(ut64)size,
		dart_function_name_quality (name));
}

void dart_app_load_info(DartApp *app) {
	if (!app || !app->file_path) {
		return;
	}
	app->dctx.core = app->core;
	app->base_addr = r_bin_get_baddr (app->core->bin);
	if (app->base_addr == UT64_MAX) {
		app->base_addr = 0;
	}
	app->heap_base = 0;
	dart_app_load_it_functions (app);
	dart_app_merge_class_methods (app);
	if (r_list_length (app->functions) == 0) {
		unsigned long long base = 0, heap_base = 0;
		int rc = dart_pool_enumerate (&app->dctx, app->file_path, add_fn_cb, app, &base, &heap_base);
		if (rc == 0) {
			app->base_addr = (ut64)base;
			app->heap_base = (ut64)heap_base;
		}
	}
	r_list_sort (app->functions, (RListComparator)dart_function_cmp);
	if (app->dctx.verbose) {
		fprintf (stderr, "Found %d functions (from Dart ObjectPool)\n", app->functions? r_list_length (app->functions): 0);
	}
}
