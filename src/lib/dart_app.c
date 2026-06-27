/* r2flutter - MIT - Copyright 2026 - pancake, Ahmeth4n */

#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_obf.h"
#include "../../include/r2flutter/dart_pool_parse.h"

enum {
	DART_MACHO_MH_MAGIC_64 = 0xfeedfacf,
	DART_MACHO_FAT_MAGIC = 0xcafebabe,
	DART_MACHO_FAT_MAGIC_64 = 0xcafebabf,
	DART_MACHO_LC_NOTE = 0x31,
	DART_MACHO_CPU_TYPE_ARM64 = 0x0100000c,
};

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

static bool buf_range_fits(ut64 off, ut64 size, ut64 fsize) {
	return size && off <= fsize && size <= fsize - off;
}

static bool buf_looks_like_macho64_at(RBuffer *b, ut64 off) {
	return r_buf_read_le32_at (b, off) == DART_MACHO_MH_MAGIC_64;
}

static bool find_dart_note_in_macho(RBuffer *b, ut64 fsize, ut64 macho_off, DartAppEmbeddedPayload *out) {
	if (!buf_looks_like_macho64_at (b, macho_off)) {
		return false;
	}
	ut32 ncmds = r_buf_read_le32_at (b, macho_off + 16);
	ut32 sizeofcmds = r_buf_read_le32_at (b, macho_off + 20);
	ut64 cmds = macho_off + 32;
	if (!buf_range_fits (cmds, sizeofcmds, fsize)) {
		return false;
	}
	ut64 end = cmds + sizeofcmds;
	ut64 cur = cmds;
	for (ut32 i = 0; i < ncmds && cur + 8 <= end; i++) {
		ut32 cmd = r_buf_read_le32_at (b, cur);
		ut32 cmdsize = r_buf_read_le32_at (b, cur + 4);
		if (cmdsize < 8 || cur + cmdsize > end) {
			return false;
		}
		if (cmd == DART_MACHO_LC_NOTE && cmdsize >= 40) {
			char owner[17] = { 0 };
			if (r_buf_read_at (b, cur + 8, (ut8 *)owner, 16) != 16) {
				return false;
			}
			if (!strcmp (owner, "__dart_app_snap")) {
				ut64 payload_off = r_buf_read_le64_at (b, cur + 24);
				ut64 payload_size = r_buf_read_le64_at (b, cur + 32);
				ut64 abs_payload = payload_off;
				if (!buf_range_fits (abs_payload, payload_size, fsize) ||
					!buf_looks_like_macho64_at (b, abs_payload)) {
					ut64 slice_relative = macho_off + payload_off;
					if (!buf_range_fits (slice_relative, payload_size, fsize) ||
						!buf_looks_like_macho64_at (b, slice_relative)) {
						return false;
					}
					abs_payload = slice_relative;
				}
				memset (out, 0, sizeof (*out));
				r_str_ncpy (out->owner, owner, sizeof (out->owner));
				out->payload_offset = abs_payload;
				out->payload_size = payload_size;
				out->macho_offset = macho_off;
				return true;
			}
		}
		cur += cmdsize;
	}
	return false;
}

static bool find_dart_note_in_fat_macho(RBuffer *b, ut64 fsize, bool fat64, DartAppEmbeddedPayload *out) {
	ut32 nfat = r_buf_read_be32_at (b, 4);
	if (!nfat || nfat > 64) {
		return false;
	}
	const ut64 arch_size = fat64? 32: 20;
	for (int pass = 0; pass < 2; pass++) {
		for (ut32 i = 0; i < nfat; i++) {
			ut64 arch_off = 8 + ((ut64)i * arch_size);
			if (!buf_range_fits (arch_off, arch_size, fsize)) {
				return false;
			}
			ut32 cputype = r_buf_read_be32_at (b, arch_off);
			if (pass == 0 && cputype != DART_MACHO_CPU_TYPE_ARM64) {
				continue;
			}
			ut64 slice_off = fat64? r_buf_read_be64_at (b, arch_off + 8): r_buf_read_be32_at (b, arch_off + 8);
			ut64 slice_size = fat64? r_buf_read_be64_at (b, arch_off + 16): r_buf_read_be32_at (b, arch_off + 12);
			if (!buf_range_fits (slice_off, slice_size, fsize)) {
				continue;
			}
			if (find_dart_note_in_macho (b, fsize, slice_off, out)) {
				return true;
			}
		}
	}
	return false;
}

bool dart_app_find_macho_embedded_dart(const char *path, DartAppEmbeddedPayload *out) {
	if (R_STR_ISEMPTY (path) || !out) {
		return false;
	}
	memset (out, 0, sizeof (*out));
	RBuffer *b = r_buf_new_file (path, O_RDONLY, 0);
	if (!b) {
		return false;
	}
	ut64 fsize = r_buf_size (b);
	bool found = false;
	if (fsize >= 32) {
		const ut32 le_magic = r_buf_read_le32_at (b, 0);
		const ut32 be_magic = r_buf_read_be32_at (b, 0);
		if (le_magic == DART_MACHO_MH_MAGIC_64) {
			found = find_dart_note_in_macho (b, fsize, 0, out);
		} else if (be_magic == DART_MACHO_FAT_MAGIC || be_magic == DART_MACHO_FAT_MAGIC_64) {
			found = find_dart_note_in_fat_macho (b, fsize, be_magic == DART_MACHO_FAT_MAGIC_64, out);
		}
	}
	r_unref (b);
	return found;
}

static FILE *try_open_temp_path(char *tmpname, char **out_path) {
	FILE *out = tmpname? fopen (tmpname, "wb"): NULL;
	if (out) {
		*out_path = tmpname;
		return out;
	}
	free (tmpname);
	return NULL;
}

static FILE *open_payload_temp(char **out_path) {
	FILE *out = try_open_temp_path (r_file_temp ("r2flutter-dart-app-snap"), out_path);
	if (!out) {
		char *name = r_str_newf ("r2flutter-dart-app-snap.%" PFMT64x, (ut64)r_time_now ());
		char *path = name? r_file_new (P_tmpdir, name, NULL): NULL;
		free (name);
		out = try_open_temp_path (path, out_path);
	}
	return out;
}

char *dart_app_extract_embedded_payload(const char *path, const DartAppEmbeddedPayload *payload) {
	if (R_STR_ISEMPTY (path) || !payload || !payload->payload_size) {
		return NULL;
	}
	FILE *in = fopen (path, "rb");
	if (!in) {
		R_LOG_ERROR ("Cannot open input file: %s", path);
		return NULL;
	}
	char *tmpname = NULL;
	FILE *out = open_payload_temp (&tmpname);
	if (!out) {
		R_LOG_ERROR ("Cannot open temporary output file");
		fclose (in);
		return NULL;
	}
	bool ok = fseeko (in, (off_t)payload->payload_offset, SEEK_SET) == 0;
	ut64 remaining = payload->payload_size;
	ut8 buf[65536];
	while (ok && remaining > 0) {
		size_t want = remaining > sizeof (buf)? sizeof (buf): (size_t)remaining;
		size_t got = fread (buf, 1, want, in);
		if (got != want || fwrite (buf, 1, got, out) != got) {
			ok = false;
			break;
		}
		remaining -= got;
	}
	if (fclose (out) != 0) {
		ok = false;
	}
	fclose (in);
	if (!ok) {
		R_LOG_ERROR ("Failed to copy embedded payload from 0x%" PFMT64x " size 0x%" PFMT64x,
			payload->payload_offset,
			payload->payload_size);
		r_file_rm (tmpname);
		free (tmpname);
		return NULL;
	}
	return tmpname;
}

void dart_function_fini(DartFunction *fn) {
	free (fn->name);
}

static ut64 dart_normalize_code_addr(ut64 addr) {
	return (addr & 1ULL)? addr - 1: addr;
}

static int dart_function_cmp(const DartFunction *fa, const DartFunction *fb) {
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
		dart_obf_apply (&app->dctx, &filtered);
	}
	DartFunction *fn;
	R_VEC_FOREACH (app->functions, fn) {
		if (fn->addr != addr) {
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
	DartFunction *newfn = RVecDartFunction_emplace_back (app->functions);
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
		newfn->name = r_str_newf ("func_%" PFMT64x, (ut64)addr);
		newfn->quality = 0;
	}
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
	RVecDartInstructionTableEntry *entries = dart_pool_extract_instruction_table (&app->dctx);
	if (!entries) {
		return;
	}
	DartInstructionTableEntry *entry;
	R_VEC_FOREACH (entries, entry) {
		if (!entry->has_code || !entry->address) {
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
	DartApp *app = R_NEW0 (DartApp);
	app->file_path = path? strdup (path): NULL;
	app->functions = RVecDartFunction_new ();
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
	RVecDartFunction_free (app->functions);
	free (app->file_path);
	free (app);
}

static void add_fn_cb(const char *name, ut64 addr, ut64 size, void *user) {
	DartApp *app = (DartApp *)user;
	dart_app_add_or_update_fn (app,
		name,
		dart_normalize_code_addr (addr),
		size,
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
	if (RVecDartFunction_length (app->functions) == 0) {
		ut64 base = 0, heap_base = 0;
		int rc = dart_pool_enumerate (&app->dctx, app->file_path, add_fn_cb, app, &base, &heap_base);
		if (rc == 0) {
			app->base_addr = base;
			app->heap_base = heap_base;
		}
	}
	RVecDartFunction_sort (app->functions, dart_function_cmp);
	if (app->dctx.verbose) {
		fprintf (stderr, "Found %zu functions (from Dart ObjectPool)\n", RVecDartFunction_length (app->functions));
	}
}
