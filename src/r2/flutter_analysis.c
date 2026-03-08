/* radare2 - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <ctype.h>
#include <r_core.h>
#include <r_flag.h>
#include <r_anal.h>
#include <r_list.h>
#include <r_util/r_json.h>
#include <r_util/r_name.h>
#include <r_util/r_str.h>
#include <sdb/ht_pp.h>
#include <sdb/ht_up.h>
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_pool_parse.h"
#include "flutter_analysis.h"

#define DART_ANALYSIS_COMMENT_PREFIX "dart: "
#define DART_ANALYSIS_MAX_REGS 32

typedef struct {
	RList *strings;
	RList *classes;
	HtPP *string_by_value;
	HtUP *string_by_addr;
	HtPP *class_by_name;
	HtUP *method_by_addr;
} FlutterAnalModel;

typedef struct {
	const DartClassInfo *klass;
	const DartFieldInfo *field;
	const DartStringInfo *string;
	const char *type_name;
	ut64 pp_off;
	bool has_pp_off;
} FlutterTrackedValue;

typedef struct {
	st64 offset;
	FlutterTrackedValue value;
} FlutterStackSlot;

typedef struct {
	FlutterTrackedValue regs[DART_ANALYSIS_MAX_REGS];
	RList *stack_slots;
} FlutterAnalState;

typedef struct {
	char regs[4][16];
	int n_regs;
	char mem_base[16];
	st64 mem_disp;
	ut64 imm;
	bool has_mem;
	bool has_imm;
} FlutterOpInfo;

typedef struct {
	ut64 functions;
	ut64 call_xrefs;
	ut64 field_refs;
	ut64 class_refs;
	ut64 type_refs;
	ut64 string_refs;
	ut64 pp_refs;
	ut64 comments;
} FlutterAnalStats;

typedef struct {
	HtUP *seen;
	RList *entries;
} FlutterEntryCollector;

static void flutter_stack_slot_free(void *p) {
	free (p);
}

static void flutter_model_fini(FlutterAnalModel *model) {
	if (!model) {
		return;
	}
	dart_string_list_free (model->strings);
	dart_class_list_free (model->classes);
	ht_pp_free (model->string_by_value);
	ht_up_free (model->string_by_addr);
	ht_pp_free (model->class_by_name);
	ht_up_free (model->method_by_addr);
	memset (model, 0, sizeof (*model));
}

static void flutter_state_init(FlutterAnalState *state) {
	memset (state, 0, sizeof (*state));
	state->stack_slots = r_list_newf (flutter_stack_slot_free);
}

static void flutter_state_fini(FlutterAnalState *state) {
	if (!state) {
		return;
	}
	r_list_free (state->stack_slots);
	memset (state, 0, sizeof (*state));
}

static ut64 flutter_normalize_code_addr(ut64 addr) {
	return (addr & 1ULL)? addr - 1: addr;
}

static const char *flutter_method_leaf_name(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return name;
	}
	if (r_str_startswith (name, "dart.method.")) {
		return name + strlen ("dart.method.");
	}
	if (r_str_startswith (name, "method.")) {
		return name + strlen ("method.");
	}
	return name;
}

static bool flutter_flag_is_method(const char *name) {
	return R_STR_ISNOTEMPTY (name) && (r_str_startswith (name, "method.") || r_str_startswith (name, "dart.method."));
}

static bool flutter_reg_is_stack(const char *name) {
	return !strcmp (name, "x15") || !strcmp (name, "sp") || !strcmp (name, "x29") || !strcmp (name, "fp");
}

static bool flutter_reg_is_pp(const char *name) {
	return !strcmp (name, "x27");
}

static int flutter_reg_index(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return -1;
	}
	if (!strcmp (name, "fp") || !strcmp (name, "x29")) {
		return 29;
	}
	if (!strcmp (name, "lr") || !strcmp (name, "x30")) {
		return 30;
	}
	if ((name[0] == 'x' || name[0] == 'w') && isdigit ((ut8)name[1])) {
		int idx = atoi (name + 1);
		if (idx >= 0 && idx < DART_ANALYSIS_MAX_REGS) {
			return idx;
		}
	}
	return -1;
}

static const DartStringInfo *flutter_model_find_string_by_value(FlutterAnalModel *model, const char *value) {
	return model && value? ht_pp_find (model->string_by_value, value, NULL): NULL;
}

static const DartStringInfo *flutter_model_find_string_by_addr(FlutterAnalModel *model, ut64 addr) {
	return model && addr? ht_up_find (model->string_by_addr, addr, NULL): NULL;
}

static const DartClassInfo *flutter_model_find_class(FlutterAnalModel *model, const char *name) {
	return model && name? ht_pp_find (model->class_by_name, name, NULL): NULL;
}

static const DartMethodInfo *flutter_model_find_method(FlutterAnalModel *model, ut64 addr) {
	return model? ht_up_find (model->method_by_addr, addr, NULL): NULL;
}

static RFlagItem *flutter_get_flag_at(RCore *core, ut64 addr) {
	if (!core || !core->flags || !addr) {
		return NULL;
	}
	RFlagItem *fi = r_flag_get_in (core->flags, addr);
	if (!fi && ! (addr & 1ULL)) {
		fi = r_flag_get_in (core->flags, addr + 1);
	}
	return fi;
}

static const DartFieldInfo *flutter_class_find_field(const DartClassInfo *ci, ut32 off) {
	if (!ci || !ci->fields) {
		return NULL;
	}
	RListIter *it;
	DartFieldInfo *fi;
	r_list_foreach (ci->fields, it, fi) {
		if (fi && fi->offset == off) {
			return fi;
		}
	}
	return NULL;
}

static FlutterStackSlot *flutter_state_get_stack_slot(FlutterAnalState *state, st64 off) {
	if (!state) {
		return NULL;
	}
	RListIter *it;
	FlutterStackSlot *slot;
	r_list_foreach (state->stack_slots, it, slot) {
		if (slot && slot->offset == off) {
			return slot;
		}
	}
	return NULL;
}

static void flutter_state_set_stack_slot(FlutterAnalState *state, st64 off, const FlutterTrackedValue *value) {
	if (!state || !value) {
		return;
	}
	FlutterStackSlot *slot = flutter_state_get_stack_slot (state, off);
	if (!slot) {
		slot = R_NEW0 (FlutterStackSlot);
		slot->offset = off;
		r_list_append (state->stack_slots, slot);
	}
	slot->value = *value;
}

static void flutter_state_clobber_callers(FlutterAnalState *state) {
	if (!state) {
		return;
	}
	for (int i = 0; i <= 18 && i < DART_ANALYSIS_MAX_REGS; i++) {
		memset (&state->regs[i], 0, sizeof (state->regs[i]));
	}
	memset (&state->regs[30], 0, sizeof (state->regs[30]));
}

static bool flutter_parse_shifted_imm(const char *line, ut64 *imm) {
	if (R_STR_ISEMPTY (line) || !imm) {
		return false;
	}
	const char *lsl = strstr (line, "lsl");
	if (!lsl) {
		return false;
	}
	const char *hash = strchr (lsl, '#');
	if (!hash) {
		return false;
	}
	int shift = atoi (hash + 1);
	if (shift <= 0 || shift >= 63) {
		return false;
	}
	*imm <<= shift;
	return true;
}

static bool flutter_parse_opinfo(const RAnalOp *op, FlutterOpInfo *info) {
	if (!op || !info) {
		return false;
	}
	memset (info, 0, sizeof (*info));
	const char *opex = r_strbuf_get ((RStrBuf *)&op->opex);
	if (R_STR_ISEMPTY (opex)) {
		return false;
	}
	char *opexdup = strdup (opex);
	RJson *j = r_json_parse (opexdup);
	if (!j) {
		free (opexdup);
		return false;
	}
	const RJson *ops = r_json_get (j, "operands");
	for (size_t i = 0;; i++) {
		const RJson *item = r_json_item (ops, i);
		if (!item) {
			break;
		}
		const char *type = r_json_get_str (item, "type");
		if (R_STR_ISEMPTY (type)) {
			continue;
		}
		if (!strcmp (type, "reg")) {
			const char *value = r_json_get_str (item, "value");
			if (R_STR_ISNOTEMPTY (value) && info->n_regs < 4) {
				r_str_ncpy (info->regs[info->n_regs], value, sizeof (info->regs[0]));
				info->n_regs++;
			}
			continue;
		}
		if (!strcmp (type, "mem")) {
			const char *base = r_json_get_str (item, "base");
			if (R_STR_ISNOTEMPTY (base)) {
				r_str_ncpy (info->mem_base, base, sizeof (info->mem_base));
				info->has_mem = true;
			}
			info->mem_disp = (st64)r_json_get_num (item, "disp");
			continue;
		}
		if (!strcmp (type, "imm")) {
			info->imm = r_json_get_num (item, "value");
			info->has_imm = true;
		}
	}
	r_json_free (j);
	free (opexdup);
	if (info->has_imm && R_STR_ISNOTEMPTY (op->mnemonic)) {
		(void)flutter_parse_shifted_imm (op->mnemonic, &info->imm);
	}
	return info->n_regs > 0 || info->has_mem || info->has_imm;
}

static char *flutter_build_flag_name(const char *prefix, const char *name, ut64 addr) {
	if (R_STR_ISEMPTY (prefix) || R_STR_ISEMPTY (name)) {
		return NULL;
	}
	char *tmp = r_str_newf ("%s.%s", prefix, name);
	if (!tmp) {
		return NULL;
	}
	r_name_filter (tmp, 0);
	if (addr != UT64_MAX) {
		char *with_addr = r_str_newf ("%s.0x%" PFMT64x, tmp, addr);
		free (tmp);
		if (!with_addr) {
			return NULL;
		}
		r_name_filter (with_addr, 0);
		return with_addr;
	}
	return tmp;
}

static void flutter_set_flag(RCore *core, const char *prefix, const char *name, ut64 addr, ut32 size, bool force_addr_suffix) {
	if (!core || !core->flags || !addr || R_STR_ISEMPTY (prefix) || R_STR_ISEMPTY (name)) {
		return;
	}
	char *flag_name = flutter_build_flag_name (prefix, name, force_addr_suffix? addr: UT64_MAX);
	if (!flag_name) {
		return;
	}
	RFlagItem *fi = r_flag_get (core->flags, flag_name);
	if (fi && fi->addr != addr) {
		free (flag_name);
		flag_name = flutter_build_flag_name (prefix, name, addr);
		if (!flag_name) {
			return;
		}
	}
	r_flag_set (core->flags, flag_name, addr, size);
	free (flag_name);
}

static bool flutter_append_comment(RCore *core, ut64 addr, const char *msg, FlutterAnalStats *stats) {
	if (!core || !core->anal || !addr || R_STR_ISEMPTY (msg)) {
		return false;
	}
	const char *old = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
	if (R_STR_ISNOTEMPTY (old) && strstr (old, msg)) {
		return false;
	}
	char *merged = old? r_str_newf ("%s | %s", old, msg): strdup (msg);
	if (!merged) {
		return false;
	}
	bool ok = r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, merged);
	free (merged);
	if (ok && stats) {
		stats->comments++;
	}
	return ok;
}

static void flutter_add_ref(RCore *core, ut64 from, ut64 to, RAnalRefType type) {
	if (!core || !core->anal || !from || !to) {
		return;
	}
	r_anal_xrefs_set (core->anal, from, to, type);
}

static bool flutter_model_load(FlutterAnalModel *model, RCore *core, DartCtx *dctx) {
	if (!model || !core || !dctx) {
		return false;
	}
	memset (model, 0, sizeof (*model));
	model->string_by_value = ht_pp_new0 ();
	model->string_by_addr = ht_up_new0 ();
	model->class_by_name = ht_pp_new0 ();
	model->method_by_addr = ht_up_new0 ();

	DartCtx ctx = *dctx;
	ctx.core = core;
	ctx.dump_fields = 1;
	model->strings = dart_pool_extract_strings (&ctx);
	model->classes = dart_pool_extract_classes (&ctx);
	if (!model->strings || !model->classes) {
		flutter_model_fini (model);
		return false;
	}

	RListIter *it;
	DartStringInfo *si;
	r_list_foreach (model->strings, it, si) {
		if (!si || !R_STR_ISNOTEMPTY (si->value)) {
			continue;
		}
		if (!ht_pp_find (model->string_by_value, si->value, NULL)) {
			ht_pp_insert (model->string_by_value, si->value, si);
		}
		if (si->address && !ht_up_find (model->string_by_addr, si->address, NULL)) {
			ht_up_insert (model->string_by_addr, si->address, si);
		}
	}

	DartClassInfo *ci;
	r_list_foreach (model->classes, it, ci) {
		if (!ci || !R_STR_ISNOTEMPTY (ci->name)) {
			continue;
		}
		if (!ht_pp_find (model->class_by_name, ci->name, NULL)) {
			ht_pp_insert (model->class_by_name, ci->name, ci);
		}
		if (!ci->methods) {
			continue;
		}
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			if (!mi || !mi->entry_point) {
				continue;
			}
			ut64 addr = flutter_normalize_code_addr (mi->entry_point);
			if (!ht_up_find (model->method_by_addr, addr, NULL)) {
				ht_up_insert (model->method_by_addr, addr, mi);
			}
		}
	}
	return true;
}

static void flutter_apply_model_to_core(FlutterAnalModel *model, RCore *core, FlutterAnalStats *stats) {
	if (!model || !core) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (model->classes, it, ci) {
		if (!ci || !R_STR_ISNOTEMPTY (ci->name)) {
			continue;
		}
		const DartStringInfo *csi = flutter_model_find_string_by_value (model, ci->name);
		if (csi && csi->address) {
			flutter_set_flag (core, "dart.class", ci->name, csi->address, 0, false);
			char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "class %s", ci->name);
			if (msg) {
				flutter_append_comment (core, csi->address, msg, stats);
				free (msg);
			}
		}
		if (R_STR_ISNOTEMPTY (ci->super_class_name)) {
			const DartStringInfo *ssi = flutter_model_find_string_by_value (model, ci->super_class_name);
			if (ssi && ssi->address) {
				flutter_set_flag (core, "dart.type", ci->super_class_name, ssi->address, 0, false);
			}
		}
		if (ci->fields) {
			RListIter *fit;
			DartFieldInfo *fi;
			r_list_foreach (ci->fields, fit, fi) {
				if (!fi || !R_STR_ISNOTEMPTY (fi->name)) {
					continue;
				}
				const DartStringInfo *fsi = flutter_model_find_string_by_value (model, fi->name);
				if (fsi && fsi->address) {
					char *field_name = r_str_newf ("%s.%s", ci->name, fi->name);
					if (field_name) {
						flutter_set_flag (core, "dart.field", field_name, fsi->address, 0, true);
						char *msg = fi->type_name? r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "field %s offset=0x%x type=%s", field_name, fi->offset, fi->type_name): r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "field %s offset=0x%x", field_name, fi->offset);
						if (msg) {
							flutter_append_comment (core, fsi->address, msg, stats);
							free (msg);
						}
						free (field_name);
					}
				}
				if (R_STR_ISNOTEMPTY (fi->type_name)) {
					const DartStringInfo *tsi = flutter_model_find_string_by_value (model, fi->type_name);
					if (tsi && tsi->address) {
						flutter_set_flag (core, "dart.type", fi->type_name, tsi->address, 0, false);
					}
				}
			}
		}
		if (ci->methods) {
			RListIter *mit;
			DartMethodInfo *mi;
			r_list_foreach (ci->methods, mit, mi) {
				if (!mi || !mi->entry_point || !R_STR_ISNOTEMPTY (mi->name)) {
					continue;
				}
				ut64 addr = flutter_normalize_code_addr (mi->entry_point);
				char *flag_name = r_str_newf ("%s.%s", ci->name, mi->name);
				if (!flag_name) {
					continue;
				}
				flutter_set_flag (core, "dart.method", flag_name, addr, 0, true);
				char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "%s.%s", ci->name, mi->name);
				if (msg) {
					flutter_append_comment (core, addr, msg, stats);
					free (msg);
				}
				free (flag_name);
			}
		}
	}
}

static void flutter_collect_entries_from_app(HtUP *seen, RList *entries, const DartApp *app) {
	if (!seen || !entries || !app || !app->functions) {
		return;
	}
	RListIter *it;
	DartFunction *fn;
	r_list_foreach (app->functions, it, fn) {
		if (!fn || !fn->addr) {
			continue;
		}
		ut64 addr = flutter_normalize_code_addr (fn->addr);
		if (ht_up_find (seen, addr, NULL)) {
			continue;
		}
		ut64 *p = R_NEW0 (ut64);
		*p = addr;
		r_list_append (entries, p);
		ht_up_insert (seen, addr, p);
	}
}

static bool flutter_collect_flag_entry_cb(RFlagItem *fi, void *user) {
	FlutterEntryCollector *collector = user;
	if (!collector || !fi || !flutter_flag_is_method (fi->name) || !fi->addr) {
		return true;
	}
	ut64 addr = flutter_normalize_code_addr (fi->addr);
	if (ht_up_find (collector->seen, addr, NULL)) {
		return true;
	}
	ut64 *p = R_NEW0 (ut64);
	*p = addr;
	r_list_append (collector->entries, p);
	ht_up_insert (collector->seen, addr, p);
	return true;
}

static void flutter_collect_entries_from_flags(HtUP *seen, RList *entries, RCore *core) {
	if (!seen || !entries || !core || !core->flags) {
		return;
	}
	FlutterEntryCollector collector = {
		.seen = seen,
		.entries = entries,
};
	r_flag_foreach_prefix (core->flags, "method.", -1, flutter_collect_flag_entry_cb, &collector);
	r_flag_foreach_prefix (core->flags, "dart.method.", -1, flutter_collect_flag_entry_cb, &collector);
}

static void flutter_apply_app_methods_to_core(RCore *core, const DartApp *app, FlutterAnalStats *stats) {
	if (!core || !app || !app->functions) {
		return;
	}
	RListIter *it;
	DartFunction *fn;
	r_list_foreach (app->functions, it, fn) {
		if (!fn || !fn->addr || !R_STR_ISNOTEMPTY (fn->name)) {
			continue;
		}
		ut64 addr = flutter_normalize_code_addr (fn->addr);
		flutter_set_flag (core, "dart.method", flutter_method_leaf_name (fn->name), addr, fn->size, true);
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "%s", fn->name);
		if (msg) {
			flutter_append_comment (core, addr, msg, stats);
			free (msg);
		}
	}
}

static void flutter_collect_entries_from_model(HtUP *seen, RList *entries, FlutterAnalModel *model) {
	if (!seen || !entries || !model || !model->classes) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (model->classes, it, ci) {
		if (!ci || !ci->methods) {
			continue;
		}
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			if (!mi || !mi->entry_point) {
				continue;
			}
			ut64 addr = flutter_normalize_code_addr (mi->entry_point);
			if (ht_up_find (seen, addr, NULL)) {
				continue;
			}
			ut64 *p = R_NEW0 (ut64);
			*p = addr;
			r_list_append (entries, p);
			ht_up_insert (seen, addr, p);
		}
	}
}

static RList *flutter_collect_entries(RCore *core, const DartApp *app, FlutterAnalModel *model) {
	RList *entries = r_list_newf (free);
	HtUP *seen = ht_up_new0 ();
	flutter_collect_entries_from_flags (seen, entries, core);
	flutter_collect_entries_from_app (seen, entries, app);
	flutter_collect_entries_from_model (seen, entries, model);
	ht_up_free (seen);
	return entries;
}

static void flutter_ensure_functions(RCore *core, RList *entries) {
	if (!core || !core->anal || !entries) {
		return;
	}
	RListIter *it;
	ut64 *addrp;
	r_list_foreach (entries, it, addrp) {
		if (!addrp || !*addrp) {
			continue;
		}
		if (!r_anal_get_fcn_in (core->anal, *addrp, 0)) {
			r_core_cmdf (core, "af @ 0x%" PFMT64x, *addrp);
		}
	}
}

static void flutter_ensure_generic_string_flag(RCore *core, const DartStringInfo *si) {
	if (!core || !si || !si->address || R_STR_ISEMPTY (si->value)) {
		return;
	}
	flutter_set_flag (core, "dart.str", si->value, si->address, si->length, true);
}

static void flutter_annotate_string_ref(RCore *core, FlutterAnalModel *model, ut64 at, const DartStringInfo *si, FlutterAnalStats *stats) {
	if (!core || !si || !si->address) {
		return;
	}
	flutter_ensure_generic_string_flag (core, si);
	flutter_add_ref (core, at, si->address, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
	stats->string_refs++;
	char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "string \"%s\"", si->value);
	if (msg) {
		flutter_append_comment (core, at, msg, stats);
		free (msg);
	}
	if (flutter_model_find_class (model, si->value)) {
		stats->class_refs++;
		char *cmt = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "class ref %s", si->value);
		if (cmt) {
			flutter_append_comment (core, at, cmt, stats);
			free (cmt);
		}
	}
}

static void flutter_annotate_field_ref(RCore *core, FlutterAnalModel *model, ut64 at, const DartClassInfo *ci, const DartFieldInfo *fi, bool is_write, FlutterAnalStats *stats) {
	if (!core || !ci || !fi) {
		return;
	}
	if (R_STR_ISNOTEMPTY (ci->name)) {
		const DartStringInfo *csi = flutter_model_find_string_by_value (model, ci->name);
		if (csi && csi->address) {
			flutter_add_ref (core, at, csi->address, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
			stats->class_refs++;
		}
	}
	if (R_STR_ISNOTEMPTY (fi->name)) {
		const DartStringInfo *fsi = flutter_model_find_string_by_value (model, fi->name);
		if (fsi && fsi->address) {
			flutter_add_ref (core, at, fsi->address, R_ANAL_REF_TYPE_STRN | (is_write? R_ANAL_REF_TYPE_WRITE: R_ANAL_REF_TYPE_READ));
			stats->field_refs++;
		}
	}
	if (R_STR_ISNOTEMPTY (fi->type_name)) {
		const DartStringInfo *tsi = flutter_model_find_string_by_value (model, fi->type_name);
		if (tsi && tsi->address) {
			flutter_add_ref (core, at, tsi->address, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
			stats->type_refs++;
		}
	}
	char *field_name = r_str_newf ("%s.%s", r_str_get (ci->name), r_str_get (fi->name));
	if (!field_name) {
		return;
	}
	char *msg = fi->type_name? r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "%s %s @ +0x%x : %s", is_write? "write": "read", field_name, fi->offset, fi->type_name): r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "%s %s @ +0x%x", is_write? "write": "read", field_name, fi->offset);
	if (msg) {
		flutter_append_comment (core, at, msg, stats);
		free (msg);
	}
	free (field_name);
}

static void flutter_process_direct_ref(RCore *core, FlutterAnalModel *model, ut64 at, ut64 target, FlutterAnalStats *stats) {
	if (!core || !model || !at || !target) {
		return;
	}
	const DartStringInfo *si = flutter_model_find_string_by_addr (model, target);
	if (si) {
		flutter_annotate_string_ref (core, model, at, si, stats);
		return;
	}
	RFlagItem *fi = flutter_get_flag_at (core, target);
	if (!fi || R_STR_ISEMPTY (fi->name)) {
		return;
	}
	if (r_str_startswith (fi->name, "dart.class.")) {
		flutter_add_ref (core, at, target, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
		stats->class_refs++;
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "class ref %s", fi->name + strlen ("dart.class."));
		if (msg) {
			flutter_append_comment (core, at, msg, stats);
			free (msg);
		}
		return;
	}
	if (r_str_startswith (fi->name, "dart.type.")) {
		flutter_add_ref (core, at, target, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
		stats->type_refs++;
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "type ref %s", fi->name + strlen ("dart.type."));
		if (msg) {
			flutter_append_comment (core, at, msg, stats);
			free (msg);
		}
		return;
	}
	if (r_str_startswith (fi->name, "dart.field.")) {
		flutter_add_ref (core, at, target, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
		stats->field_refs++;
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "field ref %s", fi->name + strlen ("dart.field."));
		if (msg) {
			flutter_append_comment (core, at, msg, stats);
			free (msg);
		}
		return;
	}
	if (r_str_startswith (fi->name, "dart.str.") || r_str_startswith (fi->name, "str.")) {
		flutter_add_ref (core, at, target, R_ANAL_REF_TYPE_STRN | R_ANAL_REF_TYPE_READ);
		stats->string_refs++;
		const char *leaf = r_str_startswith (fi->name, "dart.str.")? fi->name + strlen ("dart.str."): fi->name + strlen ("str.");
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "string %s", leaf);
		if (msg) {
			flutter_append_comment (core, at, msg, stats);
			free (msg);
		}
	}
}

static void flutter_process_call(RCore *core, FlutterAnalModel *model, ut64 at, ut64 target, FlutterAnalStats *stats) {
	if (!core || !at || !target) {
		return;
	}
	flutter_add_ref (core, at, target, R_ANAL_REF_TYPE_CALL);
	stats->call_xrefs++;
	const DartMethodInfo *mi = flutter_model_find_method (model, target);
	if (mi && R_STR_ISNOTEMPTY (mi->owner_name) && R_STR_ISNOTEMPTY (mi->name)) {
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "call %s.%s", mi->owner_name, mi->name);
		if (msg) {
			flutter_append_comment (core, at, msg, stats);
			free (msg);
		}
		return;
	}
	RFlagItem *fi = flutter_get_flag_at (core, target);
	if (fi && flutter_flag_is_method (fi->name)) {
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "call %s", flutter_method_leaf_name (fi->name));
		if (msg) {
			flutter_append_comment (core, at, msg, stats);
			free (msg);
		}
	}
}

static bool flutter_process_mov(FlutterAnalState *state, const FlutterOpInfo *info) {
	if (!state || !info || info->n_regs < 2) {
		return false;
	}
	int dst = flutter_reg_index (info->regs[0]);
	int src = flutter_reg_index (info->regs[1]);
	if (dst < 0 || src < 0) {
		return false;
	}
	state->regs[dst] = state->regs[src];
	return true;
}

static bool flutter_process_add(FlutterAnalState *state, const FlutterOpInfo *info) {
	if (!state || !info || info->n_regs < 2 || !info->has_imm) {
		return false;
	}
	int dst = flutter_reg_index (info->regs[0]);
	int src = flutter_reg_index (info->regs[1]);
	if (dst < 0 || src < 0) {
		return false;
	}
	if (flutter_reg_is_pp (info->regs[1])) {
		memset (&state->regs[dst], 0, sizeof (state->regs[dst]));
		state->regs[dst].has_pp_off = true;
		state->regs[dst].pp_off = info->imm;
		return true;
	}
	if (state->regs[src].has_pp_off) {
		state->regs[dst] = state->regs[src];
		state->regs[dst].pp_off += info->imm;
		return true;
	}
	memset (&state->regs[dst], 0, sizeof (state->regs[dst]));
	return true;
}

static bool flutter_process_stack_load(FlutterAnalState *state, const FlutterOpInfo *info) {
	if (!state || !info || info->n_regs < 1 || !info->has_mem || !flutter_reg_is_stack (info->mem_base)) {
		return false;
	}
	int dst = flutter_reg_index (info->regs[0]);
	if (dst < 0) {
		return false;
	}
	FlutterStackSlot *slot = flutter_state_get_stack_slot (state, info->mem_disp);
	if (slot) {
		state->regs[dst] = slot->value;
		return true;
	}
	memset (&state->regs[dst], 0, sizeof (state->regs[dst]));
	return true;
}

static bool flutter_process_stack_store(FlutterAnalState *state, const FlutterOpInfo *info) {
	if (!state || !info || info->n_regs < 1 || !info->has_mem || !flutter_reg_is_stack (info->mem_base)) {
		return false;
	}
	int src = flutter_reg_index (info->regs[0]);
	if (src < 0) {
		return false;
	}
	flutter_state_set_stack_slot (state, info->mem_disp, &state->regs[src]);
	return true;
}

static bool flutter_process_pp_load(RCore *core, FlutterAnalState *state, ut64 at, const FlutterOpInfo *info, FlutterAnalStats *stats) {
	if (!state || !info || info->n_regs < 1 || !info->has_mem) {
		return false;
	}
	int dst = flutter_reg_index (info->regs[0]);
	if (dst < 0) {
		return false;
	}
	ut64 pp_off = 0;
	if (flutter_reg_is_pp (info->mem_base)) {
		pp_off = (ut64)info->mem_disp;
	} else {
		int base = flutter_reg_index (info->mem_base);
		if (base < 0 || !state->regs[base].has_pp_off) {
			return false;
		}
		pp_off = state->regs[base].pp_off + (ut64)info->mem_disp;
	}
	memset (&state->regs[dst], 0, sizeof (state->regs[dst]));
	state->regs[dst].has_pp_off = true;
	state->regs[dst].pp_off = pp_off;
	char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "PP slot +0x%" PFMT64x, pp_off);
	if (msg) {
		flutter_append_comment (core, at, msg, stats);
		free (msg);
	}
	stats->pp_refs++;
	return true;
}

static bool flutter_process_field_load(RCore *core, FlutterAnalModel *model, FlutterAnalState *state, ut64 at, const FlutterOpInfo *info, FlutterAnalStats *stats) {
	if (!core || !model || !state || !info || info->n_regs < 1 || !info->has_mem) {
		return false;
	}
	int dst = flutter_reg_index (info->regs[0]);
	int base = flutter_reg_index (info->mem_base);
	if (dst < 0 || base < 0 || info->mem_disp < 0) {
		return false;
	}
	const DartClassInfo *ci = state->regs[base].klass;
	if (!ci) {
		return false;
	}
	const DartFieldInfo *fi = flutter_class_find_field (ci, (ut32)info->mem_disp);
	if (!fi) {
		memset (&state->regs[dst], 0, sizeof (state->regs[dst]));
		return false;
	}
	flutter_annotate_field_ref (core, model, at, ci, fi, false, stats);
	memset (&state->regs[dst], 0, sizeof (state->regs[dst]));
	state->regs[dst].field = fi;
	state->regs[dst].type_name = fi->type_name;
	if (R_STR_ISNOTEMPTY (fi->type_name)) {
		const DartClassInfo *field_class = flutter_model_find_class (model, fi->type_name);
		if (field_class) {
			state->regs[dst].klass = field_class;
		}
	}
	return true;
}

static bool flutter_process_field_store(RCore *core, FlutterAnalModel *model, FlutterAnalState *state, ut64 at, const FlutterOpInfo *info, FlutterAnalStats *stats) {
	if (!core || !model || !state || !info || info->n_regs < 1 || !info->has_mem) {
		return false;
	}
	int base = flutter_reg_index (info->mem_base);
	if (base < 0 || info->mem_disp < 0) {
		return false;
	}
	const DartClassInfo *ci = state->regs[base].klass;
	if (!ci) {
		return false;
	}
	const DartFieldInfo *fi = flutter_class_find_field (ci, (ut32)info->mem_disp);
	if (!fi) {
		return false;
	}
	flutter_annotate_field_ref (core, model, at, ci, fi, true, stats);
	return true;
}

static void flutter_process_indirect_call(RCore *core, FlutterAnalState *state, ut64 at, const FlutterOpInfo *info, FlutterAnalStats *stats) {
	if (!core || !state || !info || info->n_regs < 1) {
		return;
	}
	int reg = flutter_reg_index (info->regs[0]);
	if (reg < 0) {
		return;
	}
	if (state->regs[reg].has_pp_off) {
		char *msg = r_str_newf (DART_ANALYSIS_COMMENT_PREFIX "indirect call via PP+0x%" PFMT64x, state->regs[reg].pp_off);
		if (msg) {
			flutter_append_comment (core, at, msg, stats);
			free (msg);
		}
		stats->pp_refs++;
	}
}

static void flutter_scan_function(RCore *core, FlutterAnalModel *model, RAnalFunction *fcn, FlutterAnalStats *stats) {
	if (!core || !model || !fcn || !stats) {
		return;
	}
	FlutterAnalState state;
	flutter_state_init (&state);
	stats->functions++;

	const DartMethodInfo *mi = flutter_model_find_method (model, fcn->addr);
	if (mi && R_STR_ISNOTEMPTY (mi->owner_name)) {
		const DartClassInfo *owner = flutter_model_find_class (model, mi->owner_name);
		if (owner) {
			state.regs[0].klass = owner;
			state.regs[0].type_name = owner->name;
		}
	}

	HtUP *seen_ops = ht_up_new0 ();
	RListIter *it;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, it, bb) {
		if (!bb || bb->size == 0) {
			continue;
		}
		for (ut64 at = bb->addr; at < bb->addr + bb->size;) {
			if (ht_up_find (seen_ops, at, NULL)) {
				at += 4;
				continue;
			}
			RAnalOp *op = r_core_anal_op (core, at, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_OPEX | R_ARCH_OP_MASK_DISASM);
			if (!op || op->size <= 0) {
				r_anal_op_free (op);
				break;
			}
			ht_up_insert (seen_ops, at, (void *)true);

			FlutterOpInfo info;
			bool has_info = flutter_parse_opinfo (op, &info);
			if (op->ptr) {
				flutter_process_direct_ref (core, model, at, (ut64)op->ptr, stats);
			}
			if (op->val) {
				flutter_process_direct_ref (core, model, at, op->val, stats);
			}
			if (has_info && info.has_imm) {
				flutter_process_direct_ref (core, model, at, info.imm, stats);
			}

			switch (op->type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_MOV:
				if (!flutter_process_mov (&state, &info) && has_info && info.n_regs > 0) {
					int dst = flutter_reg_index (info.regs[0]);
					if (dst >= 0) {
						memset (&state.regs[dst], 0, sizeof (state.regs[dst]));
					}
				}
				break;
			case R_ANAL_OP_TYPE_ADD:
				(void)flutter_process_add (&state, &info);
				break;
			case R_ANAL_OP_TYPE_LOAD:
				if (!flutter_process_pp_load (core, &state, at, &info, stats) &&
					!flutter_process_stack_load (&state, &info) &&
					!flutter_process_field_load (core, model, &state, at, &info, stats) &&
					has_info && info.n_regs > 0) {
					int dst = flutter_reg_index (info.regs[0]);
					if (dst >= 0) {
						memset (&state.regs[dst], 0, sizeof (state.regs[dst]));
					}
				}
				break;
			case R_ANAL_OP_TYPE_STORE:
				(void)flutter_process_stack_store (&state, &info);
				(void)flutter_process_field_store (core, model, &state, at, &info, stats);
				break;
			case R_ANAL_OP_TYPE_CALL:
				if (op->jump) {
					flutter_process_call (core, model, at, op->jump, stats);
				}
				flutter_state_clobber_callers (&state);
				break;
			case R_ANAL_OP_TYPE_RCALL:
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_ICALL:
			case R_ANAL_OP_TYPE_IRCALL:
				if (has_info) {
					flutter_process_indirect_call (core, &state, at, &info, stats);
				}
				flutter_state_clobber_callers (&state);
				break;
			default:
				break;
			}
			at += op->size;
			r_anal_op_free (op);
		}
	}
	ht_up_free (seen_ops);
	flutter_state_fini (&state);
}

static void flutter_scan_functions(RCore *core, FlutterAnalModel *model, RList *entries, FlutterAnalStats *stats) {
	if (!core || !model || !entries || !stats) {
		return;
	}
	HtUP *seen_fcns = ht_up_new0 ();
	RListIter *it;
	ut64 *addrp;
	r_list_foreach (entries, it, addrp) {
		if (!addrp || !*addrp) {
			continue;
		}
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, *addrp, 0);
		if (!fcn || ht_up_find (seen_fcns, fcn->addr, NULL)) {
			continue;
		}
		ht_up_insert (seen_fcns, fcn->addr, fcn);
		flutter_scan_function (core, model, fcn, stats);
	}
	ht_up_free (seen_fcns);
}

bool r2flutter_analysis_run(RCore *core, DartCtx *dctx, bool quiet) {
	R_RETURN_VAL_IF_FAIL (core && dctx, false);
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
	dart_dumper_apply_to_core (app);

	FlutterAnalModel model;
	if (!flutter_model_load (&model, core, &app->dctx)) {
		dart_app_free (app);
		R_LOG_ERROR ("r2flutter: failed to load metadata for analysis");
		return false;
	}

	FlutterAnalStats stats = { 0 };
	flutter_apply_app_methods_to_core (core, app, &stats);
	flutter_apply_model_to_core (&model, core, &stats);

	RList *entries = flutter_collect_entries (core, app, &model);
	flutter_ensure_functions (core, entries);
	flutter_scan_functions (core, &model, entries, &stats);

	if (!quiet) {
		R_LOG_INFO ("Flutter analysis: %d functions, %d calls, %d fields, %d classes, %d types, %d strings, %d PP refs",
			(int)stats.functions,
			(int)stats.call_xrefs,
			(int)stats.field_refs,
			(int)stats.class_refs,
			(int)stats.type_refs,
			(int)stats.string_refs,
			(int)stats.pp_refs);
	}

	r_list_free (entries);
	flutter_model_fini (&model);
	dart_app_free (app);
	return true;
}
