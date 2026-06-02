/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

// ============================================================================
// Cross References
// ============================================================================

typedef struct {
	char *kind;
	char *origin;
	char *src_type;
	char *src_name;
	ut64 src_ref;
	ut64 src_addr;
	char *dst_type;
	char *dst_name;
	ut64 dst_ref;
	ut64 dst_addr;
} DartXrefInfo;

typedef struct {
	ut64 at;
	ut64 fn_index;
	ut64 pp_off;
	char *fn_name;
} DartPoolUseInfo;

static void dart_xref_info_free(void *p) {
	DartXrefInfo *xi = (DartXrefInfo *)p;
	if (xi) {
		free (xi->kind);
		free (xi->origin);
		free (xi->src_type);
		free (xi->src_name);
		free (xi->dst_type);
		free (xi->dst_name);
		free (xi);
	}
}

static void dart_pool_use_info_free(void *p) {
	DartPoolUseInfo *ui = (DartPoolUseInfo *)p;
	free (ui->fn_name);
	free (ui);
}

static char *xref_join_names(const char *owner, const char *name) {
	if (R_STR_ISNOTEMPTY (owner) && R_STR_ISNOTEMPTY (name)) {
		return r_str_newf ("%s.%s", owner, name);
	}
	if (R_STR_ISNOTEMPTY (name)) {
		return strdup (name);
	}
	if (R_STR_ISNOTEMPTY (owner)) {
		return strdup (owner);
	}
	return strdup ("?");
}

static char *xref_it_label(ut64 index) {
	return r_str_newf ("it[%" PRIu64 "]", (uint64_t)index);
}

static char *xref_ref_label(const char *prefix, ut64 ref) {
	return r_str_newf ("%s#%" PRIu64, prefix, (uint64_t)ref);
}

static const char *xref_class_origin(const DartClassInfo *ci) {
	if (!ci) {
		return "scan";
	}
	return (ci->ref_id > 0 || ci->name_ref > 0)? "metadata": "scan";
}

static const char *xref_field_origin(const DartFieldInfo *fi) {
	if (!fi) {
		return "data-image";
	}
	return (fi->ref_id > 0 || fi->name_ref > 0 || fi->owner_ref > 0 || fi->type_ref > 0)? "metadata": "data-image";
}

static const char *xref_method_origin(const DartMethodInfo *mi) {
	if (!mi) {
		return "data-image";
	}
	return (mi->ref_id > 0 || mi->name_ref > 0 || mi->owner_ref > 0 || mi->signature_ref > 0)? "metadata": "data-image";
}

static bool xref_limit_reached(ut64 count, ut64 limit) {
	return limit > 0 && count >= limit;
}

static void append_xref_info(RList *list, ut64 *count, ut64 limit, const char *origin, const char *kind, const char *src_type, const char *src_name, ut64 src_ref, ut64 src_addr, const char *dst_type, const char *dst_name, ut64 dst_ref, ut64 dst_addr) {
	if (xref_limit_reached (*count, limit)) {
		return;
	}
	DartXrefInfo *xi = R_NEW0 (DartXrefInfo);
	xi->kind = strdup (kind);
	xi->origin = strdup (origin);
	xi->src_type = strdup (src_type);
	xi->src_name = src_name? strdup (src_name): NULL;
	xi->src_ref = src_ref;
	xi->src_addr = src_addr;
	xi->dst_type = strdup (dst_type);
	xi->dst_name = dst_name? strdup (dst_name): NULL;
	xi->dst_ref = dst_ref;
	xi->dst_addr = dst_addr;
	r_list_append (list, xi);
	(*count)++;
}

static void collect_field_scan_xrefs(DartCtx *ctx, DartRecoveryModel *model, RList *xrefs, RList *seen_fields, ut64 *count, ut64 limit, ut64 data_start, ut64 data_end) {
	if (!ctx || !ctx->core || !xrefs || data_start >= data_end || xref_limit_reached (*count, limit)) {
		return;
	}
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	int field_count = 0;
	const int max_fields = 5000;
	for (ut64 pos = data_start; pos + 48 <= data_end && field_count < max_fields && !xref_limit_reached (*count, limit); pos += align) {
		DartScannedField field;
		if (!read_data_image_field (ctx, pos, data_start, data_end, 0, false, false, &field)) {
			continue;
		}
		char keybuf[320];
		snprintf (keybuf, sizeof (keybuf), "%s.%s@0x%x", field.owner_name, field.name, field.offset);
		if (r_list_find (seen_fields, keybuf, (RListComparator)strcmp)) {
			continue;
		}
		r_list_append (seen_fields, strdup (keybuf));
		char *field_label = xref_join_names (field.owner_name, field.name);
		append_xref_info (xrefs, count, limit, "data-image", "field.owner", "field", field_label, 0, 0, "class", field.owner_name, 0, 0);
		DartStringInfo *field_si = dart_recovery_model_string_by_value (model, field.name);
		append_xref_info (xrefs, count, limit, "data-image", "field.name", "field", field_label, 0, 0, "string", field.name, 0, field_si? field_si->address: 0);
		free (field_label);
		field_count++;
	}
}

static void collect_method_scan_xrefs(DartCtx *ctx, DartRecoveryModel *model, RList *xrefs, HtUP *seen_ep, ut64 *count, ut64 limit, ut64 data_start, ut64 data_end) {
	if (!ctx || !ctx->core || !ctx->layout || !xrefs || data_start >= data_end || xref_limit_reached (*count, limit)) {
		return;
	}
	DartFunctionLayout fl;
	init_function_layout (ctx, &fl);
	ut64 align = ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	if (!align) {
		align = 8;
	}
	ut64 methods_found = 0;
	const ut64 max_methods = 30000;
	for (ut64 pos = data_start; pos + fl.kind_tag_off + 8 < data_end && methods_found < max_methods && !xref_limit_reached (*count, limit); pos += align) {
		DartScannedMethod method;
		if (!read_data_image_method (ctx, pos, data_start, data_end, &fl, false, &method)) {
			continue;
		}
		if (ht_up_find (seen_ep, method.entry, NULL)) {
			continue;
		}
		char *method_label = xref_join_names (method.owner_name, method.name);
		append_xref_info (xrefs, count, limit, "data-image", "method.owner", "method", method_label, 0, 0, "class", method.owner_name, 0, 0);
		DartStringInfo *method_si = dart_recovery_model_string_by_value (model, method.name);
		append_xref_info (xrefs, count, limit, "data-image", "method.name", "method", method_label, 0, 0, "string", method.name, 0, method_si? method_si->address: 0);
		append_xref_info (xrefs, count, limit, "data-image", "method.entry", "method", method_label, 0, 0, "code", method_label, 0, method.entry);
		ht_up_insert (seen_ep, method.entry, (void *)1);
		free (method_label);
		methods_found++;
	}
}

static void collect_data_image_xrefs(DartCtx *ctx, DartRecoveryModel *model, RList *xrefs, ut64 *count, ut64 limit) {
	if (!ctx || !ctx->core || !xrefs || xref_limit_reached (*count, limit)) {
		return;
	}
	if (find_snapshots (ctx) != 0 || !ctx->iso_data) {
		return;
	}
	DartVerLayout layout_tmp;
	DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, total_len = 0, cluster_start = 0;
	ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	RList *seen_fields = r_list_newf (free);
	HtUP *seen_ep = ht_up_new0 ();
	if (parse_snapshot_header (ctx, ctx->iso_data, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) == 0) {
		ut64 data_image_base = ctx->iso_data + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
		ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: (data_image_base + (4ULL << 20));
		collect_field_scan_xrefs (ctx, model, xrefs, seen_fields, count, limit, data_image_base, data_image_end);
		collect_method_scan_xrefs (ctx, model, xrefs, seen_ep, count, limit, data_image_base, data_image_end);
	}
	if (ctx->vm_data && !xref_limit_reached (*count, limit) &&
		parse_snapshot_header (ctx, ctx->vm_data, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) == 0) {
		ut64 vm_data_base = ctx->vm_data + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
		ut64 vm_data_end = ctx->vm_instr? ctx->vm_instr: (vm_data_base + (4ULL << 20));
		collect_field_scan_xrefs (ctx, model, xrefs, seen_fields, count, limit, vm_data_base, vm_data_end);
		collect_method_scan_xrefs (ctx, model, xrefs, seen_ep, count, limit, vm_data_base, vm_data_end);
	}
	ht_up_free (seen_ep);
	r_list_free (seen_fields);
	dart_ctx_fini_layout (ctx, layout_owned);
}

static bool xref_parse_pp_offset(const char *opstr, ut64 *out) {
	if (R_STR_ISEMPTY (opstr) || !out) {
		return false;
	}
	const char *b = strstr (opstr, "[x27");
	if (!b) {
		return false;
	}
	const char *comma = strchr (b, ',');
	if (!comma) {
		*out = 0;
		return true;
	}
	const char *p = comma + 1;
	while (*p == ' ' || *p == '\t' || *p == '#') {
		p++;
	}
	if (r_str_startswith (p, "0x") || r_str_startswith (p, "0X")) {
		p += 2;
		const char *q = p;
		while (isxdigit ((ut8)*q)) {
			q++;
		}
		if (q == p) {
			return false;
		}
		char numbuf[32];
		size_t len = q - p;
		if (len > sizeof (numbuf) - 3) {
			len = sizeof (numbuf) - 3;
		}
		numbuf[0] = '0';
		numbuf[1] = 'x';
		memcpy (numbuf + 2, p, len);
		numbuf[len + 2] = '\0';
		*out = r_num_get (NULL, numbuf);
		return true;
	}
	const char *q = p;
	while (isdigit ((ut8)*q)) {
		q++;
	}
	if (q == p) {
		return false;
	}
	char numbuf[32];
	size_t len = q - p;
	if (len >= sizeof (numbuf)) {
		len = sizeof (numbuf) - 1;
	}
	memcpy (numbuf, p, len);
	numbuf[len] = '\0';
	*out = r_num_get (NULL, numbuf);
	return true;
}

static ut64 xref_object_pool_base(DartCtx *ctx) {
	if (!ctx || !ctx->core || !ctx->core->config) {
		return 0;
	}
	st64 gp = r_config_get_i (ctx->core->config, "anal.gp");
	return gp > 0? (ut64)gp: 0;
}

static ut64 xref_flag_addr(RCore *core, const char *name) {
	if (!core || !core->flags || R_STR_ISEMPTY (name)) {
		return 0;
	}
	RFlagItem *fi = r_flag_get (core->flags, name);
	return fi? fi->addr: 0;
}

static RFlagItem *xref_flag_at(RCore *core, ut64 addr) {
	if (!core || !core->flags || !addr) {
		return NULL;
	}
	RFlagItem *fi = r_flag_get_in (core->flags, addr);
	if (!fi && ! (addr & 1ULL)) {
		fi = r_flag_get_in (core->flags, addr + 1);
	}
	return fi;
}

static const char *xref_pool_flag_kind(const char *name, const char **dst_type, const char **dst_name) {
	if (R_STR_ISEMPTY (name) || !dst_type || !dst_name) {
		return NULL;
	}
	const struct {
		const char *prefix;
		const char *kind;
		const char *type;
	} map[] = {
		{ "dart.str.", "code.string", "string" },
		{ "str.", "code.string", "string" },
		{ "dart.class.", "code.class", "class" },
		{ "dart.type.", "code.type", "type" },
		{ "dart.field.", "code.field", "field" },
		{ "dart.method.", "code.method", "method" },
		{ "method.", "code.method", "method" },
};
	for (size_t i = 0; i < sizeof (map) / sizeof (map[0]); i++) {
		if (!r_str_startswith (name, map[i].prefix)) {
			continue;
		}
		*dst_type = map[i].type;
		*dst_name = name + strlen (map[i].prefix);
		return map[i].kind;
	}
	return NULL;
}

static bool xref_pool_use_seen(HtUP *seen, ut64 at, ut64 pp_off) {
	ut64 key = at ^ (pp_off << 8) ^ (pp_off >> 8);
	if (ht_up_find (seen, key, NULL)) {
		return true;
	}
	ht_up_insert (seen, key, (void *)1);
	return false;
}

static void collect_pool_uses_from_entry(DartCtx *ctx, const DartInstructionTableEntry *entry, RList *uses, HtUP *seen) {
	if (!ctx || !ctx->core || !entry || !entry->address || !uses || !seen) {
		return;
	}
	r_strf_var (cmd, 128, "pdj 96 @ 0x%" PFMT64x, entry->address);
	char *s = r_core_cmd_str (ctx->core, cmd);
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
	for (size_t i = 0;; i++) {
		const RJson *item = r_json_item (arr, i);
		if (!item) {
			break;
		}
		const char *opstr = r_json_get_str (item, "opstr");
		if (R_STR_ISEMPTY (opstr)) {
			opstr = r_json_get_str (item, "opcode");
		}
		ut64 pp_off = 0;
		if (!xref_parse_pp_offset (opstr, &pp_off)) {
			continue;
		}
		ut64 at = (ut64)r_json_get_num (item, "offset");
		if (!at) {
			at = entry->address;
		}
		if (xref_pool_use_seen (seen, at, pp_off)) {
			continue;
		}
		DartPoolUseInfo *ui = R_NEW0 (DartPoolUseInfo);
		ui->at = at;
		ui->fn_index = entry->index;
		ui->pp_off = pp_off;
		ui->fn_name = R_STR_ISNOTEMPTY (entry->name)? strdup (entry->name): xref_it_label (entry->index);
		r_list_append (uses, ui);
	}
	r_json_free (j);
	free (s);
}

static RList *collect_pool_uses(DartCtx *ctx, RVecDartInstructionTableEntry *entries, ut64 limit) {
	RList *uses = r_list_newf (dart_pool_use_info_free);
	if (!ctx || !entries || RVecDartInstructionTableEntry_length (entries) == 0) {
		return uses;
	}
	HtUP *seen = ht_up_new0 ();
	ut64 scanned = 0;
	ut64 scan_limit = limit > 0? limit: 4096;
	DartInstructionTableEntry *entry;
	R_VEC_FOREACH (entries, entry) {
		if (!entry->has_code || !entry->address) {
			continue;
		}
		if (scan_limit > 0 && scanned >= scan_limit) {
			break;
		}
		collect_pool_uses_from_entry (ctx, entry, uses, seen);
		scanned++;
	}
	ht_up_free (seen);
	return uses;
}

static bool append_string_pool_xref(DartCtx *ctx, DartRecoveryModel *model, RList *xrefs, ut64 *count, ut64 limit, const DartPoolUseInfo *use, ut64 target) {
	char buf[256];
	if (!try_read_dart_string (ctx, target, buf, sizeof (buf))) {
		return false;
	}
	DartStringInfo *si = dart_recovery_model_string_by_value (model, buf);
	append_xref_info (xrefs, count, limit, "code", "code.string", "code", use->fn_name, use->fn_index, use->at, "string", si? si->value: buf, si? si->ref_id: 0, si && si->address? si->address: target);
	if (dart_recovery_model_class_by_name (model, buf) && !xref_limit_reached (*count, limit)) {
		append_xref_info (xrefs, count, limit, "code", "code.class", "code", use->fn_name, use->fn_index, use->at, "class", buf, 0, si && si->address? si->address: target);
	}
	return true;
}

static bool append_flag_pool_xref(DartCtx *ctx, RList *xrefs, ut64 *count, ut64 limit, const DartPoolUseInfo *use, ut64 target) {
	RFlagItem *fi = xref_flag_at (ctx->core, target);
	if (!fi) {
		return false;
	}
	const char *dst_type = NULL;
	const char *dst_name = NULL;
	const char *kind = xref_pool_flag_kind (fi->name, &dst_type, &dst_name);
	if (!kind) {
		return false;
	}
	append_xref_info (xrefs, count, limit, "code", kind, "code", use->fn_name, use->fn_index, use->at, dst_type, dst_name, 0, fi->addr);
	return true;
}

static bool resolve_pool_entry_xref(DartCtx *ctx, DartRecoveryModel *model, RList *xrefs, ut64 *count, ut64 limit, const DartPoolUseInfo *use, ut64 raw, ut64 heap_base) {
	ut64 candidates[9];
	int n = 0;
	candidates[n++] = raw;
	candidates[n++] = raw & ~1ULL;
	candidates[n++] = raw & ~3ULL;
	if (heap_base && raw < 0xffffffffULL) {
		candidates[n++] = heap_base + raw;
		candidates[n++] = heap_base + (raw & ~1ULL);
		candidates[n++] = heap_base + (raw & ~3ULL);
	}
	for (int i = 0; i < n && !xref_limit_reached (*count, limit); i++) {
		ut64 target = candidates[i];
		if (!target) {
			continue;
		}
		if (append_string_pool_xref (ctx, model, xrefs, count, limit, use, target)) {
			return true;
		}
		if (append_flag_pool_xref (ctx, xrefs, count, limit, use, target)) {
			return true;
		}
	}
	return false;
}

static void collect_object_pool_xrefs(DartCtx *ctx, DartRecoveryModel *model, RList *xrefs, ut64 *count, ut64 limit) {
	if (!ctx || !ctx->core || !model || !model->it_entries || !xrefs || xref_limit_reached (*count, limit)) {
		return;
	}
	ut64 pool_base = xref_object_pool_base (ctx);
	if (!pool_base) {
		return;
	}
	RList *uses = collect_pool_uses (ctx, model->it_entries, limit);
	ut64 heap_base = xref_flag_addr (ctx->core, "app.heap_base");
	RListIter *it;
	DartPoolUseInfo *use;
	r_list_foreach (uses, it, use) {
		if (!use || xref_limit_reached (*count, limit)) {
			continue;
		}
		ut64 entry_addr = pool_base + use->pp_off;
		ut64 raw = 0;
		if (!read_u64_at (ctx, entry_addr, &raw)) {
			continue;
		}
		(void)resolve_pool_entry_xref (ctx, model, xrefs, count, limit, use, raw, heap_base);
	}
	r_list_free (uses);
}

static RList *dart_pool_extract_xrefs(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	RList *xrefs = r_list_newf (dart_xref_info_free);
	const ut64 limit = ctx->dump_fns_limit > 0? (ut64)ctx->dump_fns_limit: 0;
	ut64 count = 0;
	DartRecoveryModel model = { 0 };
	dart_recovery_model_load (ctx, &model, DART_RECOVERY_STRINGS | DART_RECOVERY_CLASSES | DART_RECOVERY_CLASS_FIELDS | DART_RECOVERY_IT);
	RList *classes = model.classes;
	RVecDartInstructionTableEntry *it_entries = model.it_entries;
	if (classes) {
		RListIter *it;
		DartClassInfo *ci;
		r_list_foreach (classes, it, ci) {
			if (!ci || !R_STR_ISNOTEMPTY (ci->name) || xref_limit_reached (count, limit)) {
				continue;
			}
			const char *class_origin = xref_class_origin (ci);
			DartStringInfo *name_si = dart_recovery_model_string_by_value (&model, ci->name);
			append_xref_info (xrefs, &count, limit, class_origin, "class.name", "class", ci->name, ci->ref_id, 0, "string", ci->name, ci->name_ref, name_si? name_si->address: 0);
			if (ci->library_ref > 0 || R_STR_ISNOTEMPTY (ci->library_name)) {
				char *library_name = ci->library_name? strdup (ci->library_name): xref_ref_label ("library", ci->library_ref);
				append_xref_info (xrefs, &count, limit, "metadata", "class.library", "class", ci->name, ci->ref_id, 0, "library", library_name, ci->library_ref, 0);
				free (library_name);
			}
			if (ci->super_class_ref > 0 || R_STR_ISNOTEMPTY (ci->super_class_name)) {
				char *super_name = ci->super_class_name? strdup (ci->super_class_name): xref_ref_label ("class", ci->super_class_ref);
				append_xref_info (xrefs, &count, limit, "metadata", "class.super", "class", ci->name, ci->ref_id, 0, "class", super_name, ci->super_class_ref, 0);
				free (super_name);
			}
			if (ci->interfaces) {
				RListIter *iit;
				DartInterfaceInfo *ii;
				r_list_foreach (ci->interfaces, iit, ii) {
					if (!ii || (ii->type_ref == 0 && R_STR_ISEMPTY (ii->name)) || xref_limit_reached (count, limit)) {
						continue;
					}
					char *interface_name = ii->name? strdup (ii->name): xref_ref_label ("type", ii->type_ref);
					append_xref_info (xrefs, &count, limit, "metadata", "class.interface", "class", ci->name, ci->ref_id, 0, "type", interface_name, ii->type_ref, 0);
					free (interface_name);
				}
			}
			if (ci->fields) {
				RListIter *fit;
				DartFieldInfo *fi;
				r_list_foreach (ci->fields, fit, fi) {
					if (!fi || xref_limit_reached (count, limit)) {
						continue;
					}
					if (fi->ref_id == 0 && fi->name_ref == 0 && fi->owner_ref == 0 && fi->type_ref == 0) {
						continue;
					}
					char *field_label = xref_join_names (ci->name, fi->name);
					const char *field_origin = xref_field_origin (fi);
					append_xref_info (xrefs, &count, limit, field_origin, "field.owner", "field", field_label, fi->ref_id, 0, "class", ci->name, fi->owner_ref, 0);
					if (R_STR_ISNOTEMPTY (fi->name)) {
						DartStringInfo *field_si = dart_recovery_model_string_by_value (&model, fi->name);
						append_xref_info (xrefs, &count, limit, field_origin, "field.name", "field", field_label, fi->ref_id, 0, "string", fi->name, fi->name_ref, field_si? field_si->address: 0);
					}
					if (fi->type_ref > 0 || R_STR_ISNOTEMPTY (fi->type_name)) {
						char *type_name = fi->type_name? strdup (fi->type_name): xref_ref_label ("type", fi->type_ref);
						append_xref_info (xrefs, &count, limit, field_origin, "field.type", "field", field_label, fi->ref_id, 0, "type", type_name, fi->type_ref, 0);
						free (type_name);
					}
					free (field_label);
				}
			}
			if (ci->methods) {
				RListIter *mit;
				DartMethodInfo *mi;
				r_list_foreach (ci->methods, mit, mi) {
					if (!mi || xref_limit_reached (count, limit)) {
						continue;
					}
					if (mi->ref_id == 0 && mi->name_ref == 0 && mi->owner_ref == 0 && mi->signature_ref == 0 && mi->entry_point == 0) {
						continue;
					}
					char *method_label = xref_join_names (ci->name, mi->name);
					const char *method_origin = xref_method_origin (mi);
					append_xref_info (xrefs, &count, limit, method_origin, "method.owner", "method", method_label, mi->ref_id, mi->entry_point, "class", ci->name, mi->owner_ref, 0);
					if (R_STR_ISNOTEMPTY (mi->name)) {
						DartStringInfo *method_si = dart_recovery_model_string_by_value (&model, mi->name);
						append_xref_info (xrefs, &count, limit, method_origin, "method.name", "method", method_label, mi->ref_id, mi->entry_point, "string", mi->name, mi->name_ref, method_si? method_si->address: 0);
					}
					if (mi->signature_ref > 0 || R_STR_ISNOTEMPTY (mi->signature)) {
						char *signature = mi->signature? strdup (mi->signature): xref_ref_label ("type", mi->signature_ref);
						append_xref_info (xrefs, &count, limit, method_origin, "method.signature", "method", method_label, mi->ref_id, mi->entry_point, "type", signature, mi->signature_ref, 0);
						free (signature);
					}
					if (mi->entry_point > 0) {
						append_xref_info (xrefs, &count, limit, method_origin, "method.entry", "method", method_label, mi->ref_id, mi->entry_point, "code", method_label, mi->code_ref, mi->entry_point);
					}
					free (method_label);
				}
			}
		}
	}
	collect_object_pool_xrefs (ctx, &model, xrefs, &count, limit);
	collect_data_image_xrefs (ctx, &model, xrefs, &count, limit);
	if (it_entries && !xref_limit_reached (count, limit)) {
		DartInstructionTableEntry *entry;
		R_VEC_FOREACH (it_entries, entry) {
			if (xref_limit_reached (count, limit)) {
				continue;
			}
			char *it_label = xref_it_label (entry->index);
			append_xref_info (xrefs, &count, limit, "metadata", entry->has_code? "it.code": "it.stub", "it", it_label, 0, 0, entry->has_code? "code": "stub", entry->name, 0, entry->address);
			free (it_label);
		}
	}
	dart_recovery_model_fini (&model);
	return xrefs;
}

static void dump_xref_node_json(PJ *pj, const char *type, const char *name, ut64 ref, ut64 addr) {
	pj_o (pj);
	pj_ks (pj, "type", type);
	if (name) {
		pj_ks (pj, "name", name);
	}
	if (ref > 0) {
		pj_kn (pj, "ref", ref);
	}
	if (addr > 0) {
		pj_kn (pj, "addr", addr);
	}
	pj_end (pj);
}

static void dump_xref_json(PJ *pj, const DartXrefInfo *xi) {
	pj_o (pj);
	pj_ks (pj, "kind", xi->kind);
	pj_ks (pj, "origin", xi->origin);
	pj_k (pj, "src");
	dump_xref_node_json (pj, xi->src_type, xi->src_name, xi->src_ref, xi->src_addr);
	pj_k (pj, "dst");
	dump_xref_node_json (pj, xi->dst_type, xi->dst_name, xi->dst_ref, xi->dst_addr);
	pj_end (pj);
}

static void dump_xref_node_text(RStrBuf *sb, const char *type, const char *name, ut64 ref, ut64 addr) {
	r_strbuf_append (sb, type);
	if (R_STR_ISNOTEMPTY (name)) {
		char *escaped = r_str_escape_utf8 (name, false, true);
		r_strbuf_appendf (sb, " %s", escaped);
		free (escaped);
	}
	if (ref > 0) {
		r_strbuf_appendf (sb, " [ref=%" PRIu64 "]", (uint64_t)ref);
	}
	if (addr > 0) {
		r_strbuf_appendf (sb, " @ 0x%" PFMT64x, (ut64)addr);
	}
}

static void dump_xref_node_compact(RStrBuf *sb, const char *type, const char *name, ut64 addr) {
	if (addr > 0) {
		r_strbuf_appendf (sb, "0x%" PFMT64x, (ut64)addr);
		return;
	}
	if (R_STR_ISNOTEMPTY (name)) {
		char *escaped = r_str_escape_utf8 (name, false, true);
		r_strbuf_append (sb, escaped);
		free (escaped);
		return;
	}
	r_strbuf_append (sb, type);
}

static void dump_xref_text(RStrBuf *sb, const DartXrefInfo *xi, int fmt, bool quiet) {
	if (fmt == 'r' && !quiet) {
		r_strbuf_append (sb, "# ");
	}
	if (fmt != 'r' || !quiet) {
		r_strbuf_appendf (sb, "%s %s ", xi->origin, xi->kind);
		if (quiet) {
			dump_xref_node_compact (sb, xi->src_type, xi->src_name, xi->src_addr);
			r_strbuf_append (sb, " -> ");
			dump_xref_node_compact (sb, xi->dst_type, xi->dst_name, xi->dst_addr);
		} else {
			dump_xref_node_text (sb, xi->src_type, xi->src_name, xi->src_ref, xi->src_addr);
			r_strbuf_append (sb, " -> ");
			dump_xref_node_text (sb, xi->dst_type, xi->dst_name, xi->dst_ref, xi->dst_addr);
		}
		r_strbuf_append (sb, "\n");
	}
	if (fmt == 'r' && xi->dst_addr > 0) {
		char safe[512];
		const char *base_name = R_STR_ISNOTEMPTY (xi->src_name)? xi->src_name: (R_STR_ISNOTEMPTY (xi->dst_name)? xi->dst_name: xi->kind);
		snprintf (safe, sizeof (safe), "xref.%s.%s", xi->kind, base_name);
		r_name_filter (safe, 0);
		r_strbuf_appendf (sb, "f %s = 0x%" PFMT64x "\n", safe, (ut64)xi->dst_addr);
	}
}

char *dart_pool_dump_xrefs(DartCtx *ctx, int fmt) {
	RList *xrefs = dart_pool_extract_xrefs (ctx);
	if (fmt == 'j') {
		if (!xrefs || r_list_length (xrefs) == 0) {
			r_list_free (xrefs);
			return strdup ("[]");
		}
		PJ *pj = pj_new ();
		pj_a (pj);
		RListIter *it;
		DartXrefInfo *xi;
		r_list_foreach (xrefs, it, xi) {
			if (xi) {
				dump_xref_json (pj, xi);
			}
		}
		pj_end (pj);
		r_list_free (xrefs);
		return pj_drain (pj);
	}
	if (!xrefs || r_list_length (xrefs) == 0) {
		r_list_free (xrefs);
		return strdup ("# No xrefs found\n");
	}
	const bool quiet = ctx && ctx->quiet;
	RStrBuf *sb = r_strbuf_new (fmt == 'r' && !quiet? "# Dart xrefs\n": "");
	RListIter *it;
	DartXrefInfo *xi;
	r_list_foreach (xrefs, it, xi) {
		if (xi) {
			dump_xref_text (sb, xi, fmt, quiet);
		}
	}
	r_list_free (xrefs);
	char *out = r_strbuf_drain (sb);
	size_t len = strlen (out);
	if (len > 0 && out[len - 1] == '\n') {
		out[len - 1] = '\0';
	}
	return out;
}
