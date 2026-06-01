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

static char *xref_join_names(const char *owner, const char *name) {
	if (R_STR_ISNOTEMPTY (owner) && R_STR_ISNOTEMPTY (name)) {
		size_t olen = strlen (owner);
		size_t nlen = strlen (name);
		char *out = malloc (olen + nlen + 2);
		if (!out) {
			return NULL;
		}
		memcpy (out, owner, olen);
		out[olen] = '.';
		memcpy (out + olen + 1, name, nlen);
		out[olen + nlen + 1] = '\0';
		return out;
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
	char buf[64];
	snprintf (buf, sizeof (buf), "it[%" PRIu64 "]", (uint64_t)index);
	return strdup (buf);
}

static char *xref_ref_label(const char *prefix, ut64 ref) {
	char buf[64];
	snprintf (buf, sizeof (buf), "%s#%" PRIu64, prefix, (uint64_t)ref);
	return strdup (buf);
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

static DartStringInfo *xref_find_string(HtPP *strings_by_value, const char *value) {
	if (!strings_by_value || R_STR_ISEMPTY (value)) {
		return NULL;
	}
	return ht_pp_find (strings_by_value, value, NULL);
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

static void collect_field_scan_xrefs(DartCtx *ctx, HtPP *strings_by_value, RList *xrefs, RList *seen_fields, ut64 *count, ut64 limit, ut64 data_start, ut64 data_end) {
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
		DartStringInfo *field_si = xref_find_string (strings_by_value, field.name);
		append_xref_info (xrefs, count, limit, "data-image", "field.name", "field", field_label, 0, 0, "string", field.name, 0, field_si? field_si->address: 0);
		free (field_label);
		field_count++;
	}
}

static void collect_method_scan_xrefs(DartCtx *ctx, HtPP *strings_by_value, RList *xrefs, HtUP *seen_ep, ut64 *count, ut64 limit, ut64 data_start, ut64 data_end) {
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
		DartStringInfo *method_si = xref_find_string (strings_by_value, method.name);
		append_xref_info (xrefs, count, limit, "data-image", "method.name", "method", method_label, 0, 0, "string", method.name, 0, method_si? method_si->address: 0);
		append_xref_info (xrefs, count, limit, "data-image", "method.entry", "method", method_label, 0, 0, "code", method_label, 0, method.entry);
		ht_up_insert (seen_ep, method.entry, (void *)1);
		free (method_label);
		methods_found++;
	}
}

static void collect_data_image_xrefs(DartCtx *ctx, HtPP *strings_by_value, RList *xrefs, ut64 *count, ut64 limit) {
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
		collect_field_scan_xrefs (ctx, strings_by_value, xrefs, seen_fields, count, limit, data_image_base, data_image_end);
		collect_method_scan_xrefs (ctx, strings_by_value, xrefs, seen_ep, count, limit, data_image_base, data_image_end);
	}
	if (ctx->vm_data && !xref_limit_reached (*count, limit) &&
		parse_snapshot_header (ctx, ctx->vm_data, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) == 0) {
		ut64 vm_data_base = ctx->vm_data + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
		ut64 vm_data_end = ctx->vm_instr? ctx->vm_instr: (vm_data_base + (4ULL << 20));
		collect_field_scan_xrefs (ctx, strings_by_value, xrefs, seen_fields, count, limit, vm_data_base, vm_data_end);
		collect_method_scan_xrefs (ctx, strings_by_value, xrefs, seen_ep, count, limit, vm_data_base, vm_data_end);
	}
	ht_up_free (seen_ep);
	r_list_free (seen_fields);
	dart_ctx_fini_layout (ctx, layout_owned);
}

static RList *dart_pool_extract_xrefs(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	RList *xrefs = r_list_newf (dart_xref_info_free);
	const ut64 limit = ctx->dump_fns_limit > 0? (ut64)ctx->dump_fns_limit: 0;
	ut64 count = 0;
	const int old_dump_fields = ctx->dump_fields;
	ctx->dump_fields = 1;
	RList *classes = dart_pool_extract_classes (ctx);
	ctx->dump_fields = old_dump_fields;
	RList *strings = dart_pool_extract_strings (ctx);
	RList *it_entries = dart_pool_extract_instruction_table (ctx);
	HtPP *strings_by_value = ht_pp_new0 ();
	if (strings) {
		RListIter *it;
		DartStringInfo *si;
		r_list_foreach (strings, it, si) {
			if (!si || !R_STR_ISNOTEMPTY (si->value)) {
				continue;
			}
			if (!ht_pp_find (strings_by_value, si->value, NULL)) {
				ht_pp_insert (strings_by_value, si->value, si);
			}
		}
	}
	if (classes) {
		RListIter *it;
		DartClassInfo *ci;
		r_list_foreach (classes, it, ci) {
			if (!ci || !R_STR_ISNOTEMPTY (ci->name) || xref_limit_reached (count, limit)) {
				continue;
			}
			const char *class_origin = xref_class_origin (ci);
			DartStringInfo *name_si = xref_find_string (strings_by_value, ci->name);
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
						DartStringInfo *field_si = xref_find_string (strings_by_value, fi->name);
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
		}
	}
	collect_data_image_xrefs (ctx, strings_by_value, xrefs, &count, limit);
	if (it_entries && !xref_limit_reached (count, limit)) {
		RListIter *it;
		DartInstructionTableEntry *entry;
		r_list_foreach (it_entries, it, entry) {
			if (!entry || xref_limit_reached (count, limit)) {
				continue;
			}
			char *it_label = xref_it_label (entry->index);
			append_xref_info (xrefs, &count, limit, "metadata", entry->has_code? "it.code": "it.stub", "it", it_label, 0, 0, entry->has_code? "code": "stub", entry->name, 0, entry->address);
			free (it_label);
		}
	}
	ht_pp_free (strings_by_value);
	dart_class_list_free (classes);
	dart_string_list_free (strings);
	dart_instruction_table_list_free (it_entries);
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

static void dump_xref_text(RStrBuf *sb, const DartXrefInfo *xi, int fmt) {
	if (fmt == 'r') {
		r_strbuf_append (sb, "# ");
	}
	r_strbuf_appendf (sb, "%s %s ", xi->origin, xi->kind);
	dump_xref_node_text (sb, xi->src_type, xi->src_name, xi->src_ref, xi->src_addr);
	r_strbuf_append (sb, " -> ");
	dump_xref_node_text (sb, xi->dst_type, xi->dst_name, xi->dst_ref, xi->dst_addr);
	r_strbuf_append (sb, "\n");
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
	RStrBuf *sb = r_strbuf_new (fmt == 'r'? "# Dart xrefs\n": "");
	RListIter *it;
	DartXrefInfo *xi;
	r_list_foreach (xrefs, it, xi) {
		if (xi) {
			dump_xref_text (sb, xi, fmt);
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
