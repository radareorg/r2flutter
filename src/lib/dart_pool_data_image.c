/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

void init_function_layout(DartCtx *ctx, DartFunctionLayout *fl) {
	bool use_compressed = (ctx && ctx->compressed_word_size == 4);
	if (use_compressed) {
		fl->entry_off = 0x4;
		fl->unchecked_off = 0x8;
		fl->name_off = 0xc;
		fl->owner_off = 0x10;
		fl->kind_tag_off = 0x28;
		fl->class_name_off = 0x4;
	} else {
		fl->entry_off = 0x8;
		fl->unchecked_off = 0x10;
		fl->name_off = 0x18;
		fl->owner_off = 0x20;
		fl->kind_tag_off = 0x48;
		fl->class_name_off = 0x8;
	}
}

static ut32 extract_cid_from_header(DartCtx *ctx, ut64 header) {
	if (!ctx || !ctx->layout) {
		return 0;
	}
	switch (ctx->layout->tag_style) {
	case DART_TAG_STYLE_OBJECT_HEADER:
		return (ut32) ((header >> 12) & 0xFFFFF);
	case DART_TAG_STYLE_CID_SHIFT1:
		return (ut32) (header >> 1);
	case DART_TAG_STYLE_CID_INT32:
	default:
		return (ut32) ((header >> 12) & 0xFFFFF);
	}
}

static bool read_object_pointer(DartCtx *ctx, const ut8 *buf, ut32 off, bool use_compressed, ut64 data_base, ut64 data_end, bool restrict_range, ut64 *out_addr) {
	(void)ctx;
	if (use_compressed) {
		ut32 rel = r_read_le32 (buf + off);
		ut64 addr = data_base + ((ut64)rel & ~3ULL);
		if (addr < data_base || addr >= data_end) {
			if (restrict_range) {
				return false;
			}
		}
		*out_addr = addr;
		return true;
	}
	ut64 addr = r_read_le64 (buf + off);
	if (!addr) {
		return false;
	}
	if (restrict_range && (addr < data_base || addr >= data_end)) {
		return false;
	}
	*out_addr = addr;
	return true;
}

void dart_scanned_field_fini(DartScannedField *field) {
	free (field->name);
	free (field->owner_name);
}

void dart_scanned_method_fini(DartScannedMethod *method) {
	free (method->name);
	free (method->owner_name);
}

bool read_data_image_field(DartCtx *ctx, ut64 pos, ut64 data_start, ut64 data_end, int fallback_index, bool allow_fallback_name, bool apply_obf, DartScannedField *field) {
	if (!ctx || !field || pos >= data_end || data_end - pos < 48) {
		return false;
	}
	ut8 hdr[48];
	if (!read_mem (ctx, pos, hdr, sizeof (hdr))) {
		return false;
	}
	ut64 header = r_read_le64 (hdr);
	if ((int) ((header >> 12) & 0xFFFFF) != kFieldCid) {
		return false;
	}
	bool use_compressed = ctx->compressed_word_size == 4;
	ut64 name_ptr = use_compressed? r_read_le32 (hdr + 8): r_read_le64 (hdr + 8);
	ut64 owner_ptr = use_compressed? r_read_le32 (hdr + 12): r_read_le64 (hdr + 16);
	if (!name_ptr || !owner_ptr) {
		return false;
	}
	memset (field, 0, sizeof (*field));
	field->flags = use_compressed? r_read_le32 (hdr + 24): r_read_le32 (hdr + 40);
	field->offset = use_compressed? r_read_le32 (hdr + 28): r_read_le32 (hdr + 44);
	ut64 name_addr = use_compressed? data_start + (name_ptr & ~3ULL): name_ptr;
	if (name_addr < data_start || name_addr >= data_end) {
		return false;
	}
	field->name = try_read_dart_string_dup (ctx, name_addr);
	if (!field->name && allow_fallback_name) {
		field->name = r_str_newf ("field_%d", fallback_index);
	}
	ut64 owner_addr = use_compressed? data_start + (owner_ptr & ~3ULL): owner_ptr;
	if (owner_addr >= data_start && owner_addr < data_end) {
		ut8 owner_hdr[32];
		if (read_mem (ctx, owner_addr, owner_hdr, sizeof (owner_hdr))) {
			ut64 owner_name_ptr = use_compressed? r_read_le32 (owner_hdr + 8): r_read_le64 (owner_hdr + 8);
			ut64 owner_name_addr = use_compressed? data_start + (owner_name_ptr & ~3ULL): owner_name_ptr;
			if (owner_name_addr >= data_start && owner_name_addr < data_end) {
				field->owner_name = try_read_dart_string_dup (ctx, owner_name_addr);
			}
		}
	}
	if (apply_obf) {
		dart_obf_apply (ctx, &field->name);
		dart_obf_apply (ctx, &field->owner_name);
	}
	if (R_STR_ISNOTEMPTY (field->name) && R_STR_ISNOTEMPTY (field->owner_name)) {
		return true;
	}
	dart_scanned_field_fini (field);
	return false;
}

void scan_fields_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end) {
	if (!ctx || !ctx->core || !class_list || data_start >= data_end) {
		return;
	}
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	int field_count = 0;
	int max_fields = 5000;
	HtPP *class_by_name = ht_pp_new0 ();
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (ci && ci->name) {
			ht_pp_insert (class_by_name, ci->name, ci);
		}
	}
	for (ut64 pos = data_start; pos + 48 <= data_end && field_count < max_fields; pos += align) {
		DartScannedField field;
		if (!read_data_image_field (ctx, pos, data_start, data_end, field_count, true, true, &field)) {
			continue;
		}
		field_count++;
		DartClassInfo *owner_ci = (DartClassInfo *)ht_pp_find (class_by_name, field.owner_name, NULL);
		if (owner_ci && owner_ci->fields) {
			DartFieldInfo *fi = R_NEW0 (DartFieldInfo);
			fi->name = field.name;
			field.name = NULL;
			fi->offset = field.offset;
			fi->flags = field.flags;
			r_list_append (owner_ci->fields, fi);
			if (ctx->verbose > 1) {
				fprintf (stderr, "[r2flutter] Found field: %s.%s offset=0x%x\n", field.owner_name, fi->name, field.offset);
			}
		} else if (ctx->verbose > 1 && field_count < 64) {
			fprintf (stderr, "[r2flutter] field owner miss: %s.%s\n", field.owner_name, field.name);
		}
		dart_scanned_field_fini (&field);
	}
	ht_pp_free (class_by_name);
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Scanned %d fields from data image\n", field_count);
	}
}

bool read_data_image_method(DartCtx *ctx, ut64 pos, ut64 data_start, ut64 data_end, const DartFunctionLayout *fl, bool apply_obf, DartScannedMethod *method) {
	if (!ctx || !ctx->layout || !fl || !method || pos >= data_end || data_end - pos <= fl->kind_tag_off + 8) {
		return false;
	}
	ut8 buf[128];
	if (!read_mem (ctx, pos, buf, sizeof (buf))) {
		return false;
	}
	const int resolved_function_cid = dart_cid_get (ctx->layout, DART_CID_FUNCTION);
	const int cid_function = resolved_function_cid >= 0? resolved_function_cid: kFunctionCid;
	if ((int)extract_cid_from_header (ctx, r_read_le64 (buf)) != cid_function) {
		return false;
	}
	ut64 entry = r_read_le64 (buf + fl->entry_off);
	if (!entry || entry == UT64_MAX || entry < ctx->iso_instr || entry > (ctx->iso_instr + (1ULL << 28))) {
		return false;
	}
	bool use_compressed = ctx->compressed_word_size == 4;
	memset (method, 0, sizeof (*method));
	method->entry = entry;
	method->kind_tag = r_read_le32 (buf + fl->kind_tag_off);
	ut64 name_addr = 0;
	if (!read_object_pointer (ctx, buf, fl->name_off, use_compressed, data_start, data_end, true, &name_addr)) {
		return false;
	}
	method->name = try_read_dart_string_dup (ctx, name_addr);
	ut64 owner_addr = 0;
	if (read_object_pointer (ctx, buf, fl->owner_off, use_compressed, data_start, data_end, false, &owner_addr) && owner_addr) {
		ut8 owner_buf[32];
		if (read_mem (ctx, owner_addr, owner_buf, sizeof (owner_buf))) {
			ut64 owner_name_ptr = 0;
			if (read_object_pointer (ctx, owner_buf, fl->class_name_off, use_compressed, data_start, data_end, true, &owner_name_ptr)) {
				method->owner_name = try_read_dart_string_dup (ctx, owner_name_ptr);
			}
		}
	}
	if (apply_obf) {
		dart_obf_apply (ctx, &method->name);
		dart_obf_apply (ctx, &method->owner_name);
	}
	if (R_STR_ISNOTEMPTY (method->name) && R_STR_ISNOTEMPTY (method->owner_name)) {
		return true;
	}
	dart_scanned_method_fini (method);
	return false;
}

const char *method_kind_name(uint32_t kind_tag) {
	static const char *kNames[] = {
		"RegularFunction",
		"ClosureFunction",
		"ImplicitClosureFunction",
		"GetterFunction",
		"SetterFunction",
		"Constructor",
		"ImplicitGetter",
		"ImplicitSetter",
		"ImplicitStaticGetter",
		"FieldInitializer",
		"MethodExtractor",
		"NoSuchMethodDispatcher",
		"InvokeFieldDispatcher",
		"IrregexpFunction",
		"DynamicInvocationForwarder",
		"FfiTrampoline",
		"RecordFieldGetter"
	};
	const size_t count = sizeof (kNames) / sizeof (kNames[0]);
	uint32_t kind = kind_tag & 0x1f;
	return (kind < count)? kNames[kind]: "Unknown";
}

void scan_methods_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end) {
	if (!ctx || !ctx->core || !class_list || data_start >= data_end) {
		return;
	}
	if (!ctx->layout) {
		return;
	}
	DartFunctionLayout fl;
	init_function_layout (ctx, &fl);
	HtPP *class_by_name = ht_pp_new0 ();
	if (!class_by_name) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (!ci || !ci->name) {
			continue;
		}
		if (!ci->methods) {
			ci->methods = r_list_newf ((RListFree)dart_method_info_free);
		}
		ht_pp_insert (class_by_name, ci->name, ci);
	}
	HtUP *seen_ep = ht_up_new0 ();
	if (!seen_ep) {
		ht_pp_free (class_by_name);
		return;
	}
	ut64 align = ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	ut64 methods_found = 0;
	const ut64 max_methods = 30000;
	for (ut64 pos = data_start; pos + fl.kind_tag_off + 8 < data_end; pos += align) {
		DartScannedMethod method;
		if (!read_data_image_method (ctx, pos, data_start, data_end, &fl, true, &method)) {
			continue;
		}
		if (ht_up_find (seen_ep, method.entry, NULL)) {
			dart_scanned_method_fini (&method);
			continue;
		}
		if (ctx->verbose > 1 && methods_found < 64) {
			fprintf (stderr, "[r2flutter] method candidate %s.%s\n", method.owner_name, method.name);
		}
		DartClassInfo *owner_ci = ht_pp_find (class_by_name, method.owner_name, NULL);
		if (!owner_ci || !owner_ci->methods) {
			dart_scanned_method_fini (&method);
			continue;
		}
		DartMethodInfo *mi = R_NEW0 (DartMethodInfo);
		mi->entry_point = method.entry;
		mi->name = method.name;
		mi->owner_name = method.owner_name;
		method.name = NULL;
		method.owner_name = NULL;
		mi->kind_tag = method.kind_tag;
		ht_up_insert (seen_ep, method.entry, mi);
		r_list_append (owner_ci->methods, mi);
		if (ctx->verbose > 1) {
			fprintf (stderr, "[r2flutter] method %s.%s @0x%" PFMT64x "\n", mi->owner_name, mi->name, method.entry);
		}
		dart_scanned_method_fini (&method);
		methods_found++;
		if (methods_found >= max_methods) {
			break;
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Scanned %" PRIu64 " methods from data image\n", methods_found);
	}
	ht_up_free (seen_ep);
	ht_pp_free (class_by_name);
}
