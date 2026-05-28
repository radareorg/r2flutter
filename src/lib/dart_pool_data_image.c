/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

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

static bool read_string_safe(DartCtx *ctx, ut64 addr, char *out, int outsz) {
	if (!addr || !try_read_dart_string (ctx, addr, out, outsz)) {
		return false;
	}
	r_str_filter_zeroline (out, outsz);
	return true;
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
	if (!try_read_dart_string (ctx, name_addr, field->name, sizeof (field->name))) {
		if (!allow_fallback_name) {
			return false;
		}
		snprintf (field->name, sizeof (field->name), "field_%d", fallback_index);
	}
	ut64 owner_addr = use_compressed? data_start + (owner_ptr & ~3ULL): owner_ptr;
	if (owner_addr < data_start || owner_addr >= data_end) {
		return false;
	}
	ut8 owner_hdr[32];
	if (!read_mem (ctx, owner_addr, owner_hdr, sizeof (owner_hdr))) {
		return false;
	}
	ut64 owner_name_ptr = use_compressed? r_read_le32 (owner_hdr + 8): r_read_le64 (owner_hdr + 8);
	ut64 owner_name_addr = use_compressed? data_start + (owner_name_ptr & ~3ULL): owner_name_ptr;
	if (owner_name_addr < data_start || owner_name_addr >= data_end || !try_read_dart_string (ctx, owner_name_addr, field->owner_name, sizeof (field->owner_name))) {
		return false;
	}
	if (apply_obf) {
		dart_obf_apply_buf (ctx, field->name, sizeof (field->name));
		dart_obf_apply_buf (ctx, field->owner_name, sizeof (field->owner_name));
	}
	return field->name[0] && field->owner_name[0];
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
			fi->name = strdup (field.name);
			fi->offset = field.offset;
			fi->flags = field.flags;
			r_list_append (owner_ci->fields, fi);
			if (ctx->verbose > 1) {
				fprintf (stderr, "[r2flutter] Found field: %s.%s offset=0x%x\n", field.owner_name, field.name, field.offset);
			}
		} else if (ctx->verbose > 1 && field_count < 64) {
			fprintf (stderr, "[r2flutter] field owner miss: %s.%s\n", field.owner_name, field.name);
		}
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
	int cid_function = ctx->layout->cid_function? ctx->layout->cid_function: kFunctionCid;
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
	if (!read_object_pointer (ctx, buf, fl->name_off, use_compressed, data_start, data_end, true, &name_addr) || !read_string_safe (ctx, name_addr, method->name, sizeof (method->name))) {
		return false;
	}
	ut64 owner_addr = 0;
	if (!read_object_pointer (ctx, buf, fl->owner_off, use_compressed, data_start, data_end, false, &owner_addr)) {
		return false;
	}
	if (owner_addr) {
		ut8 owner_buf[32];
		if (read_mem (ctx, owner_addr, owner_buf, sizeof (owner_buf))) {
			ut64 owner_name_ptr = 0;
			if (read_object_pointer (ctx, owner_buf, fl->class_name_off, use_compressed, data_start, data_end, true, &owner_name_ptr)) {
				read_string_safe (ctx, owner_name_ptr, method->owner_name, sizeof (method->owner_name));
			}
		}
	}
	if (!method->owner_name[0]) {
		return false;
	}
	if (apply_obf) {
		dart_obf_apply_buf (ctx, method->name, sizeof (method->name));
		dart_obf_apply_buf (ctx, method->owner_name, sizeof (method->owner_name));
	}
	return true;
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
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	if (!align) {
		align = 8;
	}
	ut64 methods_found = 0;
	const ut64 max_methods = 30000;
	for (ut64 pos = data_start; pos + fl.kind_tag_off + 8 < data_end; pos += align) {
		DartScannedMethod method;
		if (!read_data_image_method (ctx, pos, data_start, data_end, &fl, true, &method)) {
			continue;
		}
		if (ht_up_find (seen_ep, method.entry, NULL)) {
			continue;
		}
		if (ctx->verbose > 1 && methods_found < 64) {
			fprintf (stderr, "[r2flutter] method candidate %s.%s\n", method.owner_name, method.name);
		}
		DartClassInfo *owner_ci = ht_pp_find (class_by_name, method.owner_name, NULL);
		if (!owner_ci || !owner_ci->methods) {
			continue;
		}
		DartMethodInfo *mi = R_NEW0 (DartMethodInfo);
		mi->entry_point = method.entry;
		mi->name = strdup (method.name);
		mi->owner_name = strdup (method.owner_name);
		mi->kind_tag = method.kind_tag;
		ht_up_insert (seen_ep, method.entry, mi);
		r_list_append (owner_ci->methods, mi);
		if (ctx->verbose > 1) {
			fprintf (stderr, "[r2flutter] method %s.%s @0x%" PFMT64x "\n", method.owner_name, method.name, method.entry);
		}
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
