/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

#define DART_OBJECT_STRING_PREVIEW_BYTES 4096ULL
#define DART_OBJECT_MAX_STRING_BYTES (1024ULL * 1024ULL)
#define DART_OBJECT_MAX_CANDIDATES 8

typedef struct {
	bool valid;
	bool recognized_cid;
	bool is_string;
	bool is_two_byte;
	bool value_truncated;
	ut64 addr;
	ut64 header;
	ut64 length_raw;
	ut64 length;
	ut64 payload_addr;
	ut64 payload_size;
	int cid;
	const char *cid_name;
	char *value;
} DartObjectInfo;

typedef struct {
	ut64 addr;
	const char *kind;
	bool ok;
	DartObjectInfo object;
} DartObjectCandidate;

typedef struct {
	bool is_smi;
	st64 smi;
	ut64 raw;
	int ncandidates;
	int selected;
	DartObjectCandidate candidates[DART_OBJECT_MAX_CANDIDATES];
} DartValueInfo;

typedef struct {
	bool present;
	bool read_ok;
	bool bits_ok;
	bool slot_ok;
	ut64 offset;
	ut64 addr;
	ut64 raw;
	ut64 index;
	ut8 bits;
	DartPpInfo pp;
	DartModernPoolSlotInfo slot;
} DartPpSlotInfo;

static void dart_object_info_fini(DartObjectInfo *info) {
	if (!info) {
		return;
	}
	free (info->value);
	memset (info, 0, sizeof (*info));
}

static void dart_value_info_fini(DartValueInfo *info) {
	if (!info) {
		return;
	}
	for (int i = 0; i < info->ncandidates; i++) {
		dart_object_info_fini (&info->candidates[i].object);
	}
	memset (info, 0, sizeof (*info));
}

static void dart_pp_slot_info_fini(DartPpSlotInfo *info) {
	if (!info) {
		return;
	}
	dart_pp_info_fini (&info->pp);
	dart_modern_pool_slot_info_fini (&info->slot);
	memset (info, 0, sizeof (*info));
}

static int dart_object_heap_tag(DartCtx *ctx) {
	const int tag = ctx && ctx->layout && ctx->layout->heap_object_tag > 0? ctx->layout->heap_object_tag: 1;
	return tag;
}

static int dart_object_cid_from_header(DartCtx *ctx, ut64 header) {
	DartTagStyle style = ctx && ctx->layout? ctx->layout->tag_style: DART_TAG_STYLE_OBJECT_HEADER;
	switch (style) {
	case DART_TAG_STYLE_CID_INT32:
		return (int) (header & 0xffffffffU);
	case DART_TAG_STYLE_CID_SHIFT1:
		return (int) ((header >> 1) & 0xffffffffU);
	case DART_TAG_STYLE_OBJECT_HEADER:
	default:
		return (int) ((header >> 12) & 0xfffffU);
	}
}

static const char *dart_object_cid_name(DartCtx *ctx, int cid) {
	const DartVerLayout *layout = ctx? ctx->layout: NULL;
	for (int i = 0; i < DART_CID_KIND_COUNT; i++) {
		if (dart_cid_get (layout, (DartCidKind)i) == cid) {
			return dart_cid_kind_name ((DartCidKind)i);
		}
	}
	return NULL;
}

static bool dart_object_parse_u64(const char *s, ut64 *out) {
	if (R_STR_ISEMPTY (s) || !out) {
		return false;
	}
	while (isspace ((ut8)*s)) {
		s++;
	}
	if (!*s) {
		return false;
	}
	char *end = NULL;
	ut64 value = (ut64)strtoull (s, &end, 0);
	if (end == s) {
		return false;
	}
	while (isspace ((ut8)*end)) {
		end++;
	}
	if (*end) {
		return false;
	}
	*out = value;
	return true;
}

static bool dart_object_parse_pp_spec(const char *spec, ut64 *out) {
	if (R_STR_ISEMPTY (spec) || !out) {
		return false;
	}
	const char *p = r_str_trim_head_ro (spec);
	if (*p == '@') {
		p++;
	}
	if (tolower ((ut8)p[0]) != 'p' || tolower ((ut8)p[1]) != 'p' || (p[2] != '+' && p[2] != ':')) {
		return false;
	}
	return dart_object_parse_u64 (p + 3, out);
}

static char *dart_object_bytes_preview(const ut8 *buf, ut64 len) {
	RStrBuf *sb = r_strbuf_new ("");
	for (ut64 i = 0; i < len; i++) {
		ut8 b = buf[i];
		if (b == '\\') {
			r_strbuf_append (sb, "\\\\");
		} else if (b == '"') {
			r_strbuf_append (sb, "\\\"");
		} else if (b >= 0x20 && b < 0x7f) {
			r_strbuf_appendf (sb, "%c", b);
		} else {
			r_strbuf_appendf (sb, "\\x%02x", b);
		}
	}
	return r_strbuf_drain (sb);
}

static bool dart_object_read_one_byte_string(DartCtx *ctx, DartObjectInfo *info) {
	const ut64 nread = R_MIN (info->payload_size, DART_OBJECT_STRING_PREVIEW_BYTES);
	if (nread == 0) {
		info->value = strdup ("");
		return true;
	}
	ut8 *buf = (ut8 *)malloc ((size_t)nread);
	if (!buf) {
		return false;
	}
	bool ok = read_mem (ctx, info->payload_addr, buf, (int)nread);
	if (ok) {
		info->value = dart_object_bytes_preview (buf, nread);
		info->value_truncated = info->payload_size > nread;
	}
	free (buf);
	return ok;
}

static bool dart_object_read_two_byte_string(DartCtx *ctx, DartObjectInfo *info) {
	ut64 nbytes = R_MIN (info->payload_size, DART_OBJECT_STRING_PREVIEW_BYTES * 2ULL);
	nbytes &= ~1ULL;
	if (nbytes == 0) {
		info->value = strdup ("");
		return true;
	}
	ut8 *buf = (ut8 *)malloc ((size_t)nbytes);
	if (!buf) {
		return false;
	}
	bool ok = read_mem (ctx, info->payload_addr, buf, (int)nbytes);
	if (ok) {
		info->value = dart_utf16le_to_utf8 (buf, nbytes);
		if (!info->value) {
			info->value = dart_object_bytes_preview (buf, nbytes);
		}
		info->value_truncated = info->payload_size > nbytes;
	}
	free (buf);
	return ok;
}

static bool dart_object_read_string_payload(DartCtx *ctx, DartObjectInfo *info, bool two_byte, ut64 payload_addr) {
	info->is_string = true;
	info->is_two_byte = two_byte;
	info->payload_addr = payload_addr;
	info->payload_size = two_byte? info->length * 2ULL: info->length;
	if (info->payload_size > DART_OBJECT_MAX_STRING_BYTES) {
		info->value_truncated = true;
		return true;
	}
	return two_byte? dart_object_read_two_byte_string (ctx, info): dart_object_read_one_byte_string (ctx, info);
}

static bool dart_object_decode_string(DartCtx *ctx, DartObjectInfo *info, const ut8 *hdr) {
	const bool two_byte_cid = dart_cid_is (ctx->layout, info->cid, DART_CID_TWO_BYTE_STRING);
	const bool string_cid = dart_cid_is (ctx->layout, info->cid, DART_CID_STRING);
	const bool one_byte_cid = dart_cid_is (ctx->layout, info->cid, DART_CID_ONE_BYTE_STRING);
	if (!string_cid && !one_byte_cid && !two_byte_cid) {
		return true;
	}
	if (ctx->compressed_word_size == 4) {
		info->length_raw = r_read_le32 (hdr + 8);
	} else {
		info->length_raw = r_read_le64 (hdr + 8);
	}
	if (info->length_raw & 1ULL) {
		return true;
	}
	info->length = info->length_raw >> 1;
	ut64 payload_candidates[2];
	int npayloads = 0;
	if (ctx->compressed_word_size == 4) {
		payload_candidates[npayloads++] = info->addr + 12;
		payload_candidates[npayloads++] = info->addr + 16;
	} else {
		payload_candidates[npayloads++] = info->addr + 16;
	}
	for (int i = 0; i < npayloads; i++) {
		if (two_byte_cid) {
			if (dart_object_read_string_payload (ctx, info, true, payload_candidates[i])) {
				return true;
			}
		} else if (dart_object_read_string_payload (ctx, info, false, payload_candidates[i])) {
			return true;
		}
	}
	return true;
}

static bool dart_object_decode_at(DartCtx *ctx, ut64 addr, DartObjectInfo *out) {
	if (!ctx || !out) {
		return false;
	}
	memset (out, 0, sizeof (*out));
	ut8 hdr[32];
	if (!read_mem (ctx, addr, hdr, sizeof (hdr))) {
		return false;
	}
	out->addr = addr;
	out->header = r_read_le64 (hdr);
	out->cid = dart_object_cid_from_header (ctx, out->header);
	if (out->cid <= 0 || out->cid >= 0xfffff) {
		return false;
	}
	out->cid_name = dart_object_cid_name (ctx, out->cid);
	out->recognized_cid = R_STR_ISNOTEMPTY (out->cid_name);
	if (!out->recognized_cid) {
		return false;
	}
	out->valid = true;
	dart_object_decode_string (ctx, out, hdr);
	return true;
}

static void dart_value_add_candidate(DartValueInfo *value, ut64 addr, const char *kind) {
	if (!value || value->ncandidates >= DART_OBJECT_MAX_CANDIDATES) {
		return;
	}
	for (int i = 0; i < value->ncandidates; i++) {
		if (value->candidates[i].addr == addr) {
			return;
		}
	}
	DartObjectCandidate *candidate = &value->candidates[value->ncandidates++];
	candidate->addr = addr;
	candidate->kind = kind;
}

static void dart_value_add_compressed_candidates(DartCtx *ctx, DartValueInfo *value, ut64 raw) {
	if (!ctx || ctx->compressed_word_size != 4 || raw > UT32_MAX) {
		return;
	}
	const int tag = dart_object_heap_tag (ctx);
	ut64 data_base = 0;
	DartSnapshotHeader sh = { 0 };
	if (ctx->iso_data && dart_snapshot_header_read (ctx, ctx->iso_data, &sh) && sh.ok) {
		ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
		data_base = ctx->iso_data + ((sh.total_len + (align - 1)) & ~ (align - 1));
	}
	ut64 full = (data_base & ~0xffffffffULL) | (raw & 0xffffffffULL);
	if ((full & (ut64)tag) == (ut64)tag) {
		dart_value_add_candidate (value, full - (ut64)tag, "compressed_tagged_heap");
	}
	dart_value_add_candidate (value, data_base + (raw & ~3ULL), "compressed_data_image");
}

static void dart_value_decode(DartCtx *ctx, ut64 raw, DartValueInfo *value) {
	memset (value, 0, sizeof (*value));
	value->raw = raw;
	value->selected = -1;
	value->is_smi = (raw & 1ULL) == 0;
	if (value->is_smi) {
		value->smi = ((st64)raw) >> 1;
	}
	const int tag = dart_object_heap_tag (ctx);
	if ((raw & (ut64)tag) == (ut64)tag && raw >= (ut64)tag) {
		dart_value_add_candidate (value, raw - (ut64)tag, "tagged_heap");
	}
	dart_value_add_candidate (value, raw, "raw_address");
	if ((raw & 3ULL) != 0) {
		dart_value_add_candidate (value, raw & ~3ULL, "low_bits_stripped");
	}
	dart_value_add_compressed_candidates (ctx, value, raw);
	for (int i = 0; i < value->ncandidates; i++) {
		DartObjectCandidate *candidate = &value->candidates[i];
		candidate->ok = dart_object_decode_at (ctx, candidate->addr, &candidate->object);
		if (candidate->ok && value->selected < 0) {
			value->selected = i;
		}
	}
}

static bool dart_pp_slot_decode(DartCtx *ctx, ut64 offset, DartPpSlotInfo *slot) {
	memset (slot, 0, sizeof (*slot));
	slot->present = true;
	slot->offset = offset;
	if (!dart_resolve_pp_info (ctx, &slot->pp)) {
		return false;
	}
	DartPpSlotRaw raw_slot;
	if (!dart_pp_info_read_slot (&slot->pp, offset, &raw_slot)) {
		return false;
	}
	slot->addr = raw_slot.addr;
	slot->raw = raw_slot.raw;
	slot->index = raw_slot.index;
	slot->bits = raw_slot.bits;
	slot->bits_ok = raw_slot.bits_ok;
	slot->read_ok = true;
	if (slot->bits_ok) {
		DartSnapshotHeader sh = { 0 };
		if (dart_snapshot_header_read (ctx, slot->pp.snapshot_base, &sh) && sh.ok) {
			const DartModernClusterRequest req = {
				ctx,
				sh.cluster_start,
				slot->pp.snapshot_base + sh.total_len,
				sh.nc,
				sh.nb
			};
			slot->slot_ok = dart_modern_resolve_pp_slot (&req, offset, &slot->slot);
		}
	}
	return true;
}

static void dart_object_json_object_fields(PJ *pj, const DartObjectInfo *obj) {
	pj_kn (pj, "addr", obj->addr);
	pj_kn (pj, "header", obj->header);
	pj_ki (pj, "cid", obj->cid);
	pj_ks (pj, "cid_name", obj->cid_name? obj->cid_name: "unknown");
	pj_kb (pj, "recognized_cid", obj->recognized_cid);
	if (obj->is_string) {
		pj_ko (pj, "string");
		pj_kn (pj, "length_raw", obj->length_raw);
		pj_kn (pj, "length", obj->length);
		pj_kn (pj, "payload_addr", obj->payload_addr);
		pj_kn (pj, "payload_size", obj->payload_size);
		pj_kb (pj, "two_byte", obj->is_two_byte);
		pj_kb (pj, "value_truncated", obj->value_truncated);
		if (obj->value) {
			pj_ks (pj, "value", obj->value);
		}
		pj_end (pj);
	}
}

static void dart_object_json_value(PJ *pj, const DartValueInfo *value, bool decode_raw) {
	pj_ko (pj, "value");
	pj_kn (pj, "raw", value->raw);
	pj_kb (pj, "decoded", decode_raw);
	if (!decode_raw) {
		pj_ks (pj, "kind", "object_pool_ref");
	} else if (value->selected >= 0) {
		pj_ks (pj, "kind", "object");
		pj_ko (pj, "object");
		dart_object_json_object_fields (pj, &value->candidates[value->selected].object);
		pj_end (pj);
	} else if (value->is_smi) {
		pj_kb (pj, "smi", true);
		pj_kN (pj, "smi_value", value->smi);
		pj_ks (pj, "kind", "smi");
	} else {
		pj_kb (pj, "smi", false);
		pj_ks (pj, "kind", "unknown");
	}
	pj_ka (pj, "candidates");
	for (int i = 0; i < value->ncandidates; i++) {
		const DartObjectCandidate *candidate = &value->candidates[i];
		pj_o (pj);
		pj_ks (pj, "kind", candidate->kind);
		pj_kn (pj, "addr", candidate->addr);
		pj_kb (pj, "ok", candidate->ok);
		if (candidate->ok) {
			pj_ko (pj, "object");
			pj_kn (pj, "header", candidate->object.header);
			pj_ki (pj, "cid", candidate->object.cid);
			pj_ks (pj, "cid_name", candidate->object.cid_name? candidate->object.cid_name: "unknown");
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
}

static void dart_object_json_pool_slot(PJ *pj, const DartPpSlotInfo *slot) {
	pj_ko (pj, "pp_slot");
	pj_kn (pj, "pp", slot->pp.base);
	pj_kn (pj, "offset", slot->offset);
	pj_kn (pj, "addr", slot->addr);
	pj_kn (pj, "raw", slot->raw);
	pj_kn (pj, "index", slot->index);
	pj_kb (pj, "bits_ok", slot->bits_ok);
	if (slot->bits_ok) {
		pj_ki (pj, "bits", slot->bits);
	}
	pj_kb (pj, "resolved", slot->slot_ok);
	if (slot->slot_ok) {
		const DartModernPoolSlotInfo *si = &slot->slot;
		pj_kn (pj, "cluster_index", si->cluster_index);
		pj_kn (pj, "pool_index", si->pool_index);
		pj_kn (pj, "pool_ref", si->pool_ref);
		pj_kn (pj, "length", si->length);
		pj_kn (pj, "entry_index", si->index);
		pj_kn (pj, "pool_offset", si->pool_offset);
		pj_kn (pj, "pp_offset", si->pp_offset);
		pj_kn (pj, "stream_offset", si->stream_offset);
		pj_kn (pj, "value_offset", si->value_offset);
		pj_ki (pj, "entry_bits", si->bits);
		pj_ks (pj, "type", si->type_name? si->type_name: "unknown");
		pj_ks (pj, "patch", si->patch_name? si->patch_name: "unknown");
		pj_ks (pj, "behavior", si->behavior_name? si->behavior_name: "unknown");
		if (si->behavior == 0 && si->type == 1) {
			pj_kn (pj, "ref", si->ref);
		} else if (si->behavior == 0 && si->type == 0) {
			pj_kn (pj, "raw_value", si->raw);
		}
		if (R_STR_ISNOTEMPTY (si->resolved_kind)) {
			pj_ks (pj, "resolved_kind", si->resolved_kind);
		}
		if (R_STR_ISNOTEMPTY (si->resolved_name)) {
			pj_ks (pj, "resolved_name", si->resolved_name);
		}
		if (si->resolved_cid >= 0) {
			pj_ki (pj, "resolved_cid", si->resolved_cid);
		}
		if (si->resolved_code_index != UT64_MAX) {
			pj_kn (pj, "resolved_code_index", si->resolved_code_index);
		}
	}
	pj_end (pj);
}

static char *dart_object_dump_json(const char *spec, const DartValueInfo *value, const DartPpSlotInfo *slot, bool decode_raw) {
	PJ *pj = pj_new ();
	if (!pj) {
		return strdup ("{\"error\":\"Failed to create JSON\"}");
	}
	pj_o (pj);
	pj_ks (pj, "spec", spec? spec: "");
	if (slot && slot->present) {
		if (!slot->read_ok) {
			pj_ks (pj, "kind", "error");
			pj_ks (pj, "error", "PP slot not resolved");
		} else if (slot->slot_ok && slot->slot.behavior == 0 && slot->slot.type == 1) {
			pj_ks (pj, "kind", "object_pool_ref");
		} else {
			pj_ks (pj, "kind", "pp_slot");
		}
		dart_object_json_pool_slot (pj, slot);
	} else if (decode_raw && value->selected >= 0) {
		pj_ks (pj, "kind", "object");
	} else if (value->is_smi) {
		pj_ks (pj, "kind", "smi");
	} else {
		pj_ks (pj, "kind", "unknown");
	}
	dart_object_json_value (pj, value, decode_raw);
	pj_end (pj);
	return pj_drain (pj);
}

static void dart_object_text_object(RStrBuf *sb, const DartObjectInfo *obj, const char *prefix) {
	r_strbuf_appendf (sb, "%saddr:          0x%" PFMT64x "\n", prefix, obj->addr);
	r_strbuf_appendf (sb, "%sheader:        0x%" PFMT64x "\n", prefix, obj->header);
	r_strbuf_appendf (sb, "%scid:           %d %s\n", prefix, obj->cid, obj->cid_name? obj->cid_name: "unknown");
	if (obj->is_string) {
		r_strbuf_appendf (sb, "%sstring.len:    %" PRIu64 "\n", prefix, (uint64_t)obj->length);
		r_strbuf_appendf (sb, "%sstring.raw:    0x%" PFMT64x "\n", prefix, obj->length_raw);
		r_strbuf_appendf (sb, "%spayload:       0x%" PFMT64x " size=0x%" PFMT64x "\n", prefix, obj->payload_addr, obj->payload_size);
		r_strbuf_appendf (sb, "%sencoding:      %s\n", prefix, obj->is_two_byte? "utf16le": "one-byte");
		if (obj->value) {
			r_strbuf_appendf (sb, "%svalue:         \"%s%s\"\n", prefix, obj->value, obj->value_truncated? "...": "");
		}
	}
}

static void dart_object_text_value(RStrBuf *sb, const DartValueInfo *value, bool decode_raw) {
	r_strbuf_appendf (sb, "raw:            0x%" PFMT64x "\n", value->raw);
	if (!decode_raw) {
		r_strbuf_append (sb, "value:          object_pool_ref\n");
		return;
	}
	if (value->is_smi) {
		r_strbuf_appendf (sb, "smi:            %" PFMT64d "\n", value->smi);
	}
	if (decode_raw && value->selected >= 0) {
		const DartObjectCandidate *candidate = &value->candidates[value->selected];
		r_strbuf_appendf (sb, "object:         %s\n", candidate->kind);
		dart_object_text_object (sb, &candidate->object, "");
	} else if (!value->is_smi) {
		r_strbuf_append (sb, "object:         unresolved\n");
	}
	if (value->ncandidates > 0) {
		r_strbuf_append (sb, "candidates:\n");
		for (int i = 0; i < value->ncandidates; i++) {
			const DartObjectCandidate *candidate = &value->candidates[i];
			r_strbuf_appendf (sb, "  - %-22s 0x%" PFMT64x " %s", candidate->kind, candidate->addr, candidate->ok? "ok": "no");
			if (candidate->ok) {
				r_strbuf_appendf (sb, " cid=%d %s", candidate->object.cid, candidate->object.cid_name? candidate->object.cid_name: "unknown");
			}
			r_strbuf_append (sb, "\n");
		}
	}
}

static void dart_object_text_pool_slot(RStrBuf *sb, const DartPpSlotInfo *slot) {
	if (!slot->read_ok) {
		r_strbuf_append (sb, "pp_slot:        unresolved\n");
		return;
	}
	r_strbuf_appendf (sb, "pp:             0x%" PFMT64x "\n", slot->pp.base);
	r_strbuf_appendf (sb, "pp.offset:      0x%" PFMT64x "\n", slot->offset);
	r_strbuf_appendf (sb, "pp.addr:        0x%" PFMT64x "\n", slot->addr);
	r_strbuf_appendf (sb, "pp.raw:         0x%" PFMT64x "\n", slot->raw);
	if (slot->bits_ok) {
		r_strbuf_appendf (sb, "pp.index:       %" PRIu64 "\n", (uint64_t)slot->index);
		r_strbuf_appendf (sb, "pp.bits:        0x%02x\n", (unsigned int)slot->bits);
	}
	if (slot->slot_ok) {
		const DartModernPoolSlotInfo *si = &slot->slot;
		r_strbuf_appendf (sb, "pool.ref:       %" PRIu64 "\n", (uint64_t)si->pool_ref);
		r_strbuf_appendf (sb, "pool.index:     %" PRIu64 "\n", (uint64_t)si->pool_index);
		r_strbuf_appendf (sb, "entry.index:    %" PRIu64 "\n", (uint64_t)si->index);
		r_strbuf_appendf (sb, "entry.stream:   0x%" PFMT64x "\n", si->stream_offset);
		r_strbuf_appendf (sb, "entry.value:    0x%" PFMT64x "\n", si->value_offset);
		r_strbuf_appendf (sb, "entry.type:     %s\n", si->type_name? si->type_name: "unknown");
		r_strbuf_appendf (sb, "entry.patch:    %s\n", si->patch_name? si->patch_name: "unknown");
		r_strbuf_appendf (sb, "entry.behavior: %s\n", si->behavior_name? si->behavior_name: "unknown");
		if (si->behavior == 0 && si->type == 1) {
			r_strbuf_appendf (sb, "target.ref:     %" PRIu64 "\n", (uint64_t)si->ref);
		} else if (si->behavior == 0 && si->type == 0) {
			r_strbuf_appendf (sb, "target.raw:     0x%" PFMT64x "\n", si->raw);
		}
		if (R_STR_ISNOTEMPTY (si->resolved_kind)) {
			r_strbuf_appendf (sb, "target.kind:    %s\n", si->resolved_kind);
		}
		if (si->resolved_cid >= 0) {
			r_strbuf_appendf (sb, "target.cid:     %d\n", si->resolved_cid);
		}
		if (si->resolved_code_index != UT64_MAX) {
			r_strbuf_appendf (sb, "target.code:    %" PRIu64 "\n", (uint64_t)si->resolved_code_index);
		}
		if (R_STR_ISNOTEMPTY (si->resolved_name)) {
			r_strbuf_appendf (sb, "target.name:    \"%s\"\n", si->resolved_name);
		}
	}
}

static char *dart_object_dump_text(const char *spec, const DartValueInfo *value, const DartPpSlotInfo *slot, bool decode_raw, bool quiet) {
	RStrBuf *sb = r_strbuf_new ("");
	if (quiet) {
		if (slot && slot->present && slot->slot_ok && R_STR_ISNOTEMPTY (slot->slot.resolved_name)) {
			r_strbuf_appendf (sb, "%s", slot->slot.resolved_name);
			return r_strbuf_drain (sb);
		}
		if (decode_raw && value->selected >= 0) {
			const DartObjectInfo *obj = &value->candidates[value->selected].object;
			if (obj->is_string && obj->value) {
				r_strbuf_appendf (sb, "%s", obj->value);
				return r_strbuf_drain (sb);
			}
		}
		r_strbuf_appendf (sb, "raw=0x%" PFMT64x, value->raw);
		return r_strbuf_drain (sb);
	}
	r_strbuf_appendf (sb, "spec:           %s\n", spec? spec: "");
	if (slot && slot->present) {
		dart_object_text_pool_slot (sb, slot);
	}
	dart_object_text_value (sb, value, decode_raw);
	return r_strbuf_drain (sb);
}

static char *dart_object_dump_r2(const DartValueInfo *value, const DartPpSlotInfo *slot, bool decode_raw) {
	RStrBuf *sb = r_strbuf_new ("");
	if (slot && slot->present && slot->read_ok) {
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart PP slot offset=0x%" PFMT64x " raw=0x%" PFMT64x, slot->addr, slot->offset, slot->raw);
		if (slot->slot_ok) {
			const DartModernPoolSlotInfo *si = &slot->slot;
			r_strbuf_appendf (sb, " entry=%" PRIu64 " type=%s behavior=%s", (uint64_t)si->index, si->type_name? si->type_name: "unknown", si->behavior_name? si->behavior_name: "unknown");
			if (R_STR_ISNOTEMPTY (si->resolved_kind)) {
				r_strbuf_appendf (sb, " resolved=%s", si->resolved_kind);
			}
			if (R_STR_ISNOTEMPTY (si->resolved_name)) {
				char *escaped = r_str_escape_utf8 (si->resolved_name, false, true);
				r_strbuf_appendf (sb, " name=\"%s\"", escaped);
				free (escaped);
			}
		}
		r_strbuf_append (sb, "\n");
	}
	if (decode_raw && value->selected >= 0) {
		const DartObjectInfo *obj = &value->candidates[value->selected].object;
		r_strbuf_appendf (sb, "f dart.object 1 @ 0x%" PFMT64x "\n", obj->addr);
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart object cid=%d %s", obj->addr, obj->cid, obj->cid_name? obj->cid_name: "unknown");
		if (obj->is_string && obj->value) {
			char *escaped = r_str_escape_utf8 (obj->value, false, true);
			r_strbuf_appendf (sb, " len=%" PRIu64 " value=\"%s%s\"", (uint64_t)obj->length, escaped, obj->value_truncated? "...": "");
			free (escaped);
		}
		r_strbuf_append (sb, "\n");
	} else if (decode_raw && value->is_smi) {
		r_strbuf_appendf (sb, "'CC Dart Smi raw=0x%" PFMT64x " value=%" PFMT64d "\n", value->raw, value->smi);
	}
	return r_strbuf_drain (sb);
}

char *dart_pool_dump_object(DartCtx *ctx, const char *spec, int fmt) {
	if (!ctx || R_STR_ISEMPTY (spec)) {
		if (fmt == 'j') {
			return strdup ("{\"error\":\"missing object spec\"}");
		}
		return fmt == 'r'? strdup ("# Error: missing object spec\n"): strdup ("Error: missing object spec\n");
	}
	if (find_snapshots (ctx) != 0) {
		if (fmt == 'j') {
			return strdup ("{\"error\":\"Dart snapshots not found\"}");
		}
		return fmt == 'r'? strdup ("# Error: Dart snapshots not found\n"): strdup ("Error: Dart snapshots not found\n");
	}
	DartVerLayout layout_tmp;
	DartVerLayout *layout_owned = ctx->layout? NULL: dart_ctx_init_layout (ctx, &layout_tmp);
	ut64 raw = 0;
	ut64 pp_offset = 0;
	bool is_pp = dart_object_parse_pp_spec (spec, &pp_offset);
	if (!is_pp) {
		if (!dart_object_parse_u64 (spec, &raw)) {
			if (layout_owned) {
				dart_ctx_fini_layout (ctx, layout_owned);
			}
			if (fmt == 'j') {
				return strdup ("{\"error\":\"invalid object spec\"}");
			}
			return fmt == 'r'? strdup ("# Error: invalid object spec\n"): strdup ("Error: invalid object spec\n");
		}
		if (raw >= DART_SYNTHETIC_PP_BASE) {
			pp_offset = raw - DART_SYNTHETIC_PP_BASE;
			is_pp = true;
		}
	}
	DartValueInfo value;
	memset (&value, 0, sizeof (value));
	value.selected = -1;
	DartPpSlotInfo slot;
	memset (&slot, 0, sizeof (slot));
	bool decode_raw = true;
	if (is_pp) {
		if (dart_pp_slot_decode (ctx, pp_offset, &slot)) {
			raw = slot.slot_ok && slot.slot.behavior == 0 && slot.slot.type == 0? slot.slot.raw: slot.raw;
			decode_raw = ! (slot.slot_ok && slot.slot.behavior == 0 && slot.slot.type == 1);
		}
	}
	dart_value_decode (ctx, raw, &value);
	char *out = NULL;
	if (fmt == 'j') {
		out = dart_object_dump_json (spec, &value, is_pp? &slot: NULL, decode_raw);
	} else if (fmt == 'r') {
		out = dart_object_dump_r2 (&value, is_pp? &slot: NULL, decode_raw);
	} else {
		out = dart_object_dump_text (spec, &value, is_pp? &slot: NULL, decode_raw, ctx->quiet);
	}
	dart_value_info_fini (&value);
	dart_pp_slot_info_fini (&slot);
	if (layout_owned) {
		dart_ctx_fini_layout (ctx, layout_owned);
	}
	return out;
}
