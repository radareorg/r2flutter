/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

typedef struct {
	ut64 header_addr;
	ut32 canonical_stack_map_entries_offset;
	ut32 length;
	ut32 first_entry_with_code;
} DartInstructionTableHeader;

static void resolve_it_entry_name(DartCtx *ctx, HtUP *sym_by_addr, ut64 data_image_base, const DartInstructionTableEntry *entry, char *out, size_t outsz) {
	if (!out || outsz < 2) {
		return;
	}
	out[0] = '\0';
	if (ctx && ctx->name_by_code_index && entry->has_code && entry->code_index < ctx->name_by_code_index_count) {
		const char *ns = ctx->name_by_code_index[entry->code_index];
		if (R_STR_ISNOTEMPTY (ns)) {
			snprintf (out, outsz, "%s", ns);
		}
	}
	if (sym_by_addr) {
		RBinSymbol *bs = (RBinSymbol *)ht_up_find (sym_by_addr, entry->address, NULL);
		if (bs && bs->name) {
			const char *resolved = r_bin_name_tostring (bs->name);
			if (resolved && *resolved) {
				snprintf (out, outsz, "%s", resolved);
			}
		}
	}
	if (!*out && ctx->name_by_ep) {
		char *ns = (char *)ht_up_find (ctx->name_by_ep, entry->address, NULL);
		if (ns && *ns) {
			snprintf (out, outsz, "%s", ns);
		}
	}
	if (!entry->has_code) {
		if (!*out) {
			snprintf (out, outsz, "stub.it_%" PRIu64, (uint64_t)entry->index);
		}
		return;
	}
	if (!*out && entry->stack_map_offset > 0 && entry->stack_map_offset < (1U << 31)) {
		ut64 saddr = data_image_base + (ut64)entry->stack_map_offset;
		char sname[128];
		if (try_read_dart_string (ctx, saddr, sname, sizeof (sname))) {
			r_str_filter_zeroline (sname, sizeof (sname));
			size_t slen = strlen (sname);
			bool looks_ok = strstr (sname, "package:") || strstr (sname, "dart:");
			if (!looks_ok && slen >= 4 && (strchr (sname, '.') || strchr (sname, '/') || strchr (sname, ':'))) {
				looks_ok = true;
			}
			if (looks_ok) {
				snprintf (out, outsz, "%s", sname);
			}
		}
		if (!*out) {
			int win = 128;
			for (int delta = -win; delta <= win; delta += 8) {
				ut64 cand = saddr + (ut64)delta;
				char s2[128];
				if (try_read_dart_string (ctx, cand, s2, sizeof (s2))) {
					r_str_filter_zeroline (s2, sizeof (s2));
					size_t s2len = strlen (s2);
					if ((strstr (s2, "package:") || strstr (s2, "dart:")) ||
						(s2len >= 4 && (strchr (s2, '/') || strchr (s2, '.') || strchr (s2, ':')))) {
						snprintf (out, outsz, "%s", s2);
						break;
					}
				}
			}
		}
	}
	// Name-pool fallback is order-sensitive: pulling a name for slot N when
	// slot N is actually a stub shifts every following name by one. Only
	// consume the pool when the slot's owner is a regular Function (or the
	// owner kind could not be determined at all). Slots known to be stubs
	// must never advance the pool cursor.
	ut8 owner_kind = DART_OWNER_UNKNOWN;
	if (ctx && ctx->owner_kind_by_code_index && entry->code_index < ctx->owner_kind_by_code_index_count) {
		owner_kind = ctx->owner_kind_by_code_index[entry->code_index];
	}
	bool pool_allowed = owner_kind == DART_OWNER_FUNCTION || owner_kind == DART_OWNER_UNKNOWN;
	if (!*out && pool_allowed && ctx->use_name_pool && ctx->name_pool && entry->has_code && ctx->name_pool_idx < r_list_length (ctx->name_pool)) {
		const char *pooln = (const char *)r_list_get_n (ctx->name_pool, ctx->name_pool_idx++);
		if (pooln && *pooln) {
			snprintf (out, outsz, "%s", pooln);
		}
	}
	if (!*out) {
		switch (owner_kind) {
		case DART_OWNER_VM_STUB:
			snprintf (out, outsz, "stub.vm_%" PRIu64, (uint64_t)entry->code_index);
			break;
		case DART_OWNER_CLASS:
			snprintf (out, outsz, "stub.allocate_%" PRIu64, (uint64_t)entry->code_index);
			break;
		case DART_OWNER_TYPE:
			snprintf (out, outsz, "stub.typetest_%" PRIu64, (uint64_t)entry->code_index);
			break;
		default:
			snprintf (out, outsz, "method.fn_%" PRIu64, (uint64_t)entry->code_index);
			break;
		}
	}
	dart_obf_apply_buf (ctx, out, outsz);
}

static void emit_it_entry_record(const DartInstructionTableEntry *entry, const DartItEmitRequest *req) {
	const DartItEmitCallbacks *cb = &req->cb;
	if (cb->on_it) {
		cb->on_it (entry, cb->it_user);
	}
	if (entry->has_code && cb->on_fn) {
		cb->on_fn (entry->name? entry->name: "method.unknown", entry->address, 0, cb->fn_user);
	}
}

static bool looks_like_it_entries(DartCtx *ctx, ut64 entries_addr, ut32 length) {
	if (!ctx || !entries_addr || length == 0) {
		return false;
	}
	ut32 prev_pc = 0;
	int samples = length < 16? (int)length: 16;
	int sane = 0;
	int monotonic = 0;
	for (int i = 0; i < samples; i++) {
		ut8 ebuf[8];
		if (!read_mem (ctx, entries_addr + (ut64) (i * 8), ebuf, sizeof (ebuf))) {
			return false;
		}
		ut32 pc_offset = r_read_le32 (ebuf);
		ut32 sm_off = r_read_le32 (ebuf + 4);
		if (pc_offset < (1U << 28) && sm_off < (1U << 28)) {
			sane++;
		}
		if (i == 0 || pc_offset >= prev_pc) {
			monotonic++;
		}
		prev_pc = pc_offset;
	}
	return sane >= samples - 1 && monotonic >= samples - 2;
}

static bool read_it_data_header_from_string_object(DartCtx *ctx, ut64 obj_addr, ut64 data_image_end, ut64 itlen, DartInstructionTableHeader *out) {
	if (!ctx || !ctx->layout || !out) {
		return false;
	}
	ut8 objhdr[16];
	if (!read_mem (ctx, obj_addr, objhdr, sizeof (objhdr))) {
		return false;
	}
	ut64 tags = r_read_le64 (objhdr);
	ut32 cid = 0;
	switch (ctx->layout->tag_style) {
	case DART_TAG_STYLE_OBJECT_HEADER:
		cid = (ut32) ((tags >> 12) & 0xFFFFF);
		break;
	case DART_TAG_STYLE_CID_SHIFT1:
		cid = (ut32) (tags >> 1);
		break;
	case DART_TAG_STYLE_CID_INT32:
	default:
		cid = (ut32) ((tags >> 12) & 0xFFFFF);
		break;
	}
	const int resolved_string_cid = dart_cid_get (ctx->layout, DART_CID_ONE_BYTE_STRING);
	const int string_cid = resolved_string_cid >= 0? resolved_string_cid: kOneByteStringCid;
	if ((int)cid != string_cid) {
		return false;
	}
	ut64 len_smi = r_read_le64 (objhdr + 8);
	if (len_smi & 1ULL) {
		return false;
	}
	ut64 payload_len = len_smi >> 1;
	if (payload_len < 24) {
		return false;
	}
	ut64 payload_addr = obj_addr + 16;
	if (data_image_end && payload_addr + payload_len > data_image_end) {
		return false;
	}
	ut8 hdr[16];
	if (!read_mem (ctx, payload_addr, hdr, sizeof (hdr))) {
		return false;
	}
	ut32 canonical = r_read_le32 (hdr);
	ut32 length = r_read_le32 (hdr + 4);
	ut32 first = r_read_le32 (hdr + 8);
	if (!length || length > (1U << 24) || first > length) {
		return false;
	}
	if (16ULL + ((ut64)length * 8ULL) > payload_len) {
		return false;
	}
	if (canonical && (canonical < sizeof (hdr) + ((ut64)length * 8ULL) || canonical >= payload_len)) {
		return false;
	}
	if (itlen && (length < (itlen / 2) || length > (itlen * 128))) {
		return false;
	}
	if (!looks_like_it_entries (ctx, payload_addr + 16, length)) {
		return false;
	}
	out->header_addr = payload_addr;
	out->canonical_stack_map_entries_offset = canonical;
	out->length = length;
	out->first_entry_with_code = first;
	return true;
}

static bool scan_it_data_header_in_strings(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end, ut64 itlen, DartInstructionTableHeader *out) {
	static const ut64 image_header_size = 0x40;
	if (!ctx || !out || data_image_end <= data_image_base + image_header_size) {
		return false;
	}
	DartInstructionTableHeader best = { 0 };
	ut32 best_len = 0;
	for (ut64 addr = data_image_base + image_header_size; addr + 32 < data_image_end; addr += 16) {
		DartInstructionTableHeader cand = { 0 };
		if (!read_it_data_header_from_string_object (ctx, addr, data_image_end, itlen, &cand)) {
			continue;
		}
		if (cand.length > best_len) {
			best = cand;
			best_len = cand.length;
		}
	}
	if (!best_len) {
		return false;
	}
	*out = best;
	return true;
}

static bool locate_it_data_header(DartCtx *ctx, ut64 table_addr, ut64 data_image_base, ut64 data_image_end, ut64 itlen, DartInstructionTableHeader *out) {
	static const int probes[] = { 16, 0, 8, 12 };
	if (!ctx || !out) {
		return false;
	}
	DartInstructionTableHeader best = { 0 };
	ut32 best_len = 0;
	for (size_t i = 0; i < sizeof (probes) / sizeof (probes[0]); i++) {
		ut64 base = table_addr + probes[i];
		for (int delta = -64; delta <= 64; delta += 4) {
			ut8 hdr[16];
			ut64 addr = base + delta;
			if (!read_mem (ctx, addr, hdr, sizeof (hdr))) {
				continue;
			}
			ut32 canonical = r_read_le32 (hdr);
			ut32 length = r_read_le32 (hdr + 4);
			ut32 first = r_read_le32 (hdr + 8);
			if (!length || length > (1U << 24) || first > length) {
				continue;
			}
			if (itlen && (length < (itlen / 4) || length > (itlen * 2))) {
				continue;
			}
			if (canonical && canonical < sizeof (hdr) + (length * 8)) {
				continue;
			}
			if (!looks_like_it_entries (ctx, addr + 16, length)) {
				continue;
			}
			if (itlen && length == itlen) {
				out->header_addr = addr;
				out->canonical_stack_map_entries_offset = canonical;
				out->length = length;
				out->first_entry_with_code = first;
				return true;
			}
			if (length > best_len) {
				best.header_addr = addr;
				best.canonical_stack_map_entries_offset = canonical;
				best.length = length;
				best.first_entry_with_code = first;
				best_len = length;
			}
		}
	}
	DartInstructionTableHeader str_hdr = { 0 };
	bool found_str_hdr = scan_it_data_header_in_strings (ctx, data_image_base, data_image_end, itlen, &str_hdr);
	if (found_str_hdr && (!best_len || str_hdr.length > best_len)) {
		best = str_hdr;
		best_len = str_hdr.length;
	}
	if (best_len > 0) {
		*out = best;
		return true;
	}
	ut64 scan_end = data_image_base + 0x40000;
	if (data_image_end && scan_end > data_image_end) {
		scan_end = data_image_end;
	}
	for (ut64 addr = data_image_base + 0x40; addr + 16 < scan_end; addr += 8) {
		ut8 hdr[16];
		if (!read_mem (ctx, addr, hdr, sizeof (hdr))) {
			continue;
		}
		ut32 canonical = r_read_le32 (hdr);
		ut32 length = r_read_le32 (hdr + 4);
		ut32 first = r_read_le32 (hdr + 8);
		if (length < 64 || length > (1U << 24) || first > length) {
			continue;
		}
		if (itlen && (length < (itlen / 4) || length > (itlen * 2))) {
			continue;
		}
		if (canonical && canonical < sizeof (hdr) + (length * 8)) {
			continue;
		}
		if (!looks_like_it_entries (ctx, addr + 16, length)) {
			continue;
		}
		if (length > best_len) {
			best.header_addr = addr;
			best.canonical_stack_map_entries_offset = canonical;
			best.length = length;
			best.first_entry_with_code = first;
			best_len = length;
		}
	}
	if (best_len > 0) {
		*out = best;
		return true;
	}
	if (found_str_hdr) {
		*out = str_hdr;
		return true;
	}
	return false;
}

int dart_it_emit_linear(const DartItEmitRequest *req) {
	DartCtx *ctx = req? req->ctx: NULL;
	if (!ctx || !ctx->iso_instr) {
		return -1;
	}
	const ut64 itlen = req->itlen;
	const ut64 max_entries = req->max_entries;
	const ut64 limit = max_entries && max_entries < itlen? max_entries: itlen;
	ctx->it_length = itlen;
	ctx->it_first_with_code = 0;
	ctx->it_canonical_stack_map_offset = 0;
	for (ut64 i = 0; i < limit; i++) {
		char name[64];
		DartInstructionTableEntry entry = {
			.index = i,
			.code_index = i,
			.address = ctx->iso_instr + (i * 4),
			.pc_offset = (ut32) (i * 4),
			.stack_map_offset = 0,
			.has_code = true,
			.name = name,
};
		snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
		dart_obf_apply_buf (ctx, name, sizeof (name));
		emit_it_entry_record (&entry, req);
	}
	return 0;
}

int dart_it_emit_fixed(const DartItEmitRequest *req) {
	DartCtx *ctx = req? req->ctx: NULL;
	if (!ctx || !ctx->core) {
		return -1;
	}
	DartInstructionTableHeader hdr = { 0 };
	ut64 data_image_end = req->data_image_end? req->data_image_end: ctx->iso_instr;
	if (!data_image_end || data_image_end < req->data_image_base) {
		data_image_end = req->data_image_base + (1ULL << 22);
	}
	if (!locate_it_data_header (ctx, req->table_addr, req->data_image_base, data_image_end, req->itlen, &hdr)) {
		return -1;
	}
	ctx->it_length = hdr.length;
	ctx->it_first_with_code = hdr.first_entry_with_code;
	ctx->it_canonical_stack_map_offset = hdr.canonical_stack_map_entries_offset;
	ut64 entries_addr = hdr.header_addr + 16;
	ut64 effective_max = req->max_entries;
	if (!req->include_stubs && req->itlen && (!effective_max || effective_max > req->itlen)) {
		effective_max = req->itlen;
	}
	ut64 emitted = 0;
	for (ut64 idx = 0; idx < hdr.length; idx++) {
		if (effective_max && emitted >= effective_max) {
			break;
		}
		ut8 ebuf[8];
		ut64 entry_addr = entries_addr + (idx * 8);
		if (!read_mem (ctx, entry_addr, ebuf, sizeof (ebuf))) {
			break;
		}
		bool has_code = idx >= hdr.first_entry_with_code;
		if (!req->include_stubs && !has_code) {
			continue;
		}
		char name[128];
		DartInstructionTableEntry entry = {
			.index = idx,
			.code_index = has_code? idx - hdr.first_entry_with_code: UT64_MAX,
			.address = ctx->iso_instr + (ut64)r_read_le32 (ebuf),
			.pc_offset = r_read_le32 (ebuf),
			.stack_map_offset = r_read_le32 (ebuf + 4),
			.has_code = has_code,
			.name = name,
};
		resolve_it_entry_name (ctx, req->sym_by_addr, req->data_image_base, &entry, name, sizeof (name));
		emit_it_entry_record (&entry, req);
		emitted++;
	}
	return 0;
}

int dart_it_emit_varint(const DartItEmitRequest *req) {
	DartCtx *ctx = req? req->ctx: NULL;
	if (!ctx || !ctx->core) {
		return -1;
	}
	ut64 p = req->table_addr;
	ut64 header_len = 0;
	ut64 first_with_code = 0;
	if (!dart_read_unsigned_at (ctx, p, &header_len, &p)) {
		return -1;
	}
	if (!dart_read_unsigned_at (ctx, p, &first_with_code, &p)) {
		return -1;
	}
	if (header_len == 0 || header_len > (1ULL << 26)) {
		return -1;
	}
	if (first_with_code > header_len) {
		return -1;
	}
	ctx->it_length = header_len;
	ctx->it_first_with_code = first_with_code;
	ctx->it_canonical_stack_map_offset = 0;
	ut64 pc_acc = 0;
	ut64 sm_acc = 0;
	ut64 emitted = 0;
	for (ut64 idx = 0; idx < header_len; idx++) {
		ut64 dpc = 0;
		ut64 dsm = 0;
		if (!dart_read_unsigned_at (ctx, p, &dpc, &p)) {
			return -1;
		}
		if (!dart_read_unsigned_at (ctx, p, &dsm, &p)) {
			return -1;
		}
		pc_acc += dpc;
		sm_acc += dsm;
		bool has_code = idx >= first_with_code;
		if (!req->include_stubs && !has_code) {
			continue;
		}
		if (req->max_entries && emitted >= req->max_entries) {
			break;
		}
		char name[128];
		DartInstructionTableEntry entry = {
			.index = idx,
			.code_index = has_code? idx - first_with_code: UT64_MAX,
			.address = ctx->iso_instr + pc_acc,
			.pc_offset = (ut32)pc_acc,
			.stack_map_offset = (ut32)sm_acc,
			.has_code = has_code,
			.name = name,
};
		resolve_it_entry_name (ctx, req->sym_by_addr, req->data_image_base, &entry, name, sizeof (name));
		emit_it_entry_record (&entry, req);
		emitted++;
	}
	return 0;
}
