/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

// ============================================================================
// String Extraction
// ============================================================================

#define DART_SYNTHETIC_STRING_REF_BASE 0x200000000ULL

void dart_string_ref_free(DartStringRef *sr) {
	free (sr->kind);
	free (sr->object_name);
	free (sr);
}

void dart_string_info_free(DartStringInfo *si) {
	if (si) {
		free (si->value);
		r_list_free (si->references);
		free (si);
	}
}

void dart_string_list_free(RList *list) {
	r_list_free (list);
}

#define DART_STRING_SCAN_LIMIT 50000
DartStringCategory dart_string_classify_value(const char *s) {
	if (R_STR_ISEMPTY (s)) {
		return DART_STRING_CAT_UNKNOWN;
	}
	if (r_str_startswith (s, "dart:") || strstr (s, "dartvm") || strstr (s, "dart/")) {
		return DART_STRING_CAT_RUNTIME;
	}
	if (r_str_startswith (s, "package:") || strstr (s, ".dart")) {
		return DART_STRING_CAT_LIBRARY;
	}
	for (const char *p = s; *p; p++) {
		if (isspace ((unsigned char)*p) || strchr ("!?,;:'\"", *p)) {
			return DART_STRING_CAT_APP;
		}
	}
	if (strchr (s, '/')) {
		return DART_STRING_CAT_LIBRARY;
	}
	return DART_STRING_CAT_LIBRARY;
}

static const char *string_category_name(DartStringCategory cat) {
	switch (cat) {
	case DART_STRING_CAT_APP: return "app";
	case DART_STRING_CAT_LIBRARY: return "lib";
	case DART_STRING_CAT_RUNTIME: return "rnt";
	default: return "unknown";
	}
}

static void scan_utf16_strings(const ut8 *buf, ut64 base, ut64 size, RList *list, HtUP *seen_addrs, ut64 *ref_counter);
static bool should_scan_section(const RBinSection *sec);

static bool is_common_text_punct(ut8 ch) {
	return strchr ("_.$:/-'\"!?(),[]+*=#%&", ch) != NULL;
}

static bool is_short_text_punct(ut8 ch) {
	return strchr ("_.$:/-'", ch) != NULL;
}

static bool looks_like_text(const char *s) {
	if (!s) {
		return false;
	}
	size_t len = strlen (s);
	if (len < 4 || len > 512) {
		return false;
	}
	int alpha = 0;
	int digit = 0;
	int spaces = 0;
	int short_punct = 0;
	int common_punct = 0;
	int weird = 0;
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		if (*p < 0x20 && *p != '\t' && *p != '\n' && *p != '\r') {
			return false;
		}
		if (isalpha (*p)) {
			alpha++;
			continue;
		}
		if (isdigit (*p)) {
			digit++;
			continue;
		}
		if (isspace (*p)) {
			spaces++;
			continue;
		}
		if (is_short_text_punct (*p)) {
			short_punct++;
		}
		if (is_common_text_punct (*p)) {
			common_punct++;
			continue;
		}
		weird++;
	}
	if (alpha < 1) {
		return false;
	}
	if (len <= 4) {
		return weird == 0 && spaces == 0 &&
			(alpha + digit + short_punct) == (int)len &&
			short_punct <= 1;
	}
	if (len <= 6) {
		return weird == 0 && alpha >= 2 && spaces <= 1 &&
			(alpha + digit + common_punct + spaces) == (int)len;
	}
	if (weird > 0 && (len < 12 || weird * 4 > (int)len)) {
		return false;
	}
	return (alpha + digit + common_punct) >= R_MAX (2, (int)len / 2);
}

#define DART_PACKED_STRING_MAX_LEN 512
#define DART_PACKED_STRING_MIN_RUN 4
#define DART_PACKED_STRING_MAX_SKIPS 4
#define DART_PACKED_STRING_MAX_RECORDS 256

typedef struct {
	ut64 payload_off;
	ut64 next_off;
	ut32 length;
	ut32 flags;
	char *value;
} PackedStringRecord;

static void packed_string_record_fini(PackedStringRecord *rec) {
	if (!rec) {
		return;
	}
	free (rec->value);
	rec->value = NULL;
}

static void append_string_info(RList *list, HtUP *seen_addrs, const char *value, ut32 len, ut32 flags, ut64 addr, DartStringCategory cat, ut64 *ref_counter) {
	if (!list || !value) {
		return;
	}
	if (r_list_length (list) >= DART_STRING_SCAN_LIMIT) {
		return;
	}
	if (seen_addrs && addr && ht_up_find (seen_addrs, addr, NULL)) {
		return;
	}
	DartStringInfo *si = R_NEW0 (DartStringInfo);
	si->ref_id = ref_counter? (*ref_counter)++: 0;
	si->length = len;
	si->flags = flags | DART_STRING_CANONICAL;
	si->address = addr;
	si->category = cat;
	si->references = r_list_newf ((RListFree)dart_string_ref_free);
	si->value = strdup (value);
	r_list_append (list, si);
	if (seen_addrs && addr) {
		ht_up_insert (seen_addrs, addr, si);
	}
}

static void scan_ascii_strings(const ut8 *buf, ut64 base, ut64 size, RList *list, HtUP *seen_addrs, ut64 *ref_counter) {
	if (!buf || !size) {
		return;
	}
	ut64 pos = 0;
	while (pos < size) {
		while (pos < size && !IS_PRINTABLE (buf[pos])) {
			pos++;
		}
		ut64 start = pos;
		while (pos < size && IS_PRINTABLE (buf[pos])) {
			pos++;
		}
		ut64 length = pos - start;
		if (length >= 4 && length <= 512) {
			char *tmp = (char *)malloc (length + 1);
			if (tmp) {
				memcpy (tmp, buf + start, length);
				tmp[length] = '\0';
				if (looks_like_text (tmp)) {
					append_string_info (list, seen_addrs, tmp, (ut32)length, 0, base + start, dart_string_classify_value (tmp), ref_counter);
				}
				free (tmp);
			}
		}
	}
}

static int emit_utf16le(const ut8 *buf, ut64 start, ut64 end, RStrBuf *sb) {
	ut64 pos = start;
	while (pos + 1 < end) {
		ut32 code = r_read_le16 (buf + pos);
		if (!code) {
			break;
		}
		if (code < 0x20 && code != '\t' && code != '\n' && code != '\r') {
			break;
		}
		if (code < 0x80) {
			r_strbuf_append_n (sb, (const char *)&code, 1);
		} else if (code < 0x800) {
			char tmp[2] = {
				(char) (0xC0 | (code >> 6)),
				(char) (0x80 | (code & 0x3F))
			};
			r_strbuf_append_n (sb, tmp, 2);
		} else {
			char tmp[3] = {
				(char) (0xE0 | (code >> 12)),
				(char) (0x80 | ((code >> 6) & 0x3F)),
				(char) (0x80 | (code & 0x3F))
			};
			r_strbuf_append_n (sb, tmp, 3);
		}
		pos += 2;
	}
	return (int) ((pos - start) / 2);
}

static bool utf16le_has_ascii_profile(const ut8 *buf, ut64 start, ut64 end) {
	if (!buf || start >= end || (end - start) < 8) {
		return false;
	}
	int units = 0;
	int asciiish = 0;
	int alpha = 0;
	for (ut64 pos = start; pos + 1 < end; pos += 2) {
		ut32 code = r_read_le16 (buf + pos);
		if (!code) {
			return false;
		}
		if (code >= 0xD800 && code <= 0xDFFF) {
			return false;
		}
		if (code >= 32 && code < 127) {
			asciiish++;
			if (isalpha ((unsigned char)code)) {
				alpha++;
			}
		}
		units++;
	}
	if (units < 4) {
		return false;
	}
	return asciiish >= R_MAX (2, units / 2) && alpha >= 1;
}

static bool parse_packed_string_record_any(const ut8 *buf, ut64 size, ut64 pos, ut64 *out_next) {
	ut64 encoded = 0;
	ut64 next = 0;
	if (!dart_read_unsigned_buf (buf, size, pos, &encoded, &next)) {
		return false;
	}
	ut64 length = encoded >> 1;
	if (length == 0 || length > DART_PACKED_STRING_MAX_LEN) {
		return false;
	}
	ut64 payload_size = (encoded & 1)? (length * 2): length;
	if (next + payload_size > size) {
		return false;
	}
	if (out_next) {
		*out_next = next + payload_size;
	}
	return true;
}

static bool parse_packed_string_record_text(const ut8 *buf, ut64 size, ut64 pos, PackedStringRecord *out) {
	if (!buf || !out) {
		return false;
	}
	memset (out, 0, sizeof (*out));
	ut64 encoded = 0;
	ut64 payload_off = 0;
	if (!dart_read_unsigned_buf (buf, size, pos, &encoded, &payload_off)) {
		return false;
	}
	ut64 length = encoded >> 1;
	if (length < 4 || length > DART_PACKED_STRING_MAX_LEN) {
		return false;
	}
	if ((encoded & 1) == 0) {
		if (payload_off + length > size) {
			return false;
		}
		char *value = (char *)malloc ((size_t)length + 1);
		if (!value) {
			return false;
		}
		memcpy (value, buf + payload_off, (size_t)length);
		value[length] = '\0';
		if (!looks_like_text (value)) {
			free (value);
			return false;
		}
		out->payload_off = payload_off;
		out->next_off = payload_off + length;
		out->length = (ut32)length;
		out->flags = 0;
		out->value = value;
		return true;
	}
	ut64 payload_size = length * 2;
	if (payload_off + payload_size > size || !utf16le_has_ascii_profile (buf, payload_off, payload_off + payload_size)) {
		return false;
	}
	RStrBuf sb;
	r_strbuf_init (&sb);
	int units = emit_utf16le (buf, payload_off, payload_off + payload_size, &sb);
	const char *utf8 = r_strbuf_get (&sb);
	if (units != (int)length || R_STR_ISEMPTY (utf8) || !looks_like_text (utf8)) {
		r_strbuf_fini (&sb);
		return false;
	}
	out->payload_off = payload_off;
	out->next_off = payload_off + payload_size;
	out->length = (ut32)strlen (utf8);
	out->flags = DART_STRING_TWO_BYTE;
	out->value = strdup (utf8);
	r_strbuf_fini (&sb);
	return out->value != NULL;
}

static void scan_packed_string_runs(const ut8 *buf, ut64 base, ut64 size, RList *list, HtUP *seen_addrs, ut64 *ref_counter) {
	if (!buf || !size || !list) {
		return;
	}
	ut64 pos = 0;
	while (pos < size && r_list_length (list) < DART_STRING_SCAN_LIMIT) {
		PackedStringRecord probe = { 0 };
		if (!parse_packed_string_record_text (buf, size, pos, &probe)) {
			pos++;
			continue;
		}
		packed_string_record_fini (&probe);
		PackedStringRecord records[DART_PACKED_STRING_MAX_RECORDS] = { 0 };
		int n_records = 0;
		int skips = 0;
		ut64 cursor = pos;
		ut64 run_end = pos;
		for (;;) {
			if (n_records >= DART_PACKED_STRING_MAX_RECORDS || skips >= DART_PACKED_STRING_MAX_SKIPS) {
				break;
			}
			PackedStringRecord rec = { 0 };
			if (parse_packed_string_record_text (buf, size, cursor, &rec)) {
				records[n_records++] = rec;
				cursor = rec.next_off;
				run_end = cursor;
				skips = 0;
				continue;
			}
			ut64 next = 0;
			if (!parse_packed_string_record_any (buf, size, cursor, &next)) {
				break;
			}
			cursor = next;
			run_end = next;
			skips++;
		}
		if (n_records >= DART_PACKED_STRING_MIN_RUN) {
			for (int i = 0; i < n_records && r_list_length (list) < DART_STRING_SCAN_LIMIT; i++) {
				PackedStringRecord *rec = &records[i];
				append_string_info (list, seen_addrs, rec->value, rec->length, rec->flags, base + rec->payload_off, dart_string_classify_value (rec->value), ref_counter);
			}
			pos = run_end;
		} else {
			pos++;
		}
		for (int i = 0; i < n_records; i++) {
			packed_string_record_fini (&records[i]);
		}
	}
}

static void scan_packed_strings_from_snapshot(DartCtx *ctx, ut64 snapshot_base, RList *list, HtUP *seen_addrs, ut64 *ref_counter) {
	if (!ctx || !snapshot_base || !list) {
		return;
	}
	ut8 hdrbuf[12];
	if (!read_mem (ctx, snapshot_base, hdrbuf, sizeof (hdrbuf))) {
		return;
	}
	if (r_read_le32 (hdrbuf) != DART_SNAPSHOT_MAGIC) {
		return;
	}
	ut64 total_len = r_read_le64 (hdrbuf + 4) + 4;
	if (total_len < sizeof (hdrbuf) || total_len > (64ULL << 20)) {
		return;
	}
	ut8 *buf = (ut8 *)malloc ((size_t)total_len);
	if (!buf) {
		return;
	}
	if (!read_mem (ctx, snapshot_base, buf, (int)total_len)) {
		free (buf);
		return;
	}
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read_buf (buf, total_len, &hdr)) {
		free (buf);
		return;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] packed string scan snapshot=0x%" PFMT64x " cluster_start=0x%" PFMT64x " total=0x%" PFMT64x "\n", snapshot_base, snapshot_base + hdr.cluster_start, hdr.total_len);
	}
	scan_packed_string_runs (buf + hdr.cluster_start, snapshot_base + hdr.cluster_start, hdr.total_len - hdr.cluster_start, list, seen_addrs, ref_counter);
	free (buf);
}

#define DART_SNAPSHOT_SCAN_MAX (64ULL << 20)
#define DART_DATA_IMAGE_SCAN_MAX (8ULL << 20)

static void scan_string_buffer(const ut8 *buf, ut64 base, ut64 size, RList *list, HtUP *seen_addrs, ut64 *ref_counter) {
	if (!buf || !size || !list) {
		return;
	}
	scan_ascii_strings (buf, base, size, list, seen_addrs, ref_counter);
	scan_utf16_strings (buf, base, size, list, seen_addrs, ref_counter);
}

static void scan_snapshot_region(DartCtx *ctx, ut64 start, ut64 size, RList *list, HtUP *seen_addrs, ut64 *ref_counter) {
	if (!ctx || !ctx->core || !ctx->core->bin || !start || !size || !list || size > DART_SNAPSHOT_SCAN_MAX) {
		return;
	}
	ut64 end = start + size;
	if (end <= start) {
		return;
	}
	RVecRBinSection *sections = r_bin_get_sections_vec (ctx->core->bin);
	if (!sections) {
		return;
	}
	RBinSection *sec;
	R_VEC_FOREACH (sections, sec) {
		if (!should_scan_section (sec)) {
			continue;
		}
		ut64 sec_start = sec->vaddr;
		ut64 sec_end = sec->vaddr + sec->vsize;
		if (sec_end <= sec_start || sec_end <= start || sec_start >= end) {
			continue;
		}
		ut64 chunk_start = sec_start > start? sec_start: start;
		ut64 chunk_end = sec_end < end? sec_end: end;
		ut64 chunk_size = chunk_end - chunk_start;
		if (chunk_size == 0 || chunk_size > DART_SNAPSHOT_SCAN_MAX) {
			continue;
		}
		ut8 *buf = (ut8 *)malloc ((size_t)chunk_size);
		if (!buf) {
			continue;
		}
		if (!read_mem (ctx, chunk_start, buf, (int)chunk_size)) {
			free (buf);
			continue;
		}
		scan_string_buffer (buf, chunk_start, chunk_size, list, seen_addrs, ref_counter);
		free (buf);
	}
}

static void scan_strings_from_snapshot_window(DartCtx *ctx, ut64 snapshot_base, ut64 upper_bound, RList *list, HtUP *seen_addrs, ut64 *ref_counter) {
	if (!ctx || !snapshot_base || !list) {
		return;
	}
	ut64 before_count = r_list_length (list);
	DartSnapshotHeader sh;
	if (!dart_snapshot_header_read (ctx, snapshot_base, &sh)) {
		goto fallback;
	}
	if (sh.total_len == 0 || sh.total_len > DART_SNAPSHOT_SCAN_MAX || sh.cluster_start >= sh.total_len) {
		goto fallback;
	}
	if (ctx->compressed_word_size == 4) {
		scan_packed_strings_from_snapshot (ctx, snapshot_base, list, seen_addrs, ref_counter);
		return;
	}
	scan_snapshot_region (ctx, snapshot_base + sh.cluster_start, sh.total_len - sh.cluster_start, list, seen_addrs, ref_counter);
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	if (align == 0) {
		align = 16;
	}
	ut64 data_start = snapshot_base + ((sh.total_len + (align - 1)) & ~ (align - 1));
	ut64 data_end = upper_bound;
	if (data_end > data_start && (data_end - data_start) <= DART_DATA_IMAGE_SCAN_MAX) {
		scan_snapshot_region (ctx, data_start, data_end - data_start, list, seen_addrs, ref_counter);
	}
	if ((ut64)r_list_length (list) > before_count) {
		return;
	}
fallback:
	if (upper_bound > snapshot_base + 0x100 && (upper_bound - (snapshot_base + 0x100)) <= DART_DATA_IMAGE_SCAN_MAX) {
		scan_snapshot_region (ctx, snapshot_base + 0x100, upper_bound - (snapshot_base + 0x100), list, seen_addrs, ref_counter);
	}
}

static void scan_utf16_strings(const ut8 *buf, ut64 base, ut64 size, RList *list, HtUP *seen_addrs, ut64 *ref_counter) {
	if (!buf || size < 8) {
		return;
	}
	ut64 pos = 0;
	while (pos + 1 < size) {
		ut32 code = r_read_le16 (buf + pos);
		if (!code) {
			pos++;
			continue;
		}
		if (code < 0x20 && code != '\t' && code != '\n' && code != '\r' && code != ' ') {
			pos += 2;
			continue;
		}
		ut64 start = pos;
		RStrBuf sb;
		r_strbuf_init (&sb);
		int units = emit_utf16le (buf, start, size, &sb);
		if (units == 0) {
			pos = start + 2;
		} else {
			pos = start + (units * 2);
		}
		const char *utf8 = r_strbuf_get (&sb);
		if (utf8 && units >= 4 && utf16le_has_ascii_profile (buf, start, start + (units * 2))) {
			ut32 ulen = (ut32)strlen (utf8);
			if (ulen >= 4 && ulen <= 512 && looks_like_text (utf8)) {
				append_string_info (list, seen_addrs, utf8, ulen, DART_STRING_TWO_BYTE, base + start, dart_string_classify_value (utf8), ref_counter);
			}
		}
		r_strbuf_fini (&sb);
	}
}

static bool should_scan_section(const RBinSection *sec) {
	if (!sec || sec->vsize == 0) {
		return false;
	}
	if (! (sec->perm & R_PERM_R)) {
		return false;
	}
	const char *name = sec->name? sec->name: "";
	return r_str_endswith (name, ".__const") ||
		r_str_endswith (name, ".__cstring") ||
		r_str_endswith (name, ".rodata") ||
		r_str_endswith (name, ".data.rel.ro");
}

static int string_info_addr_cmp(const void *a, const void *b) {
	const DartStringInfo *sa = (const DartStringInfo *)a;
	const DartStringInfo *sb = (const DartStringInfo *)b;
	if (!sa && !sb) {
		return 0;
	}
	if (!sa) {
		return -1;
	}
	if (!sb) {
		return 1;
	}
	if (sa->address < sb->address) {
		return -1;
	}
	if (sa->address > sb->address) {
		return 1;
	}
	return strcmp (sa->value? sa->value: "", sb->value? sb->value: "");
}

RList *dart_pool_extract_strings(DartCtx *ctx) {
	if (!ctx || !ctx->core || !ctx->core->bin) {
		return NULL;
	}
	RList *string_list = r_list_newf ((RListFree)dart_string_info_free);
	HtUP *seen_addrs = ht_up_new0 ();
	if (!seen_addrs) {
		return string_list;
	}
	RVecRBinSection *sections = r_bin_get_sections_vec (ctx->core->bin);
	if (!sections) {
		ht_up_free (seen_addrs);
		return string_list;
	}
	ut64 ref_counter = 0;
	if (find_snapshots (ctx) == 0 && ctx->vm_data) {
		DartVerLayout layout_tmp;
		DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
		ut64 vm_upper = 0;
		if (ctx->iso_data > ctx->vm_data) {
			vm_upper = ctx->iso_data;
		} else if (ctx->vm_instr > ctx->vm_data) {
			vm_upper = ctx->vm_instr;
		}
		ut64 iso_upper = 0;
		if (ctx->vm_data > ctx->iso_data) {
			iso_upper = ctx->vm_data;
		} else if (ctx->iso_instr > ctx->iso_data) {
			iso_upper = ctx->iso_instr;
		}
		scan_strings_from_snapshot_window (ctx, ctx->vm_data, vm_upper, string_list, seen_addrs, &ref_counter);
		scan_strings_from_snapshot_window (ctx, ctx->iso_data, iso_upper, string_list, seen_addrs, &ref_counter);
		if (r_list_length (string_list) == 0) {
			if (vm_upper > ctx->vm_data + 0x100) {
				scan_snapshot_region (ctx, ctx->vm_data + 0x100, vm_upper - (ctx->vm_data + 0x100), string_list, seen_addrs, &ref_counter);
			}
			if (iso_upper > ctx->iso_data + 0x100) {
				scan_snapshot_region (ctx, ctx->iso_data + 0x100, iso_upper - (ctx->iso_data + 0x100), string_list, seen_addrs, &ref_counter);
			}
		}
		dart_ctx_fini_layout (ctx, layout_owned);
	}
	RBinSection *sec;
	R_VEC_FOREACH (sections, sec) {
		if (!should_scan_section (sec)) {
			continue;
		}
		ut64 size = sec->vsize;
		if (size == 0 || size > (32ULL << 20)) {
			continue;
		}
		ut8 *buf = (ut8 *)malloc ((size_t)size);
		if (!buf) {
			continue;
		}
		if (!read_mem (ctx, sec->vaddr, buf, (int)size)) {
			free (buf);
			continue;
		}
		scan_string_buffer (buf, sec->vaddr, size, string_list, seen_addrs, &ref_counter);
		free (buf);
		if (r_list_length (string_list) >= DART_STRING_SCAN_LIMIT) {
			break;
		}
	}
	if (r_list_length (string_list) == 0) {
		ut64 size = r_io_size (ctx->core->io);
		if (size > 0 && size <= DART_SNAPSHOT_SCAN_MAX) {
			ut8 *buf = (ut8 *)malloc ((size_t)size);
			if (buf && read_mem (ctx, 0, buf, (int)size)) {
				scan_string_buffer (buf, 0, size, string_list, seen_addrs, &ref_counter);
			}
			free (buf);
		}
	}
	ht_up_free (seen_addrs);
	r_list_sort (string_list, (RListComparator)string_info_addr_cmp);
	return string_list;
}

RList *dart_pool_extract_object_pool_strings(DartCtx *ctx) {
	if (!ctx || !ctx->core || !ctx->core->bin) {
		return NULL;
	}
	RList *string_list = r_list_newf ((RListFree)dart_string_info_free);
	ut64 ref_counter = 0;
	if (find_snapshots (ctx) == 0 && ctx->vm_data) {
		DartVerLayout layout_tmp;
		DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
		if (dart_modern_is_supported_snapshot (ctx)) {
			const ut64 snapshots[] = {
				ctx->vm_data,
				ctx->iso_data
			};
			for (size_t i = 0; i < R_ARRAY_SIZE (snapshots); i++) {
				ut64 base = snapshots[i];
				DartSnapshotHeader sh = { 0 };
				if (!base || !dart_snapshot_header_read (ctx, base, &sh) || !sh.ok) {
					continue;
				}
				HtUP *seen_refs = ht_up_new0 ();
				if (!seen_refs) {
					continue;
				}
				const DartModernClusterRequest req = { ctx, sh.cluster_start, base + sh.total_len, sh.nc, sh.nb };
				(void)dart_modern_extract_object_pool_strings_from_clusters (&req, string_list, seen_refs, &ref_counter);
				ht_up_free (seen_refs);
			}
		}
		dart_ctx_fini_layout (ctx, layout_owned);
	}
	r_list_sort (string_list, (RListComparator)string_info_addr_cmp);
	return string_list;
}

static const char *string_ref_type_name(ut32 object_type) {
	switch (object_type) {
	case DART_REF_FUNCTION: return "function";
	case DART_REF_CLASS: return "class";
	case DART_REF_FIELD: return "field";
	case DART_REF_LIBRARY: return "library";
	case DART_REF_CODE: return "code";
	default: return "other";
	}
}

static void dump_string_json(PJ *pj, const DartStringInfo *si, bool refs) {
	pj_o (pj);
	pj_kn (pj, "ref", si->ref_id);
	pj_ki (pj, "len", si->length);
	if (si->value) {
		pj_ks (pj, "value", si->value);
	}
	pj_ks (pj, "category", string_category_name (si->category));
	pj_kb (pj, "two_byte", (si->flags & DART_STRING_TWO_BYTE) != 0);
	pj_kb (pj, "canonical", (si->flags & DART_STRING_CANONICAL) != 0);
	if (si->address) {
		pj_kn (pj, "addr", si->address);
	}
	if (refs && si->references && r_list_length (si->references) > 0) {
		pj_ka (pj, "refs");
		RListIter *rit;
		DartStringRef *sr;
		r_list_foreach (si->references, rit, sr) {
			if (!sr) {
				continue;
			}
			pj_o (pj);
			pj_kn (pj, "obj", sr->object_ref);
			pj_ks (pj, "type", string_ref_type_name (sr->object_type));
			if (sr->kind) {
				pj_ks (pj, "kind", sr->kind);
			}
			if (sr->object_name) {
				pj_ks (pj, "name", sr->object_name);
			}
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
}

static char *make_string_flagname(const DartStringInfo *si) {
	const char *value = si && R_STR_ISNOTEMPTY (si->value)? si->value: "string";
	char *safe = strdup (value);
	r_name_filter (safe, 0);
	if (R_STR_ISEMPTY (safe)) {
		free (safe);
		safe = strdup ("string");
	}
	char *flagname = r_str_newf ("str.%s.0x%" PFMT64x, safe, si? si->address: 0);
	free (safe);
	return flagname;
}

static void dump_string_ref_text(RStrBuf *sb, const DartStringRef *sr) {
	r_strbuf_appendf (sb, "#     %s %s", r_str_get (sr->kind), string_ref_type_name (sr->object_type));
	if (R_STR_ISNOTEMPTY (sr->object_name)) {
		char *escaped = r_str_escape_utf8 (sr->object_name, false, true);
		r_strbuf_appendf (sb, " %s", escaped);
		free (escaped);
	}
	if (sr->object_ref > 0) {
		r_strbuf_appendf (sb, " [ref=%" PRIu64 "]", (uint64_t)sr->object_ref);
	}
	if (sr->source_addr > 0) {
		r_strbuf_appendf (sb, " @ 0x%" PFMT64x, (ut64)sr->source_addr);
	}
	r_strbuf_append (sb, "\n");
}

static ut64 string_ref_r2_source_addr(const DartStringRef *sr) {
	if (!sr) {
		return 0;
	}
	if (sr->source_addr > 0) {
		return sr->source_addr;
	}
	if (sr->object_ref > 0) {
		return DART_SYNTHETIC_STRING_REF_BASE + sr->object_ref;
	}
	return 0;
}

static void dump_string_ref_r2(RStrBuf *sb, const DartStringInfo *si, const DartStringRef *sr, bool quiet) {
	if (!quiet) {
		dump_string_ref_text (sb, sr);
	}
	const ut64 source_addr = string_ref_r2_source_addr (sr);
	if (si && si->address > 0 && source_addr > 0) {
		r_strbuf_appendf (sb, "ax 0x%" PFMT64x " 0x%" PFMT64x "\n", (ut64)si->address, source_addr);
	}
}

static void dump_string_text(RStrBuf *sb, const DartStringInfo *si, int fmt, bool quiet, bool refs) {
	if (!si || !si->value) {
		return;
	}
	if (fmt == 'r') {
		// | iz+ ([addr]) ([len]) ([type])  add string manually (addr=current seek if not specified, len=auto, type=auto-detect)
		r_strbuf_appendf (sb, "iz+ 0x%08" PFMT64x " %d\n", si->address, si->length);
		char *flagname = make_string_flagname (si);
		r_strbuf_appendf (sb, "f %s %d @ 0x%08" PFMT64x "\n", flagname, si->length, si->address);
		free (flagname);
		r_strbuf_appendf (sb, "%s %d @ 0x%08" PFMT64x "\n", (si->flags & DART_STRING_TWO_BYTE)? "Csw": "Cs8", si->length, si->address);
	} else {
		char *str = r_str_escape_utf8 (si->value, false, true);
		if (quiet) {
			r_strbuf_appendf (sb, "%s\n", str);
		} else {
			r_strbuf_appendf (sb, "0x%08" PRIx64 " %4d :%s \"%s\"\n", si->address, si->length, string_category_name (si->category), str);
		}
		free (str);
	}
	if (refs && si->references && r_list_length (si->references) > 0) {
		if (!quiet) {
			r_strbuf_appendf (sb, "#   referenced by %d objects\n", r_list_length (si->references));
		}
		RListIter *rit;
		DartStringRef *sr;
		r_list_foreach (si->references, rit, sr) {
			if (!sr) {
				continue;
			}
			if (fmt == 'r') {
				dump_string_ref_r2 (sb, si, sr, quiet);
			} else if (!quiet) {
				dump_string_ref_text (sb, sr);
			}
		}
	}
}

static char *dump_strings_list(DartCtx *ctx, RList *strings, int fmt) {
	const bool refs = ctx && ctx->dump_string_refs;
	if (fmt == 'j') {
		if (!strings || r_list_length (strings) == 0) {
			return strdup ("[]");
		}
		PJ *pj = pj_new ();
		pj_a (pj);
		RListIter *it;
		DartStringInfo *si;
		r_list_foreach (strings, it, si) {
			if (si) {
				dump_string_json (pj, si, refs);
			}
		}
		pj_end (pj);
		return pj_drain (pj);
	}
	if (!strings) {
		return strdup ("# No strings found\n");
	}
	const bool quiet = ctx && ctx->quiet;
	RStrBuf *sb = r_strbuf_new (fmt == 'r' && !quiet? "# Dart Strings\n": "");
	RListIter *it;
	DartStringInfo *si;
	r_list_foreach (strings, it, si) {
		dump_string_text (sb, si, fmt, quiet, refs);
	}
	if (fmt == 'r' && !quiet) {
		r_strbuf_appendf (sb, "# Total: %d strings\n", r_list_length (strings));
	}
	return r_strbuf_drain (sb);
}

char *dart_pool_dump_strings(DartCtx *ctx, int fmt) {
	RList *strings = dart_pool_extract_object_pool_strings (ctx);
	char *out = dump_strings_list (ctx, strings, fmt);
	dart_string_list_free (strings);
	return out;
}

char *dart_pool_dump_strings_fuzzy(DartCtx *ctx, int fmt) {
	DartRecoveryModel model = { 0 };
	dart_recovery_model_load (ctx, &model, DART_RECOVERY_STRINGS | DART_RECOVERY_CLASSES | DART_RECOVERY_STRING_REFS);
	char *out = dump_strings_list (ctx, model.strings, fmt);
	dart_recovery_model_fini (&model);
	return out;
}
