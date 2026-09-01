/* r2flutter - MIT - Copyright 2026 - pancake */

#include <ctype.h>
#include "dart_pool_parse_priv.h"

// Window size for the read cache. Cluster streams are decoded one byte at a
// time, so serving those reads from a prefetched window turns millions of
// r_io_read_at calls into a handful.
#define RMEM_WINDOW (1024 * 1024)

bool read_mem(DartCtx *ctx, ut64 addr, void *buf, int len) {
	if (!ctx || !ctx->core || !buf || len <= 0) {
		return false;
	}
	// Fast path: request fully contained in the cached window.
	if (ctx->rmem_cache && addr >= ctx->rmem_cache_addr) {
		ut64 off = addr - ctx->rmem_cache_addr;
		if (off + (ut64)len <= (ut64)ctx->rmem_cache_len) {
			memcpy (buf, ctx->rmem_cache + off, (size_t)len);
			return true;
		}
	}
	// Reads larger than the window bypass the cache.
	if (len > RMEM_WINDOW) {
		return r_io_read_at (ctx->core->io, addr, (ut8 *)buf, len);
	}
	if (!ctx->rmem_cache) {
		ctx->rmem_cache = malloc (RMEM_WINDOW);
		if (!ctx->rmem_cache) {
			return r_io_read_at (ctx->core->io, addr, (ut8 *)buf, len);
		}
		ctx->rmem_cache_cap = RMEM_WINDOW;
	}
	// Refill the window at addr. r_io_read_at only succeeds when the whole
	// range is readable, so a successful window read means every byte in it is
	// valid and safe to serve. On failure (e.g. near the end of a mapped
	// region) fall back to an exact read and keep any previous window intact.
	if (r_io_read_at (ctx->core->io, addr, ctx->rmem_cache, ctx->rmem_cache_cap)) {
		ctx->rmem_cache_addr = addr;
		ctx->rmem_cache_len = ctx->rmem_cache_cap;
		memcpy (buf, ctx->rmem_cache, (size_t)len);
		return true;
	}
	return r_io_read_at (ctx->core->io, addr, (ut8 *)buf, len);
}

#define READ_LE_AT(bits, type) \
	bool read_u ## bits ## _at (DartCtx *ctx, ut64 addr, type *out) { \
		ut8 buf[bits / 8]; \
		if (!out || !read_mem (ctx, addr, buf, sizeof (buf))) { \
			return false; \
		} \
		*out = r_read_le ## bits (buf); \
		return true; \
	}

READ_LE_AT(32, ut32)
READ_LE_AT(64, ut64)

bool dart_read_unsigned_at(DartCtx *ctx, ut64 addr, ut64 *out_val, ut64 *out_next) {
	ut64 v = 0;
	int shift = 0;
	for (int i = 0; i < 10; i++) {
		ut8 b = 0;
		if (!read_mem (ctx, addr + i, &b, 1)) {
			return false;
		}
		if (b > 0x7f) {
			v |= ((ut64) (b - 0x80)) << shift;
			if (out_val) {
				*out_val = v;
			}
			if (out_next) {
				*out_next = addr + i + 1;
			}
			return true;
		}
		v |= ((ut64)b) << shift;
		shift += 7;
	}
	return false;
}

bool dart_read_unsigned_buf(const ut8 *buf, ut64 size, ut64 pos, ut64 *out_val, ut64 *out_next) {
	if (!buf || pos >= size) {
		return false;
	}
	ut64 v = 0;
	int shift = 0;
	ut64 end = pos + R_MIN (size - pos, 10);
	for (; pos < end; pos++, shift += 7) {
		ut8 b = buf[pos];
		if (b > 0x7f) {
			v |= ((ut64) (b - 0x80)) << shift;
			if (out_val) {
				*out_val = v;
			}
			if (out_next) {
				*out_next = pos + 1;
			}
			return true;
		}
		v |= ((ut64)b) << shift;
	}
	return false;
}

char *dart_utf16le_to_utf8(const ut8 *buf, ut64 size) {
	if (!buf || size < 2 || (size & 1)) {
		return NULL;
	}
	RStrBuf sb;
	r_strbuf_init (&sb);
	for (ut64 pos = 0; pos + 1 < size; pos += 2) {
		ut32 code = r_read_le16 (buf + pos);
		if (!code || (code >= 0xd800 && code <= 0xdfff)) {
			r_strbuf_fini (&sb);
			return NULL;
		}
		if (code < 0x80) {
			char ch = (char)code;
			r_strbuf_append_n (&sb, &ch, 1);
		} else if (code < 0x800) {
			char tmp[2] = {
				(char) (0xc0 | (code >> 6)),
				(char) (0x80 | (code & 0x3f))
			};
			r_strbuf_append_n (&sb, tmp, 2);
		} else {
			char tmp[3] = {
				(char) (0xe0 | (code >> 12)),
				(char) (0x80 | ((code >> 6) & 0x3f)),
				(char) (0x80 | (code & 0x3f))
			};
			r_strbuf_append_n (&sb, tmp, 3);
		}
	}
	const char *utf8 = r_strbuf_get (&sb);
	char *out = utf8? strdup (utf8): NULL;
	r_strbuf_fini (&sb);
	return out;
}

static const DartVerLayout *dart_snapshot_header_layout(DartCtx *ctx, const char *hash) {
	if (ctx && ctx->layout) {
		return ctx->layout;
	}
	if (ctx && R_STR_ISNOTEMPTY (ctx->dart_version_override)) {
		const DartVerLayout *layout = dart_profile_from_version (ctx->dart_version_override);
		if (layout) {
			return layout;
		}
	}
	const char *version = dart_version_from_hash (hash);
	const DartVerLayout *layout = version? dart_profile_from_version (version): NULL;
	return layout? layout: dart_newest_profile ();
}

static bool dart_snapshot_header_set_fields(DartSnapshotHeader *out, const DartVerLayout *layout, const ut64 *fields, int count) {
	if (!out || !layout || !fields || count != layout->header_fields) {
		return false;
	}
	switch (layout->header_style) {
	case DART_HEADER_STYLE_210:
		out->nb = fields[0];
		out->no = fields[1];
		out->nc = fields[2];
		out->field_table_len = fields[3];
		break;
	case DART_HEADER_STYLE_212:
		if (UT64_MAX - fields[2] < fields[3]) {
			return false;
		}
		out->nb = fields[0];
		out->no = fields[1];
		out->ncc = fields[2];
		out->nc = fields[2] + fields[3];
		out->field_table_len = fields[4];
		break;
	case DART_HEADER_STYLE_214:
		out->nb = fields[0];
		out->no = fields[1];
		out->nc = fields[2];
		out->field_table_len = fields[3];
		out->itlen = fields[4];
		break;
	case DART_HEADER_STYLE_216:
		out->nb = fields[0];
		out->no = fields[1];
		out->nc = fields[2];
		out->field_table_len = fields[3];
		out->itlen = fields[4];
		out->itdata = fields[5];
		break;
	case DART_HEADER_STYLE_MODERN:
		out->nb = fields[0];
		out->no = fields[1];
		out->nc = fields[2];
		out->itlen = fields[3];
		out->itdata = fields[4];
		break;
	default:
		return false;
	}
	return true;
}

static bool dart_snapshot_outer_read(DartCtx *ctx, ut64 base, DartSnapshotHeader *out, ut64 *out_cursor) {
	if (!ctx || !out) {
		return false;
	}
	memset (out, 0, sizeof (*out));
	ut8 hdr[DART_SNAPSHOT_FIXED_SIZE];
	if (!read_mem (ctx, base, hdr, sizeof (hdr))) {
		return false;
	}
	out->magic = r_read_le32 (hdr);
	if (out->magic != DART_SNAPSHOT_MAGIC) {
		return false;
	}
	const ut64 stored_len = r_read_le64 (hdr + 4);
	if (stored_len > UT64_MAX - 4) {
		return false;
	}
	out->total_len = stored_len + 4;
	if (out->total_len < DART_SNAPSHOT_FIXED_SIZE + DART_SNAPSHOT_HASH_SIZE + 1 || out->total_len > (1ULL << 34) || base > UT64_MAX - out->total_len) {
		return false;
	}
	RIOMap *map = r_io_map_get_at (ctx->core->io, base);
	if (map && base + out->total_len - 1 > r_io_map_to (map)) {
		return false;
	}
	out->kind = r_read_le64 (hdr + 12);
	ut64 cursor = base + DART_SNAPSHOT_FIXED_SIZE;
	if (!read_mem (ctx, cursor, out->hash, DART_SNAPSHOT_HASH_SIZE)) {
		return false;
	}
	out->hash[DART_SNAPSHOT_HASH_SIZE] = '\0';
	for (int i = 0; i < DART_SNAPSHOT_HASH_SIZE; i++) {
		if (!isxdigit ((ut8)out->hash[i])) {
			return false;
		}
	}
	cursor += DART_SNAPSHOT_HASH_SIZE;
	ut8 b = 0;
	int scanned = 0;
	const ut64 snapshot_end = base + out->total_len;
	while (scanned < DART_SNAPSHOT_FEATURES_SCAN_MAX && cursor + (ut64)scanned < snapshot_end) {
		if (!read_mem (ctx, cursor + scanned, &b, 1)) {
			return false;
		}
		if (!b) {
			break;
		}
		scanned++;
	}
	if (b || cursor + (ut64)scanned >= snapshot_end) {
		return false;
	}
	int tocopy = R_MIN (scanned, (int)sizeof (out->flags) - 1);
	if (tocopy > 0 && !read_mem (ctx, cursor, (ut8 *)out->flags, tocopy)) {
		return false;
	}
	out->flags[tocopy] = '\0';
	cursor += (ut64)scanned + 1;
	if (cursor >= snapshot_end) {
		return false;
	}
	if (out_cursor) {
		*out_cursor = cursor;
	}
	return true;
}

bool dart_snapshot_fingerprint_read(DartCtx *ctx, ut64 base, DartSnapshotHeader *out) {
	return dart_snapshot_outer_read (ctx, base, out, NULL);
}

bool dart_snapshot_header_read(DartCtx *ctx, ut64 base, DartSnapshotHeader *out) {
	ut64 cursor = 0;
	if (!dart_snapshot_outer_read (ctx, base, out, &cursor)) {
		return false;
	}
	const DartVerLayout *layout = dart_snapshot_header_layout (ctx, out->hash);
	if (!layout || layout->header_fields < 4 || layout->header_fields > 6) {
		return false;
	}
	ut64 next = cursor;
	ut64 fields[6] = { 0 };
	for (int i = 0; i < layout->header_fields; i++) {
		if (!dart_read_unsigned_at (ctx, next, &fields[i], &next)) {
			return false;
		}
	}
	if (!dart_snapshot_header_set_fields (out, layout, fields, layout->header_fields)) {
		return false;
	}
	out->cluster_start = next;
	out->ok = true;
	return true;
}

bool dart_snapshot_header_read_buf(const ut8 *buf, ut64 size, const DartVerLayout *layout, DartSnapshotHeader *out) {
	if (!buf || !out || size < DART_SNAPSHOT_FIXED_SIZE + DART_SNAPSHOT_HASH_SIZE + 1) {
		return false;
	}
	memset (out, 0, sizeof (*out));
	out->magic = r_read_le32 (buf);
	if (out->magic != DART_SNAPSHOT_MAGIC) {
		return false;
	}
	out->total_len = r_read_le64 (buf + 4) + 4;
	if (out->total_len > size) {
		return false;
	}
	out->kind = r_read_le64 (buf + 12);
	ut64 cursor = DART_SNAPSHOT_FIXED_SIZE;
	memcpy (out->hash, buf + cursor, DART_SNAPSHOT_HASH_SIZE);
	out->hash[DART_SNAPSHOT_HASH_SIZE] = '\0';
	cursor += DART_SNAPSHOT_HASH_SIZE;
	int scanned = 0;
	while (cursor + scanned < size && scanned < DART_SNAPSHOT_FEATURES_SCAN_MAX) {
		if (!buf[cursor + scanned]) {
			break;
		}
		scanned++;
	}
	if (cursor + scanned >= size || buf[cursor + scanned]) {
		return false;
	}
	int tocopy = R_MIN (scanned, (int)sizeof (out->flags) - 1);
	if (tocopy > 0) {
		memcpy (out->flags, buf + cursor, (size_t)tocopy);
	}
	out->flags[tocopy] = '\0';
	cursor += (ut64)scanned + 1;
	if (!layout) {
		layout = dart_snapshot_header_layout (NULL, out->hash);
	}
	if (!layout || layout->header_fields < 4 || layout->header_fields > 6) {
		return false;
	}
	ut64 next = cursor;
	ut64 fields[6] = { 0 };
	for (int i = 0; i < layout->header_fields; i++) {
		if (!dart_read_unsigned_buf (buf, size, next, &fields[i], &next)) {
			return false;
		}
	}
	if (!dart_snapshot_header_set_fields (out, layout, fields, layout->header_fields)) {
		return false;
	}
	if (next >= out->total_len) {
		return false;
	}
	out->cluster_start = next;
	out->ok = true;
	return true;
}

bool cs_read_u8(ClusterStream *s, ut8 *out) {
	if (!s || !out || s->cursor >= s->end) {
		return false;
	}
	return read_mem (s->ctx, s->cursor++, out, 1);
}

bool cs_read_u32(ClusterStream *s, uint32_t *out) {
	if (!s || !out || s->cursor + 4 > s->end) {
		return false;
	}
	bool ok = read_u32_at (s->ctx, s->cursor, out);
	s->cursor += 4;
	return ok;
}

bool cs_read_unsigned(ClusterStream *s, ut64 *out) {
	if (!s || s->cursor >= s->end) {
		return false;
	}
	ut8 buf[10];
	ut64 next = 0;
	int len = (int)R_MIN (s->end - s->cursor, sizeof (buf));
	if (!read_mem (s->ctx, s->cursor, buf, len) || !dart_read_unsigned_buf (buf, len, 0, out, &next)) {
		return false;
	}
	s->cursor += next;
	return true;
}

bool cs_read_ref_id(ClusterStream *s, ut64 *out) {
	if (s && s->ctx && s->ctx->layout && s->ctx->layout->ref_encoding == DART_REF_ENCODING_UNSIGNED) {
		return cs_read_unsigned (s, out);
	}
	int64_t result = 0;
	for (int i = 0; i < 5; i++) {
		ut8 raw = 0;
		if (!cs_read_u8 (s, &raw)) {
			return false;
		}
		int8_t b = (int8_t)raw;
		result = (int64_t)b + (result << 7);
		if (b < 0) {
			if (out) {
				*out = (ut64) (result + 128);
			}
			return true;
		}
	}
	return false;
}

bool cs_read_tagged32(ClusterStream *s, ut32 *out) {
	ut8 b = 0;
	if (!cs_read_u8 (s, &b)) {
		return false;
	}
	if (b > 0x7f) {
		if (out) {
			*out = (ut32) (b - 0xc0);
		}
		return true;
	}
	ut32 v = 0;
	int shift = 0;
	v |= (ut32)b;
	shift += 7;
	for (int i = 1; i < 5; i++) {
		if (!cs_read_u8 (s, &b)) {
			return false;
		}
		if (b > 0x7f) {
			v |= ((ut32) (b - 0xc0)) << shift;
			if (out) {
				*out = v;
			}
			return true;
		}
		v |= ((ut32)b) << shift;
		shift += 7;
	}
	return false;
}

bool cs_read_tagged64(ClusterStream *s, int64_t *out) {
	ut8 raw = 0;
	if (!cs_read_u8 (s, &raw)) {
		return false;
	}
	int8_t b = (int8_t)raw;
	if (b < 0) {
		if (out) {
			*out = (int64_t)b + 192;
		}
		return true;
	}
	int64_t v = (int64_t)raw;
	int shift = 7;
	for (int i = 1; i < 10; i++) {
		if (!cs_read_u8 (s, &raw)) {
			return false;
		}
		b = (int8_t)raw;
		if (b < 0) {
			v |= ((int64_t)b + 192) << shift;
			if (out) {
				*out = v;
			}
			return true;
		}
		v |= ((int64_t)raw) << shift;
		shift += 7;
	}
	return false;
}

bool cs_read_bytes(ClusterStream *s, ut8 *buf, int len) {
	if (!s || !buf || len <= 0 || s->cursor + len > s->end) {
		return false;
	}
	bool ok = read_mem (s->ctx, s->cursor, buf, len);
	s->cursor += len;
	return ok;
}
