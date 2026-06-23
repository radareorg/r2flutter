/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

bool read_mem(DartCtx *ctx, ut64 addr, void *buf, int len) {
	if (!ctx || !ctx->core || !buf || len <= 0) {
		return false;
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

bool dart_snapshot_header_read(DartCtx *ctx, ut64 base, DartSnapshotHeader *out) {
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
	out->total_len = r_read_le64 (hdr + 4) + 4;
	out->kind = r_read_le64 (hdr + 12);
	ut64 cursor = base + DART_SNAPSHOT_FIXED_SIZE;
	if (!read_mem (ctx, cursor, out->hash, DART_SNAPSHOT_HASH_SIZE)) {
		return false;
	}
	out->hash[DART_SNAPSHOT_HASH_SIZE] = '\0';
	cursor += DART_SNAPSHOT_HASH_SIZE;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < DART_SNAPSHOT_FEATURES_SCAN_MAX) {
		if (!read_mem (ctx, cursor + scanned, &b, 1)) {
			return false;
		}
		if (!b) {
			break;
		}
		scanned++;
	}
	if (b) {
		return false;
	}
	int tocopy = R_MIN (scanned, (int)sizeof (out->flags) - 1);
	if (tocopy > 0 && !read_mem (ctx, cursor, (ut8 *)out->flags, tocopy)) {
		return false;
	}
	out->flags[tocopy] = '\0';
	cursor += (ut64)scanned + 1;
	ut64 next = cursor;
	if (!dart_read_unsigned_at (ctx, next, &out->nb, &next)) {
		return false;
	}
	if (!dart_read_unsigned_at (ctx, next, &out->no, &next)) {
		return false;
	}
	if (!dart_read_unsigned_at (ctx, next, &out->nc, &next)) {
		return false;
	}
	if (!dart_read_unsigned_at (ctx, next, &out->itlen, &next)) {
		return false;
	}
	if (!dart_read_unsigned_at (ctx, next, &out->itdata, &next)) {
		return false;
	}
	out->cluster_start = next;
	out->ok = true;
	return true;
}

bool dart_snapshot_header_read_buf(const ut8 *buf, ut64 size, DartSnapshotHeader *out) {
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
	ut64 next = cursor;
	if (!dart_read_unsigned_buf (buf, size, next, &out->nb, &next)) {
		return false;
	}
	if (!dart_read_unsigned_buf (buf, size, next, &out->no, &next)) {
		return false;
	}
	if (!dart_read_unsigned_buf (buf, size, next, &out->nc, &next)) {
		return false;
	}
	if (!dart_read_unsigned_buf (buf, size, next, &out->itlen, &next)) {
		return false;
	}
	if (!dart_read_unsigned_buf (buf, size, next, &out->itdata, &next)) {
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
