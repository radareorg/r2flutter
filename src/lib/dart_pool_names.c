/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

typedef struct {
	ut64 ep_offs[8];
	int ep_offs_n;
	ut64 owner_offs[8];
	int owner_offs_n;
	ut64 name_offs[8];
	int name_offs_n;
} LayoutHints;

static void init_layout_hints(LayoutHints *lh) {
	memset (lh, 0, sizeof (*lh));
	lh->ep_offs[lh->ep_offs_n++] = 8;
	lh->ep_offs[lh->ep_offs_n++] = 24;
	lh->ep_offs[lh->ep_offs_n++] = 16;
	lh->ep_offs[lh->ep_offs_n++] = 32;
	lh->owner_offs[lh->owner_offs_n++] = 56;
	lh->name_offs[lh->name_offs_n++] = 24;
	lh->name_offs[lh->name_offs_n++] = 8;
}

static bool read_heap_ptr(DartCtx *ctx, ut64 addr, ut64 data_image_base, ut64 *out_abs) {
	if (!ctx || !out_abs) {
		return false;
	}
	if (ctx->compressed_word_size == 4) {
		ut64 v64_abs = 0;
		if (read_u64_at (ctx, addr, &v64_abs)) {
			if (v64_abs >= data_image_base && v64_abs < data_image_base + (1ULL << 34)) {
				*out_abs = v64_abs;
				return true;
			}
		}
		ut32 v32 = 0;
		if (!read_u32_at (ctx, addr, &v32)) {
			return false;
		}
		const ut64 masks[] = { 0ULL, 1ULL, 3ULL, 7ULL };
		const ut64 shifts[] = { 0ULL, 1ULL, 2ULL, 3ULL };
		for (int im = 0; im < 4; im++) {
			for (int is = 0; is < 4; is++) {
				ut64 off = ((ut64)v32 & ~masks[im]) << shifts[is];
				ut64 abs = data_image_base + off;
				if (abs >= data_image_base && abs < data_image_base + (1ULL << 34)) {
					*out_abs = abs;
					return true;
				}
			}
		}
		return false;
	}
	ut64 v64 = 0;
	if (!read_u64_at (ctx, addr, &v64)) {
		return false;
	}
	*out_abs = v64;
	return true;
}

// Returns 1 for a decoded text string, 0 when addr is not a recognised 64-bit
// string object, and -1 for a recognised string whose payload is not text.
static int try_read_dart_string_object64(DartCtx *ctx, ut64 addr, char *out, int outsz) {
	if (!ctx || !ctx->layout || ctx->compressed_word_size != 8) {
		return false;
	}
	ut8 hdr[16];
	if (!read_mem (ctx, addr, hdr, sizeof (hdr))) {
		return false;
	}
	const ut32 cid = dart_cid_from_object_header (r_read_le64 (hdr));
	const int one_byte_cid = dart_cid_get (ctx->layout, DART_CID_ONE_BYTE_STRING);
	const int two_byte_cid = dart_cid_get (ctx->layout, DART_CID_TWO_BYTE_STRING);
	const bool is_two_byte = two_byte_cid >= 0 && cid == (ut32)two_byte_cid;
	if (!is_two_byte && (one_byte_cid < 0 || cid != (ut32)one_byte_cid)) {
		return false;
	}
	const ut64 length_smi = r_read_le64 (hdr + 8);
	if ((length_smi & 1) != 0) {
		return -1;
	}
	const ut64 length = length_smi >> 1;
	if (!length || length > 1024) {
		return -1;
	}
	const ut64 bytes_len = is_two_byte? length * 2: length;
	ut8 *bytes = (ut8 *)malloc ((size_t)bytes_len);
	if (!bytes || !read_mem (ctx, addr + 16, bytes, (int)bytes_len)) {
		free (bytes);
		return -1;
	}
	if (is_two_byte) {
		for (ut64 i = 0; i < length; i++) {
			const ut16 code = r_read_le16 (bytes + (i * 2));
			if (code < 0x20 || (code >= 0x7f && code < 0xa0)) {
				free (bytes);
				return -1;
			}
		}
		char *utf8 = dart_utf16le_to_utf8 (bytes, bytes_len);
		free (bytes);
		if (R_STR_ISEMPTY (utf8)) {
			free (utf8);
			return -1;
		}
		r_str_ncpy (out, utf8, outsz);
		free (utf8);
		return true;
	}
	int written = 0;
	for (ut64 i = 0; i < length; i++) {
		const ut8 ch = bytes[i];
		if (ch < 0x20 || (ch >= 0x7f && ch < 0xa0)) {
			free (bytes);
			return -1;
		}
		if (ch < 0x80) {
			if (written + 1 >= outsz) {
				break;
			}
			out[written++] = (char)ch;
		} else {
			if (written + 2 >= outsz) {
				break;
			}
			out[written++] = (char) (0xc0 | (ch >> 6));
			out[written++] = (char) (0x80 | (ch & 0x3f));
		}
	}
	out[written] = '\0';
	free (bytes);
	return true;
}

bool try_read_dart_string(DartCtx *ctx, ut64 addr, char *out, int outsz) {
	if (!ctx || !out || outsz <= 1) {
		return false;
	}
	const int object_string = try_read_dart_string_object64 (ctx, addr, out, outsz);
	if (object_string) {
		return object_string > 0;
	}
	ut8 hdr[32];
	if (!read_mem (ctx, addr, hdr, sizeof (hdr))) {
		return false;
	}
	for (int off = 0; off <= 16; off += 8) {
		ut64 len_smi = r_read_le64 (hdr + off + 8);
		ut64 len = 0;
		if ((len_smi & 1ULL) == 0) {
			len = len_smi >> 1;
		} else {
			len = len_smi & 0xffffffffULL;
		}
		if (len == 0 || len > 1024) {
			continue;
		}
		ut64 str_addr = addr + off + 24;
		int ok = 1;
		for (ut64 i = 0; i < len; i++) {
			ut8 b2 = 0;
			if (!read_mem (ctx, str_addr + i, &b2, 1)) {
				ok = 0;
				break;
			}
			if (!IS_PRINTABLE (b2)) {
				ok = 0;
				break;
			}
		}
		if (!ok) {
			continue;
		}
		ut64 cplen = len < (ut64) (outsz - 1)? len: (ut64) (outsz - 1);
		if (!read_mem (ctx, str_addr, (ut8 *)out, (int)cplen)) {
			continue;
		}
		out[cplen] = '\0';
		return true;
	}
	ut8 tmp[256];
	if (read_mem (ctx, addr, tmp, sizeof (tmp))) {
		int start = -1, end = -1;
		for (int i = 0; i < (int)sizeof (tmp); i++) {
			if (IS_PRINTABLE (tmp[i])) {
				if (start < 0) {
					start = i;
				}
				end = i;
			} else if (start >= 0) {
				break;
			}
		}
		if (start >= 0 && end >= start) {
			int n = end - start + 1;
			r_str_ncpy (out, (const char *)tmp + start, R_MIN (n + 1, outsz));
			return true;
		}
	}
	return false;
}

char *try_read_dart_string_dup(DartCtx *ctx, ut64 addr) {
	char buf[1025];
	return try_read_dart_string (ctx, addr, buf, sizeof (buf))? strdup (buf): NULL;
}

HtUP *scan_code_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	LayoutHints lh;
	init_layout_hints (&lh);
	HtUP *name_by_ep = ht_up_new0 ();
	if (!name_by_ep) {
		return NULL;
	}
	ut64 max_hits = 200;
	if (data_image_end <= data_image_base) {
		return name_by_ep;
	}
	for (ut64 a = data_image_base; a + 0x30 < data_image_end; a += 16) {
		for (int ie = 0; ie < lh.ep_offs_n; ie++) {
			ut64 ep = 0;
			if (!read_u64_at (ctx, a + lh.ep_offs[ie], &ep)) {
				continue;
			}
			if (ep < ctx->iso_instr) {
				continue;
			}
			if (ep - ctx->iso_instr > (1ULL << 24)) {
				continue;
			}
			for (int io = 0; io < lh.owner_offs_n; io++) {
				ut64 owner = 0;
				if (!read_heap_ptr (ctx, a + lh.owner_offs[io], data_image_base, &owner)) {
					continue;
				}
				if (owner < data_image_base || owner >= data_image_end) {
					continue;
				}
				for (int in = 0; in < lh.name_offs_n; in++) {
					ut64 namep = 0;
					if (!read_heap_ptr (ctx, owner + lh.name_offs[in], data_image_base, &namep)) {
						continue;
					}
					if (namep < data_image_base || namep >= data_image_end) {
						continue;
					}
					char sname[128];
					if (try_read_dart_string (ctx, namep, sname, sizeof (sname))) {
						r_str_filter_zeroline (sname, sizeof (sname));
						bool looks_ok = false;
						if (strstr (sname, "package:") || strstr (sname, "dart:")) {
							looks_ok = true;
						}
						if (!looks_ok && (strchr (sname, '.') || strchr (sname, '/') || strchr (sname, ':'))) {
							looks_ok = true;
						}
						if (looks_ok) {
							char *dup = strdup (sname);
							if (dup) {
								ht_up_update (name_by_ep, ep, dup);
								if (--max_hits == 0) {
									return name_by_ep;
								}
							}
						}
					}
				}
			}
		}
	}
	return name_by_ep;
}

#define CHUNK_SIZE 4096

typedef struct {
	const char *needle;
	int len;
	int min_match;
} DataNameNeedle;

static const DataNameNeedle data_name_needles[] = {
	{ "package:", 8, 8 },
	{ "dart:", 5, 5 },
};

// Extract a printable ASCII string starting at buf[pos], return length or 0
static int extract_printable_string(const ut8 *buf, int pos, int buflen, char *out, int outsz) {
	int k = 0;
	for (int j = pos; j < buflen && k < outsz - 1; j++) {
		ut8 ch = buf[j];
		if (ch == '\0') {
			break;
		}
		if (IS_PRINTABLE (ch)) {
			out[k++] = (char)ch;
		} else {
			break;
		}
	}
	out[k] = '\0';
	return k;
}

RList *collect_data_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	ut8 buf[CHUNK_SIZE];
	RList *out = r_list_newf (free);
	ut64 limit = data_image_end - data_image_base;
	if (limit > (1ULL << 22)) {
		limit = (1ULL << 22);
	}
	ut64 cap = 512;
	for (ut64 off = 0; off < limit; off += (sizeof (buf) - 8)) {
		ut64 addr = data_image_base + off;
		int toread = (int) ((off + sizeof (buf) <= limit)? sizeof (buf): (limit - off));
		if (toread <= 0) {
			break;
		}
		if (!read_mem (ctx, addr, buf, toread)) {
			break;
		}
		for (int i = 0; i + 8 < toread; i++) {
			size_t n;
			for (n = 0; n < R_ARRAY_SIZE (data_name_needles); n++) {
				const DataNameNeedle *needle = &data_name_needles[n];
				if (buf[i] != needle->needle[0]) {
					continue;
				}
				if (i + needle->len > toread) {
					continue;
				}
				if (memcmp (buf + i, needle->needle, needle->len)) {
					continue;
				}
				char s[128];
				int k = extract_printable_string (buf, i, toread, s, sizeof (s));
				if (k > needle->min_match) {
					char *dup = strdup (s);
					if (dup) {
						r_list_append (out, dup);
						if (--cap == 0) {
							return out;
						}
					}
				}
				break;
			}
		}
	}
	return out;
}

void collect_data_names_with_r2(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return;
	}
	if (!ctx->name_pool) {
		ctx->name_pool = r_list_newf (free);
	}
	ut64 limit = data_image_end - data_image_base;
	if (limit > (1ULL << 22)) {
		limit = (1ULL << 22);
	}
	const char *needles[] = { "package:", "dart:" };
	char *out = NULL;
	for (int k = 0; k < 2; k++) {
		out = r_core_cmd_strf (ctx->core, "e search.in=range; e search.from=0x%" PFMT64x "; e search.to=0x%" PFMT64x "; /c %s\n", data_image_base, data_image_base + limit, needles[k]);
		if (!out) {
			continue;
		}
		char *line, *saveptr = NULL;
		for (line = strtok_r (out, "\n", &saveptr); line; line = strtok_r (NULL, "\n", &saveptr)) {
			if (!r_str_startswith (line, "0x")) {
				continue;
			}
			ut64 addr = (ut64)strtoull (line, NULL, 16);
			char s[128] = { 0 };
			if (try_read_dart_string (ctx, addr, s, sizeof (s))) {
				char *dup = strdup (s);
				if (dup) {
					r_list_append (ctx->name_pool, dup);
				}
			} else {
				ut8 buf[128];
				if (read_mem (ctx, addr, buf, sizeof (buf))) {
					char s2[128];
					int z = extract_printable_string (buf, 0, sizeof (buf), s2, sizeof (s2));
					if (z > 5) {
						char *dup2 = strdup (s2);
						if (dup2) {
							r_list_append (ctx->name_pool, dup2);
						}
					}
				}
			}
			if (r_list_length (ctx->name_pool) >= 512) {
				break;
			}
		}
		free (out);
		if (r_list_length (ctx->name_pool) >= 512) {
			break;
		}
	}
}
