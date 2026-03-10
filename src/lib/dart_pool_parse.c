/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <r_core.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_util/r_json.h>
#include <r_util/r_file.h>
#include <r_util/r_name.h>
#include <r_util/r_strbuf.h>
#include <sdb/ht_pp.h>
#include <r_list.h>
#include "../../include/r2flutter/dart_obf.h"
#include "../../include/r2flutter/dart_pool_parse.h"
#include "../../include/r2flutter/dart_version.h"
#include "../../include/r2flutter/dart_r2.h"

static const char *dart_tag_style_names[] = {
	"CID_INT32", // DART_TAG_STYLE_CID_INT32 = 0
	"CID_SHIFT1", // DART_TAG_STYLE_CID_SHIFT1 = 1
	"OBJECT_HEADER", // DART_TAG_STYLE_OBJECT_HEADER = 2
};

static inline const char *dart_tag_style_to_string(DartTagStyle style) {
	if (style >= 0 && style < (sizeof (dart_tag_style_names) / sizeof (dart_tag_style_names[0]))) {
		return dart_tag_style_names[style];
	}
	return "unknown";
}

static inline const char *dart_tag_style_to_string_verbose(DartTagStyle style) {
	switch (style) {
	case DART_TAG_STYLE_CID_INT32:
		return "CID_INT32 (v2.10-2.13)";
	case DART_TAG_STYLE_CID_SHIFT1:
		return "CID_SHIFT1 (v2.14-3.3)";
	case DART_TAG_STYLE_OBJECT_HEADER:
		return "OBJECT_HEADER (v3.4+)";
	default:
		return "unknown";
	}
}

typedef enum {
	kIllegalCid = 0,
	kClassCid = 5,
	kPatchClassCid = 6,
	kFunctionCid = 7,
	kClosureDataCid = 8,
	kFfiTrampolineDataCid = 9,
	kFieldCid = 10,
	kScriptCid = 11,
	kLibraryCid = 12,
	kNamespaceCid = 13,
	kKernelProgramInfoCid = 14,
	kCodeCid = 40,
	kInstructionsCid = 41,
	kObjectPoolCid = 45,
	kCodeSourceMapCid = 49,
	kPcDescriptorsCid = 50,
	kStringCid = 72,
	kOneByteStringCid = 73,
	kTwoByteStringCid = 74,
	kArrayCid = 75,
	kImmutableArrayCid = 76,
	kGrowableObjectArrayCid = 77,
	kTypedDataBaseCid = 80,
	kMintCid = 78,
	kDoubleCid = 79,
	kTypeCid = 110,
	kFunctionTypeCid = 111,
	kRecordTypeCid = 112,
	kTypeParametersCid = 113,
	kTypeParameterCid = 114,
	kTypeArgumentsCid = 115,
	kNumPredefinedCids = 128
} DartCid;

typedef struct {
	ut64 ref_id;
	ut64 name_ref;
	ut64 library_ref;
	char *name;
	int instance_size;
} DartClass;

typedef struct {
	ut64 ref_id;
	ut64 name_ref;
	ut64 owner_ref;
	ut64 code_ref;
	ut64 entry_point;
	char *name;
} DartPoolFunction;

static bool read_mem(DartCtx *ctx, ut64 addr, void *buf, int len) {
	if (!ctx || !ctx->core || !buf || len <= 0) {
		return false;
	}
	int r = r_io_read_at (ctx->core->io, addr, (ut8 *)buf, len);
	return r > 0;
}
static bool read_uleb128_at(DartCtx *ctx, ut64 addr, ut64 *out_val, ut64 *out_next) {
	ut64 v = 0;
	int shift = 0;
	for (int i = 0; i < 10; i++) {
		ut8 b = 0;
		if (!read_mem (ctx, addr + i, &b, 1)) {
			return false;
		}
		v |= ((ut64) (b & 0x7f)) << shift;
		if ((b & 0x80) == 0) {
			if (out_val) {
				*out_val = v;
			}
			if (out_next) {
				*out_next = addr + i + 1;
			}
			return true;
		}
		shift += 7;
	}
	return false;
}

static bool try_read_dart_string(DartCtx *ctx, ut64 addr, char *out, int outsz);
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
	lh->ep_offs[lh->ep_offs_n++] = 0x10;
	lh->ep_offs[lh->ep_offs_n++] = 0x18;
	lh->ep_offs[lh->ep_offs_n++] = 0x20;
	lh->owner_offs[lh->owner_offs_n++] = 0x10;
	lh->owner_offs[lh->owner_offs_n++] = 0x18;
	lh->owner_offs[lh->owner_offs_n++] = 0x20;
	lh->name_offs[lh->name_offs_n++] = 0x10;
	lh->name_offs[lh->name_offs_n++] = 0x18;
	lh->name_offs[lh->name_offs_n++] = 0x20;
}

static void read_json_u64_array(const RJson *parent, const char *key, ut64 *out, int *out_n, int max) {
	const RJson *arr = r_json_get (parent, key);
	if (arr && arr->type == R_JSON_ARRAY) {
		*out_n = 0;
		size_t n = arr->children.count;
		for (size_t i = 0; i < n && *out_n < max; i++) {
			const RJson *el = r_json_item (arr, i);
			if (el && el->type == R_JSON_INTEGER) {
				out[(*out_n)++] = (ut64)el->num.u_value;
			}
		}
	}
}

static void enrich_layout_hints_from_json(LayoutHints *lh, const char *hash) {
	if (!lh || !hash) {
		return;
	}
	char *s = r_file_slurp ("r2flutter/offsets.json", NULL);
	if (!s) {
		s = r_file_slurp ("offsets.json", NULL);
	}
	if (!s) {
		return;
	}
	RJson *j = r_json_parse (s);
	if (!j) {
		free (s);
		return;
	}
	const RJson *item = r_json_get (r_json_get (j, "hashes"), hash);
	if (item) {
		read_json_u64_array (item, "code_entry_point_offsets", lh->ep_offs, &lh->ep_offs_n, 8);
		read_json_u64_array (item, "code_owner_offsets", lh->owner_offs, &lh->owner_offs_n, 8);
		read_json_u64_array (item, "function_name_offsets", lh->name_offs, &lh->name_offs_n, 8);
	}
	r_json_free (j);
	free (s);
}

static bool read_heap_ptr(DartCtx *ctx, ut64 addr, ut64 data_image_base, ut64 *out_abs) {
	if (!ctx || !out_abs) {
		return false;
	}
	if (ctx->compressed_word_size == 4) {
		ut64 v64_abs = 0;
		if (read_mem (ctx, addr, &v64_abs, sizeof (v64_abs))) {
			if (v64_abs >= data_image_base && v64_abs < data_image_base + (1ULL << 34)) {
				*out_abs = v64_abs;
				return true;
			}
		}
		ut32 v32 = 0;
		if (!read_mem (ctx, addr, &v32, sizeof (v32))) {
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
	if (!read_mem (ctx, addr, &v64, sizeof (v64))) {
		return false;
	}
	*out_abs = v64;
	return true;
}

static bool try_read_dart_string(DartCtx *ctx, ut64 addr, char *out, int outsz) {
	if (!ctx || !out || outsz <= 1) {
		return false;
	}
	ut8 hdr[32];
	if (!read_mem (ctx, addr, hdr, sizeof (hdr))) {
		return false;
	}
	for (int off = 0; off <= 16; off += 8) {
		ut64 len_smi = *(ut64 *) (hdr + off + 8);
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
			if (n >= outsz) {
				n = outsz - 1;
			}
			memcpy (out, tmp + start, n);
			out[n] = '\0';
			return true;
		}
	}
	return false;
}

static HtUP *scan_code_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	LayoutHints lh;
	init_layout_hints (&lh);
	enrich_layout_hints_from_json (&lh, ctx->snapshot_hash);
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
			if (!read_mem (ctx, a + lh.ep_offs[ie], &ep, sizeof (ep))) {
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

static RList *collect_data_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	struct {
		const char *needle;
		int len;
		int min_match;
	} needles[] = {
		{ "package:", 8, 8 },
		{ "dart:", 5, 5 },
};
	ut8 buf[CHUNK_SIZE];
	RList *out = r_list_newf (free);
	if (!out) {
		return NULL;
	}
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
		if (r_io_read_at (ctx->core->io, addr, buf, toread) != toread) {
			break;
		}
		for (int i = 0; i + 8 < toread; i++) {
			size_t n;
			for (n = 0; n < sizeof (needles) / sizeof (needles[0]); n++) {
				if (buf[i] != needles[n].needle[0]) {
					continue;
				}
				if (i + needles[n].len > toread) {
					continue;
				}
				if (memcmp (buf + i, needles[n].needle, needles[n].len)) {
					continue;
				}
				char s[128];
				int k = extract_printable_string (buf, i, toread, s, sizeof (s));
				if (k > needles[n].min_match) {
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

static void collect_data_names_with_r2(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return;
	}
	if (!ctx->name_pool) {
		ctx->name_pool = r_list_newf (free);
	}
	if (!ctx->name_pool) {
		return;
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
			char s[128];
			if (try_read_dart_string (ctx, addr, s, sizeof (s))) {
				char *dup = strdup (s);
				if (dup) {
					r_list_append (ctx->name_pool, dup);
				}
			} else {
				ut8 buf[128];
				int n = r_io_read_at (ctx->core->io, addr, buf, sizeof (buf));
				if (n > 0) {
					char s2[128];
					int z = extract_printable_string (buf, 0, n, s2, sizeof (s2));
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

typedef void(*DartInstructionTableEntryCallback)(const DartInstructionTableEntry *entry, void *user);

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
			bool looks_ok = strstr (sname, "package:") || strstr (sname, "dart:");
			if (!looks_ok && (strchr (sname, '.') || strchr (sname, '/') || strchr (sname, ':'))) {
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
					if (strstr (s2, "package:") || strstr (s2, "dart:") || strchr (s2, '/')) {
						snprintf (out, outsz, "%s", s2);
						break;
					}
				}
			}
		}
	}
	if (!*out && ctx->use_name_pool && ctx->name_pool && entry->has_code && ctx->name_pool_idx < r_list_length (ctx->name_pool)) {
		const char *pooln = (const char *)r_list_get_n (ctx->name_pool, ctx->name_pool_idx++);
		if (pooln && *pooln) {
			snprintf (out, outsz, "%s", pooln);
		}
	}
	if (!*out) {
		snprintf (out, outsz, "method.fn_%" PRIu64, (uint64_t)entry->code_index);
	}
	dart_obf_apply_buf (ctx, out, outsz);
}

static void emit_it_entry_record(const DartInstructionTableEntry *entry, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *fn_user, DartInstructionTableEntryCallback on_it, void *it_user) {
	if (on_it) {
		on_it (entry, it_user);
	}
	if (entry->has_code && on_fn) {
		on_fn (entry->name? entry->name: "method.unknown", (unsigned long long)entry->address, 0, fn_user);
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
		ut32 pc_offset = *(ut32 *) (ebuf + 0);
		ut32 sm_off = *(ut32 *) (ebuf + 4);
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
			ut32 canonical = *(ut32 *) (hdr + 0);
			ut32 length = *(ut32 *) (hdr + 4);
			ut32 first = *(ut32 *) (hdr + 8);
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
	if (best_len > 0) {
		*out = best;
		return true;
	}
	ut64 scan_end = data_image_base + 0x40000;
	if (data_image_end && scan_end > data_image_end) {
		scan_end = data_image_end;
	}
	for (ut64 addr = data_image_base; addr + 16 < scan_end; addr += 8) {
		ut8 hdr[16];
		if (!read_mem (ctx, addr, hdr, sizeof (hdr))) {
			continue;
		}
		ut32 canonical = *(ut32 *) (hdr + 0);
		ut32 length = *(ut32 *) (hdr + 4);
		ut32 first = *(ut32 *) (hdr + 8);
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
	return false;
}

static int emit_it_linear(DartCtx *ctx, ut64 itlen, ut64 max_entries, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *fn_user, DartInstructionTableEntryCallback on_it, void *it_user) {
	if (!ctx || !ctx->iso_instr) {
		return -1;
	}
	ut64 limit = max_entries && max_entries < itlen? max_entries: itlen;
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
		emit_it_entry_record (&entry, on_fn, fn_user, on_it, it_user);
	}
	return 0;
}

static int emit_it_fixed(DartCtx *ctx, ut64 table_addr, ut64 data_image_base, ut64 itlen, ut64 max_entries, bool include_stubs, HtUP *sym_by_addr, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *fn_user, DartInstructionTableEntryCallback on_it, void *it_user) {
	if (!ctx || !ctx->core) {
		return -1;
	}
	DartInstructionTableHeader hdr = { 0 };
	ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: data_image_base + (1ULL << 22);
	if (data_image_end < data_image_base) {
		data_image_end = data_image_base + (1ULL << 22);
	}
	if (!locate_it_data_header (ctx, table_addr, data_image_base, data_image_end, itlen, &hdr)) {
		return -1;
	}
	ctx->it_length = hdr.length;
	ctx->it_first_with_code = hdr.first_entry_with_code;
	ctx->it_canonical_stack_map_offset = hdr.canonical_stack_map_entries_offset;
	ut64 entries_addr = hdr.header_addr + 16;
	ut64 emitted = 0;
	for (ut64 idx = 0; idx < hdr.length; idx++) {
		if (max_entries && emitted >= max_entries) {
			break;
		}
		ut8 ebuf[8];
		ut64 entry_addr = entries_addr + (idx * 8);
		if (!read_mem (ctx, entry_addr, ebuf, sizeof (ebuf))) {
			break;
		}
		bool has_code = idx >= hdr.first_entry_with_code;
		if (!include_stubs && !has_code) {
			continue;
		}
		char name[128];
		DartInstructionTableEntry entry = {
			.index = idx,
			.code_index = has_code? idx - hdr.first_entry_with_code: UT64_MAX,
			.address = ctx->iso_instr + (ut64) (*(ut32 *) (ebuf + 0)),
			.pc_offset = *(ut32 *) (ebuf + 0),
			.stack_map_offset = *(ut32 *) (ebuf + 4),
			.has_code = has_code,
			.name = name,
};
		resolve_it_entry_name (ctx, sym_by_addr, data_image_base, &entry, name, sizeof (name));
		emit_it_entry_record (&entry, on_fn, fn_user, on_it, it_user);
		emitted++;
	}
	return 0;
}

static int emit_it_varint(DartCtx *ctx, ut64 addr, ut64 data_image_base, ut64 max_entries, bool include_stubs, HtUP *sym_by_addr, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *fn_user, DartInstructionTableEntryCallback on_it, void *it_user) {
	if (!ctx || !ctx->core) {
		return -1;
	}
	ut64 p = addr;
	ut64 header_len = 0;
	ut64 first_with_code = 0;
	if (!read_uleb128_at (ctx, p, &header_len, &p)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, p, &first_with_code, &p)) {
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
		if (!read_uleb128_at (ctx, p, &dpc, &p)) {
			return -1;
		}
		if (!read_uleb128_at (ctx, p, &dsm, &p)) {
			return -1;
		}
		pc_acc += dpc;
		sm_acc += dsm;
		bool has_code = idx >= first_with_code;
		if (!include_stubs && !has_code) {
			continue;
		}
		if (max_entries && emitted >= max_entries) {
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
		resolve_it_entry_name (ctx, sym_by_addr, data_image_base, &entry, name, sizeof (name));
		emit_it_entry_record (&entry, on_fn, fn_user, on_it, it_user);
		emitted++;
	}
	return 0;
}

static bool looks_like_data_snapshot(DartCtx *ctx, ut64 base, ut64 *out_total_len) {
	if (!ctx || !base) {
		return false;
	}
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (ctx, base, hdr, sizeof (hdr))) {
		return false;
	}
	uint32_t magic = *(uint32_t *) (hdr + 0);
	if (magic != 0xdcdcf5f5) {
		return false;
	}
	uint64_t length_ex_magic = *(uint64_t *) (hdr + 4);
	uint64_t total_len = length_ex_magic + 4;
	ut64 cursor = base + 4 + 8 + 8;
	const int max_scan = 2048;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem (ctx, cursor + scanned, &b, 1)) {
			return false;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	if (b != '\0') {
		return false;
	}
	ut64 next = cursor + (ut64) (scanned + 1);
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, tmp = next;
	if (!read_uleb128_at (ctx, tmp, &nb, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (ctx, tmp, &no, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (ctx, tmp, &nc, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (ctx, tmp, &itlen, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (ctx, tmp, &itdata, &tmp)) {
		return false;
	}
	if (nb == 0 || no == 0 || nc == 0) {
		return false;
	}
	if (itlen > (1ULL << 32)) {
		return false;
	}
	if (itdata > (1ULL << 40)) {
		return false;
	}
	if (out_total_len) {
		*out_total_len = total_len;
	}
	return true;
}

static const DartVerLayout *load_layout_from_json(const char *hash, DartVerLayout *out) {
	if (!hash || !out) {
		return NULL;
	}
	char *s = r_file_slurp ("r2flutter/offsets.json", NULL);
	if (!s) {
		s = r_file_slurp ("offsets.json", NULL);
	}
	if (!s) {
		return NULL;
	}
	RJson *j = r_json_parse (s);
	if (!j) {
		free (s);
		return NULL;
	}
	const RJson *hashes = r_json_get (j, "hashes");
	const RJson *item = r_json_get (hashes, hash);
	if (!item) {
		r_json_free (j);
		free (s);
		return NULL;
	}
	const char *version = dart_version_from_hash (hash);
	const DartVerLayout *base_profile = version? dart_profile_from_version (version): NULL;
	if (base_profile) {
		memcpy (out, base_profile, sizeof (*out));
	} else {
		memset (out, 0, sizeof (*out));
		out->tag_style = DART_TAG_STYLE_OBJECT_HEADER;
		out->cid_class = 5;
		out->cid_function = 7;
		out->cid_code = 18;
		out->cid_string = 93;
		out->cid_one_byte_string = 94;
		out->cid_two_byte_string = 95;
		out->cid_array = 90;
		out->cid_mint = 61;
		out->cid_object_pool = 23;
		out->num_predefined_cids = 175;
	}
	const char *h = r_json_get_str (item, "hash");
	if (h && *h) {
		strncpy (out->hash, h, 32);
	} else {
		strncpy (out->hash, hash, 32);
	}
	out->hash[32] = '\0';
	int cws = (int)r_json_get_num (item, "compressed_word_size");
	if (cws > 0) {
		out->compressed_word_size = cws;
	}
	int hot = (int)r_json_get_num (item, "heap_object_tag");
	if (hot > 0) {
		out->heap_object_tag = hot;
	}
	int mal = (int)r_json_get_num (item, "max_alignment");
	if (mal > 0) {
		out->max_alignment = mal;
	}
	ut64 cap = (ut64)r_json_get_num (item, "it_cap");
	if (cap > 0) {
		out->it_cap = cap;
	}
	r_json_free (j);
	free (s);
	return out;
}

static void extract_snapshot_hash_flags(DartCtx *ctx, ut64 vm_data) {
	if (!ctx || !vm_data) {
		return;
	}
	ctx->snapshot_hash[0] = '\0';
	ut8 buf[20 + 32 + 256] = { 0 };
	if (!read_mem (ctx, vm_data, buf, sizeof (buf))) {
		return;
	}
	memcpy (ctx->snapshot_hash, buf + 20, 32);
	ctx->snapshot_hash[32] = '\0';
	const char *flags = (const char *) (buf + 20 + 32);
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] snapshot_hash=%.*s flags=%.128s\n", 32, (const char *) (buf + 20), flags);
	}
}

static void derive_layout_from_flags(DartCtx *ctx) {
	if (!ctx || !ctx->vm_data) {
		return;
	}
	ut8 buf[20 + 32 + 256] = { 0 };
	if (!read_mem (ctx, ctx->vm_data, buf, sizeof (buf))) {
		return;
	}
	const char *flags = (const char *) (buf + 20 + 32);
	bool has_compressed = strstr (flags, "compressed-pointer") != NULL;
	bool has_no_compressed = strstr (flags, "no-compressed-pointer") != NULL ||
		strstr (flags, "no-compressed") != NULL;
	if (has_compressed && !has_no_compressed) {
		ctx->compressed_word_size = 4;
	} else {
		ctx->compressed_word_size = 8;
	}
	if (ctx->layout && ctx->compressed_word_size == 4) {
		int major = 0;
		int minor = 0;
		const char *version = dart_version_from_hash (ctx->snapshot_hash);
		bool use_64_alignment = ctx->layout->tag_style == DART_TAG_STYLE_OBJECT_HEADER;
		if (!use_64_alignment && version && sscanf (version, "%d.%d", &major, &minor) == 2) {
			use_64_alignment = major > 2 || (major == 2 && minor >= 19);
		}
		if (use_64_alignment && ctx->layout->max_alignment < 64) {
			((DartVerLayout *)ctx->layout)->max_alignment = 64;
		}
	} else if (ctx->layout && ctx->layout->max_alignment != 16) {
		((DartVerLayout *)ctx->layout)->max_alignment = 16;
	}
}

static DartVerLayout *dart_ctx_init_layout(DartCtx *ctx, DartVerLayout *tmp) {
	extract_snapshot_hash_flags (ctx, ctx->vm_data);
	ctx->layout = load_layout_from_json (ctx->snapshot_hash, tmp);
	DartVerLayout *owned = NULL;
	if (!ctx->layout) {
		owned = dart_pick_layout_by_hash (ctx->snapshot_hash);
		ctx->layout = owned;
	}
	derive_layout_from_flags (ctx);
	return owned;
}

static void dart_ctx_fini_layout(DartCtx *ctx, DartVerLayout *owned) {
	dart_ver_layout_free (owned);
	ctx->layout = NULL;
}

// ============================================================================
// Clustered Snapshot Deserializer
// ============================================================================

typedef struct {
	DartCtx *ctx;
	ut64 cursor;
	ut64 end;
} ClusterStream;

static bool cs_read_u8(ClusterStream *s, ut8 *out) {
	if (!s || !out || s->cursor >= s->end) {
		return false;
	}
	return read_mem (s->ctx, s->cursor++, out, 1);
}

static bool cs_read_u32(ClusterStream *s, uint32_t *out) {
	if (!s || !out || s->cursor + 4 > s->end) {
		return false;
	}
	bool ok = read_mem (s->ctx, s->cursor, out, 4);
	s->cursor += 4;
	return ok;
}

static bool cs_read_unsigned(ClusterStream *s, ut64 *out) {
	ut64 v = 0;
	int shift = 0;
	for (int i = 0; i < 10; i++) {
		ut8 b = 0;
		if (!cs_read_u8 (s, &b)) {
			return false;
		}
		v |= ((ut64) (b & 0x7f)) << shift;
		if ((b & 0x80) == 0) {
			if (out) {
				*out = v;
			}
			return true;
		}
		shift += 7;
	}
	return false;
}

static bool cs_read_ref_id(ClusterStream *s, ut64 *out) {
	return cs_read_unsigned (s, out);
}

static bool cs_read_bytes(ClusterStream *s, ut8 *buf, int len) {
	if (!s || !buf || len <= 0 || s->cursor + len > s->end) {
		return false;
	}
	bool ok = read_mem (s->ctx, s->cursor, buf, len);
	s->cursor += len;
	return ok;
}

static void free_dart_string(void *p) {
	DartString *ds = (DartString *)p;
	if (ds) {
		free (ds->value);
		free (ds);
	}
}

static void free_dart_class(void *p) {
	DartClass *dc = (DartClass *)p;
	if (dc) {
		free (dc->name);
		free (dc);
	}
}

static void free_dart_func(void *p) {
	DartPoolFunction *df = (DartPoolFunction *)p;
	if (df) {
		free (df->name);
		free (df);
	}
}

static int decode_string_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] String cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 encoded = 0;
		if (!cs_read_unsigned (s, &encoded)) {
			return -1;
		}
		bool is_two_byte = (encoded & 1) != 0;
		ut64 length = encoded >> 1;
		if (length > 65536) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] String too long: %" PRIu64 "\n", length);
			}
			continue;
		}
		DartString *ds = R_NEW0 (DartString);
		ds->ref_id = (*ref_counter)++;
		ds->is_two_byte = is_two_byte;
		ds->length = (int)length;
		if (length > 0) {
			if (is_two_byte) {
				ds->value = (char *)malloc (length * 2 + 1);
				if (ds->value && !cs_read_bytes (s, (ut8 *)ds->value, length * 2)) {
					free (ds->value);
					ds->value = NULL;
				}
			} else {
				ds->value = (char *)malloc (length + 1);
				if (ds->value) {
					if (cs_read_bytes (s, (ut8 *)ds->value, (int)length)) {
						ds->value[length] = '\0';
					} else {
						free (ds->value);
						ds->value = NULL;
					}
				}
			}
		}
		if (ctx->strings) {
			r_list_append (ctx->strings, ds);
		}
		if (ctx->refs && ds->ref_id < ctx->refs_count) {
			ctx->refs[ds->ref_id] = ds;
		}
	}
	return 0;
}

static int decode_class_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Class cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartClass *dc = R_NEW0 (DartClass);
		dc->ref_id = (*ref_counter)++;
		uint32_t instance_size = 0;
		cs_read_u32 (s, &instance_size);
		dc->instance_size = (int)instance_size;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		dc->name_ref = name_ref;
		ut64 library_ref = 0;
		cs_read_ref_id (s, &library_ref);
		dc->library_ref = library_ref;
		ut64 skip_count = 6;
		for (ut64 j = 0; j < skip_count; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		if (ctx->classes) {
			r_list_append (ctx->classes, dc);
		}
		if (ctx->refs && dc->ref_id < ctx->refs_count) {
			ctx->refs[dc->ref_id] = dc;
		}
	}
	return 0;
}

static int decode_function_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, ut64 iso_instr, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Function cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartPoolFunction *df = R_NEW0 (DartPoolFunction);
		df->ref_id = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		df->name_ref = name_ref;
		ut64 owner_ref = 0;
		cs_read_ref_id (s, &owner_ref);
		df->owner_ref = owner_ref;
		ut64 code_idx = 0;
		cs_read_unsigned (s, &code_idx);
		if (code_idx > 0 && iso_instr > 0) {
			df->entry_point = iso_instr + (code_idx - 1) * 4;
		}
		ut64 skip_refs = 4;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		uint32_t kind_tag = 0;
		cs_read_u32 (s, &kind_tag);
		if (ctx->functions) {
			r_list_append (ctx->functions, df);
		}
		if (ctx->refs && df->ref_id < ctx->refs_count) {
			ctx->refs[df->ref_id] = df;
		}
	}
	return 0;
}

static void skip_generic_cluster(ClusterStream *stream) {
	ut64 count = 0;
	if (cs_read_unsigned (stream, &count)) {
		if (count < 100000) {
			for (ut64 j = 0; j < count; j++) {
				ut64 skip = 0;
				for (int k = 0; k < 8 && stream->cursor < stream->end; k++) {
					if (!cs_read_unsigned (stream, &skip)) {
						break;
					}
					if (skip == 0) {
						break;
					}
				}
			}
		}
	}
}

static int deserialize_clusters(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 iso_instr) {
	if (!ctx || !ctx->core || cluster_start >= cluster_end) {
		return -1;
	}
	ctx->strings = r_list_newf (free_dart_string);
	ctx->classes = r_list_newf (free_dart_class);
	ctx->functions = r_list_newf (free_dart_func);
	ut64 total_refs = ctx->num_base_objects + ctx->num_objects + 16;
	ctx->refs_count = total_refs;
	ctx->refs = (void **)calloc (total_refs, sizeof (void *));
	ClusterStream stream = {
		.ctx = ctx,
		.cursor = cluster_start,
		.end = cluster_end
	};
	ut64 ref_counter = ctx->num_base_objects + 1;
	for (ut64 ci = 0; ci < num_clusters && stream.cursor < stream.end; ci++) {
		uint32_t tags = 0;
		if (!cs_read_u32 (&stream, &tags)) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] Failed to read cluster tag at %" PRIu64 "\n", ci);
			}
			break;
		}
		uint32_t cid = (tags >> 12) & 0xFFFFF;
		bool is_canonical = tags & 1;
		if (ctx->verbose > 1) {
			fprintf (stderr, "[r2flutter] Cluster %" PRIu64 ": cid=%u canonical=%d cursor=0x%" PFMT64x "\n", ci, cid, is_canonical, stream.cursor);
		}
		int rc = 0;
		switch (cid) {
		case kOneByteStringCid:
		case kTwoByteStringCid:
		case kStringCid:
			rc = decode_string_cluster (&stream, ctx, &ref_counter, is_canonical);
			break;
		case kClassCid:
			rc = decode_class_cluster (&stream, ctx, &ref_counter, is_canonical);
			break;
		case kFunctionCid:
			rc = decode_function_cluster (&stream, ctx, &ref_counter, iso_instr, is_canonical);
			break;
		default:
			skip_generic_cluster (&stream);
			break;
		}
		if (rc < 0) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] Error decoding cluster cid=%u\n", cid);
			}
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Decoded: strings=%d classes=%d functions=%d\n", ctx->strings? r_list_length (ctx->strings): 0, ctx->classes? r_list_length (ctx->classes): 0, ctx->functions? r_list_length (ctx->functions): 0);
	}
	return 0;
}

static void resolve_names(DartCtx *ctx) {
	if (!ctx || !ctx->refs) {
		return;
	}
	if (ctx->classes) {
		RListIter *it;
		DartClass *dc;
		r_list_foreach (ctx->classes, it, dc) {
			if (!dc || dc->name) {
				continue;
			}
			if (dc->name_ref > 0 && dc->name_ref < ctx->refs_count) {
				DartString *ds = (DartString *)ctx->refs[dc->name_ref];
				if (ds && ds->value) {
					dc->name = strdup (ds->value);
					dart_obf_apply (ctx, &dc->name);
				}
			}
		}
	}
	if (ctx->functions) {
		RListIter *it;
		DartPoolFunction *df;
		r_list_foreach (ctx->functions, it, df) {
			if (!df || df->name) {
				continue;
			}
			if (df->name_ref > 0 && df->name_ref < ctx->refs_count) {
				DartString *ds = (DartString *)ctx->refs[df->name_ref];
				if (ds && ds->value) {
					df->name = strdup (ds->value);
					dart_obf_apply (ctx, &df->name);
				}
			}
		}
	}
}

static int decode_pool_and_emit(DartCtx *ctx,
	void (*on_fn) (const char *name, unsigned long long addr, unsigned long long size, void *user),
	void *fn_user,
	DartInstructionTableEntryCallback on_it,
	void *it_user,
	bool include_stubs,
	ut64 it_limit) {
	if (!ctx || !ctx->iso_data) {
		return -1;
	}
	if (!ctx->layout) {
		fprintf (stderr, "[r2flutter] No layout for snapshot hash %s. Populate known_layouts.\n", ctx->snapshot_hash);
		return -1;
	}
	const ut64 base = ctx->iso_data;
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (ctx, base, hdr, sizeof (hdr))) {
		eprintf ("Cannot read head\n");
		return -1;
	}
	uint32_t magic = *(uint32_t *) (hdr + 0);
	if (magic != 0xdcdcf5f5) {
		fprintf (stderr, "[r2flutter] Unexpected snapshot magic at 0x%" PFMT64x "\n", (ut64)base);
		return -1;
	}
	uint64_t length_ex_magic = *(uint64_t *) (hdr + 4);
	uint64_t total_len = length_ex_magic + 4;
	uint64_t kind = *(uint64_t *) (hdr + 12);
	ut64 cursor = base + 4 + 8 + 8;
	cursor += 32;
	const int max_scan = 1024;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem (ctx, cursor + scanned, &b, 1)) {
			break;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	if (b != '\0') {
		if (ctx->verbose > 0) {
			eprintf ("[r2flutter] warning: could not find features terminator within %d bytes\n", max_scan);
		}
	} else if (ctx->verbose > 1) {
		char feat[256];
		memset (feat, 0, sizeof (feat));
		int toshow = scanned > 255? 255: scanned;
		if (read_mem (ctx, cursor, (ut8 *)feat, toshow)) {
			eprintf ("[r2flutter] features: %s\n", feat);
		}
	}
	cursor += (ut64) (scanned + 1);
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0;
	ut64 next = cursor;
	if (!read_uleb128_at (ctx, next, &nb, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, &no, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, &nc, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, &itlen, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, &itdata, &next)) {
		return -1;
	}
	bool header_valid = (nc > 0 && nc < 1000000 && no > 0 && no < 10000000);
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] snapshot clustered header: base_objs=%" PRIu64 " objs=%" PRIu64 " clusters=%" PRIu64 " it_len=%" PRIu64 " it_data_off=%" PRIu64 " total_len=%" PRIu64 " valid=%d\n", (uint64_t)nb, (uint64_t)no, (uint64_t)nc, (uint64_t)itlen, (uint64_t)itdata, (uint64_t)total_len, header_valid);
	}
	if (!header_valid) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] warning: snapshot header values out of expected range, skipping cluster deserialization\n");
		}
		nc = 0;
	}

	if (ctx->dump_snapshot_json) {
		printf ("{\"kind\":%llu,\"hash\":\"%s\",\"vm_data\":%llu,\"vm_instr\":%llu,\"iso_data\":%llu,\"iso_instr\":%llu,\"cluster\":{\"base\":%llu,\"objs\":%llu,\"clusters\":%llu,\"it_len\":%llu,\"it_off\":%llu,\"total\":%llu},\"cws\":%d}\n",
			(unsigned long long)kind,
			ctx->snapshot_hash,
			(unsigned long long)ctx->vm_data,
			(unsigned long long)ctx->vm_instr,
			(unsigned long long)ctx->iso_data,
			(unsigned long long)ctx->iso_instr,
			(unsigned long long)nb,
			(unsigned long long)no,
			(unsigned long long)nc,
			(unsigned long long)itlen,
			(unsigned long long)itdata,
			(unsigned long long)total_len,
			ctx->compressed_word_size);
	}

	ctx->num_base_objects = nb;
	ctx->num_objects = no;
	ctx->num_clusters = nc;
	ctx->it_length = 0;
	ctx->it_first_with_code = 0;
	ctx->it_canonical_stack_map_offset = 0;

	ut64 cluster_start = next;
	ut64 cluster_end = base + total_len;
	if (nc > 0 && nc < 5000 && no < 500000 && cluster_start < cluster_end) {
		int deser_rc = deserialize_clusters (ctx, cluster_start, cluster_end, nc, ctx->iso_instr);
		if (deser_rc == 0) {
			resolve_names (ctx);
			if (ctx->functions && on_fn) {
				RListIter *fit;
				DartPoolFunction *df;
				r_list_foreach (ctx->functions, fit, df) {
					if (!df || df->entry_point == 0) {
						continue;
					}
					const char *fname = df->name? df->name: "method.unknown";
					char clean_name[256];
					snprintf (clean_name, sizeof (clean_name), "%s", fname);
					r_name_filter (clean_name, 0);
					on_fn (clean_name, (unsigned long long)df->entry_point, 0, fn_user);
				}
			}
			if (ctx->verbose > 1 && ctx->strings) {
				RListIter *sit;
				DartString *ds;
				int str_count = 0;
				r_list_foreach (ctx->strings, sit, ds) {
					if (ds && ds->value && str_count < 50) {
						fprintf (stderr, "[r2flutter] String[%" PRIu64 "]: %s\n", ds->ref_id, ds->value);
						str_count++;
					}
				}
			}
		}
	}

	HtUP *sym_by_addr = ht_up_new0 ();
	if (ctx->core && ctx->core->bin && sym_by_addr) {
		RVecRBinSymbol *v = r_bin_get_symbols_vec (ctx->core->bin);
		if (v) {
			RBinSymbol *sym;
			R_VEC_FOREACH (v, sym) {
				if (!sym) {
					continue;
				}
				if (sym->type && strcmp (sym->type, R_BIN_TYPE_FUNC_STR)) {
					continue;
				}
				if (sym->vaddr) {
					ht_up_insert (sym_by_addr, sym->vaddr, sym);
				}
			}
		}
	}
	if (!ctx->iso_instr) {
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	ut64 data_image_base = base + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
	ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: (data_image_base + (1ULL << 22));
	if (data_image_end < data_image_base) {
		data_image_end = data_image_base + (1ULL << 22);
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] data_image_base=0x%" PFMT64x " data_image_end=0x%" PFMT64x "\n", (ut64)data_image_base, (ut64)data_image_end);
	}
	ctx->name_by_ep = scan_code_names (ctx, data_image_base, data_image_end);
	ctx->name_pool = collect_data_names (ctx, data_image_base, data_image_end);
	if (!ctx->name_pool || r_list_length (ctx->name_pool) == 0) {
		collect_data_names_with_r2 (ctx, data_image_base, data_image_end);
		if (ctx->verbose > 0 && ctx->name_pool) {
			fprintf (stderr, "[r2flutter] name_pool(r2)=%d\n", r_list_length (ctx->name_pool));
		}
	}
	ctx->name_pool_idx = 0;
	if (ctx->verbose > 0 && ctx->name_pool) {
		fprintf (stderr, "[r2flutter] name_pool=%d\n", r_list_length (ctx->name_pool));
	}
	if (itlen == 0) {
		goto beach;
	}
	ut64 max_entries = 0;
	if (it_limit > 0) {
		max_entries = it_limit;
	} else if (on_it) {
		max_entries = itlen;
	} else {
		max_entries = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
	}
	if (itdata == 0) {
		(void)emit_it_linear (ctx, itlen, max_entries, on_fn, fn_user, on_it, it_user);
		goto beach;
	}
	ut64 table_addr = data_image_base + itdata;
	if (on_it && emit_it_fixed (ctx, table_addr, data_image_base, itlen, max_entries, include_stubs, sym_by_addr, on_fn, fn_user, on_it, it_user) == 0) {
		goto beach;
	}
	for (int delta = -64; delta <= 64; delta += 4) {
		if (emit_it_varint (ctx, table_addr + delta, data_image_base, max_entries, include_stubs, sym_by_addr, on_fn, fn_user, on_it, it_user) == 0) {
			goto beach;
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Could not decode InstructionsTable::Data at 0x%" PFMT64x ", using sequential fallback\n", (ut64) (data_image_base + itdata));
	}
	(void)emit_it_linear (ctx, itlen, max_entries, on_fn, fn_user, on_it, it_user);
beach:
	if (ctx->name_by_ep) {
		ht_up_free (ctx->name_by_ep);
		ctx->name_by_ep = NULL;
	}
	if (sym_by_addr) {
		ht_up_free (sym_by_addr);
	}
	if (ctx->name_pool) {
		r_list_free (ctx->name_pool);
		ctx->name_pool = NULL;
	}
	return 0;
}

static int find_snapshots(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return -1;
	}
	RCore *core = ctx->core;
	ctx->vm_data = 0;
	ctx->vm_instr = 0;
	ctx->iso_data = 0;
	ctx->iso_instr = 0;

	const char *names[8] = {
		"_kDartVmSnapshotData",
		"DartVmSnapshotData",
		"_kDartVmSnapshotInstructions",
		"DartVmSnapshotInstructions",
		"_kDartIsolateSnapshotData",
		"DartIsolateSnapshotData",
		"_kDartIsolateSnapshotInstructions",
		"DartIsolateSnapshotInstructions",
};
	ut64 *outs[4] = { &ctx->vm_data, &ctx->vm_instr, &ctx->iso_data, &ctx->iso_instr };
	if (core->bin) {
		RVecRBinSymbol *v = r_bin_get_symbols_vec (core->bin);
		if (v) {
			RBinSymbol *sym;
			R_VEC_FOREACH (v, sym) {
				if (!sym || !sym->name) {
					continue;
				}
				const char *nm = r_bin_name_tostring2 (sym->name, 'o');
				if (R_STR_ISEMPTY (nm)) {
					continue;
				}
				for (int k = 0; k < 8; k++) {
					if (!strcmp (nm, names[k])) {
						int idx = k / 2;
						*outs[idx] = sym->vaddr? sym->vaddr: 0;
					}
				}
			}
		}
	}
	if (ctx->vm_data && ctx->vm_instr && ctx->iso_data && ctx->iso_instr) {
		return 0;
	}

	RList *sections = r_bin_get_sections (core->bin);
	const uint32_t kMagic = 0xdcdcf5f5;
	ut64 found_addrs[32];
	int found_cnt = 0;
	if (sections) {
		RListIter *it;
		RBinSection *sec;
		r_list_foreach (sections, it, sec) {
			if (!sec || !sec->vaddr || !sec->vsize) {
				continue;
			}
			ut64 vaddr = sec->vaddr;
			ut64 size = sec->vsize;
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] scanning section '%s' vaddr=0x%" PFMT64x " size=0x%" PFMT64x "\n", sec->name? sec->name: "(null)", (ut64)vaddr, (ut64)size);
			}
			ut8 buf[4096];
			for (ut64 off = 0; off + 4 <= size; off += (sizeof (buf) - 16)) {
				ut64 addr = vaddr + off;
				int toread = (int) ((off + sizeof (buf) <= size)? sizeof (buf): (size - off));
				if (toread <= 0) {
					break;
				}
				if (r_io_read_at (core->io, addr, buf, toread) != toread) {
					break;
				}
				for (int j2 = 0; j2 + 4 <= toread; j2 += 4) {
					uint32_t val = *(uint32_t *) (buf + j2);
					if (val == kMagic) {
						if (found_cnt < (int) (sizeof (found_addrs) / sizeof (found_addrs[0]))) {
							found_addrs[found_cnt++] = addr + j2;
						}
					}
				}
				if (found_cnt >= 8) {
					break;
				}
			}
			if (found_cnt >= 8) {
				break;
			}
		}
	}
	if (found_cnt >= 1) {
		ut64 data_addrs[4];
		ut64 data_lens[4];
		int data_cnt = 0;
		ut64 instr_addrs[4];
		ut64 instr_lens[4];
		int instr_cnt = 0;
		for (int i = 0; i < found_cnt; i++) {
			ut8 hdr2[16];
			if (r_io_read_at (core->io, found_addrs[i] + 4, hdr2, sizeof (hdr2)) < 1) {
				continue;
			}
			ut64 total_len = *(uint64_t *) (hdr2 + 0) + 4;
			ut64 classified_len = 0;
			bool is_data = looks_like_data_snapshot (ctx, found_addrs[i], &classified_len);
			if (is_data) {
				if (data_cnt < 4) {
					data_addrs[data_cnt] = found_addrs[i];
					data_lens[data_cnt] = total_len;
					data_cnt++;
				}
			} else {
				if (instr_cnt < 4) {
					instr_addrs[instr_cnt] = found_addrs[i];
					instr_lens[instr_cnt] = total_len;
					instr_cnt++;
				}
			}
		}
		if (data_cnt >= 1) {
			ut64 vm_addr = 0, iso_addr = 0;
			ut64 vm_len = (ut64)-1, iso_len = 0;
			for (int i = 0; i < data_cnt; i++) {
				if (data_lens[i] < vm_len) {
					vm_len = data_lens[i];
					vm_addr = data_addrs[i];
				}
				if (data_lens[i] > iso_len) {
					iso_len = data_lens[i];
					iso_addr = data_addrs[i];
				}
			}
			if (vm_addr) {
				ctx->vm_data = vm_addr;
			}
			if (iso_addr) {
				ctx->iso_data = iso_addr;
			}
		}
		if (instr_cnt >= 1) {
			ut64 vm_addr = 0, iso_addr = 0;
			ut64 vm_len = (ut64)-1, iso_len = 0;
			for (int i = 0; i < instr_cnt; i++) {
				if (instr_lens[i] < vm_len) {
					vm_len = instr_lens[i];
					vm_addr = instr_addrs[i];
				}
				if (instr_lens[i] > iso_len) {
					iso_len = instr_lens[i];
					iso_addr = instr_addrs[i];
				}
			}
			if (vm_addr) {
				ctx->vm_instr = vm_addr;
			}
			if (iso_addr) {
				ctx->iso_instr = iso_addr;
			}
		}
		if (ctx->vm_data || ctx->iso_data || ctx->vm_instr || ctx->iso_instr) {
			return 0;
		}
	}
	return -1;
}

static void emit_stub_symbols(DartCtx *ctx,
	void (*on_fn) (const char *name, unsigned long long addr, unsigned long long size, void *user),
	void *user) {
	if (!ctx || !ctx->core || !ctx->core->bin || !on_fn) {
		return;
	}
	RVecRBinSymbol *v = r_bin_get_symbols_vec (ctx->core->bin);
	if (!v) {
		return;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (v, sym) {
		if (!sym) {
			continue;
		}
		if (sym->type && strcmp (sym->type, R_BIN_TYPE_FUNC_STR)) {
			continue;
		}
		ut64 addr = sym->vaddr;
		if (!addr) {
			continue;
		}
		ut64 size = sym->size;
		const char *nm = sym->name? r_bin_name_tostring2 (sym->name, 'o'): NULL;
		if (!nm) {
			nm = "sym.func";
		}
		char tmp[512];
		snprintf (tmp, sizeof (tmp), "%s", nm);
		for (char *p = tmp; *p; p++) {
			if (*p == ' ') {
				*p = '.';
			}
		}
		on_fn (tmp, (unsigned long long)addr, (unsigned long long)size, user);
	}
}

int dart_pool_enumerate(DartCtx *ctx, const char *libapp_path, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user, unsigned long long *out_base, unsigned long long *out_heap_base) {
	(void)libapp_path;
	if (!ctx || !ctx->core) {
		return -1;
	}
	int ok = find_snapshots (ctx);
	if (ok == 0) {
		if (out_base) {
			*out_base = (unsigned long long)r_bin_get_baddr (ctx->core->bin);
		}
		if (out_heap_base) {
			*out_heap_base = 0;
		}
		if (ctx->verbose > 0) {
			eprintf ("[r2flutter] Found Dart snapshots: vm_data=0x%llx vm_instr=0x%llx iso_data=0x%llx iso_instr=0x%llx\n",
				(unsigned long long)ctx->vm_data,
				(unsigned long long)ctx->vm_instr,
				(unsigned long long)ctx->iso_data,
				(unsigned long long)ctx->iso_instr);
		}
		DartVerLayout layout_tmp;
		DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
		if (ctx->verbose > 1) {
			ut8 peek[32] = { 0 };
			if (read_mem (ctx, ctx->iso_data, peek, sizeof (peek))) {
				fprintf (stderr, "[r2flutter] iso_data[0..32]: ");
				for (int i = 0; i < 32; i++) {
					fprintf (stderr, "%02x", (unsigned int)peek[i]);
				}
				fprintf (stderr, "\n");
			}
		}
		if (!ctx->no_stubs) {
			emit_stub_symbols (ctx, on_fn, user);
		}
		int rc = decode_pool_and_emit (ctx, on_fn, user, NULL, NULL, false, 0);
		dart_ctx_fini_layout (ctx, layout_owned);
		return rc;
	}
	if (out_base) {
		*out_base = 0;
	}
	if (out_heap_base) {
		*out_heap_base = 0;
	}
	eprintf ("[r2flutter] Dart snapshots not found in symbols (file=%s).\n", libapp_path? libapp_path: "(null)");
	return -1;
}

// ============================================================================
// Class and Field Extraction
// ============================================================================

void dart_field_info_free(DartFieldInfo *fi) {
	if (fi) {
		free (fi->name);
		free (fi->type_name);
		free (fi);
	}
}

void dart_class_info_free(DartClassInfo *ci) {
	if (ci) {
		free (ci->name);
		free (ci->library_name);
		free (ci->super_class_name);
		r_list_free (ci->enums);
		r_list_free (ci->fields);
		r_list_free (ci->interfaces);
		r_list_free (ci->methods);
		free (ci);
	}
}

void dart_type_info_free(DartTypeInfo *ti) {
	if (ti) {
		free (ti->name);
		r_list_free (ti->type_args);
		free (ti);
	}
}

void dart_method_info_free(DartMethodInfo *mi) {
	if (mi) {
		free (mi->name);
		free (mi->owner_name);
		free (mi);
	}
}

void dart_instruction_table_entry_free(DartInstructionTableEntry *ie) {
	if (ie) {
		free (ie->name);
		free (ie);
	}
}

void dart_instruction_table_list_free(RList *list) {
	r_list_free (list);
}

void dart_class_list_free(RList *list) {
	r_list_free (list);
}

typedef enum {
	kFieldCid_extract = 10,
	kLibraryCid_extract = 12,
	kTypeArgumentsCid_extract = 115,
} ExtraCids;

static int decode_field_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *field_list, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Field cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartFieldInfo *fi = R_NEW0 (DartFieldInfo);
		fi->ref_id = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		fi->name_ref = name_ref;
		ut64 owner_ref = 0;
		cs_read_ref_id (s, &owner_ref);
		fi->owner_ref = owner_ref;
		ut64 type_ref = 0;
		cs_read_ref_id (s, &type_ref);
		fi->type_ref = type_ref;
		ut64 initializer_ref = 0;
		cs_read_ref_id (s, &initializer_ref);
		uint32_t kind_bits = 0;
		cs_read_u32 (s, &kind_bits);
		fi->flags = kind_bits;
		ut64 offset_or_id = 0;
		cs_read_ref_id (s, &offset_or_id);
		fi->offset = (ut32)offset_or_id;
		r_list_append (field_list, fi);
		if (ctx->refs && fi->ref_id < ctx->refs_count) {
			ctx->refs[fi->ref_id] = fi;
		}
	}
	return 0;
}

static int decode_class_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *class_list, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Class cluster (ext): count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartClassInfo *ci = R_NEW0 (DartClassInfo);
		ci->ref_id = (*ref_counter)++;
		ci->fields = r_list_newf ((RListFree)dart_field_info_free);
		ci->interfaces = r_list_newf (free);
		uint32_t instance_size = 0;
		cs_read_u32 (s, &instance_size);
		ci->instance_size = instance_size;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		ci->name_ref = name_ref;
		ut64 library_ref = 0;
		cs_read_ref_id (s, &library_ref);
		ci->library_ref = library_ref;
		ut64 super_class_ref = 0;
		cs_read_ref_id (s, &super_class_ref);
		ci->super_class_ref = super_class_ref;
		ut64 type_args_ref = 0;
		cs_read_ref_id (s, &type_args_ref);
		uint32_t num_type_params = 0;
		cs_read_u32 (s, &num_type_params);
		ci->num_type_parameters = num_type_params;
		uint32_t type_arg_offset = 0;
		cs_read_u32 (s, &type_arg_offset);
		ci->type_argument_offset = type_arg_offset;
		uint32_t flags = 0;
		cs_read_u32 (s, &flags);
		ci->flags = 0;
		if (flags & (1 << 0)) {
			ci->flags |= DART_CLASS_ABSTRACT;
		}
		if (flags & (1 << 1)) {
			ci->flags |= DART_CLASS_ENUM;
		}
		if (flags & (1 << 2)) {
			ci->flags |= DART_CLASS_MIXIN;
		}
		ut64 interfaces_ref = 0;
		cs_read_ref_id (s, &interfaces_ref);
		ut64 skip_refs = 3;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		r_list_append (class_list, ci);
		if (ctx->refs && ci->ref_id < ctx->refs_count) {
			ctx->refs[ci->ref_id] = ci;
		}
	}
	return 0;
}

typedef struct {
	ut64 ref_id;
	char *uri;
	ut64 name_ref;
} LibraryInfo;

static void free_library_info(void *p) {
	LibraryInfo *li = (LibraryInfo *)p;
	if (li) {
		free (li->uri);
		free (li);
	}
}

typedef struct {
	char *name;
	bool saw_plain_name;
	bool saw_trailing_dot;
	RList *values;
} DartEnumCandidate;

static void free_enum_candidate(void *p) {
	DartEnumCandidate *ec = (DartEnumCandidate *)p;
	if (ec) {
		free (ec->name);
		r_list_free (ec->values);
		free (ec);
	}
}
static bool has_lowercase_after(const char *s, int start) {
	for (int i = start; s[i]; i++) {
		if (islower ((ut8)s[i])) {
			return true;
		}
	}
	return false;
}

static bool is_type_name_candidate(const char *s) {
	static const char *const skip_prefixes[] = {
		"get:",
		"set:",
		"init:",
		"dyn:",
		"vm:",
		"dart:",
		"package:",
		NULL
	};
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	const char *const *prefix = skip_prefixes;
	while (*prefix) {
		if (r_str_startswith (s, *prefix)) {
			return false;
		}
		prefix++;
	}
	if (strchr (s, ':') != NULL) {
		return false;
	}
	if (isupper ((ut8)s[0])) {
		return has_lowercase_after (s, 1);
	}
	if (s[0] == '_' && isupper ((ut8)s[1])) {
		return has_lowercase_after (s, 2);
	}
	return false;
}

static bool is_enum_value_candidate(const char *s) {
	if (!R_STR_ISNOTEMPTY (s) || !isalpha ((ut8)s[0]) || !islower ((ut8)s[0])) {
		return false;
	}
	for (const ut8 *p = (const ut8 *)s + 1; *p; p++) {
		if (isalpha (*p) || isdigit (*p) || *p == '_') {
			continue;
		}
		return false;
	}
	return true;
}

static DartEnumCandidate *enum_candidate_get_or_add(RList *list, HtPP *by_name, const char *name) {
	if (!R_STR_ISNOTEMPTY (name)) {
		return NULL;
	}
	DartEnumCandidate *ec = ht_pp_find (by_name, name, NULL);
	if (ec) {
		return ec;
	}
	ec = R_NEW0 (DartEnumCandidate);
	ec->name = strdup (name);
	ec->values = r_list_newf (free);
	if (!ec->name) {
		free_enum_candidate (ec);
		return NULL;
	}
	r_list_append (list, ec);
	ht_pp_insert (by_name, ec->name, ec);
	return ec;
}

static void enum_candidate_add_value(DartEnumCandidate *ec, const char *value) {
	if (!R_STR_ISNOTEMPTY (value)) {
		return;
	}
	if (r_list_find (ec->values, value, (RListComparator)strcmp)) {
		return;
	}
	r_list_append (ec->values, strdup (value));
}

static bool has_enum_like_suffix(const char *name) {
	static const char *suffixes[] = {
		"Action",
		"Affinity",
		"Alignment",
		"Behavior",
		"Direction",
		"Kind",
		"Mode",
		"Platform",
		"Side",
		"Size",
		"State",
		"Status",
		"Style"
	};
	for (size_t i = 0; i < sizeof (suffixes) / sizeof (suffixes[0]); i++) {
		if (r_str_endswith (name, suffixes[i])) {
			return true;
		}
	}
	return false;
}

static bool is_factory_like_value(const char *value) {
	static const char *bad_values[] = {
		"builder",
		"child",
		"compose",
		"copy",
		"current",
		"dark",
		"delayed",
		"directory",
		"empty",
		"error",
		"exit",
		"fallback",
		"filled",
		"file",
		"from",
		"generate",
		"identity",
		"inverted",
		"light",
		"matrix",
		"microtask",
		"now",
		"of",
		"parse",
		"root",
		"separated",
		"spawn",
		"sync",
		"timestamp",
		"unmodifiable",
		"utc",
		"value",
		"zero"
	};
	for (size_t i = 0; i < sizeof (bad_values) / sizeof (bad_values[0]); i++) {
		if (!strcmp (value, bad_values[i])) {
			return true;
		}
	}
	return false;
}

static int enum_candidate_score(const DartEnumCandidate *ec) {
	if (!ec || !ec->name) {
		return 0;
	}
	int score = 0;
	int count = ec->values? r_list_length (ec->values): 0;
	if (count >= 4) {
		score += 2;
	} else if (count >= 3) {
		score += 1;
	}
	if (has_enum_like_suffix (ec->name)) {
		score += 3;
	}
	if (ec->values) {
		RListIter *it;
		char *value;
		r_list_foreach (ec->values, it, value) {
			if (is_factory_like_value (value)) {
				score -= 2;
				break;
			}
		}
	}
	return score;
}

static int cmp_cstr_ptr(const void *a, const void *b) {
	const char *const *sa = (const char *const *)a;
	const char *const *sb = (const char *const *)b;
	return strcmp (*sa, *sb);
}

static void class_info_add_enum_values(DartClassInfo *ci, RList *values) {
	if (r_list_length (values) == 0) {
		return;
	}
	if (!ci->enums) {
		ci->enums = r_list_newf (free);
	}
	int count = r_list_length (values);
	char **sorted = calloc ((size_t)count, sizeof (char *));
	if (!sorted) {
		return;
	}
	int idx = 0;
	RListIter *it;
	char *value;
	r_list_foreach (values, it, value) {
		if (value && idx < count) {
			sorted[idx++] = value;
		}
	}
	if (idx > 1) {
		qsort (sorted, (size_t)idx, sizeof (char *), cmp_cstr_ptr);
	}
	for (int i = 0; i < idx; i++) {
		if (!sorted[i] || r_list_find (ci->enums, sorted[i], (RListComparator)strcmp)) {
			continue;
		}
		r_list_append (ci->enums, strdup (sorted[i]));
	}
	free (sorted);
}

static void recover_enum_types_from_strings(DartCtx *ctx, RList *class_list) {
	if (!ctx || !ctx->core || !class_list) {
		return;
	}
	RList *strings = dart_pool_extract_strings (ctx);
	if (!strings || r_list_length (strings) == 0) {
		dart_string_list_free (strings);
		return;
	}
	HtPP *class_by_name = ht_pp_new0 ();
	HtPP *candidate_by_name = ht_pp_new0 ();
	RList *candidates = r_list_newf (free_enum_candidate);
	if (!class_by_name || !candidate_by_name) {
		ht_pp_free (class_by_name);
		ht_pp_free (candidate_by_name);
		dart_string_list_free (strings);
		r_list_free (candidates);
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (ci && ci->name) {
			ht_pp_insert (class_by_name, ci->name, ci);
		}
	}
	DartStringInfo *si;
	r_list_foreach (strings, it, si) {
		if (!si || !si->value || !*si->value) {
			continue;
		}
		const char *s = si->value;
		size_t len = strlen (s);
		if (len > 1 && s[len - 1] == '.') {
			char *prefix = r_str_ndup (s, len - 1);
			if (prefix && is_type_name_candidate (prefix)) {
				DartEnumCandidate *ec = enum_candidate_get_or_add (candidates, candidate_by_name, prefix);
				if (ec) {
					ec->saw_trailing_dot = true;
				}
			}
			free (prefix);
			continue;
		}
		const char *dot = strchr (s, '.');
		if (dot && dot != s && dot[1] && !strchr (dot + 1, '.')) {
			char *prefix = r_str_ndup (s, (size_t) (dot - s));
			if (!prefix) {
				continue;
			}
			if (is_type_name_candidate (prefix) && is_enum_value_candidate (dot + 1)) {
				DartEnumCandidate *ec = enum_candidate_get_or_add (candidates, candidate_by_name, prefix);
				if (ec) {
					enum_candidate_add_value (ec, dot + 1);
				}
			}
			free (prefix);
			continue;
		}
		if (is_type_name_candidate (s)) {
			DartEnumCandidate *ec = enum_candidate_get_or_add (candidates, candidate_by_name, s);
			if (ec) {
				ec->saw_plain_name = true;
			}
		}
	}
	DartEnumCandidate *ec;
	int recovered = 0;
	r_list_foreach (candidates, it, ec) {
		if (!ec || !ec->name || r_list_length (ec->values) < 2) {
			continue;
		}
		int score = enum_candidate_score (ec);
		if (!ec->saw_trailing_dot || score < 3) {
			continue;
		}
		DartClassInfo *eci = ht_pp_find (class_by_name, ec->name, NULL);
		if (!eci) {
			eci = R_NEW0 (DartClassInfo);
			eci->name = strdup (ec->name);
			eci->fields = r_list_newf ((RListFree)dart_field_info_free);
			eci->interfaces = r_list_newf (free);
			if (!eci->name || !eci->fields || !eci->interfaces) {
				dart_class_info_free (eci);
				continue;
			}
			r_list_append (class_list, eci);
			ht_pp_insert (class_by_name, eci->name, eci);
		}
		eci->flags |= DART_CLASS_ENUM;
		class_info_add_enum_values (eci, ec->values);
		recovered++;
		if (ctx->verbose > 1) {
			fprintf (stderr, "[r2flutter] recovered enum %s (%d values, score=%d)\n", ec->name, r_list_length (ec->values), score);
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Recovered %d enums from strings\n", recovered);
	}
	r_list_free (candidates);
	ht_pp_free (candidate_by_name);
	ht_pp_free (class_by_name);
	dart_string_list_free (strings);
}

static int decode_library_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *libraries, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 10000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Library cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		LibraryInfo *li = R_NEW0 (LibraryInfo);
		li->ref_id = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		li->name_ref = name_ref;
		ut64 skip_refs = 5;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		r_list_append (libraries, li);
		if (ctx->refs && li->ref_id < ctx->refs_count) {
			ctx->refs[li->ref_id] = li;
		}
	}
	return 0;
}

static void resolve_class_and_field_names(DartCtx *ctx, RList *class_list, RList *field_list) {
	if (!ctx || !ctx->refs || !class_list) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (!ci) {
			continue;
		}
		if (!ci->name && ci->name_ref > 0 && ci->name_ref < ctx->refs_count) {
			void *ref = ctx->refs[ci->name_ref];
			if (ref) {
				DartString *ds = (DartString *)ref;
				if (ds->value) {
					ci->name = strdup (ds->value);
					dart_obf_apply (ctx, &ci->name);
				}
			}
		}
		if (ci->super_class_ref > 0 && ci->super_class_ref < ctx->refs_count) {
			void *ref = ctx->refs[ci->super_class_ref];
			if (ref) {
				DartClassInfo *parent = (DartClassInfo *)ref;
				if (parent->name) {
					ci->super_class_name = strdup (parent->name);
					dart_obf_apply (ctx, &ci->super_class_name);
				}
			}
		}
		if (ci->library_ref > 0 && ci->library_ref < ctx->refs_count) {
			void *ref = ctx->refs[ci->library_ref];
			if (ref) {
				LibraryInfo *lib = (LibraryInfo *)ref;
				if (lib->uri) {
					ci->library_name = strdup (lib->uri);
					dart_obf_apply (ctx, &ci->library_name);
				}
			}
		}
	}
	if (!field_list) {
		return;
	}
	DartFieldInfo *fi;
	r_list_foreach (field_list, it, fi) {
		if (!fi) {
			continue;
		}
		if (!fi->name && fi->name_ref > 0 && fi->name_ref < ctx->refs_count) {
			void *ref = ctx->refs[fi->name_ref];
			if (ref) {
				DartString *ds = (DartString *)ref;
				if (ds->value) {
					fi->name = strdup (ds->value);
					dart_obf_apply (ctx, &fi->name);
				}
			}
		}
		if (fi->owner_ref > 0 && fi->owner_ref < ctx->refs_count) {
			void *ref = ctx->refs[fi->owner_ref];
			if (ref) {
				DartClassInfo *owner = (DartClassInfo *)ref;
				if (owner->fields) {
					DartFieldInfo *fi_copy = R_NEW0 (DartFieldInfo);
					fi_copy->ref_id = fi->ref_id;
					fi_copy->name = fi->name? strdup (fi->name): NULL;
					fi_copy->type_name = fi->type_name? strdup (fi->type_name): NULL;
					fi_copy->offset = fi->offset;
					fi_copy->flags = fi->flags;
					fi_copy->type_ref = fi->type_ref;
					fi_copy->name_ref = fi->name_ref;
					fi_copy->owner_ref = fi->owner_ref;
					r_list_append (owner->fields, fi_copy);
				}
			}
		}
	}
}

static int parse_snapshot_header(DartCtx *ctx, ut64 snapshot_base, ut64 *out_nb, ut64 *out_no, ut64 *out_nc, ut64 *out_itlen, ut64 *out_itdata, ut64 *out_total_len, ut64 *out_cluster_start) {
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (ctx, snapshot_base, hdr, sizeof (hdr))) {
		return -1;
	}
	uint32_t magic = *(uint32_t *) (hdr + 0);
	if (magic != 0xdcdcf5f5) {
		return -1;
	}
	uint64_t length_ex_magic = *(uint64_t *) (hdr + 4);
	*out_total_len = length_ex_magic + 4;
	ut64 cursor = snapshot_base + 4 + 8 + 8 + 32;
	const int max_scan = 1024;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem (ctx, cursor + scanned, &b, 1)) {
			break;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	cursor += (ut64) (scanned + 1);
	ut64 next = cursor;
	if (!read_uleb128_at (ctx, next, out_nb, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, out_no, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, out_nc, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, out_itlen, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, next, out_itdata, &next)) {
		return -1;
	}
	*out_cluster_start = next;
	return 0;
}

static void scan_fields_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end);
static void scan_methods_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end);

RList *dart_pool_extract_classes(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	if (find_snapshots (ctx) != 0 || !ctx->iso_data) {
		return NULL;
	}
	ut64 snapshot_base = ctx->iso_data;
	DartVerLayout layout_tmp;
	DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, total_len = 0, cluster_start = 0;
	if (parse_snapshot_header (ctx, snapshot_base, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) != 0) {
		dart_ctx_fini_layout (ctx, layout_owned);
		return NULL;
	}
	bool header_valid = (nc > 0 && nc < 1000000 && no > 0 && no < 10000000);
	RList *class_list = r_list_newf ((RListFree)dart_class_info_free);
	RList *field_list = r_list_newf ((RListFree)dart_field_info_free);
	ctx->strings = r_list_newf (free_dart_string);
	RList *libraries = r_list_newf (free_library_info);
	if (header_valid) {
		ctx->num_base_objects = nb;
		ctx->num_objects = no;
		ctx->num_clusters = nc;
		ut64 total_refs = nb + no + 16;
		ctx->refs_count = total_refs;
		ctx->refs = (void **)calloc (total_refs, sizeof (void *));
		ClusterStream stream = {
			.ctx = ctx,
			.cursor = cluster_start,
			.end = snapshot_base + total_len
		};
		ut64 ref_counter = nb + 1;
		for (ut64 ci2 = 0; ci2 < nc && stream.cursor < stream.end; ci2++) {
			uint32_t tags = 0;
			if (!cs_read_u32 (&stream, &tags)) {
				break;
			}
			uint32_t cid = (tags >> 12) & 0xFFFFF;
			bool is_canonical = tags & 1;
			(void)is_canonical;
			if (ctx->verbose > 1) {
				fprintf (stderr, "[r2flutter] Cluster %" PRIu64 ": cid=%u (Class=%d,Field=%d,String=%d)\n", ci2, cid, kClassCid, kFieldCid_extract, kOneByteStringCid);
			}
			int rc = 0;
			switch (cid) {
			case kOneByteStringCid:
			case kTwoByteStringCid:
			case kStringCid:
				rc = decode_string_cluster (&stream, ctx, &ref_counter, false);
				break;
			case kClassCid:
				rc = decode_class_cluster_ext (&stream, ctx, class_list, &ref_counter);
				break;
			case kFieldCid_extract:
				rc = decode_field_cluster_ext (&stream, ctx, field_list, &ref_counter);
				break;
			case kLibraryCid_extract:
				rc = decode_library_cluster_ext (&stream, ctx, libraries, &ref_counter);
				break;
			default:
				skip_generic_cluster (&stream);
				break;
			}
			if (rc < 0) {
				break;
			}
		}
		resolve_class_and_field_names (ctx, class_list, field_list);
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] Extracted fields from clusters: %d\n", field_list? r_list_length (field_list): 0);
		}
	} else {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] class extraction: skipping cluster parse (clusters=%" PRIu64 " objs=%" PRIu64 ")\n", nc, no);
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Extracted classes from clusters: %d\n", class_list? r_list_length (class_list): 0);
	}
	if (!class_list || r_list_length (class_list) == 0) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] Falling back to string-based type extraction\n");
		}
		ut64 scan_start = ctx->vm_data;
		ut64 scan_end = ctx->iso_data;
		if (scan_end > scan_start && (scan_end - scan_start) < 0x1000000) {
			ut64 pos = scan_start;
			int class_count = 0;
			while (pos < scan_end - 4 && class_count < 4000) {
				ut8 buf[128];
				int to_read = (scan_end - pos > 127)? 127: (int) (scan_end - pos);
				if (!read_mem (ctx, pos, buf, to_read)) {
					break;
				}
				int slen = 0;
				while (slen < to_read && buf[slen] >= 0x20 && buf[slen] < 0x7f) {
					slen++;
				}
				if (slen >= 3 && slen < 80 && (buf[slen] == 0 || buf[slen] < 0x20 || buf[slen] >= 0x7f)) {
					char saved = buf[slen];
					buf[slen] = 0;
					char *s = (char *)buf;
					if (is_type_name_candidate (s)) {
						DartClassInfo *ci = R_NEW0 (DartClassInfo);
						ci->name = strdup (s);
						dart_obf_apply (ctx, &ci->name);
						ci->ref_id = 0;
						ci->instance_size = 0;
						ci->flags = 0;
						ci->fields = r_list_newf ((RListFree)dart_field_info_free);
						ci->interfaces = r_list_newf (free);
						r_list_append (class_list, ci);
						class_count++;
					}
					buf[slen] = saved;
					pos += slen + 1;
				} else {
					pos++;
				}
			}
		}
	}
	free (ctx->refs);
	ctx->refs = NULL;
	ctx->refs_count = 0;
	r_list_free (ctx->strings);
	ctx->strings = NULL;
	r_list_free (libraries);
	r_list_free (field_list);
	if (ctx->dump_fields && r_list_length (class_list) > 0) {
		ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
		ut64 data_image_base = snapshot_base + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
		ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: (data_image_base + (4ULL << 20));
		scan_fields_from_data_image (ctx, class_list, data_image_base, data_image_end);
		scan_methods_from_data_image (ctx, class_list, data_image_base, data_image_end);
		if (ctx->vm_data) {
			ut64 vm_nb = 0, vm_no = 0, vm_nc = 0, vm_itlen = 0, vm_itdata = 0, vm_total = 0, vm_cluster = 0;
			if (parse_snapshot_header (ctx, ctx->vm_data, &vm_nb, &vm_no, &vm_nc, &vm_itlen, &vm_itdata, &vm_total, &vm_cluster) == 0) {
				ut64 vm_data_base = ctx->vm_data + ((vm_total + (kAlign - 1)) & ~ (kAlign - 1));
				ut64 vm_data_end = ctx->vm_instr? ctx->vm_instr: (vm_data_base + (4ULL << 20));
				scan_fields_from_data_image (ctx, class_list, vm_data_base, vm_data_end);
				scan_methods_from_data_image (ctx, class_list, vm_data_base, vm_data_end);
			}
		}
	}
	dart_ctx_fini_layout (ctx, layout_owned);
	return class_list;
}

RList *dart_pool_get_class_hierarchy(DartCtx *ctx, ut64 class_ref) {
	(void)ctx;
	(void)class_ref;
	return r_list_newf (free);
}

static void scan_fields_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end) {
	if (!ctx || !ctx->core || !class_list || data_start >= data_end) {
		return;
	}
	ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	bool use_compressed = (ctx->compressed_word_size == 4);
	int cid_field = kFieldCid;
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
	for (ut64 pos = data_start; pos < data_end - 48 && field_count < max_fields; pos += kAlign) {
		ut8 hdr[48];
		if (!read_mem (ctx, pos, hdr, sizeof (hdr))) {
			continue;
		}
		ut64 header = *(ut64 *)hdr;
		ut32 obj_cid = (header >> 12) & 0xFFFFF;
		if ((int)obj_cid != cid_field) {
			continue;
		}
		ut64 name_ptr = 0, owner_ptr = 0;
		ut32 kind_bits = 0, offset_val = 0;
		if (use_compressed) {
			name_ptr = *(ut32 *) (hdr + 8);
			owner_ptr = *(ut32 *) (hdr + 12);
			kind_bits = *(ut32 *) (hdr + 24);
			offset_val = *(ut32 *) (hdr + 28);
		} else {
			name_ptr = *(ut64 *) (hdr + 8);
			owner_ptr = *(ut64 *) (hdr + 16);
			kind_bits = *(ut32 *) (hdr + 40);
			offset_val = *(ut32 *) (hdr + 44);
		}
		if (name_ptr == 0 || owner_ptr == 0) {
			continue;
		}
		char field_name[128] = { 0 };
		ut64 name_addr = use_compressed? (data_start + (name_ptr & ~3ULL)): name_ptr;
		if (name_addr >= data_start && name_addr < data_end) {
			if (!try_read_dart_string (ctx, name_addr, field_name, sizeof (field_name))) {
				snprintf (field_name, sizeof (field_name), "field_%d", field_count);
			}
		}
		dart_obf_apply_buf (ctx, field_name, sizeof (field_name));
		char owner_name[128] = { 0 };
		ut64 owner_addr = use_compressed? (data_start + (owner_ptr & ~3ULL)): owner_ptr;
		if (owner_addr >= data_start && owner_addr < data_end) {
			ut8 owner_hdr[32];
			if (read_mem (ctx, owner_addr, owner_hdr, sizeof (owner_hdr))) {
				ut64 owner_name_ptr = use_compressed? *(ut32 *) (owner_hdr + 8): *(ut64 *) (owner_hdr + 8);
				ut64 owner_name_addr = use_compressed? (data_start + (owner_name_ptr & ~3ULL)): owner_name_ptr;
				if (owner_name_addr >= data_start && owner_name_addr < data_end) {
					try_read_dart_string (ctx, owner_name_addr, owner_name, sizeof (owner_name));
				}
			}
		}
		dart_obf_apply_buf (ctx, owner_name, sizeof (owner_name));
		if (owner_name[0] && field_name[0]) {
			field_count++;
			DartClassInfo *owner_ci = (DartClassInfo *)ht_pp_find (class_by_name, owner_name, NULL);
			if (owner_ci && owner_ci->fields) {
				DartFieldInfo *fi = R_NEW0 (DartFieldInfo);
				fi->name = strdup (field_name);
				fi->offset = offset_val;
				fi->flags = kind_bits;
				r_list_append (owner_ci->fields, fi);
				if (ctx->verbose > 1) {
					fprintf (stderr, "[r2flutter] Found field: %s.%s offset=0x%x\n", owner_name, field_name, offset_val);
				}
			} else if (ctx->verbose > 1 && field_count < 64) {
				fprintf (stderr, "[r2flutter] field owner miss: %s.%s\n", owner_name, field_name);
			}
		}
	}
	ht_pp_free (class_by_name);
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Scanned %d fields from data image\n", field_count);
	}
}

typedef struct {
	ut32 entry_off;
	ut32 unchecked_off;
	ut32 name_off;
	ut32 owner_off;
	ut32 kind_tag_off;
	ut32 class_name_off;
} DartFunctionLayout;

static void init_function_layout(DartCtx *ctx, DartFunctionLayout *fl) {
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
		ut32 rel = *(const ut32 *) (buf + off);
		ut64 addr = data_base + ((ut64)rel & ~3ULL);
		if (addr < data_base || addr >= data_end) {
			if (restrict_range) {
				return false;
			}
		}
		*out_addr = addr;
		return true;
	}
	ut64 addr = *(const ut64 *) (buf + off);
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

static const char *method_kind_name(uint32_t kind_tag) {
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

static void scan_methods_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end) {
	if (!ctx || !ctx->core || !class_list || data_start >= data_end) {
		return;
	}
	if (!ctx->layout) {
		return;
	}
	bool use_compressed = (ctx->compressed_word_size == 4);
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
	int cid_function = ctx->layout->cid_function? ctx->layout->cid_function: kFunctionCid;
	ut64 methods_found = 0;
	const ut64 max_methods = 30000;
	char method_name[128];
	char owner_name[128];
	for (ut64 pos = data_start; pos + fl.kind_tag_off + 8 < data_end; pos += align) {
		ut8 buf[128];
		if (!read_mem (ctx, pos, buf, sizeof (buf))) {
			continue;
		}
		ut64 header = *(ut64 *)buf;
		ut32 cid = extract_cid_from_header (ctx, header);
		if ((int)cid != cid_function) {
			continue;
		}
		ut64 entry = *(ut64 *) (buf + fl.entry_off);
		if (!entry || entry == UT64_MAX) {
			continue;
		}
		if (entry < ctx->iso_instr || entry > (ctx->iso_instr + (1ULL << 28))) {
			continue;
		}
		if (ht_up_find (seen_ep, entry, NULL)) {
			continue;
		}
		ut64 name_addr = 0;
		if (!read_object_pointer (ctx, buf, fl.name_off, use_compressed, data_start, data_end, true, &name_addr)) {
			continue;
		}
		if (!read_string_safe (ctx, name_addr, method_name, sizeof (method_name))) {
			continue;
		}
		dart_obf_apply_buf (ctx, method_name, sizeof (method_name));
		ut64 owner_addr = 0;
		if (!read_object_pointer (ctx, buf, fl.owner_off, use_compressed, data_start, data_end, false, &owner_addr)) {
			continue;
		}
		owner_name[0] = '\0';
		if (owner_addr) {
			ut8 owner_buf[32];
			if (read_mem (ctx, owner_addr, owner_buf, sizeof (owner_buf))) {
				ut64 owner_name_ptr = 0;
				if (read_object_pointer (ctx, owner_buf, fl.class_name_off, use_compressed, data_start, data_end, true, &owner_name_ptr)) {
					read_string_safe (ctx, owner_name_ptr, owner_name, sizeof (owner_name));
				}
			}
		}
		dart_obf_apply_buf (ctx, owner_name, sizeof (owner_name));
		if (!*owner_name) {
			continue;
		}
		if (ctx->verbose > 1 && methods_found < 64) {
			fprintf (stderr, "[r2flutter] method candidate %s.%s\n", owner_name, method_name);
		}
		DartClassInfo *owner_ci = ht_pp_find (class_by_name, owner_name, NULL);
		if (!owner_ci || !owner_ci->methods) {
			continue;
		}
		DartMethodInfo *mi = R_NEW0 (DartMethodInfo);
		if (!mi) {
			continue;
		}
		mi->entry_point = entry;
		mi->name = strdup (method_name);
		mi->owner_name = strdup (owner_name);
		mi->kind_tag = *(uint32_t *) (buf + fl.kind_tag_off);
		ht_up_insert (seen_ep, entry, mi);
		r_list_append (owner_ci->methods, mi);
		if (ctx->verbose > 1) {
			fprintf (stderr, "[r2flutter] method %s.%s @0x%" PFMT64x "\n", owner_name, method_name, (ut64)entry);
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

RList *dart_pool_extract_fields(DartCtx *ctx, ut64 class_ref) {
	(void)ctx;
	(void)class_ref;
	return r_list_newf ((RListFree)dart_field_info_free);
}

static void dump_class_json(PJ *pj, const DartClassInfo *ci) {
	pj_o (pj);
	pj_kn (pj, "ref", ci->ref_id);
	if (ci->name) {
		pj_ks (pj, "name", ci->name);
	}
	if (ci->library_name || ci->library_ref) {
		pj_k (pj, "library");
		pj_o (pj);
		pj_kn (pj, "ref", ci->library_ref);
		if (ci->library_name) {
			pj_ks (pj, "name", ci->library_name);
		}
		pj_end (pj);
	}
	if (ci->super_class_name || ci->super_class_ref) {
		pj_k (pj, "super");
		pj_o (pj);
		pj_kn (pj, "ref", ci->super_class_ref);
		if (ci->super_class_name) {
			pj_ks (pj, "name", ci->super_class_name);
		}
		pj_end (pj);
	}
	pj_k (pj, "layout");
	pj_o (pj);
	pj_ki (pj, "instance_size", ci->instance_size);
	pj_ki (pj, "type_params", ci->num_type_parameters);
	pj_ki (pj, "type_arg_offset", ci->type_argument_offset);
	pj_end (pj);
	pj_k (pj, "flags");
	pj_o (pj);
	pj_kb (pj, "abstract", (ci->flags & DART_CLASS_ABSTRACT) != 0);
	pj_kb (pj, "enum", (ci->flags & DART_CLASS_ENUM) != 0);
	pj_kb (pj, "mixin", (ci->flags & DART_CLASS_MIXIN) != 0);
	pj_kb (pj, "toplevel", (ci->flags & DART_CLASS_TOPLEVEL) != 0);
	pj_end (pj);
	if (ci->enums && r_list_length (ci->enums) > 0) {
		pj_ka (pj, "enums");
		RListIter *eit;
		char *value;
		r_list_foreach (ci->enums, eit, value) {
			if (value) {
				pj_s (pj, value);
			}
		}
		pj_end (pj);
	}
	if (ci->fields && r_list_length (ci->fields) > 0) {
		pj_ka (pj, "fields");
		RListIter *fit;
		DartFieldInfo *fi;
		r_list_foreach (ci->fields, fit, fi) {
			pj_o (pj);
			if (fi->name) {
				pj_ks (pj, "name", fi->name);
			}
			if (fi->type_name) {
				pj_ks (pj, "type", fi->type_name);
			}
			pj_ki (pj, "offset", fi->offset);
			pj_k (pj, "flags");
			pj_o (pj);
			pj_kb (pj, "static", (fi->flags & DART_FIELD_STATIC) != 0);
			pj_kb (pj, "final", (fi->flags & DART_FIELD_FINAL) != 0);
			pj_kb (pj, "const", (fi->flags & DART_FIELD_CONST) != 0);
			pj_kb (pj, "late", (fi->flags & DART_FIELD_LATE) != 0);
			pj_end (pj);
			pj_end (pj);
		}
		pj_end (pj);
	}
	if (ci->methods && r_list_length (ci->methods) > 0) {
		pj_ka (pj, "methods");
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			pj_o (pj);
			if (mi->name) {
				pj_ks (pj, "name", mi->name);
			}
			pj_kn (pj, "entry", mi->entry_point);
			if (mi->owner_name) {
				pj_ks (pj, "owner", mi->owner_name);
			}
			pj_kn (pj, "kind_tag", mi->kind_tag);
			pj_ks (pj, "kind", method_kind_name (mi->kind_tag));
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
}

static void append_enum_values(RStrBuf *sb, const DartClassInfo *ci) {
	if (!sb || !ci || !ci->enums || r_list_length (ci->enums) == 0) {
		return;
	}
	char *joined = r_str_list_join (ci->enums, ", ");
	if (!joined) {
		return;
	}
	r_strbuf_append (sb, " { ");
	r_strbuf_append (sb, joined);
	r_strbuf_append (sb, " }");
	free (joined);
}

static void dump_class_text(RStrBuf *sb, const DartClassInfo *ci, int fmt, bool type_view) {
	const bool emit_r2 = fmt == 'r';
	const bool emit_enum_literal = type_view &&
		(ci->flags & DART_CLASS_ENUM) &&
		ci->enums &&
		r_list_length (ci->enums) > 0;
	if (!ci || !ci->name) {
		return;
	}
	if (emit_r2) {
		char safe_name[256];
		snprintf (safe_name, sizeof (safe_name), "%s", ci->name);
		r_name_filter (safe_name, 0);
		if (emit_enum_literal) {
			r_strbuf_appendf (sb, "# enum %s", ci->name);
			append_enum_values (sb, ci);
			r_strbuf_append (sb, "\n");
			r_strbuf_appendf (sb, "\"td struct.dart.%s { };\"\n", safe_name);
			return;
		}
		r_strbuf_appendf (sb, "# class %s", ci->name);
		if (ci->super_class_name) {
			r_strbuf_appendf (sb, " extends %s", ci->super_class_name);
		}
		r_strbuf_appendf (sb, " (size=%u", ci->instance_size);
		if (ci->flags & DART_CLASS_ABSTRACT) {
			r_strbuf_append (sb, " abstract");
		}
		if (ci->flags & DART_CLASS_ENUM) {
			r_strbuf_append (sb, " enum");
		}
		if (ci->flags & DART_CLASS_MIXIN) {
			r_strbuf_append (sb, " mixin");
		}
		r_strbuf_append (sb, ")\n");
		if (ci->library_name) {
			r_strbuf_appendf (sb, "#   library: %s\n", ci->library_name);
		}
		if (ci->num_type_parameters > 0) {
			r_strbuf_appendf (sb, "#   type_params: %u\n", ci->num_type_parameters);
		}
		r_strbuf_appendf (sb, "\"td struct.dart.%s {", safe_name);
		if (ci->fields && r_list_length (ci->fields) > 0) {
			RListIter *fit;
			DartFieldInfo *fi;
			r_list_foreach (ci->fields, fit, fi) {
				r_strbuf_appendf (sb, " %s %s @ 0x%x;", r_str_get (fi->type_name), r_str_get (fi->name), fi->offset);
			}
		}
		r_strbuf_append (sb, " };\"\n");
		if (ci->methods && r_list_length (ci->methods) > 0) {
			RListIter *mit;
			DartMethodInfo *mi;
			r_list_foreach (ci->methods, mit, mi) {
				r_strbuf_appendf (sb, "#   method 0x%08" PFMT64x " %s (%s)\n", (ut64)mi->entry_point, r_str_get (mi->name), method_kind_name (mi->kind_tag));
			}
		}
		return;
	}
	if (emit_enum_literal) {
		r_strbuf_appendf (sb, "enum %s", ci->name);
		append_enum_values (sb, ci);
		r_strbuf_append (sb, "\n");
		return;
	}
	r_strbuf_appendf (sb, "class %s", ci->name);
	if (ci->super_class_name) {
		r_strbuf_appendf (sb, " extends %s", ci->super_class_name);
	}
	r_strbuf_appendf (sb, " (size=%u", ci->instance_size);
	if (ci->flags & DART_CLASS_ABSTRACT) {
		r_strbuf_append (sb, " abstract");
	}
	if (ci->flags & DART_CLASS_ENUM) {
		r_strbuf_append (sb, " enum");
	}
	if (ci->flags & DART_CLASS_MIXIN) {
		r_strbuf_append (sb, " mixin");
	}
	r_strbuf_append (sb, ")\n");
	if (ci->library_name) {
		r_strbuf_appendf (sb, "  library: %s\n", ci->library_name);
	}
	if (ci->fields && r_list_length (ci->fields) > 0) {
		r_strbuf_append (sb, "  fields:\n");
		RListIter *fit;
		DartFieldInfo *fi;
		r_list_foreach (ci->fields, fit, fi) {
			r_strbuf_appendf (sb, "    +0x%x %s %s", fi->offset, r_str_get (fi->type_name), r_str_get (fi->name));
			if (fi->flags & DART_FIELD_STATIC) {
				r_strbuf_append (sb, " static");
			}
			if (fi->flags & DART_FIELD_FINAL) {
				r_strbuf_append (sb, " final");
			}
			if (fi->flags & DART_FIELD_CONST) {
				r_strbuf_append (sb, " const");
			}
			r_strbuf_append (sb, "\n");
		}
	}
	if (ci->methods && r_list_length (ci->methods) > 0) {
		r_strbuf_append (sb, "  methods:\n");
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			r_strbuf_appendf (sb, "    0x%08" PFMT64x " %s (%s)\n", (ut64)mi->entry_point, r_str_get (mi->name), method_kind_name (mi->kind_tag));
		}
	}
}

char *dart_pool_dump_classes(DartCtx *ctx, int fmt) {
	RList *classes = dart_pool_extract_classes (ctx);
	const bool type_view = ctx && ctx->dump_classes == 3;
	if (!classes && type_view) {
		classes = r_list_newf ((RListFree)dart_class_info_free);
	}
	if (classes && type_view) {
		recover_enum_types_from_strings (ctx, classes);
	}
	if (fmt == 'j') {
		if (!classes || r_list_length (classes) == 0) {
			if (classes) {
				dart_class_list_free (classes);
			}
			return strdup ("[]");
		}
		PJ *pj = pj_new ();
		pj_a (pj);
		RListIter *it;
		DartClassInfo *ci;
		r_list_foreach (classes, it, ci) {
			if (ci) {
				dump_class_json (pj, ci);
			}
		}
		pj_end (pj);
		dart_class_list_free (classes);
		return pj_drain (pj);
	}
	if (!classes) {
		return strdup ("# No classes found\n");
	}
	RStrBuf *sb = r_strbuf_new (fmt == 'r'? "# Dart classes extracted from snapshot\n": "");
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (classes, it, ci) {
		dump_class_text (sb, ci, fmt, type_view);
	}
	dart_class_list_free (classes);
	return r_strbuf_drain (sb);
}

// ============================================================================
// String Extraction
// ============================================================================

void dart_string_ref_free(DartStringRef *sr) {
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
static DartStringCategory classify_string_value(const char *s) {
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
static int parse_snapshot_header(DartCtx *ctx, ut64 snapshot_base, ut64 *out_nb, ut64 *out_no, ut64 *out_nc, ut64 *out_itlen, ut64 *out_itdata, ut64 *out_total_len, ut64 *out_cluster_start);
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

typedef struct {
	bool ok;
	ut64 total_len;
	ut64 cluster_start;
} PackedSnapshotHeader;

static void packed_string_record_fini(PackedStringRecord *rec) {
	if (!rec) {
		return;
	}
	free (rec->value);
	rec->value = NULL;
}

static bool read_dart_unsigned_buf(const ut8 *buf, ut64 size, ut64 pos, ut64 *out_val, ut64 *out_next) {
	if (!buf || pos >= size) {
		return false;
	}
	ut8 b = buf[pos++];
	if (b > 0x7f) {
		if (out_val) {
			*out_val = b - 0x80;
		}
		if (out_next) {
			*out_next = pos;
		}
		return true;
	}
	ut64 value = 0;
	int shift = 0;
	for (;;) {
		value |= ((ut64)b) << shift;
		shift += 7;
		if (pos >= size) {
			return false;
		}
		b = buf[pos++];
		if (b > 0x7f) {
			value |= ((ut64) (b - 0x80)) << shift;
			if (out_val) {
				*out_val = value;
			}
			if (out_next) {
				*out_next = pos;
			}
			return true;
		}
	}
}

static bool read_packed_snapshot_header(const ut8 *buf, ut64 size, PackedSnapshotHeader *out) {
	if (!buf || !out || size < 4 + 8 + 8 + 32 + 1) {
		return false;
	}
	memset (out, 0, sizeof (*out));
	uint32_t magic = *(const uint32_t *)buf;
	if (magic != 0xdcdcf5f5) {
		return false;
	}
	ut64 total_len = *(const ut64 *) (buf + 4) + 4;
	if (total_len > size) {
		return false;
	}
	ut64 cursor = 4 + 8 + 8 + 32;
	int scanned = 0;
	while (cursor + scanned < size && scanned < 1024) {
		if (buf[cursor + scanned] == '\0') {
			break;
		}
		scanned++;
	}
	if (cursor + scanned >= size || buf[cursor + scanned] != '\0') {
		return false;
	}
	cursor += (ut64) (scanned + 1);
	ut64 next = cursor;
	ut64 dummy = 0;
	for (int i = 0; i < 5; i++) {
		if (!read_dart_unsigned_buf (buf, size, next, &dummy, &next)) {
			return false;
		}
	}
	if (next >= total_len) {
		return false;
	}
	out->ok = true;
	out->total_len = total_len;
	out->cluster_start = next;
	return true;
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
	if (!si->value) {
		dart_string_info_free (si);
		return;
	}
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
					append_string_info (list, seen_addrs, tmp, (ut32)length, 0, base + start, classify_string_value (tmp), ref_counter);
				}
				free (tmp);
			}
		}
	}
}

static bool decode_utf16le_unit(const ut8 *buf, ut64 size, ut64 idx, ut32 *out) {
	if (idx + 1 >= size) {
		return false;
	}
	uint16_t lo = buf[idx];
	uint16_t hi = buf[idx + 1];
	ut32 code = (hi << 8) | lo;
	if (!code) {
		return false;
	}
	*out = code;
	return true;
}

static int emit_utf16le(const ut8 *buf, ut64 start, ut64 end, RStrBuf *sb) {
	ut64 pos = start;
	while (pos + 1 < end) {
		ut32 code = 0;
		if (!decode_utf16le_unit (buf, end, pos, &code)) {
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
		ut32 code = 0;
		if (!decode_utf16le_unit (buf, end, pos, &code)) {
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
	if (!read_dart_unsigned_buf (buf, size, pos, &encoded, &next)) {
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
	if (!read_dart_unsigned_buf (buf, size, pos, &encoded, &payload_off)) {
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
				append_string_info (list, seen_addrs, rec->value, rec->length, rec->flags, base + rec->payload_off, classify_string_value (rec->value), ref_counter);
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
	if (*(const ut32 *)hdrbuf != 0xdcdcf5f5) {
		return;
	}
	ut64 total_len = *(const ut64 *) (hdrbuf + 4) + 4;
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
	PackedSnapshotHeader hdr = { 0 };
	if (!read_packed_snapshot_header (buf, total_len, &hdr)) {
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
	RBinObject *bobj = r_bin_cur_object (ctx->core->bin);
	if (!bobj || !bobj->sections) {
		return;
	}
	RListIter *iter;
	RBinSection *sec;
	r_list_foreach (bobj->sections, iter, sec) {
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
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, total_len = 0, cluster_start = 0;
	if (parse_snapshot_header (ctx, snapshot_base, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) != 0) {
		goto fallback;
	}
	if (total_len == 0 || total_len > DART_SNAPSHOT_SCAN_MAX || cluster_start >= total_len) {
		goto fallback;
	}
	if (ctx->compressed_word_size == 4) {
		scan_packed_strings_from_snapshot (ctx, snapshot_base, list, seen_addrs, ref_counter);
		return;
	}
	scan_snapshot_region (ctx, snapshot_base + cluster_start, total_len - cluster_start, list, seen_addrs, ref_counter);
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	if (align == 0) {
		align = 16;
	}
	ut64 data_start = snapshot_base + ((total_len + (align - 1)) & ~ (align - 1));
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
		ut32 code = 0;
		if (!decode_utf16le_unit (buf, size, pos, &code)) {
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
				append_string_info (list, seen_addrs, utf8, ulen, DART_STRING_TWO_BYTE, base + start, classify_string_value (utf8), ref_counter);
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
	if (!string_list) {
		return NULL;
	}
	HtUP *seen_addrs = ht_up_new0 ();
	if (!seen_addrs) {
		return string_list;
	}
	RBinObject *bobj = r_bin_cur_object (ctx->core->bin);
	if (!bobj || !bobj->sections) {
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
	RListIter *iter;
	RBinSection *sec;
	r_list_foreach (bobj->sections, iter, sec) {
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
	ht_up_free (seen_addrs);
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

static void dump_string_json(PJ *pj, const DartStringInfo *si) {
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
	if (si->references && r_list_length (si->references) > 0) {
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
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
}

static void dump_string_text(RStrBuf *sb, const DartStringInfo *si, int fmt) {
	if (!si || !si->value) {
		return;
	}
	if (fmt == 'r') {
		// | iz+ ([addr]) ([len]) ([type])  add string manually (addr=current seek if not specified, len=auto, type=auto-detect)
		r_strbuf_appendf (sb, "iz+ 0x%08" PFMT64x " %d\n", si->address, si->length);
	} else {
		char *str = r_str_escape_utf8 (si->value, false, true);
		r_strbuf_appendf (sb, "0x%08" PRIx64 " %4d :%s \"%s\"\n", si->address, si->length, string_category_name (si->category), str);
		free (str);
	}
	if (si->references && r_list_length (si->references) > 0) {
		r_strbuf_appendf (sb, "#   referenced by %d objects\n", r_list_length (si->references));
	}
}

char *dart_pool_dump_strings(DartCtx *ctx, int fmt) {
	RList *strings = dart_pool_extract_strings (ctx);
	if (fmt == 'j') {
		if (!strings || r_list_length (strings) == 0) {
			if (strings) {
				dart_string_list_free (strings);
			}
			return strdup ("[]");
		}
		PJ *pj = pj_new ();
		pj_a (pj);
		RListIter *it;
		DartStringInfo *si;
		r_list_foreach (strings, it, si) {
			if (si) {
				dump_string_json (pj, si);
			}
		}
		pj_end (pj);
		dart_string_list_free (strings);
		return pj_drain (pj);
	}
	if (!strings) {
		return strdup ("# No strings found\n");
	}
	RStrBuf *sb = r_strbuf_new (fmt == 'r'? "# Dart Strings\n": "");
	RListIter *it;
	DartStringInfo *si;
	r_list_foreach (strings, it, si) {
		dump_string_text (sb, si, fmt);
	}
	if (fmt == 'r') {
		r_strbuf_appendf (sb, "# Total: %d strings\n", r_list_length (strings));
	}
	dart_string_list_free (strings);
	return r_strbuf_drain (sb);
}

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
	ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	bool use_compressed = ctx->compressed_word_size == 4;
	int cid_field = kFieldCid;
	int field_count = 0;
	const int max_fields = 5000;
	for (ut64 pos = data_start; pos < data_end - 48 && field_count < max_fields && !xref_limit_reached (*count, limit); pos += kAlign) {
		ut8 hdr[48];
		if (!read_mem (ctx, pos, hdr, sizeof (hdr))) {
			continue;
		}
		ut64 header = *(ut64 *)hdr;
		ut32 obj_cid = (header >> 12) & 0xFFFFF;
		if ((int)obj_cid != cid_field) {
			continue;
		}
		ut64 name_ptr = 0, owner_ptr = 0;
		ut32 offset_val = 0;
		if (use_compressed) {
			name_ptr = *(ut32 *) (hdr + 8);
			owner_ptr = *(ut32 *) (hdr + 12);
			offset_val = *(ut32 *) (hdr + 28);
		} else {
			name_ptr = *(ut64 *) (hdr + 8);
			owner_ptr = *(ut64 *) (hdr + 16);
			offset_val = *(ut32 *) (hdr + 44);
		}
		if (!name_ptr || !owner_ptr) {
			continue;
		}
		char field_name[128] = { 0 };
		ut64 name_addr = use_compressed? (data_start + (name_ptr & ~3ULL)): name_ptr;
		if (name_addr >= data_start && name_addr < data_end && !try_read_dart_string (ctx, name_addr, field_name, sizeof (field_name))) {
			continue;
		}
		char owner_name[128] = { 0 };
		ut64 owner_addr = use_compressed? (data_start + (owner_ptr & ~3ULL)): owner_ptr;
		if (owner_addr >= data_start && owner_addr < data_end) {
			ut8 owner_hdr[32];
			if (read_mem (ctx, owner_addr, owner_hdr, sizeof (owner_hdr))) {
				ut64 owner_name_ptr = use_compressed? *(ut32 *) (owner_hdr + 8): *(ut64 *) (owner_hdr + 8);
				ut64 owner_name_addr = use_compressed? (data_start + (owner_name_ptr & ~3ULL)): owner_name_ptr;
				if (owner_name_addr >= data_start && owner_name_addr < data_end) {
					read_string_safe (ctx, owner_name_addr, owner_name, sizeof (owner_name));
				}
			}
		}
		if (!R_STR_ISNOTEMPTY (owner_name) || !R_STR_ISNOTEMPTY (field_name)) {
			continue;
		}
		char keybuf[320];
		snprintf (keybuf, sizeof (keybuf), "%s.%s@0x%x", owner_name, field_name, offset_val);
		if (r_list_find (seen_fields, keybuf, (RListComparator)strcmp)) {
			continue;
		}
		r_list_append (seen_fields, strdup (keybuf));
		char *field_label = xref_join_names (owner_name, field_name);
		append_xref_info (xrefs, count, limit, "data-image", "field.owner", "field", field_label, 0, 0, "class", owner_name, 0, 0);
		DartStringInfo *field_si = xref_find_string (strings_by_value, field_name);
		append_xref_info (xrefs, count, limit, "data-image", "field.name", "field", field_label, 0, 0, "string", field_name, 0, field_si? field_si->address: 0);
		free (field_label);
		field_count++;
	}
}

static void collect_method_scan_xrefs(DartCtx *ctx, HtPP *strings_by_value, RList *xrefs, HtUP *seen_ep, ut64 *count, ut64 limit, ut64 data_start, ut64 data_end) {
	if (!ctx || !ctx->core || !ctx->layout || !xrefs || data_start >= data_end || xref_limit_reached (*count, limit)) {
		return;
	}
	bool use_compressed = ctx->compressed_word_size == 4;
	DartFunctionLayout fl;
	init_function_layout (ctx, &fl);
	ut64 align = ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 8;
	if (!align) {
		align = 8;
	}
	int cid_function = ctx->layout->cid_function? ctx->layout->cid_function: kFunctionCid;
	ut64 methods_found = 0;
	const ut64 max_methods = 30000;
	char method_name[128];
	char owner_name[128];
	for (ut64 pos = data_start; pos + fl.kind_tag_off + 8 < data_end && methods_found < max_methods && !xref_limit_reached (*count, limit); pos += align) {
		ut8 buf[128];
		if (!read_mem (ctx, pos, buf, sizeof (buf))) {
			continue;
		}
		ut64 header = *(ut64 *)buf;
		ut32 cid = extract_cid_from_header (ctx, header);
		if ((int)cid != cid_function) {
			continue;
		}
		ut64 entry = *(ut64 *) (buf + fl.entry_off);
		if (!entry || entry == UT64_MAX) {
			continue;
		}
		if (entry < ctx->iso_instr || entry > (ctx->iso_instr + (1ULL << 28))) {
			continue;
		}
		if (ht_up_find (seen_ep, entry, NULL)) {
			continue;
		}
		ut64 name_addr = 0;
		if (!read_object_pointer (ctx, buf, fl.name_off, use_compressed, data_start, data_end, true, &name_addr)) {
			continue;
		}
		if (!read_string_safe (ctx, name_addr, method_name, sizeof (method_name))) {
			continue;
		}
		ut64 owner_addr = 0;
		if (!read_object_pointer (ctx, buf, fl.owner_off, use_compressed, data_start, data_end, false, &owner_addr)) {
			continue;
		}
		owner_name[0] = '\0';
		if (owner_addr) {
			ut8 owner_buf[32];
			if (read_mem (ctx, owner_addr, owner_buf, sizeof (owner_buf))) {
				ut64 owner_name_ptr = 0;
				if (read_object_pointer (ctx, owner_buf, fl.class_name_off, use_compressed, data_start, data_end, true, &owner_name_ptr)) {
					read_string_safe (ctx, owner_name_ptr, owner_name, sizeof (owner_name));
				}
			}
		}
		if (!R_STR_ISNOTEMPTY (owner_name)) {
			continue;
		}
		char *method_label = xref_join_names (owner_name, method_name);
		append_xref_info (xrefs, count, limit, "data-image", "method.owner", "method", method_label, 0, 0, "class", owner_name, 0, 0);
		DartStringInfo *method_si = xref_find_string (strings_by_value, method_name);
		append_xref_info (xrefs, count, limit, "data-image", "method.name", "method", method_label, 0, 0, "string", method_name, 0, method_si? method_si->address: 0);
		append_xref_info (xrefs, count, limit, "data-image", "method.entry", "method", method_label, 0, 0, "code", method_label, 0, entry);
		ht_up_insert (seen_ep, entry, (void *)1);
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

typedef struct {
	bool ok;
	uint32_t magic;
	uint64_t total_len;
	uint64_t kind;
	char hash[33];
	char flags[512];
	ut64 nb;
	ut64 no;
	ut64 nc;
	ut64 itlen;
	ut64 itdata;
} SnapshotHeader;

static SnapshotHeader read_snapshot_hdr(DartCtx *ctx, ut64 base) {
	SnapshotHeader hdr = { 0 };
	if (!ctx || !base) {
		return hdr;
	}
	ut8 buf[4 + 8 + 8];
	if (!read_mem (ctx, base, buf, sizeof (buf))) {
		return hdr;
	}
	hdr.magic = *(uint32_t *) (buf + 0);
	if (hdr.magic != 0xdcdcf5f5) {
		return hdr;
	}
	uint64_t length_ex_magic = *(uint64_t *) (buf + 4);
	hdr.total_len = length_ex_magic + 4;
	hdr.kind = *(uint64_t *) (buf + 12);
	ut64 cursor = base + 4 + 8 + 8;
	ut8 hashbuf[32];
	if (read_mem (ctx, cursor, hashbuf, 32)) {
		memcpy (hdr.hash, hashbuf, 32);
		hdr.hash[32] = '\0';
	}
	cursor += 32;
	int scanned = 0;
	ut8 b = 0;
	while (scanned < 1024) {
		if (!read_mem (ctx, cursor + scanned, &b, 1)) {
			break;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	int tocopy = scanned < (int) (sizeof (hdr.flags) - 1)? scanned: (int) (sizeof (hdr.flags) - 1);
	if (tocopy > 0) {
		read_mem (ctx, cursor, (ut8 *)hdr.flags, tocopy);
	}
	hdr.flags[tocopy] = '\0';
	cursor += (ut64) (scanned + 1);
	ut64 next = cursor;
	if (!read_uleb128_at (ctx, next, &hdr.nb, &next)) {
		return hdr;
	}
	if (!read_uleb128_at (ctx, next, &hdr.no, &next)) {
		return hdr;
	}
	if (!read_uleb128_at (ctx, next, &hdr.nc, &next)) {
		return hdr;
	}
	if (!read_uleb128_at (ctx, next, &hdr.itlen, &next)) {
		return hdr;
	}
	if (!read_uleb128_at (ctx, next, &hdr.itdata, &next)) {
		return hdr;
	}
	hdr.ok = true;
	return hdr;
}

static int prepare_header_data(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return -1;
	}
	int ok = find_snapshots (ctx);
	if (ok != 0) {
		return -1;
	}
	extract_snapshot_hash_flags (ctx, ctx->vm_data);
	ctx->layout = dart_pick_layout_by_hash (ctx->snapshot_hash);
	derive_layout_from_flags (ctx);
	return 0;
}

char *dart_pool_dump_header(DartCtx *ctx, int fmt) {
	if (prepare_header_data (ctx) != 0) {
		if (fmt == 'j') {
			return strdup ("{\"error\":\"Dart snapshots not found\"}");
		}
		return fmt == 'r'? strdup ("# Error: Dart snapshots not found\n"): strdup ("Error: Dart snapshots not found\n");
	}
	const char *version = dart_version_from_hash (ctx->snapshot_hash);
	if (fmt == 'j') {
		ut64 header_addr = ctx->iso_data? ctx->iso_data: ctx->vm_data;
		SnapshotHeader sh = read_snapshot_hdr (ctx, header_addr);
		PJ *pj = pj_new ();
		if (!pj) {
			return strdup ("{\"error\":\"Failed to create JSON\"}");
		}
		pj_o (pj);
		pj_kn (pj, "kind", sh.kind);
		pj_ks (pj, "hash", r_str_get (ctx->snapshot_hash));
		pj_kn (pj, "vm_data", ctx->vm_data);
		pj_kn (pj, "vm_instr", ctx->vm_instr);
		pj_kn (pj, "iso_data", ctx->iso_data);
		pj_kn (pj, "iso_instr", ctx->iso_instr);
		pj_k (pj, "cluster");
		pj_o (pj);
		pj_kn (pj, "base", sh.nb);
		pj_kn (pj, "objs", sh.no);
		pj_kn (pj, "clusters", sh.nc);
		pj_kn (pj, "it_len", sh.itlen);
		pj_kn (pj, "it_off", sh.itdata);
		pj_kn (pj, "total", sh.total_len);
		pj_end (pj);
		pj_ki (pj, "cws", ctx->compressed_word_size);
		pj_ks (pj, "dart_version", version? version: "unknown");
		if (ctx->layout) {
			const DartVerLayout *l = ctx->layout;
			pj_ks (pj, "tag_style", dart_tag_style_to_string (l->tag_style));
			pj_ki (pj, "alignment", l->max_alignment);
			pj_ki (pj, "header_fields", l->header_fields);
			pj_kn (pj, "it_capacity", l->it_cap);
			pj_k (pj, "cid_table");
			pj_o (pj);
			pj_ki (pj, "cid_class", l->cid_class);
			pj_ki (pj, "cid_function", l->cid_function);
			pj_ki (pj, "cid_code", l->cid_code);
			pj_ki (pj, "cid_string", l->cid_string);
			pj_ki (pj, "cid_one_byte_string", l->cid_one_byte_string);
			pj_ki (pj, "cid_two_byte_string", l->cid_two_byte_string);
			pj_ki (pj, "cid_array", l->cid_array);
			pj_ki (pj, "cid_mint", l->cid_mint);
			pj_ki (pj, "cid_object_pool", l->cid_object_pool);
			pj_ki (pj, "num_predefined", l->num_predefined_cids);
			pj_end (pj);
		}
		pj_end (pj);
		return pj_drain (pj);
	}
	if (fmt == 'r') {
		RStrBuf *sb = r_strbuf_new ("'# Dart AOT Snapshot Info\n");
		// Create flags for snapshot addresses
		r_strbuf_appendf (sb, "'fs dart\n");
		r_strbuf_appendf (sb, "'f dart.vm_data = 0x%" PFMT64x "\n", (ut64)ctx->vm_data);
		r_strbuf_appendf (sb, "'f dart.vm_instr = 0x%" PFMT64x "\n", (ut64)ctx->vm_instr);
		r_strbuf_appendf (sb, "'f dart.iso_data = 0x%" PFMT64x "\n", (ut64)ctx->iso_data);
		r_strbuf_appendf (sb, "'f dart.iso_instr = 0x%" PFMT64x "\n", (ut64)ctx->iso_instr);
		// Add comments with metadata
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart snapshot hash: %s\n", (ut64)ctx->vm_data, ctx->snapshot_hash[0]? ctx->snapshot_hash: "(unknown)");
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart version: %s\n", (ut64)ctx->vm_data, version? version: "unknown");
		if (ctx->layout) {
			const DartVerLayout *l = ctx->layout;
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Tag style: %s\n", (ut64)ctx->vm_data, dart_tag_style_to_string (l->tag_style));
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Alignment: %d, CWS: %d\n", (ut64)ctx->vm_data, l->max_alignment, l->compressed_word_size);
		}
		return r_strbuf_drain (sb);
	}

	RStrBuf *sb = r_strbuf_new ("");
	r_strbuf_appendf (sb, "Dart AOT Snapshot Header\n");
	r_strbuf_appendf (sb, "========================\n\n");
	r_strbuf_appendf (sb, "snapshot_hash: %s\n", ctx->snapshot_hash[0]? ctx->snapshot_hash: "(unknown)");
	r_strbuf_appendf (sb, "dart_version:  %s\n", version? version: "unknown");
	if (ctx->layout) {
		const DartVerLayout *l = ctx->layout;
		r_strbuf_appendf (sb, "tag_style:     %s\n", dart_tag_style_to_string_verbose (l->tag_style));
		r_strbuf_appendf (sb, "cws:           %d\n", l->compressed_word_size);
		r_strbuf_appendf (sb, "alignment:     %d\n", l->max_alignment);
		r_strbuf_appendf (sb, "header_fields: %d\n", l->header_fields);
		r_strbuf_appendf (sb, "it_capacity:   %" PRIu64 "\n", (uint64_t)l->it_cap);
	}

	r_strbuf_appendf (sb, "\nSnapshot Addresses\n");
	r_strbuf_appendf (sb, "------------------\n");
	r_strbuf_appendf (sb, "vm_data:       0x%" PFMT64x "\n", (ut64)ctx->vm_data);
	r_strbuf_appendf (sb, "vm_instr:      0x%" PFMT64x "\n", (ut64)ctx->vm_instr);
	r_strbuf_appendf (sb, "iso_data:      0x%" PFMT64x "\n", (ut64)ctx->iso_data);
	r_strbuf_appendf (sb, "iso_instr:     0x%" PFMT64x "\n", (ut64)ctx->iso_instr);

	ut64 addrs[2] = { ctx->vm_data, ctx->iso_data };
	const char *labels[2] = { "VM", "Isolate" };
	for (int si = 0; si < 2; si++) {
		if (!addrs[si]) {
			continue;
		}
		SnapshotHeader sh = read_snapshot_hdr (ctx, addrs[si]);
		if (!sh.ok) {
			r_strbuf_appendf (sb, "\n%s Snapshot: failed to read header at 0x%" PFMT64x "\n", labels[si], (ut64)addrs[si]);
			continue;
		}
		r_strbuf_appendf (sb, "\n%s Snapshot (0x%" PFMT64x ")\n", labels[si], (ut64)addrs[si]);
		r_strbuf_appendf (sb, "  magic:       0x%08x\n", sh.magic);
		r_strbuf_appendf (sb, "  total_len:   %" PRIu64 " bytes\n", sh.total_len);
		r_strbuf_appendf (sb, "  kind:        %" PRIu64 "\n", sh.kind);
		r_strbuf_appendf (sb, "  hash:        %s\n", sh.hash[0]? sh.hash: "(empty)");
		r_strbuf_appendf (sb, "  flags:       %s\n", sh.flags[0]? sh.flags: "(none)");
		r_strbuf_appendf (sb, "  base_objects: %" PRIu64 "\n", (uint64_t)sh.nb);
		r_strbuf_appendf (sb, "  objects:     %" PRIu64 "\n", (uint64_t)sh.no);
		r_strbuf_appendf (sb, "  clusters:    %" PRIu64 "\n", (uint64_t)sh.nc);
		r_strbuf_appendf (sb, "  it_length:   %" PRIu64 "\n", (uint64_t)sh.itlen);
		r_strbuf_appendf (sb, "  it_data_off: %" PRIu64 "\n", (uint64_t)sh.itdata);
	}

	if (ctx->layout) {
		const DartVerLayout *l = ctx->layout;
		r_strbuf_appendf (sb, "\nClass IDs (CID Table)\n");
		r_strbuf_appendf (sb, "---------------------\n");
		r_strbuf_appendf (sb, "  cid_class:          %d\n", l->cid_class);
		r_strbuf_appendf (sb, "  cid_function:       %d\n", l->cid_function);
		r_strbuf_appendf (sb, "  cid_code:           %d\n", l->cid_code);
		r_strbuf_appendf (sb, "  cid_string:         %d\n", l->cid_string);
		r_strbuf_appendf (sb, "  cid_one_byte_string: %d\n", l->cid_one_byte_string);
		r_strbuf_appendf (sb, "  cid_two_byte_string: %d\n", l->cid_two_byte_string);
		r_strbuf_appendf (sb, "  cid_array:          %d\n", l->cid_array);
		r_strbuf_appendf (sb, "  cid_mint:           %d\n", l->cid_mint);
		r_strbuf_appendf (sb, "  cid_object_pool:    %d\n", l->cid_object_pool);
		r_strbuf_appendf (sb, "  num_predefined:     %d\n", l->num_predefined_cids);
	}

	return r_strbuf_drain (sb);
}

static void collect_it_entry_cb(const DartInstructionTableEntry *entry, void *user) {
	RList *list = (RList *)user;
	if (!entry || !list) {
		return;
	}
	DartInstructionTableEntry *dup = R_NEW0 (DartInstructionTableEntry);
	dup->index = entry->index;
	dup->code_index = entry->code_index;
	dup->address = entry->address;
	dup->pc_offset = entry->pc_offset;
	dup->stack_map_offset = entry->stack_map_offset;
	dup->has_code = entry->has_code;
	dup->name = entry->name? strdup (entry->name): NULL;
	r_list_append (list, dup);
}

RList *dart_pool_extract_instruction_table(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)dart_instruction_table_entry_free);
	if (!list) {
		return NULL;
	}
	int ok = find_snapshots (ctx);
	if (ok != 0) {
		r_list_free (list);
		return NULL;
	}
	if (ctx->verbose > 0) {
		eprintf ("[r2flutter] Found Dart snapshots: vm_data=0x%llx vm_instr=0x%llx iso_data=0x%llx iso_instr=0x%llx\n",
			(unsigned long long)ctx->vm_data,
			(unsigned long long)ctx->vm_instr,
			(unsigned long long)ctx->iso_data,
			(unsigned long long)ctx->iso_instr);
	}
	DartVerLayout layout_tmp;
	DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
	if (decode_pool_and_emit (ctx, NULL, NULL, collect_it_entry_cb, list, true, ctx->dump_fns_limit > 0? (ut64)ctx->dump_fns_limit: 0) != 0) {
		r_list_free (list);
		list = NULL;
	}
	dart_ctx_fini_layout (ctx, layout_owned);
	return list;
}

char *dart_pool_dump_it(DartCtx *ctx, int fmt) {
	RList *entries = dart_pool_extract_instruction_table (ctx);
	if (!entries) {
		return fmt == 'j'? strdup ("{\"error\":\"Dart snapshots not found\"}"): strdup ("Error: Dart snapshots not found\n");
	}
	if (fmt == 'j') {
		PJ *pj = pj_new ();
		if (!pj) {
			dart_instruction_table_list_free (entries);
			return strdup ("{\"error\":\"Failed to create JSON\"}");
		}
		pj_o (pj);
		pj_kn (pj, "length", ctx->it_length);
		pj_kn (pj, "first_entry_with_code", ctx->it_first_with_code);
		pj_kn (pj, "canonical_stack_map_entries_offset", ctx->it_canonical_stack_map_offset);
		pj_ka (pj, "entries");
		RListIter *it;
		DartInstructionTableEntry *entry;
		r_list_foreach (entries, it, entry) {
			if (!entry) {
				continue;
			}
			pj_o (pj);
			pj_kn (pj, "index", entry->index);
			if (entry->has_code) {
				pj_kn (pj, "code_index", entry->code_index);
			}
			pj_kn (pj, "address", entry->address);
			pj_ki (pj, "pc_offset", entry->pc_offset);
			pj_ki (pj, "stack_map_offset", entry->stack_map_offset);
			pj_ks (pj, "kind", entry->has_code? "code": "stub");
			if (entry->name && *entry->name) {
				pj_ks (pj, "name", entry->name);
			}
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
		dart_instruction_table_list_free (entries);
		return pj_drain (pj);
	}
	RStrBuf *sb = fmt == 'r'? r_strbuf_new ("# Dart InstructionTable entries\n"): r_strbuf_new ("");
	r_strbuf_appendf (sb, "# length=%" PRIu64 " first_entry_with_code=%" PRIu64 " canonical_stack_map_entries_offset=%" PRIu64 "\n", (uint64_t)ctx->it_length, (uint64_t)ctx->it_first_with_code, (uint64_t)ctx->it_canonical_stack_map_offset);
	RListIter *it;
	DartInstructionTableEntry *entry;
	r_list_foreach (entries, it, entry) {
		if (!entry) {
			continue;
		}
		if (fmt == 'r') {
			if (entry->name && *entry->name) {
				r_strbuf_appendf (sb, "# it[%" PRIu64 "] %s\n", (uint64_t)entry->index, entry->name);
			}
			r_strbuf_appendf (sb, "f it.%s_%" PRIu64 " = 0x%" PFMT64x "\n", entry->has_code? "code": "stub", (uint64_t)entry->index, (ut64)entry->address);
			continue;
		}
		r_strbuf_appendf (sb, "%" PRIu64 " 0x%" PFMT64x " %s", (uint64_t)entry->index, (ut64)entry->address, entry->has_code? "code": "stub");
		if (entry->name && *entry->name) {
			r_strbuf_appendf (sb, " %s", entry->name);
		}
		r_strbuf_append (sb, "\n");
	}
	dart_instruction_table_list_free (entries);
	char *out = r_strbuf_drain (sb);
	size_t len = strlen (out);
	if (len > 0 && out[len - 1] == '\n') {
		out[len - 1] = '\0';
	}
	return out;
}
