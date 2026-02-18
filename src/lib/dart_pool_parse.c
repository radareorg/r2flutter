#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <r_core.h>
#include <r_io.h>
#include <r_util/r_json.h>
#include <r_util/r_file.h>
#include <r_util/r_name.h>
#include <r_list.h>
#include "../../include/r2flutter/dart_pool_parse.h"
#include "../../include/r2flutter/dart_version.h"
#include "../../include/r2flutter/dart_r2.h"

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

static bool read_mem (DartCtx *ctx, ut64 addr, void *buf, int len) {
	if (!ctx || !ctx->core || !buf || len <= 0) {
		return false;
	}
	int r = r_io_read_at (ctx->core->io, addr, (ut8 *)buf, len);
	return r > 0;
}

static bool read_uleb128_at (DartCtx *ctx, ut64 addr, ut64 *out_val, ut64 *out_next) {
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

static bool try_read_dart_string (DartCtx *ctx, ut64 addr, char *out, int outsz);

static bool is_print_ascii (ut8 ch) {
	return (ch >= 32 && ch < 127) || ch == '\t';
}


typedef struct {
	ut64 ep_offs[8];
	int ep_offs_n;
	ut64 owner_offs[8];
	int owner_offs_n;
	ut64 name_offs[8];
	int name_offs_n;
} LayoutHints;

static void init_layout_hints (LayoutHints *lh) {
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

static void enrich_layout_hints_from_json (LayoutHints *lh, const char *hash) {
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
	const RJson *hashes = r_json_get (j, "hashes");
	const RJson *item = r_json_get (hashes, hash);
	if (item) {
		const RJson *arr;
		arr = r_json_get (item, "code_entry_point_offsets");
		if (arr && arr->type == R_JSON_ARRAY) {
			lh->ep_offs_n = 0;
			size_t n = arr->children.count;
			for (size_t i = 0; i < n && (int)i < 8; i++) {
				const RJson *el = r_json_item (arr, i);
				if (el && el->type == R_JSON_INTEGER) {
					lh->ep_offs[lh->ep_offs_n++] = (ut64)el->num.u_value;
				}
			}
		}
		arr = r_json_get (item, "code_owner_offsets");
		if (arr && arr->type == R_JSON_ARRAY) {
			lh->owner_offs_n = 0;
			size_t n = arr->children.count;
			for (size_t i = 0; i < n && (int)i < 8; i++) {
				const RJson *el = r_json_item (arr, i);
				if (el && el->type == R_JSON_INTEGER) {
					lh->owner_offs[lh->owner_offs_n++] = (ut64)el->num.u_value;
				}
			}
		}
		arr = r_json_get (item, "function_name_offsets");
		if (arr && arr->type == R_JSON_ARRAY) {
			lh->name_offs_n = 0;
			size_t n = arr->children.count;
			for (size_t i = 0; i < n && (int)i < 8; i++) {
				const RJson *el = r_json_item (arr, i);
				if (el && el->type == R_JSON_INTEGER) {
					lh->name_offs[lh->name_offs_n++] = (ut64)el->num.u_value;
				}
			}
		}
	}
	r_json_free (j);
	free (s);
}

static bool read_heap_ptr (DartCtx *ctx, ut64 addr, ut64 data_image_base, ut64 *out_abs) {
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


static bool try_read_dart_string (DartCtx *ctx, ut64 addr, char *out, int outsz) {
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
			if (!is_print_ascii (b2)) {
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
			if (is_print_ascii (tmp[i])) {
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

static HtUP *scan_code_names (DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
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
						for (char *q = sname; *q; q++) {
							if ((ut8)*q < 32) {
								*q = ' ';
							}
						}
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

static RList *collect_data_names (DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	const char *needle1 = "package:";
	const char *needle2 = "dart:";
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
			if (buf[i] == 'p') {
				if (i + 8 < toread && !memcmp (buf + i, needle1, 8)) {
					char s[128];
					int k = 0;
					for (int j = i; j < toread && k < (int)sizeof (s) - 1; j++) {
						ut8 ch = buf[j];
						if (ch == '\0') {
							break;
						}
						if ((ch >= 32 && ch < 127) || ch == '\t') {
							s[k++] = (char)ch;
						} else {
							break;
						}
					}
					s[k] = '\0';
					if (k > 8) {
						char *dup = strdup (s);
						if (dup) {
							r_list_append (out, dup);
							if (--cap == 0) {
								return out;
							}
						}
					}
				}
			} else if (buf[i] == 'd') {
				if (i + 5 < toread && !memcmp (buf + i, needle2, 5)) {
					char s[128];
					int k = 0;
					for (int j = i; j < toread && k < (int)sizeof (s) - 1; j++) {
						ut8 ch = buf[j];
						if (ch == '\0') {
							break;
						}
						if ((ch >= 32 && ch < 127) || ch == '\t') {
							s[k++] = (char)ch;
						} else {
							break;
						}
					}
					s[k] = '\0';
					if (k > 5) {
						char *dup = strdup (s);
						if (dup) {
							r_list_append (out, dup);
							if (--cap == 0) {
								return out;
							}
						}
					}
				}
			}
		}
	}
	return out;
}

static void collect_data_names_with_r2 (DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
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
					int z = 0;
					for (int i = 0; i < n && z < (int)sizeof (s2) - 1; i++) {
						ut8 ch = buf[i];
						if (ch == '\0') {
							break;
						}
						if ((ch >= 32 && ch < 127) || ch == '\t') {
							s2[z++] = (char)ch;
						} else {
							break;
						}
					}
					s2[z] = '\0';
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


static int emit_it_varint (DartCtx *ctx, ut64 addr, ut64 data_image_base, ut64 itlen, ut64 cap, HtUP *sym_by_addr, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user) {
	(void)sym_by_addr;
	if (!ctx || !ctx->core || !on_fn) {
		return -1;
	}
	ut64 p = addr;
	ut64 header_len = 0, first_with_code = 0;
	if (!read_uleb128_at (ctx, p, &header_len, &p)) {
		return -1;
	}
	if (!read_uleb128_at (ctx, p, &first_with_code, &p)) {
		return -1;
	}
	if (header_len == 0 || header_len > (1ULL << 26)) {
		return -1;
	}
	if (first_with_code >= header_len) {
		return -1;
	}
	ut64 pc_acc = 0;
	ut64 sm_acc = 0;
	ut64 limit = itlen > cap? cap: itlen;
	for (ut64 idx = 0; idx < header_len; idx++) {
		ut64 dpc = 0, dsm = 0;
		if (!read_uleb128_at (ctx, p, &dpc, &p)) {
			return -1;
		}
		if (!read_uleb128_at (ctx, p, &dsm, &p)) {
			return -1;
		}
		pc_acc += dpc;
		sm_acc += dsm;
		if (idx < first_with_code) {
			continue;
		}
		ut64 i = idx - first_with_code;
		if (i >= limit) {
			break;
		}
		ut64 ep = ctx->iso_instr + pc_acc;
		char name[128];
		name[0] = '\0';
		if (ctx->name_by_ep) {
			char *ns = (char *)ht_up_find (ctx->name_by_ep, ep, NULL);
			if (ns && *ns) {
				snprintf (name, sizeof (name), "%s", ns);
			}
		}
		if (sm_acc > 0 && sm_acc < (1ULL << 31)) {
			ut64 saddr = data_image_base + sm_acc;
			char sname[128];
			if (try_read_dart_string (ctx, saddr, sname, sizeof (sname))) {
				for (char *q = sname; *q; q++) {
					if ((ut8)*q < 32) {
						*q = ' ';
					}
				}
				bool looks_ok = false;
				if (strstr (sname, "package:") || strstr (sname, "dart:")) {
					looks_ok = true;
				}
				if (!looks_ok && (strchr (sname, '.') || strchr (sname, '/') || strchr (sname, ':'))) {
					looks_ok = true;
				}
				if (looks_ok) {
					snprintf (name, sizeof (name), "%s", sname);
				}
			}
		}
		if (!*name) {
			snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
		}
		on_fn (name, (unsigned long long)ep, 0, user);
		if (ctx->dump_it) {
			fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64)ep);
		}
	}
	return 0;
}

static bool looks_like_data_snapshot (DartCtx *ctx, ut64 base, ut64 *out_total_len) {
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

static const DartVerLayout *load_layout_from_json (const char *hash, DartVerLayout *out) {
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

static void extract_snapshot_hash_flags (DartCtx *ctx, ut64 vm_data) {
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

static void derive_layout_from_flags (DartCtx *ctx) {
	if (!ctx || !ctx->vm_data) {
		return;
	}
	ut8 buf[20 + 32 + 256] = { 0 };
	if (!read_mem (ctx, ctx->vm_data, buf, sizeof (buf))) {
		return;
	}
	const char *flags = (const char *) (buf + 20 + 32);
	if (strstr (flags, "compressed") || strstr (flags, "compress")) {
		ctx->compressed_word_size = 4;
	} else {
		ctx->compressed_word_size = 8;
	}
	if (ctx->layout) {
		ctx->compressed_word_size = ctx->layout->compressed_word_size;
	}
}


// ============================================================================
// Clustered Snapshot Deserializer
// ============================================================================

typedef struct {
	DartCtx *ctx;
	ut64 cursor;
	ut64 end;
} ClusterStream;

static bool cs_read_u8 (ClusterStream *s, ut8 *out) {
	if (!s || !out || s->cursor >= s->end) {
		return false;
	}
	return read_mem (s->ctx, s->cursor++, out, 1);
}

static bool cs_read_u32 (ClusterStream *s, uint32_t *out) {
	if (!s || !out || s->cursor + 4 > s->end) {
		return false;
	}
	bool ok = read_mem (s->ctx, s->cursor, out, 4);
	s->cursor += 4;
	return ok;
}

static bool cs_read_unsigned (ClusterStream *s, ut64 *out) {
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

static bool cs_read_ref_id (ClusterStream *s, ut64 *out) {
	return cs_read_unsigned (s, out);
}

static bool cs_read_bytes (ClusterStream *s, ut8 *buf, int len) {
	if (!s || !buf || len <= 0 || s->cursor + len > s->end) {
		return false;
	}
	bool ok = read_mem (s->ctx, s->cursor, buf, len);
	s->cursor += len;
	return ok;
}

static void free_dart_string (void *p) {
	DartString *ds = (DartString *)p;
	if (ds) {
		free (ds->value);
		free (ds);
	}
}

static void free_dart_class (void *p) {
	DartClass *dc = (DartClass *)p;
	if (dc) {
		free (dc->name);
		free (dc);
	}
}

static void free_dart_func (void *p) {
	DartPoolFunction *df = (DartPoolFunction *)p;
	if (df) {
		free (df->name);
		free (df);
	}
}

static int decode_string_cluster (ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
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

static int decode_class_cluster (ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
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

static int decode_function_cluster (ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, ut64 iso_instr, bool is_canonical) {
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

static void skip_generic_cluster (ClusterStream *stream) {
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

static int deserialize_clusters (DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 iso_instr) {
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
			fprintf (stderr, "[r2flutter] Cluster %" PRIu64 ": cid=%u canonical=%d cursor=0x%" PFMT64x "\n",
				ci, cid, is_canonical, stream.cursor);
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
		fprintf (stderr, "[r2flutter] Decoded: strings=%d classes=%d functions=%d\n",
			ctx->strings? r_list_length (ctx->strings): 0,
			ctx->classes? r_list_length (ctx->classes): 0,
			ctx->functions? r_list_length (ctx->functions): 0);
	}
	return 0;
}

static void resolve_names (DartCtx *ctx) {
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
				}
			}
		}
	}
}


static int decode_pool_and_emit (DartCtx *ctx,
	void (*on_fn) (const char *name, unsigned long long addr, unsigned long long size, void *user),
	void *user) {
	(void)on_fn;
	(void)user;
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
	bool header_valid = (nc > 0 && nc < 10000 && no > 0 && no < 1000000);
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
					on_fn (clean_name, (unsigned long long)df->entry_point, 0, user);
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
		if (ctx->name_by_ep) {
			ht_up_free (ctx->name_by_ep);
			ctx->name_by_ep = NULL;
		}
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	if (itdata == 0) {
		ut64 cap2 = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
		if (cap2 > 256) {
			cap2 = 256;
		}
		ut64 limit2 = itlen > cap2? cap2: itlen;
		for (ut64 i = 0; i < limit2; i++) {
			ut64 ep = ctx->iso_instr + (i * 4);
			char name[64];
			snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
			if (on_fn) {
				on_fn (name, (unsigned long long)ep, 0, user);
			}
			if (ctx->dump_it) {
				fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64) (ctx->iso_instr + (i * 4)));
			}
		}
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	ut64 cand = data_image_base + itdata;
	uint32_t header_len = 0;
	uint32_t first_with_code = 0;
	bool found = false;
	ut8 hdr2[8];
	for (int delta = -64; delta <= 64; delta += 4) {
		ut64 addr = cand + delta;
		if (!read_mem (ctx, addr, hdr2, sizeof (hdr2))) {
			continue;
		}
		header_len = *(uint32_t *) (hdr2 + 0);
		first_with_code = *(uint32_t *) (hdr2 + 4);
		if (header_len > 0 && header_len < (1u << 24) && first_with_code < header_len) {
			found = true;
			cand = addr;
			break;
		}
	}
	if (!found) {
		ut64 cap2 = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
		if (cap2 > 256) {
			cap2 = 256;
		}
		int okv = -1;
		for (int delta = -64; delta <= 64; delta += 4) {
			okv = emit_it_varint (ctx, cand + delta, data_image_base, itlen, cap2, sym_by_addr, on_fn, user);
			if (okv == 0) {
				break;
			}
		}
		if (okv == 0) {
			if (sym_by_addr) {
				ht_up_free (sym_by_addr);
			}
			return 0;
		}
		fprintf (stderr, "[r2flutter] Could not locate InstructionsTable::Data at 0x%" PFMT64x "\n", (ut64) (data_image_base + itdata));
		ut64 limit2 = itlen > cap2? cap2: itlen;
		for (ut64 i = 0; i < limit2; i++) {
			ut64 ep = ctx->iso_instr + (i * 4);
			char name[64];
			snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
			if (on_fn) {
				on_fn (name, (unsigned long long)ep, 0, user);
			}
			if (ctx->dump_it) {
				fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64) (ctx->iso_instr + (i * 4)));
			}
		}
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	ut64 entries_addr = cand + 8;
	if (header_len > 200000) {
		header_len = 200000;
	}
	if (first_with_code >= header_len) {
		ut64 cap2 = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
		if (cap2 > 256) {
			cap2 = 256;
		}
		ut64 limit2 = itlen > cap2? cap2: itlen;
		for (ut64 i = 0; i < limit2; i++) {
			ut64 ep = ctx->iso_instr + (i * 4);
			char name[64];
			snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
			if (on_fn) {
				on_fn (name, (unsigned long long)ep, 0, user);
			}
			if (ctx->dump_it) {
				fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64)ep);
			}
		}
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	ut64 cap = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
	ut64 limit = itlen > cap? cap: itlen;
	for (ut64 i = 0; i < limit; i++) {
		ut64 idx = (ut64)first_with_code + i;
		if (idx >= header_len) {
			break;
		}
		ut64 entry_addr = entries_addr + idx * 8;
		ut8 ebuf[8];
		if (!read_mem (ctx, entry_addr, ebuf, sizeof (ebuf))) {
			break;
		}
		uint32_t pc_offset = *(uint32_t *) (ebuf + 0);
		uint32_t sm_off = *(uint32_t *) (ebuf + 4);
		ut64 ep = ctx->iso_instr + (ut64)pc_offset;
		const char *resolved = NULL;
		if (sym_by_addr) {
			RBinSymbol *bs = (RBinSymbol *)ht_up_find (sym_by_addr, ep, NULL);
			if (bs && bs->name) {
				resolved = r_bin_name_tostring (bs->name);
			}
		}
		char name[128];
		if (resolved && *resolved) {
			snprintf (name, sizeof (name), "%s", resolved);
		} else {
			if (ctx->name_by_ep) {
				char *ns = (char *)ht_up_find (ctx->name_by_ep, ep, NULL);
				if (ns && *ns) {
					snprintf (name, sizeof (name), "%s", ns);
					if (on_fn) {
						on_fn (name, (unsigned long long)ep, 0, user);
					}
					if (ctx->dump_it) {
						fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64)ep);
					}
					continue;
				}
			}
			name[0] = '\0';
			if (sm_off > 0 && sm_off < (1u << 31)) {
				ut64 saddr = data_image_base + (ut64)sm_off;
				char sname[128];
				if (try_read_dart_string (ctx, saddr, sname, sizeof (sname))) {
					for (char *p = sname; *p; p++) {
						if ((ut8)*p < 32) {
							*p = ' ';
						}
					}
					bool looks_ok = strstr (sname, "package:") || strstr (sname, "dart:");
					if (!looks_ok && (strchr (sname, '.') || strchr (sname, '/') || strchr (sname, ':'))) {
						looks_ok = true;
					}
					if (looks_ok) {
						snprintf (name, sizeof (name), "%s", sname);
					}
				}
				if (!*name) {
					int win = 128;
					for (int delta = -win; delta <= win; delta += 8) {
						ut64 cand2 = saddr + (ut64)delta;
						char s2[128];
						if (try_read_dart_string (ctx, cand2, s2, sizeof (s2))) {
							for (char *p = s2; *p; p++) {
								if ((ut8)*p < 32) {
									*p = ' ';
								}
							}
							if (strstr (s2, "package:") || strstr (s2, "dart:") || strchr (s2, '/')) {
								snprintf (name, sizeof (name), "%s", s2);
								break;
							}
						}
					}
				}
			}
			if (!*name && ctx->use_name_pool) {
				if (ctx->name_pool && ctx->name_pool_idx < r_list_length (ctx->name_pool)) {
					const char *pooln = (const char *)r_list_get_n (ctx->name_pool, ctx->name_pool_idx++);
					if (pooln && *pooln) {
						snprintf (name, sizeof (name), "%s", pooln);
					}
				}
			}
			if (!*name) {
				snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
			}
		}
		if (on_fn) {
			on_fn (name, (unsigned long long)ep, 0, user);
		}
		if (ctx->dump_it) {
			fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64)ep);
		}
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


static int find_snapshots (DartCtx *ctx) {
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
				if (!nm || !*nm) {
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

static void emit_stub_symbols (DartCtx *ctx,
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

int dart_pool_enumerate (DartCtx *ctx, const char *libapp_path, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user, unsigned long long *out_base, unsigned long long *out_heap_base) {
	(void)on_fn;
	(void)user;
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
		eprintf ("[r2flutter] Found Dart snapshots: vm_data=0x%llx vm_instr=0x%llx iso_data=0x%llx iso_instr=0x%llx\n",
			(unsigned long long)ctx->vm_data,
			(unsigned long long)ctx->vm_instr,
			(unsigned long long)ctx->iso_data,
			(unsigned long long)ctx->iso_instr);
		extract_snapshot_hash_flags (ctx, ctx->vm_data);
		DartVerLayout layout_tmp;
		ctx->layout = load_layout_from_json (ctx->snapshot_hash, &layout_tmp);
		if (!ctx->layout) {
			ctx->layout = dart_pick_layout_by_hash (ctx->snapshot_hash);
		}
		derive_layout_from_flags (ctx);
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
		(void)decode_pool_and_emit (ctx, on_fn, user);
		return 0;
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

void dart_field_info_free (DartFieldInfo *fi) {
	if (fi) {
		free (fi->name);
		free (fi->type_name);
		free (fi);
	}
}

void dart_class_info_free (DartClassInfo *ci) {
	if (ci) {
		free (ci->name);
		free (ci->library_name);
		free (ci->super_class_name);
		if (ci->fields) {
			r_list_free (ci->fields);
		}
		if (ci->interfaces) {
			r_list_free (ci->interfaces);
		}
		free (ci);
	}
}

void dart_type_info_free (DartTypeInfo *ti) {
	if (ti) {
		free (ti->name);
		if (ti->type_args) {
			r_list_free (ti->type_args);
		}
		free (ti);
	}
}

void dart_class_list_free (RList *list) {
	r_list_free (list);
}

typedef enum {
	kFieldCid_extract = 10,
	kLibraryCid_extract = 12,
	kTypeArgumentsCid_extract = 115,
} ExtraCids;

static int decode_field_cluster_ext (ClusterStream *s, DartCtx *ctx, ut64 *ref_counter) {
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
		ut64 ref_id = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		ut64 owner_ref = 0;
		cs_read_ref_id (s, &owner_ref);
		ut64 type_ref = 0;
		cs_read_ref_id (s, &type_ref);
		fi->type_ref = type_ref;
		uint32_t flags = 0;
		cs_read_u32 (s, &flags);
		fi->flags = 0;
		if (flags & (1 << 0)) {
			fi->flags |= DART_FIELD_STATIC;
		}
		if (flags & (1 << 1)) {
			fi->flags |= DART_FIELD_FINAL;
		}
		if (flags & (1 << 2)) {
			fi->flags |= DART_FIELD_CONST;
		}
		if (flags & (1 << 3)) {
			fi->flags |= DART_FIELD_LATE;
		}
		uint32_t offset = 0;
		cs_read_u32 (s, &offset);
		fi->offset = offset;
		ut64 skip_count = 2;
		for (ut64 j = 0; j < skip_count; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		if (ctx->refs && ref_id < ctx->refs_count) {
			ctx->refs[ref_id] = fi;
		}
		(void)name_ref;
		(void)owner_ref;
	}
	return 0;
}

static int decode_class_cluster_ext (ClusterStream *s, DartCtx *ctx, RList *class_list, ut64 *ref_counter) {
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
		(void)name_ref;
	}
	return 0;
}

typedef struct {
	ut64 ref_id;
	char *uri;
	ut64 name_ref;
} LibraryInfo;

static void free_library_info (void *p) {
	LibraryInfo *li = (LibraryInfo *)p;
	if (li) {
		free (li->uri);
		free (li);
	}
}

static int decode_library_cluster_ext (ClusterStream *s, DartCtx *ctx, RList *libraries, ut64 *ref_counter) {
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

static void resolve_class_names (DartCtx *ctx, RList *class_list) {
	if (!ctx || !ctx->refs || !class_list) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (!ci) {
			continue;
		}
		if (ci->super_class_ref > 0 && ci->super_class_ref < ctx->refs_count) {
			void *ref = ctx->refs[ci->super_class_ref];
			if (ref) {
				DartClassInfo *parent = (DartClassInfo *)ref;
				if (parent->name) {
					ci->super_class_name = strdup (parent->name);
				}
			}
		}
		if (ci->library_ref > 0 && ci->library_ref < ctx->refs_count) {
			void *ref = ctx->refs[ci->library_ref];
			if (ref) {
				LibraryInfo *lib = (LibraryInfo *)ref;
				if (lib->uri) {
					ci->library_name = strdup (lib->uri);
				}
			}
		}
	}
}

static int parse_snapshot_header (DartCtx *ctx, ut64 snapshot_base, ut64 *out_nb, ut64 *out_no, ut64 *out_nc, ut64 *out_itlen, ut64 *out_itdata, ut64 *out_total_len, ut64 *out_cluster_start) {
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (ctx, snapshot_base, hdr, sizeof (hdr))) {
		return -1;
	}
	uint32_t magic = *(uint32_t *)(hdr + 0);
	if (magic != 0xdcdcf5f5) {
		return -1;
	}
	uint64_t length_ex_magic = *(uint64_t *)(hdr + 4);
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
	cursor += (ut64)(scanned + 1);
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


RList *dart_pool_extract_classes (DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	if (find_snapshots (ctx) != 0 || !ctx->iso_data) {
		return NULL;
	}
	ut64 snapshot_base = ctx->iso_data;
	extract_snapshot_hash_flags (ctx, ctx->vm_data);
	DartVerLayout layout_tmp;
	bool layout_is_dynamic = false;
	ctx->layout = load_layout_from_json (ctx->snapshot_hash, &layout_tmp);
	if (!ctx->layout) {
		ctx->layout = dart_pick_layout_by_hash (ctx->snapshot_hash);
		layout_is_dynamic = true;
	}
	if (ctx->layout) {
		ctx->compressed_word_size = ctx->layout->compressed_word_size;
	} else {
		ctx->compressed_word_size = 4;
	}
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, total_len = 0, cluster_start = 0;
	if (parse_snapshot_header (ctx, snapshot_base, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) != 0) {
		if (layout_is_dynamic) {
			free ((void *)ctx->layout);
			ctx->layout = NULL;
		}
		return NULL;
	}
	bool header_valid = (nc > 0 && nc < 10000 && no > 0 && no < 1000000);
	if (!header_valid) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] class extraction: invalid header (clusters=%" PRIu64 " objs=%" PRIu64 ")\n", nc, no);
		}
		if (layout_is_dynamic) {
			free ((void *)ctx->layout);
			ctx->layout = NULL;
		}
		return r_list_newf ((RListFree)dart_class_info_free);
	}
	ctx->num_base_objects = nb;
	ctx->num_objects = no;
	ctx->num_clusters = nc;
	RList *class_list = r_list_newf ((RListFree)dart_class_info_free);
	ctx->strings = r_list_newf (free_dart_string);
	RList *libraries = r_list_newf (free_library_info);
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
			rc = decode_field_cluster_ext (&stream, ctx, &ref_counter);
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
	resolve_class_names (ctx, class_list);
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Extracted classes from clusters: %d\n",
			class_list? r_list_length (class_list): 0);
	}
	if (!class_list || r_list_length (class_list) == 0) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] Falling back to string-based type extraction\n");
		}
		ut64 scan_start = ctx->vm_data;
		ut64 scan_end = ctx->iso_data;
		if (scan_end > scan_start && (scan_end - scan_start) < 0x100000) {
			ut64 pos = scan_start;
			int class_count = 0;
			while (pos < scan_end - 4 && class_count < 2000) {
				ut8 buf[128];
				int to_read = (scan_end - pos > 127)? 127: (int)(scan_end - pos);
				if (!read_mem (ctx, pos, buf, to_read)) {
					break;
				}
				int slen = 0;
				while (slen < to_read && buf[slen] >= 0x20 && buf[slen] < 0x7f) {
					slen++;
				}
				if (slen >= 3 && slen < 80 && buf[slen] == 0) {
					char *s = (char *)buf;
					bool is_type = false;
					if (strncmp (s, "get:", 4) == 0 || strncmp (s, "set:", 4) == 0 ||
					    strncmp (s, "init:", 5) == 0 || strncmp (s, "dyn:", 4) == 0 ||
					    strncmp (s, "vm:", 3) == 0 || strncmp (s, "dart:", 5) == 0 ||
					    strncmp (s, "package:", 8) == 0 || strchr (s, ':') != NULL) {
					} else if (s[0] >= 'A' && s[0] <= 'Z') {
						bool has_lower = false;
						for (int i = 1; i < slen && !has_lower; i++) {
							if (s[i] >= 'a' && s[i] <= 'z') {
								has_lower = true;
							}
						}
						is_type = has_lower;
					} else if (s[0] == '_' && slen > 1 && s[1] >= 'A' && s[1] <= 'Z') {
						bool has_lower = false;
						for (int i = 2; i < slen && !has_lower; i++) {
							if (s[i] >= 'a' && s[i] <= 'z') {
								has_lower = true;
							}
						}
						is_type = has_lower;
					}
					if (is_type) {
						DartClassInfo *ci = R_NEW0 (DartClassInfo);
						ci->name = strdup (s);
						ci->ref_id = 0;
						ci->instance_size = 0;
						ci->flags = 0;
						r_list_append (class_list, ci);
						class_count++;
					}
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
	if (layout_is_dynamic) {
		free ((void *)ctx->layout);
		ctx->layout = NULL;
	}
	return class_list;
}

RList *dart_pool_get_class_hierarchy (DartCtx *ctx, ut64 class_ref) {
	(void)ctx;
	(void)class_ref;
	return r_list_newf (free);
}

RList *dart_pool_extract_fields (DartCtx *ctx, ut64 class_ref) {
	(void)ctx;
	(void)class_ref;
	return r_list_newf ((RListFree)dart_field_info_free);
}

char *dart_pool_dump_classes_json (DartCtx *ctx) {
	RList *classes = dart_pool_extract_classes (ctx);
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
		if (!ci) {
			continue;
		}
		pj_o (pj);
		pj_kn (pj, "ref", ci->ref_id);
		if (ci->name) {
			pj_ks (pj, "name", ci->name);
		}
		if (ci->library_name) {
			pj_ks (pj, "library", ci->library_name);
		}
		if (ci->super_class_name) {
			pj_ks (pj, "super", ci->super_class_name);
		}
		pj_ki (pj, "size", ci->instance_size);
		pj_ki (pj, "type_params", ci->num_type_parameters);
		pj_ki (pj, "flags", ci->flags);
		if (ci->fields && r_list_length (ci->fields) > 0) {
			pj_ka (pj, "fields");
			RListIter *fit;
			DartFieldInfo *fi;
			r_list_foreach (ci->fields, fit, fi) {
				if (!fi) {
					continue;
				}
				pj_o (pj);
				if (fi->name) {
					pj_ks (pj, "name", fi->name);
				}
				if (fi->type_name) {
					pj_ks (pj, "type", fi->type_name);
				}
				pj_ki (pj, "offset", fi->offset);
				pj_ki (pj, "flags", fi->flags);
				pj_end (pj);
			}
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
	dart_class_list_free (classes);
	return pj_drain (pj);
}

char *dart_pool_dump_classes_r2 (DartCtx *ctx) {
	RList *classes = dart_pool_extract_classes (ctx);
	if (!classes) {
		return strdup ("# No classes found\n");
	}
	RStrBuf *sb = r_strbuf_new ("# Dart classes extracted from snapshot\n");
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (classes, it, ci) {
		if (!ci || !ci->name) {
			continue;
		}
		char safe_name[256];
		snprintf (safe_name, sizeof (safe_name), "%s", ci->name);
		r_name_filter (safe_name, 0);
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
				if (!fi) {
					continue;
				}
				const char *tname = fi->type_name? fi->type_name: "void*";
				const char *fname = fi->name? fi->name: "field";
				r_strbuf_appendf (sb, " %s %s @ 0x%x;", tname, fname, fi->offset);
			}
		}
		r_strbuf_append (sb, " };\"\n");
	}
	dart_class_list_free (classes);
	return r_strbuf_drain (sb);
}


// ============================================================================
// String Extraction
// ============================================================================

void dart_string_ref_free (DartStringRef *sr) {
	free (sr);
}

void dart_string_info_free (DartStringInfo *si) {
	if (si) {
		free (si->value);
		if (si->references) {
			r_list_free (si->references);
		}
		free (si);
	}
}

void dart_string_list_free (RList *list) {
	r_list_free (list);
}

static int decode_one_byte_string_cluster (ClusterStream *s, RList *string_list, DartCtx *ctx, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] OneByteString cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 encoded = 0;
		if (!cs_read_unsigned (s, &encoded)) {
			return -1;
		}
		bool is_two_byte = (encoded & 1) != 0;
		ut64 length = encoded >> 1;
		if (length > 65536) {
			continue;
		}
		DartStringInfo *si = R_NEW0 (DartStringInfo);
		si->ref_id = (*ref_counter)++;
		si->length = (ut32)length;
		si->flags = 0;
		if (is_two_byte) {
			si->flags |= DART_STRING_TWO_BYTE;
		}
		si->references = r_list_newf ((RListFree)dart_string_ref_free);
		if (length > 0) {
			if (is_two_byte) {
				ut8 *raw = (ut8 *)malloc (length * 2);
				if (raw && cs_read_bytes (s, raw, length * 2)) {
					si->value = (char *)malloc (length * 4 + 1);
					if (si->value) {
						int out_idx = 0;
						for (ut64 j = 0; j < length; j++) {
							uint16_t ch = raw[j * 2] | ((uint16_t)raw[j * 2 + 1] << 8);
							if (ch < 0x80) {
								si->value[out_idx++] = (char)ch;
							} else if (ch < 0x800) {
								si->value[out_idx++] = (char)(0xC0 | (ch >> 6));
								si->value[out_idx++] = (char)(0x80 | (ch & 0x3F));
							} else {
								si->value[out_idx++] = (char)(0xE0 | (ch >> 12));
								si->value[out_idx++] = (char)(0x80 | ((ch >> 6) & 0x3F));
								si->value[out_idx++] = (char)(0x80 | (ch & 0x3F));
							}
						}
						si->value[out_idx] = '\0';
					}
				}
				free (raw);
			} else {
				si->value = (char *)malloc (length + 1);
				if (si->value) {
					if (cs_read_bytes (s, (ut8 *)si->value, (int)length)) {
						si->value[length] = '\0';
					} else {
						free (si->value);
						si->value = NULL;
					}
				}
			}
		}
		r_list_append (string_list, si);
		if (ctx->refs && si->ref_id < ctx->refs_count) {
			ctx->refs[si->ref_id] = si;
		}
	}
	return 0;
}

static int decode_two_byte_string_cluster (ClusterStream *s, RList *string_list, DartCtx *ctx, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 encoded = 0;
		if (!cs_read_unsigned (s, &encoded)) {
			return -1;
		}
		ut64 length = encoded >> 1;
		if (length > 65536) {
			continue;
		}
		DartStringInfo *si = R_NEW0 (DartStringInfo);
		si->ref_id = (*ref_counter)++;
		si->length = (ut32)length;
		si->flags = DART_STRING_TWO_BYTE;
		si->references = r_list_newf ((RListFree)dart_string_ref_free);
		if (length > 0) {
			ut8 *raw = (ut8 *)malloc (length * 2);
			if (raw && cs_read_bytes (s, raw, length * 2)) {
				si->value = (char *)malloc (length * 4 + 1);
				if (si->value) {
					int out_idx = 0;
					for (ut64 j = 0; j < length; j++) {
						uint16_t ch = raw[j * 2] | ((uint16_t)raw[j * 2 + 1] << 8);
						if (ch >= 0xD800 && ch <= 0xDBFF && j + 1 < length) {
							uint16_t lo = raw[(j + 1) * 2] | ((uint16_t)raw[(j + 1) * 2 + 1] << 8);
							if (lo >= 0xDC00 && lo <= 0xDFFF) {
								uint32_t cp = 0x10000 + ((ch - 0xD800) << 10) + (lo - 0xDC00);
								si->value[out_idx++] = (char)(0xF0 | (cp >> 18));
								si->value[out_idx++] = (char)(0x80 | ((cp >> 12) & 0x3F));
								si->value[out_idx++] = (char)(0x80 | ((cp >> 6) & 0x3F));
								si->value[out_idx++] = (char)(0x80 | (cp & 0x3F));
								j++;
								continue;
							}
						}
						if (ch < 0x80) {
							si->value[out_idx++] = (char)ch;
						} else if (ch < 0x800) {
							si->value[out_idx++] = (char)(0xC0 | (ch >> 6));
							si->value[out_idx++] = (char)(0x80 | (ch & 0x3F));
						} else {
							si->value[out_idx++] = (char)(0xE0 | (ch >> 12));
							si->value[out_idx++] = (char)(0x80 | ((ch >> 6) & 0x3F));
							si->value[out_idx++] = (char)(0x80 | (ch & 0x3F));
						}
					}
					si->value[out_idx] = '\0';
				}
			}
			free (raw);
		}
		r_list_append (string_list, si);
		if (ctx->refs && si->ref_id < ctx->refs_count) {
			ctx->refs[si->ref_id] = si;
		}
	}
	return 0;
}

static void track_string_refs_from_functions (DartCtx *ctx, ClusterStream *s, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return;
	}
	if (count == 0 || count > 100000) {
		return;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 fn_ref = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		if (name_ref > 0 && name_ref < ctx->refs_count && ctx->refs[name_ref]) {
			DartStringInfo *si = (DartStringInfo *)ctx->refs[name_ref];
			if (si->references) {
				DartStringRef *sr = R_NEW0 (DartStringRef);
				sr->object_ref = fn_ref;
				sr->object_type = DART_REF_FUNCTION;
				sr->field_offset = 0;
				r_list_append (si->references, sr);
			}
		}
		ut64 skip_refs = 6;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		uint32_t kind_tag = 0;
		cs_read_u32 (s, &kind_tag);
	}
}

static void track_string_refs_from_classes (DartCtx *ctx, ClusterStream *s, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return;
	}
	if (count == 0 || count > 50000) {
		return;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 class_ref = (*ref_counter)++;
		uint32_t instance_size = 0;
		cs_read_u32 (s, &instance_size);
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		if (name_ref > 0 && name_ref < ctx->refs_count && ctx->refs[name_ref]) {
			DartStringInfo *si = (DartStringInfo *)ctx->refs[name_ref];
			if (si->references) {
				DartStringRef *sr = R_NEW0 (DartStringRef);
				sr->object_ref = class_ref;
				sr->object_type = DART_REF_CLASS;
				sr->field_offset = 0;
				r_list_append (si->references, sr);
			}
		}
		ut64 skip_refs = 6;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
	}
}

RList *dart_pool_extract_strings (DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	if (find_snapshots (ctx) != 0 || !ctx->iso_data) {
		return NULL;
	}
	ut64 snapshot_base = ctx->iso_data;
	extract_snapshot_hash_flags (ctx, ctx->vm_data);
	DartVerLayout layout_tmp;
	bool layout_is_dynamic = false;
	ctx->layout = load_layout_from_json (ctx->snapshot_hash, &layout_tmp);
	if (!ctx->layout) {
		ctx->layout = dart_pick_layout_by_hash (ctx->snapshot_hash);
		layout_is_dynamic = true;
	}
	if (ctx->layout) {
		ctx->compressed_word_size = ctx->layout->compressed_word_size;
	} else {
		ctx->compressed_word_size = 4;
	}
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, total_len = 0, cluster_start = 0;
	if (parse_snapshot_header (ctx, snapshot_base, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) != 0) {
		if (layout_is_dynamic) {
			free ((void *)ctx->layout);
			ctx->layout = NULL;
		}
		return NULL;
	}
	bool header_valid = (nc > 0 && nc < 10000 && no > 0 && no < 1000000);
	if (!header_valid) {
		if (layout_is_dynamic) {
			free ((void *)ctx->layout);
			ctx->layout = NULL;
		}
		return r_list_newf ((RListFree)dart_string_info_free);
	}
	ctx->num_base_objects = nb;
	ctx->num_objects = no;
	ctx->num_clusters = nc;
	RList *string_list = r_list_newf ((RListFree)dart_string_info_free);
	ut64 total_refs = nb + no + 16;
	ctx->refs_count = total_refs;
	ctx->refs = (void **)calloc (total_refs, sizeof (void *));
	ClusterStream stream = {
		.ctx = ctx,
		.cursor = cluster_start,
		.end = snapshot_base + total_len
	};
	ut64 ref_counter = nb + 1;
	int cid_one_byte = ctx->layout? ctx->layout->cid_one_byte_string: kOneByteStringCid;
	int cid_two_byte = ctx->layout? ctx->layout->cid_two_byte_string: kTwoByteStringCid;
	int cid_string = ctx->layout? ctx->layout->cid_string: kStringCid;
	int cid_function = ctx->layout? ctx->layout->cid_function: kFunctionCid;
	int cid_class = ctx->layout? ctx->layout->cid_class: kClassCid;
	for (ut64 ci2 = 0; ci2 < nc && stream.cursor < stream.end; ci2++) {
		uint32_t tags = 0;
		if (!cs_read_u32 (&stream, &tags)) {
			break;
		}
		uint32_t cid = 0;
		if (ctx->layout && ctx->layout->tag_style == DART_TAG_STYLE_OBJECT_HEADER) {
			cid = (tags >> 12) & 0xFFFFF;
		} else if (ctx->layout && ctx->layout->tag_style == DART_TAG_STYLE_CID_SHIFT1) {
			cid = tags >> 1;
		} else {
			cid = (tags >> 12) & 0xFFFFF;
		}
		int rc = 0;
		if ((int)cid == cid_one_byte || (int)cid == cid_string) {
			rc = decode_one_byte_string_cluster (&stream, string_list, ctx, &ref_counter);
		} else if ((int)cid == cid_two_byte) {
			rc = decode_two_byte_string_cluster (&stream, string_list, ctx, &ref_counter);
		} else if ((int)cid == cid_function) {
			track_string_refs_from_functions (ctx, &stream, &ref_counter);
		} else if ((int)cid == cid_class) {
			track_string_refs_from_classes (ctx, &stream, &ref_counter);
		} else {
			skip_generic_cluster (&stream);
		}
		if (rc < 0) {
			break;
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Extracted strings from clusters: %d\n",
			string_list? r_list_length (string_list): 0);
	}
	if (!string_list || r_list_length (string_list) == 0) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] Falling back to data section string scan\n");
		}
		ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
		ut64 data_image_base = snapshot_base + ((total_len + (kAlign - 1)) & ~(kAlign - 1));
		ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: (data_image_base + (1ULL << 20));
		if (ctx->vm_data > 0 && ctx->iso_data > ctx->vm_data) {
			data_image_base = ctx->vm_data;
			data_image_end = ctx->iso_data;
		}
		if (data_image_end > data_image_base && (data_image_end - data_image_base) < 0x400000) {
			ut64 pos = data_image_base;
			int str_count = 0;
			while (pos < data_image_end - 4 && str_count < 10000) {
				ut8 buf[256];
				int to_read = (data_image_end - pos > 255)? 255: (int)(data_image_end - pos);
				if (!read_mem (ctx, pos, buf, to_read)) {
					break;
				}
				int slen = 0;
				while (slen < to_read && buf[slen] >= 0x20 && buf[slen] < 0x7f) {
					slen++;
				}
				if (slen >= 3 && slen < 200 && buf[slen] == 0) {
					DartStringInfo *si = R_NEW0 (DartStringInfo);
					si->ref_id = str_count;
					si->value = r_str_ndup ((char *)buf, slen);
					si->length = slen;
					si->flags = 0;
					si->address = pos;
					si->references = r_list_newf ((RListFree)dart_string_ref_free);
					r_list_append (string_list, si);
					str_count++;
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
	if (layout_is_dynamic) {
		free ((void *)ctx->layout);
		ctx->layout = NULL;
	}
	return string_list;
}

char *dart_pool_dump_strings_json (DartCtx *ctx) {
	RList *strings = dart_pool_extract_strings (ctx);
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
		if (!si) {
			continue;
		}
		pj_o (pj);
		pj_kn (pj, "ref", si->ref_id);
		pj_ki (pj, "len", si->length);
		if (si->value) {
			pj_ks (pj, "value", si->value);
		}
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
				const char *type_str = "other";
				switch (sr->object_type) {
				case DART_REF_FUNCTION: type_str = "function"; break;
				case DART_REF_CLASS: type_str = "class"; break;
				case DART_REF_FIELD: type_str = "field"; break;
				case DART_REF_LIBRARY: type_str = "library"; break;
				case DART_REF_CODE: type_str = "code"; break;
				}
				pj_ks (pj, "type", type_str);
				pj_end (pj);
			}
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
	dart_string_list_free (strings);
	return pj_drain (pj);
}

char *dart_pool_dump_strings_r2 (DartCtx *ctx) {
	RList *strings = dart_pool_extract_strings (ctx);
	if (!strings) {
		return strdup ("# No strings found\n");
	}
	RStrBuf *sb = r_strbuf_new ("# Dart strings extracted from snapshot\n");
	RListIter *it;
	DartStringInfo *si;
	int idx = 0;
	r_list_foreach (strings, it, si) {
		if (!si || !si->value) {
			continue;
		}
		char safe_val[64];
		int max_len = 60;
		int len = strlen (si->value);
		if (len > max_len) {
			snprintf (safe_val, sizeof (safe_val), "%.57s...", si->value);
		} else {
			snprintf (safe_val, sizeof (safe_val), "%s", si->value);
		}
		for (char *p = safe_val; *p; p++) {
			if (*p == '\n' || *p == '\r' || *p == '"') {
				*p = ' ';
			}
		}
		r_strbuf_appendf (sb, "# str[%d] ref=%" PRIu64 " len=%u%s: \"%s\"\n",
			idx++, si->ref_id, si->length,
			(si->flags & DART_STRING_TWO_BYTE)? " (utf16)": "",
			safe_val);
		if (si->references && r_list_length (si->references) > 0) {
			r_strbuf_appendf (sb, "#   referenced by %d objects\n", r_list_length (si->references));
		}
	}
	r_strbuf_appendf (sb, "# Total: %d strings\n", r_list_length (strings));
	dart_string_list_free (strings);
	return r_strbuf_drain (sb);
}
