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
#include <r_endian.h>
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
#include "dart_pool_parse_priv.h"

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

bool try_read_dart_string(DartCtx *ctx, ut64 addr, char *out, int outsz) {
	if (!ctx || !out || outsz <= 1) {
		return false;
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
			char s[128] = { 0 };
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

static bool looks_like_data_snapshot(DartCtx *ctx, ut64 base, ut64 *out_total_len) {
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read (ctx, base, &hdr)) {
		return false;
	}
	if (hdr.nb == 0 || hdr.no == 0 || hdr.nc == 0) {
		return false;
	}
	if (hdr.itlen > (1ULL << 32)) {
		return false;
	}
	if (hdr.itdata > (1ULL << 40)) {
		return false;
	}
	if (out_total_len) {
		*out_total_len = hdr.total_len;
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
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read (ctx, vm_data, &hdr)) {
		return;
	}
	memcpy (ctx->snapshot_hash, hdr.hash, 32);
	ctx->snapshot_hash[32] = '\0';
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] snapshot_hash=%.*s flags=%.128s\n", 32, hdr.hash, hdr.flags);
	}
}

static void derive_layout_from_flags(DartCtx *ctx) {
	if (!ctx || !ctx->vm_data) {
		return;
	}
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read (ctx, ctx->vm_data, &hdr)) {
		return;
	}
	const char *flags = hdr.flags;
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

DartVerLayout *dart_ctx_init_layout(DartCtx *ctx, DartVerLayout *tmp) {
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

void dart_ctx_fini_layout(DartCtx *ctx, DartVerLayout *owned) {
	dart_ver_layout_free (owned);
	ctx->layout = NULL;
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
	DartSnapshotHeader sh;
	if (!dart_snapshot_header_read (ctx, base, &sh)) {
		eprintf ("Cannot read head\n");
		return -1;
	}
	if (ctx->verbose > 1 && sh.flags[0]) {
		eprintf ("[r2flutter] features: %s\n", sh.flags);
	}
	uint64_t total_len = sh.total_len;
	uint64_t kind = sh.kind;
	ut64 nb = sh.nb;
	ut64 no = sh.no;
	ut64 nc = sh.nc;
	ut64 itlen = sh.itlen;
	ut64 itdata = sh.itdata;
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

	ut64 cluster_start = sh.cluster_start;
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
	if (dart_modern_is_supported_snapshot (ctx)) {
		dart_modern_scan_names_from_clusters (ctx, cluster_start, cluster_end, nc, itlen);
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
		(void)dart_it_emit_linear (ctx, itlen, max_entries, on_fn, fn_user, on_it, it_user);
		goto beach;
	}
	ut64 table_addr = data_image_base + itdata;
	if (dart_it_emit_fixed (ctx, table_addr, data_image_base, itlen, max_entries, include_stubs, sym_by_addr, on_fn, fn_user, on_it, it_user) == 0) {
		goto beach;
	}
	for (int delta = -64; delta <= 64; delta += 4) {
		if (dart_it_emit_varint (ctx, table_addr + delta, data_image_base, max_entries, include_stubs, sym_by_addr, on_fn, fn_user, on_it, it_user) == 0) {
			goto beach;
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Could not decode InstructionsTable::Data at 0x%" PFMT64x ", using sequential fallback\n", (ut64) (data_image_base + itdata));
	}
	(void)dart_it_emit_linear (ctx, itlen, max_entries, on_fn, fn_user, on_it, it_user);
beach:
	if (ctx->name_by_code_index) {
		for (ut64 i = 0; i < ctx->name_by_code_index_count; i++) {
			free (ctx->name_by_code_index[i]);
		}
		free (ctx->name_by_code_index);
		ctx->name_by_code_index = NULL;
		ctx->name_by_code_index_count = 0;
	}
	if (ctx->owner_kind_by_code_index) {
		free (ctx->owner_kind_by_code_index);
		ctx->owner_kind_by_code_index = NULL;
		ctx->owner_kind_by_code_index_count = 0;
	}
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

int find_snapshots(DartCtx *ctx) {
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

	RVecRBinSection *sections = r_bin_get_sections_vec (core->bin);
	const uint32_t kMagic = 0xdcdcf5f5;
	ut64 found_addrs[32];
	int found_cnt = 0;
	if (sections) {
		RBinSection *sec;
		R_VEC_FOREACH (sections, sec) {
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
					uint32_t val = r_read_le32 (buf + j2);
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
			ut64 total_len = r_read_le64 (hdr2) + 4;
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
		DartSnapshotHeader sh = { 0 };
		dart_snapshot_header_read (ctx, header_addr, &sh);
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
		if (ctx->container_kind[0]) {
			pj_k (pj, "container");
			pj_o (pj);
			pj_ks (pj, "kind", ctx->container_kind);
			pj_ks (pj, "note_owner", ctx->container_note_owner);
			pj_kn (pj, "payload_offset", ctx->container_payload_offset);
			pj_kn (pj, "payload_size", ctx->container_payload_size);
			pj_kn (pj, "macho_offset", ctx->container_macho_offset);
			pj_end (pj);
		}
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
		if (ctx->container_kind[0]) {
			r_strbuf_appendf (sb, "'f dart.container_payload = 0x%" PFMT64x "\n", (ut64)ctx->container_payload_offset);
			r_strbuf_appendf (sb, "'f dart.container_payload_size = 0x%" PFMT64x "\n", (ut64)ctx->container_payload_size);
		}
		// Add comments with metadata
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart snapshot hash: %s\n", (ut64)ctx->vm_data, ctx->snapshot_hash[0]? ctx->snapshot_hash: "(unknown)");
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart version: %s\n", (ut64)ctx->vm_data, version? version: "unknown");
		if (ctx->layout) {
			const DartVerLayout *l = ctx->layout;
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Tag style: %s\n", (ut64)ctx->vm_data, dart_tag_style_to_string (l->tag_style));
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Alignment: %d, CWS: %d\n", (ut64)ctx->vm_data, l->max_alignment, ctx->compressed_word_size);
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
		r_strbuf_appendf (sb, "cws:           %d\n", ctx->compressed_word_size);
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
	if (ctx->container_kind[0]) {
		r_strbuf_appendf (sb, "\nContainer\n");
		r_strbuf_appendf (sb, "---------\n");
		r_strbuf_appendf (sb, "kind:          %s\n", ctx->container_kind);
		r_strbuf_appendf (sb, "note_owner:    %s\n", ctx->container_note_owner[0]? ctx->container_note_owner: "(unknown)");
		r_strbuf_appendf (sb, "payload_off:   0x%" PFMT64x "\n", (ut64)ctx->container_payload_offset);
		r_strbuf_appendf (sb, "payload_size:  %" PRIu64 " bytes\n", (uint64_t)ctx->container_payload_size);
		r_strbuf_appendf (sb, "macho_off:     0x%" PFMT64x "\n", (ut64)ctx->container_macho_offset);
	}

	ut64 addrs[2] = { ctx->vm_data, ctx->iso_data };
	const char *labels[2] = { "VM", "Isolate" };
	for (int si = 0; si < 2; si++) {
		if (!addrs[si]) {
			continue;
		}
		DartSnapshotHeader sh = { 0 };
		dart_snapshot_header_read (ctx, addrs[si], &sh);
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
