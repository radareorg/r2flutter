#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <r_core.h>
#include <r_io.h>
#include <r_util/r_json.h>
#include <r_util/r_file.h>
#include <r_list.h>
#include "../../include/r2flutter/dart_pool_parse.h"

// Minimal, standalone AOT snapshot/ObjectPool decoder scaffolding.
// This file will progressively implement decoding without Dart VM deps.

typedef struct {
	char hash[33]; // snapshot hash as ASCII (32 chars)
	int compressed_word_size; // 4 or 8
	int heap_object_tag; // usually 1
	int max_alignment; // alignment for DataImage rounding (default 16)
	ut64 it_cap; // cap for instruction table entries to emit
		// Future: offsets for Code.entry_point, Code.size, Function.name, etc.
} DartVerLayout;

#if 0
static const DartVerLayout known_layouts[] = {
	// Known snapshot hashes may be added here.
	//{"0123456789abcdef0123456789abcdef", 4, 1},
};

static const DartVerLayout* pick_layout_by_hash(const char* hash) {
	if (!hash) return NULL;
	for (size_t i = 0; i < sizeof (known_layouts)/sizeof (known_layouts[0]); i++) {
		if (!strncmp (known_layouts[i].hash, hash, 32)) return &known_layouts[i];
	}
	return NULL;
}
#else
static const DartVerLayout *pick_layout_by_hash(const char *hash) {
	DartVerLayout *dvl = R_NEW0 (DartVerLayout);
	dvl->compressed_word_size = 4;
	dvl->heap_object_tag = 4;
	dvl->max_alignment = 16;
	dvl->it_cap = 20000;
	(void)hash;
	return dvl;
}
#endif

typedef struct {
	RCore *core;
	ut64 vm_data;
	ut64 vm_instr;
	ut64 iso_data;
	ut64 iso_instr;
	char snapshot_hash[33];
	const DartVerLayout *layout;
	int compressed_word_size; // derived from flags or layout
	HtUP *name_by_ep; // optional ep->name mapping from data image scan
	RList *name_pool; // optional pool of discovered names (strings)
	int name_pool_idx;
} DartCtx;

// Debug/diagnostic controls
static int G_VERBOSE = 0;
static int G_NO_STUBS = 0;
static int G_DUMP_SNAPSHOT_JSON = 0;
static int G_DUMP_IT = 0;
static int G_QUIET = 0;
static int G_DUMP_FNS = 0;
static int G_USE_NAME_POOL = 0;

void dart_pool_set_verbose(int level) {
	G_VERBOSE = level;
}
void dart_pool_set_no_stubs(int on) {
	G_NO_STUBS = on? 1: 0;
}
void dart_pool_set_dump_snapshot_json(int on) {
	G_DUMP_SNAPSHOT_JSON = on? 1: 0;
}
void dart_pool_set_dump_it(int on) {
	G_DUMP_IT = on? 1: 0;
}
void dart_pool_set_quiet(int on) {
	G_QUIET = on? 1: 0;
}
int dart_pool_is_quiet(void) {
	return G_QUIET;
}
void dart_pool_set_dump_fns(int n) {
	G_DUMP_FNS = n;
}
int dart_pool_get_dump_fns(void) {
	return G_DUMP_FNS;
}
void dart_pool_set_use_name_pool(int on) {
	G_USE_NAME_POOL = on? 1: 0;
}
int dart_pool_get_use_name_pool(void) {
	return G_USE_NAME_POOL;
}

static bool read_mem(RCore *core, ut64 addr, void *buf, int len) {
	if (!core || !buf || len <= 0) {
		return false;
	}
	int r = r_io_read_at (core->io, addr, (ut8 *)buf, len);
	return r > 0;
}

// Note: r_json_parse does not take ownership of the input buffer.
// We must free the buffer after freeing the parser.
// Keep parsing local so we can release resources deterministically.

static bool read_uleb128_at(RCore *core, ut64 addr, ut64 *out_val, ut64 *out_next) {
	// Read unsigned LEB128 value from memory at addr.
	// Returns true on success, false on failure.
	ut64 v = 0;
	int shift = 0;
	for (int i = 0; i < 10; i++) {
		ut8 b = 0;
		if (!read_mem (core, addr + i, &b, 1)) {
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

// Forward decl for minimal string reader
static bool try_read_dart_string(RCore *core, ut64 addr, char *out, int outsz);

// Parse a packed/varint InstructionsTable::Data format.
// Heuristic format:
//   header_len:   uleb128
//   first_with_code: uleb128
//   then header_len entries of two uleb128 values each:
//     pc_offset_delta, sm_off_delta (both non-negative), accumulated over the stream
// We only emit entries starting at first_with_code.
static int emit_it_varint(DartCtx *ctx, ut64 addr, ut64 data_image_base, ut64 itlen, ut64 cap, HtUP *sym_by_addr, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user) {
	(void)sym_by_addr;
	if (!ctx || !ctx->core || !on_fn) {
		return -1;
	}
	ut64 p = addr;
	ut64 header_len = 0, first_with_code = 0;
	if (!read_uleb128_at (ctx->core, p, &header_len, &p)) {
		return -1;
	}
	if (!read_uleb128_at (ctx->core, p, &first_with_code, &p)) {
		return -1;
	}
	if (header_len == 0 || header_len > (1ULL << 26)) {
		return -1;
	}
	if (first_with_code >= header_len) {
		return -1;
	}
	// Walk entries accumulating deltas. Keep bounds tight.
	ut64 pc_acc = 0;
	ut64 sm_acc = 0;
	ut64 limit = itlen > cap? cap: itlen;
	for (ut64 idx = 0; idx < header_len; idx++) {
		ut64 dpc = 0, dsm = 0;
		if (!read_uleb128_at (ctx->core, p, &dpc, &p)) {
			return -1;
		}
		if (!read_uleb128_at (ctx->core, p, &dsm, &p)) {
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
			if (try_read_dart_string (ctx->core, saddr, sname, sizeof (sname))) {
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
		if (G_DUMP_IT) {
			fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64)ep);
		}
	}
	return 0;
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
	// Reasonable defaults for 64-bit object layouts
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

static bool read_heap_ptr(DartCtx *ctx, ut64 addr, ut64 data_image_base, ut64 *out_abs) {
	if (!ctx || !out_abs) {
		return false;
	}
	if (ctx->compressed_word_size == 4) {
		// Try 64-bit absolute pointer first in case fields are widened
		ut64 v64_abs = 0;
		if (read_mem (ctx->core, addr, &v64_abs, sizeof (v64_abs))) {
			if (v64_abs >= data_image_base && v64_abs < data_image_base + (1ULL << 34)) {
				*out_abs = v64_abs;
				return true;
			}
		}
		ut32 v32 = 0;
		if (!read_mem (ctx->core, addr, &v32, sizeof (v32))) {
			return false;
		}
		// Try a few common decompression patterns
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
	if (!read_mem (ctx->core, addr, &v64, sizeof (v64))) {
		return false;
	}
	*out_abs = v64;
	return true;
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
			if (!read_mem (ctx->core, a + lh.ep_offs[ie], &ep, sizeof (ep))) {
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
					if (try_read_dart_string (ctx->core, namep, sname, sizeof (sname))) {
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

static RList *collect_data_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	const char *needle1 = "package:";
	const char *needle2 = "dart:";
	const int chunk = 4096;
	ut8 buf[chunk];
	RList *out = r_list_newf (free);
	if (!out) {
		return NULL;
	}
	ut64 limit = data_image_end - data_image_base;
	if (limit > (1ULL << 22)) {
		limit = (1ULL << 22);
	}
	ut64 cap = 512;
	for (ut64 off = 0; off < limit; off += (chunk - 8)) {
		ut64 addr = data_image_base + off;
		int toread = (int) ((off + chunk <= limit)? chunk: (limit - off));
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
			// Expect lines like: 0xADDR hitX_Y package:
			if (!r_str_startswith (line, "0x")) {
				continue;
			}
			// Extract address
			ut64 addr = (ut64)strtoull (line, NULL, 16);
			char s[128];
			if (try_read_dart_string (ctx->core, addr, s, sizeof (s))) {
				char *dup = strdup (s);
				if (dup) {
					r_list_append (ctx->name_pool, dup);
				}
			} else {
				// Fallback: read inline ascii until non-print
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

// Helpers to decode minimal String objects and extract ASCII names from data image.
static bool is_print_ascii(ut8 ch) {
	return (ch >= 32 && ch < 127) || ch == '\t';
}

// Attempt to decode a OneByteString-like object at or near addr.
// Layout heuristic (64-bit words): tags, length (Smi), hash, then bytes.
// We try small offsets (0, 8, 16) to account for header variants.
static bool try_read_dart_string(RCore *core, ut64 addr, char *out, int outsz) {
	if (!core || !out || outsz <= 1) {
		return false;
	}
	ut8 hdr[32];
	if (!read_mem (core, addr, hdr, sizeof (hdr))) {
		return false;
	}
	for (int off = 0; off <= 16; off += 8) {
		ut64 len_smi = *(ut64 *) (hdr + off + 8);
		ut64 len = 0;
		if ((len_smi & 1ULL) == 0) {
			len = len_smi >> 1; // assume SmiTag=0 -> shift 1
		} else {
			len = len_smi & 0xffffffffULL; // fallback: 32-bit length
		}
		if (len == 0 || len > 1024) {
			continue;
		}
		ut64 str_addr = addr + off + 24; // payload start guess
		int ok = 1;
		for (ut64 i = 0; i < len; i++) {
			ut8 b2 = 0;
			if (!read_mem (core, str_addr + i, &b2, 1)) {
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
		if (!read_mem (core, str_addr, (ut8 *)out, (int)cplen)) {
			continue;
		}
		out[cplen] = '\0';
		return true;
	}
	ut8 tmp[256];
	if (read_mem (core, addr, tmp, sizeof (tmp))) {
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

// Try to classify a snapshot header at base as DATA snapshot by attempting to
// parse the clustered header fields that only exist in DATA snapshots.
// Returns true if it looks like a DATA snapshot; false otherwise.
static bool looks_like_data_snapshot(RCore *core, ut64 base, ut64 *out_total_len) {
	if (!core || !base) {
		return false;
	}
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (core, base, hdr, sizeof (hdr))) {
		return false;
	}
	uint32_t magic = *(uint32_t *) (hdr + 0);
	if (magic != 0xdcdcf5f5) {
		return false;
	}
	uint64_t length_ex_magic = *(uint64_t *) (hdr + 4);
	uint64_t total_len = length_ex_magic + 4;
	// skip version+features strings to the first NUL terminator after header
	ut64 cursor = base + 4 + 8 + 8; // after header
	const int max_scan = 2048;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem (core, cursor + scanned, &b, 1)) {
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
	// Now clustered header: 5 unsigned LEB128s.
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, tmp = next;
	if (!read_uleb128_at (core, tmp, &nb, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &no, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &nc, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &itlen, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &itdata, &tmp)) {
		return false;
	}
	// Plausibility checks
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
	memset (out, 0, sizeof (*out));
	const char *h = r_json_get_str (item, "hash");
	if (h && *h) {
		strncpy (out->hash, h, 32);
	} else {
		strncpy (out->hash, hash, 32);
	}
	out->hash[32] = '\0';
	out->compressed_word_size = (int)r_json_get_num (item, "compressed_word_size");
	out->heap_object_tag = (int)r_json_get_num (item, "heap_object_tag");
	int mal = (int)r_json_get_num (item, "max_alignment");
	out->max_alignment = mal > 0? mal: 16;
	ut64 cap = (ut64)r_json_get_num (item, "it_cap");
	out->it_cap = cap > 0? cap: 20000;
	r_json_free (j);
	free (s);
	return out;
}

static void extract_snapshot_hash_flags(RCore *core, ut64 vm_data, char out_hash[33]) {
	if (out_hash) {
		out_hash[0] = '\0';
	}
	if (!core || !vm_data) {
		return;
	}
	ut8 buf[20 + 32 + 256] = { 0 };
	if (!read_mem (core, vm_data, buf, sizeof (buf))) {
		return;
	}
	if (out_hash) {
		memcpy (out_hash, buf + 20, 32);
		out_hash[32] = '\0';
	}
	const char *flags = (const char *) (buf + 20 + 32);
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] snapshot_hash=%.*s flags=%.128s\n", 32, (const char *) (buf + 20), flags);
	}
}

static void derive_layout_from_flags(DartCtx *ctx) {
	// Read flags again to infer compressed pointer mode when no per-hash layout is available.
	if (!ctx || !ctx->vm_data) {
		return;
	}
	ut8 buf[20 + 32 + 256] = { 0 };
	if (!read_mem (ctx->core, ctx->vm_data, buf, sizeof (buf))) {
		return;
	}
	const char *flags = (const char *) (buf + 20 + 32);
	// Heuristic: many 64-bit AOT builds use 4-byte compressed pointers; check flag substring
	if (strstr (flags, "compressed") || strstr (flags, "compress")) {
		ctx->compressed_word_size = 4;
	} else {
		ctx->compressed_word_size = 8;
	}
	if (ctx->layout) {
		// layout wins if provided
		ctx->compressed_word_size = ctx->layout->compressed_word_size;
	}
}

// Placeholder: future decoding of ObjectPool and emission of functions
static int decode_pool_and_emit(DartCtx *ctx,
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
	// Minimal clustered snapshot header reader (pre-work for full pool decode)
	// Layout reference: third_party/dartvm/snapshot.h + app_snapshot.cc (SnapshotHeaderReader + Deserializer)
	// We only parse the header and clustered-section counters to validate access.
	const ut64 base = ctx->iso_data;
	// Snapshot header: magic (u32), length (i64, not incl. magic), kind (i64)
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (ctx->core, base, hdr, sizeof (hdr))) {
		eprintf ("Cannot read head\n");
		return -1;
	}
	uint32_t magic = *(uint32_t *) (hdr + 0);
	if (magic != 0xdcdcf5f5) {
		fprintf (stderr, "[r2flutter] Unexpected snapshot magic at 0x%" PFMT64x "\n", (ut64)base);
		return -1;
	}
	// length (excluding magic) + magic size yields total
	uint64_t length_ex_magic = *(uint64_t *) (hdr + 4);
	uint64_t total_len = length_ex_magic + 4;
	uint64_t kind = *(uint64_t *) (hdr + 12);
	// Skip version+features header.
	// In AOT, the version string is NOT guaranteed to be NUL-terminated,
	// while the features string IS NUL-terminated and follows immediately.
	// So from the position after header, we advance to the first NUL byte,
	// which marks the end of the features string.
	ut64 cursor = base + 4 + 8 + 8; // after header
					// Scan up to a reasonable cap to find the 0 terminator of features
	const int max_scan = 1024;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem (ctx->core, cursor + scanned, &b, 1)) {
			break;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	if (b != '\0') {
		// couldn't find terminator; continue, but LEB128 parsing may fail
		if (G_VERBOSE > 0) {
			eprintf ("[r2flutter] warning: could not find features terminator within %d bytes\n", max_scan);
		}
	} else if (G_VERBOSE > 1) {
		// For debugging, try to print a tail of what we scanned (it's the end of features)
		int toshow = scanned > 128? 128: scanned;
		char feat[129];
		memset (feat, 0, sizeof (feat));
		// read up to toshow bytes ending at scanned position
		int start = scanned - toshow;
		for (int i = 0; i < toshow; i++) {
			ut8 ch = 0;
			if (!read_mem (ctx->core, cursor + start + i, &ch, 1)) {
				break;
			}
			feat[i] = (ch >= 32 && ch < 127)? (char)ch: '.';
		}
		eprintf ("[r2flutter] features tail: %s\n", feat);
	}
	cursor += (ut64) (scanned + 1);
	// Now clustered header (Deserializer::Deserialize):
	// num_base_objects, num_objects, num_clusters, instructions_table_len, instruction_table_data_offset
	// These are encoded as unsigned LEB128 in Dart snapshot streams.
	// Implement a small LEB128 reader over memory.
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0;
	ut64 next = cursor;
	if (!read_uleb128_at (ctx->core, next, &nb, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx->core, next, &no, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx->core, next, &nc, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx->core, next, &itlen, &next)) {
		return -1;
	}
	if (!read_uleb128_at (ctx->core, next, &itdata, &next)) {
		return -1;
	}
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] snapshot clustered header: base_objs=%" PRIu64 " objs=%" PRIu64 " clusters=%" PRIu64 " it_len=%" PRIu64 " it_data_off=%" PRIu64 " total_len=%" PRIu64 "\n", (uint64_t)nb, (uint64_t)no, (uint64_t)nc, (uint64_t)itlen, (uint64_t)itdata, (uint64_t)total_len);
	}

	if (G_DUMP_SNAPSHOT_JSON) {
		// Emit a compact single-line JSON with basic snapshot info
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

	// Build symbol cache for name lookup using r_bin APIs (faster than core JSON)
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
	// Attempt to enumerate code entrypoints using InstructionsTable rodata.
	if (!ctx->iso_instr) {
		// Without instructions image base, we cannot map pc_offsets to addresses.
		return 0;
	}
	// Compute data image base = iso_data + RoundUp (total_len, kMaxObjectAlignment)
	// Use 16-byte alignment as a reasonable default on 64-bit.
	ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	ut64 data_image_base = base + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
	// Try to guess data image end conservatively as the start of the instructions image.
	ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: (data_image_base + (1ULL << 22));
	if (data_image_end < data_image_base) {
		data_image_end = data_image_base + (1ULL << 22);
	}
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] data_image_base=0x%" PFMT64x " data_image_end=0x%" PFMT64x "\n", (ut64)data_image_base, (ut64)data_image_end);
	}
	// Pre-scan data image to recover entrypoint->name mapping from Code/Function objects.
	ctx->name_by_ep = scan_code_names (ctx, data_image_base, data_image_end);
	// Also collect a pool of human-readable names to use as last-resort fallbacks
	ctx->name_pool = collect_data_names (ctx, data_image_base, data_image_end);
	if (!ctx->name_pool || r_list_length (ctx->name_pool) == 0) {
		// Fall back to r2 search if direct scanning didn't find names
		collect_data_names_with_r2 (ctx, data_image_base, data_image_end);
		if (G_VERBOSE > 0 && ctx->name_pool) {
			fprintf (stderr, "[r2flutter] name_pool(r2)=%d\n", r_list_length (ctx->name_pool));
		}
	}
	ctx->name_pool_idx = 0;
	if (G_VERBOSE > 0 && ctx->name_pool) {
		fprintf (stderr, "[r2flutter] name_pool=%d\n", r_list_length (ctx->name_pool));
	}
	// instruction_table_data_offset is optional; if 0, we can't read rodata entries easily.
	if (itlen == 0) {
		// nothing to emit
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
		// No rodata pointer: emit a conservative number of sequential entries.
		ut64 cap2 = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
		if (cap2 > 256) {
			cap2 = 256; // keep outputs small/deterministic
		}
		ut64 limit2 = itlen > cap2? cap2: itlen;
		for (ut64 i = 0; i < limit2; i++) {
			ut64 ep = ctx->iso_instr + (i * 4);
			char name[64];
			snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
			if (on_fn) {
				on_fn (name, (unsigned long long)ep, 0, user);
			}
			if (G_DUMP_IT) {
				fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64) (ctx->iso_instr + (i * 4)));
			}
		}
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	// Try to locate InstructionsTable::Data bytes. It's stored in a String object.
	// We heuristically scan around data_image_base + itdata to find a header where
	//   header.length is reasonable and header.first_entry_with_code < header.length.
	ut64 cand = data_image_base + itdata;
	uint32_t header_len = 0;
	uint32_t first_with_code = 0;
	bool found = false;
	ut8 hdr2[8];
	for (int delta = -64; delta <= 64; delta += 4) {
		ut64 addr = cand + delta;
		if (!read_mem (ctx->core, addr, hdr2, sizeof (hdr2))) {
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
		// Try varint/packed table
		ut64 cap2 = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
		if (cap2 > 256) {
			cap2 = 256; // keep outputs small/deterministic
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
		// Fallback: sequential entrypoints when table is not found
		ut64 limit2 = itlen > cap2? cap2: itlen;
		for (ut64 i = 0; i < limit2; i++) {
			ut64 ep = ctx->iso_instr + (i * 4);
			char name[64];
			snprintf (name, sizeof (name), "method.fn_%" PRIu64, (uint64_t)i);
			if (on_fn) {
				on_fn (name, (unsigned long long)ep, 0, user);
			}
			if (G_DUMP_IT) {
				fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64) (ctx->iso_instr + (i * 4)));
			}
		}
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	// Read DataEntry array (header_len entries), each entry is {uint32 pc_offset; uint32 sm_offset}
	// Binary search table is exactly header_len entries and comes right after 8-byte header.
	ut64 entries_addr = cand + 8;
	// Sanity cap
	if (header_len > 200000) {
		header_len = 200000;
	}
	if (first_with_code >= header_len) {
		// Bad header; fall back to sequential enumeration
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
			if (G_DUMP_IT) {
				fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64)ep);
			}
		}
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	// We need pc offsets for indices first_with_code .. first_with_code + itlen - 1
	// We'll read those selectively instead of allocating the whole array.
	ut64 cap = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
	ut64 limit = itlen > cap? cap: itlen;
	for (ut64 i = 0; i < limit; i++) {
		ut64 idx = (ut64)first_with_code + i;
		if (idx >= header_len) {
			break;
		}
		ut64 entry_addr = entries_addr + idx * 8;
		ut8 ebuf[8];
		if (!read_mem (ctx->core, entry_addr, ebuf, sizeof (ebuf))) {
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
					if (G_DUMP_IT) {
						fprintf (stderr, "[it] %" PRIu64 " 0x%" PFMT64x "\n", (uint64_t)i, (ut64)ep);
					}
					continue;
				}
			}
			name[0] = '\0';
			if (sm_off > 0 && sm_off < (1u << 31)) {
				ut64 saddr = data_image_base + (ut64)sm_off;
				char sname[128];
				if (try_read_dart_string (ctx->core, saddr, sname, sizeof (sname))) {
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
					// Scan a small neighborhood around sm_off for string-like blobs
					int win = 128;
					for (int delta = -win; delta <= win; delta += 8) {
						ut64 cand = saddr + (ut64)delta;
						char s2[128];
						if (try_read_dart_string (ctx->core, cand, s2, sizeof (s2))) {
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
			if (!*name && G_USE_NAME_POOL) {
				// Last-resort: take next human-readable name from pool
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
		if (G_DUMP_IT) {
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
// Standalone AOT snapshot/ObjectPool parser (no Dart VM deps)
// Snapshot discovery is implemented in find_snapshots_with_r2; pool decoding is handled in decode_pool_and_emit.
// For now it’s a stub that returns not implemented.

static int find_snapshots_with_r2(RCore *core, ut64 *vm_data, ut64 *vm_instr, ut64 *iso_data, ut64 *iso_instr) {
	if (!core) {
		return -1;
	}
	if (vm_data) {
		*vm_data = 0;
	}
	if (vm_instr) {
		*vm_instr = 0;
	}
	if (iso_data) {
		*iso_data = 0;
	}
	if (iso_instr) {
		*iso_instr = 0;
	}

	// 1) Prefer symbol names via r_bin APIs
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
	ut64 *outs[4] = { vm_data, vm_instr, iso_data, iso_instr };
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
						if (outs[idx]) {
							*outs[idx] = sym->vaddr? sym->vaddr: 0;
						}
					}
				}
			}
		}
	}
	if (vm_data && *vm_data && vm_instr && *vm_instr && iso_data && *iso_data && iso_instr && *iso_instr) {
		return 0;
	}

	// 2) Fallback: scan sections for magic using r_bin sections and classify
	RList *sections = r_bin_get_sections (core->bin);
	const uint32_t kMagic = 0xdcdcf5f5; // Snapshot::kMagicValue
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
			const int chunk = 4096;
			ut8 buf[chunk];
			for (ut64 off = 0; off + 4 <= size; off += (chunk - 16)) {
				ut64 addr = vaddr + off;
				int toread = (int) ((off + chunk <= size)? chunk: (size - off));
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
		// Classify candidates into DATA vs INSTR by attempting to parse clustered header
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
			bool is_data = looks_like_data_snapshot (core, found_addrs[i], &classified_len);
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
		// Choose VM/Isolate for DATA: min=len as VM, max=len as ISO
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
			if (vm_addr && vm_data) {
				*vm_data = vm_addr;
			}
			if (iso_addr && iso_data) {
				*iso_data = iso_addr;
			}
		}
		// Choose VM/Isolate for INSTR similarly: min as VM_INSTR, max as ISO_INSTR
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
			if (vm_addr && vm_instr) {
				*vm_instr = vm_addr;
			}
			if (iso_addr && iso_instr) {
				*iso_instr = iso_addr;
			}
		}
		if ((vm_data && *vm_data) || (iso_data && *iso_data) || (vm_instr && *vm_instr) || (iso_instr && *iso_instr)) {
			return 0;
		}
	}
	return -1;
}

static void read_snapshot_hash_flags(RCore *core, ut64 vm_data, char out_hash[33]) {
	extract_snapshot_hash_flags (core, vm_data, out_hash);
}

static void emit_stub_symbols(RCore *core,
	void (*on_fn) (const char *name, unsigned long long addr, unsigned long long size, void *user),
	void *user) {
	if (!core || !core->bin || !on_fn) {
		return;
	}
	RVecRBinSymbol *v = r_bin_get_symbols_vec (core->bin);
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

static ut64 find_pp_base_via_r2(RCore *core, ut64 iso_instr) {
	(void)core;
	(void)iso_instr;
	// Disabled heuristic to avoid slow JSON disassembly; use 0 until we add a fast r_asm pattern.
	return 0;
}

int dart_pool_enumerate(RCore *core, const char *libapp_path, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user, unsigned long long *out_base, unsigned long long *out_heap_base) {
	(void)on_fn;
	(void)user;
	(void)libapp_path;
	if (!core) {
		return -1;
	}
	ut64 vm_data = 0, vm_instr = 0, iso_data = 0, iso_instr = 0;
	int ok = find_snapshots_with_r2 (core, &vm_data, &vm_instr, &iso_data, &iso_instr);
	if (ok == 0) {
		if (out_base) {
			*out_base = (unsigned long long)r_bin_get_baddr (core->bin);
		}
		if (out_heap_base) {
			*out_heap_base = 0;
		}
		eprintf ("[r2flutter] Found Dart snapshots: vm_data=0x%llx vm_instr=0x%llx iso_data=0x%llx iso_instr=0x%llx\n",
			(unsigned long long)vm_data,
			(unsigned long long)vm_instr,
			(unsigned long long)iso_data,
			(unsigned long long)iso_instr);
		DartCtx ctx = { 0 };
		ctx.core = core;
		ctx.vm_data = vm_data;
		ctx.vm_instr = vm_instr;
		ctx.iso_data = iso_data;
		ctx.iso_instr = iso_instr;
		read_snapshot_hash_flags (core, vm_data, ctx.snapshot_hash);
		DartVerLayout layout_tmp;
		ctx.layout = load_layout_from_json (ctx.snapshot_hash, &layout_tmp);
		if (!ctx.layout) {
			ctx.layout = pick_layout_by_hash (ctx.snapshot_hash);
		}
		derive_layout_from_flags (&ctx);
		// Debug: dump first 32 bytes of isolate snapshot data
		if (G_VERBOSE > 1) {
			ut8 peek[32] = { 0 };
			if (read_mem (core, iso_data, peek, sizeof (peek))) {
				fprintf (stderr, "[r2flutter] iso_data[0..32]: ");
				for (int i = 0; i < 32; i++) {
					fprintf (stderr, "%02x", (unsigned int)peek[i]);
				}
				fprintf (stderr, "\n");
			}
		}
		// Emit FUNC symbols available in the binary (e.g., VM stubs)
		if (!G_NO_STUBS) {
			emit_stub_symbols (core, on_fn, user);
		}
		// Decode and emit functions from ObjectPool if layout is known (WIP)
		(void)decode_pool_and_emit (&ctx, on_fn, user);
		// Try to guess PP base (global ObjectPool) using adrp/add prologue pattern
		ut64 pp_base = find_pp_base_via_r2 (core, iso_instr);
		if (!pp_base && vm_instr) {
			pp_base = find_pp_base_via_r2 (core, vm_instr);
		}
		if (pp_base && out_heap_base) {
			*out_heap_base = (unsigned long long)pp_base;
			if (G_VERBOSE > 0) {
				fprintf (stderr, "[r2flutter] PP(base)=0x%" PFMT64x "\n", (uint64_t)pp_base);
			}
		}
		return 0; // return 0 to let caller proceed even if pool decoding isn't finished
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
