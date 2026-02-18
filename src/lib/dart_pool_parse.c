#include <stdint.h>
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

// Minimal, standalone AOT snapshot/ObjectPool decoder scaffolding.
// This file will progressively implement decoding without Dart VM deps.
//
// Supported Dart SDK versions: 2.10.0 - 3.10.7
// Based on unflutter's version profiles and CID tables.

// Debug/diagnostic controls (forward declaration)
static int G_VERBOSE = 0;

// Tag encoding styles across Dart versions
typedef enum {
	TAG_STYLE_CID_INT32 = 0,     // v2.10-2.13: raw int32 CID
	TAG_STYLE_CID_SHIFT1 = 1,    // v2.14-3.3: (cid << 1) | canonical
	TAG_STYLE_OBJECT_HEADER = 2  // v3.4.3+: ObjectHeader with ClassIdTag at bits 12-31
} DartTagStyle;

typedef struct {
	char hash[33];
	const char *dart_version;
	int compressed_word_size;
	int heap_object_tag;
	int max_alignment;
	ut64 it_cap;
	DartTagStyle tag_style;
	int header_fields;
	int cid_class;
	int cid_function;
	int cid_code;
	int cid_string;
	int cid_one_byte_string;
	int cid_two_byte_string;
	int cid_array;
	int cid_mint;
	int cid_object_pool;
	int num_predefined_cids;
} DartVerLayout;

// Known snapshot hashes mapped to Dart SDK versions
// Sources: unflutter version.go, reFlutter enginehash.csv, blutter precompiled SDKs
static const struct {
	const char *hash;
	const char *version;
} known_hashes[] = {
	// Dart 2.10.x (Flutter 1.22.x)
	{"8ee4ef7a67df9845fba331734198a953", "2.10.0"},
	// Dart 2.13.x (Flutter 2.2.x - 2.3.x)
	{"e4a09dbf2bb120fe4674e0576617a0dc", "2.13.0"},
	{"34f6eec64e9371856eaaa278ccf56538", "2.13.0"},
	{"7a5b240780941844bae88eca5dbaa7b8", "2.13.0"},
	// Dart 2.14.x (Flutter 2.4.x - 2.5.x)
	{"9cf77f4405212c45daf608e1cd646852", "2.14.0"},
	{"659a72e41e3276e882709901c27de33d", "2.14.0"},
	// Dart 2.15.x (Flutter 2.6.x - 2.7.x)
	{"f10776149bf76be288def3c2ca73bdc1", "2.15.0"},
	{"24d9d411c2f90c8fbe8907f99e89d4b0", "2.15.0"},
	// Dart 2.16.x (Flutter 2.8.x - 2.16.x)
	{"d56742caf7b3b3f4bd2df93a9bbb5503", "2.16.0"},
	{"3318fe66091c0ffbb64faec39976cb7d", "2.16.0"},
	{"adf563436d12ba0d50ea5beb7f3be1bb", "2.16.0"},
	// Dart 2.17.x (Flutter 2.17.x)
	{"1441d6b13b8623fa7fbf61433abebd31", "2.17.6"},
	{"a0cb0c928b23bc17a26e062b351dc44d", "2.17.6"},
	{"ded6ef11c73fdc638d6ff6d3ad22a67b", "2.17.6"},
	// Dart 2.18.x (Flutter 3.3.x)
	{"b0e899ec5a90e4661501f0b69e9dd70f", "2.18.0"},
	{"b6d0a1f034d158b0d37b51d559379697", "2.18.0"},
	{"8e50e448b241be23b9e990094f4dca39", "2.18.0"},
	{"6a9b5a03a7e784a4558b10c769f188d9", "2.18.0"},
	// Dart 2.19.x (Flutter 3.7.x)
	{"adb4292f3ec25074ca70abcd2d5c7251", "2.19.0"},
	{"501ef5cbd64ca70b6b42672346af6a8a", "2.19.0"},
	// Dart 3.0.x (Flutter 3.10.x - 3.12.x)
	{"90b56a561f70cd55e972cb49b79b3d8b", "3.0.5"},
	{"aa64af18e7d086041ac127cc4bc50c5e", "3.0.5"},
	{"36b0375d284ee2af0d0fffc6e6e48fde", "3.0.5"},
	{"16ad76edd19b537bf6ea64fdd31977a7", "3.0.5"},
	// Dart 3.1.x (Flutter 3.13.x)
	{"7dbbeeb8ef7b91338640dca3927636de", "3.1.0"},
	// Dart 3.2.x (Flutter 3.16.x)
	{"f71c76320d35b65f1164dbaa6d95fe09", "3.2.5"},
	// Dart 3.3.x (Flutter 3.19.x)
	{"ee1eb666c76a5cb7746faf39d0b97547", "3.3.0"},
	// Dart 3.4.x (Flutter 3.22.x)
	{"d20a1be77c3d3c41b2a5accaee1ce549", "3.4.3"},
	// Dart 3.5.x (Flutter 3.24.x)
	{"80a49c7111088100a233b2ae788e1f48", "3.5.0"},
	{"cda356e9bae476c70de33809fd92e009", "3.5.0"},
	{"2858c2c0920495f00b9bce9edf6a8cd9", "3.6.2"},
	// Dart 3.6.x (Flutter 3.27.x)
	{"f956f595844a2f845a55707faaaa51e4", "3.6.2"},
	// Dart 3.7.x (Flutter 3.29.x)
	{"d91c0e6f35f0eb2e44124e8f42aa44a7", "3.7.0"},
	// Dart 3.8.x (Flutter 3.32.x)
	{"830f4f59e7969c70b595182826435c19", "3.8.1"},
	// Dart 3.9.x (Flutter 3.35.x)
	{"97ff04a728735e6b6b098bdf983faaba", "3.9.2"},
	// Dart 3.10.x (Flutter 3.38.x)
	{"1ce86630892e2dca9a8543fdb8ed8e22", "3.10.7"},
	{NULL, NULL}
};

// Version profiles with CID tables - based on unflutter's version.go
static const DartVerLayout version_profiles[] = {
	// Dart 2.10.0 - raw int32 tag, 4 header fields, pre-FunctionType split
	{"", "2.10.0", 8, 1, 16, 20000, TAG_STYLE_CID_INT32, 4,
		4, 6, 16, 80, 81, 82, 78, 53, 20, 156},
	// Dart 2.13.0 - raw int32 tag, 5 header fields, split canonical
	{"", "2.13.0", 8, 1, 16, 20000, TAG_STYLE_CID_INT32, 5,
		4, 6, 15, 77, 78, 79, 75, 51, 18, 148},
	// Dart 2.14.0 - shift1 tag, 5 header fields
	{"", "2.14.0", 8, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		4, 6, 16, 81, 82, 83, 79, 54, 20, 152},
	// Dart 2.15.0 - shift1 tag, 5 header fields, NativePointer inserted
	{"", "2.15.0", 8, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		5, 7, 17, 82, 83, 84, 79, 55, 21, 153},
	// Dart 2.16.0 - shift1 tag, 6 header fields, adds ConstMap/ConstSet
	{"", "2.16.0", 8, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 6,
		5, 7, 17, 84, 85, 86, 81, 55, 21, 154},
	// Dart 2.17.6 - shift1 tag, 6 header fields
	{"", "2.17.6", 4, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 6,
		5, 7, 17, 89, 90, 91, 86, 59, 21, 158},
	// Dart 2.18.0 - shift1 tag, 5 header fields, adds SuspendState
	{"", "2.18.0", 4, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		5, 7, 17, 90, 91, 92, 87, 59, 21, 159},
	// Dart 2.19.0 - shift1 tag, 5 header fields, adds RecordType/Record
	{"", "2.19.0", 4, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		5, 7, 17, 92, 93, 94, 89, 60, 21, 176},
	// Dart 3.0.5 - shift1 tag, 5 header fields, adds WeakArray
	{"", "3.0.5", 4, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		5, 7, 18, 93, 94, 95, 90, 61, 22, 177},
	// Dart 3.1.0 - shift1 tag, 5 header fields
	{"", "3.1.0", 4, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		5, 7, 18, 92, 93, 94, 89, 60, 22, 176},
	// Dart 3.2.5 - shift1 tag, 5 header fields, PoolType swapped
	{"", "3.2.5", 4, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		5, 7, 18, 92, 93, 94, 89, 60, 22, 176},
	// Dart 3.3.0 - shift1 tag, 5 header fields
	{"", "3.3.0", 4, 1, 16, 20000, TAG_STYLE_CID_SHIFT1, 5,
		5, 7, 18, 92, 93, 94, 89, 60, 22, 176},
	// Dart 3.4.3 - ObjectHeader tag, 5 header fields
	{"", "3.4.3", 4, 1, 16, 20000, TAG_STYLE_OBJECT_HEADER, 5,
		5, 7, 18, 92, 93, 94, 89, 60, 22, 174},
	// Dart 3.5.0 - ObjectHeader tag, 5 header fields
	{"", "3.5.0", 4, 1, 16, 20000, TAG_STYLE_OBJECT_HEADER, 5,
		5, 7, 18, 92, 93, 94, 89, 60, 22, 174},
	// Dart 3.6.2 - ObjectHeader tag, 5 header fields
	{"", "3.6.2", 4, 1, 16, 20000, TAG_STYLE_OBJECT_HEADER, 5,
		5, 7, 18, 93, 94, 95, 90, 61, 23, 175},
	// Dart 3.7.0 - ObjectHeader tag, 5 header fields
	{"", "3.7.0", 4, 1, 16, 20000, TAG_STYLE_OBJECT_HEADER, 5,
		5, 7, 18, 93, 94, 95, 90, 61, 23, 175},
	// Dart 3.8.1 - ObjectHeader tag, 5 header fields
	{"", "3.8.1", 4, 1, 16, 20000, TAG_STYLE_OBJECT_HEADER, 5,
		5, 7, 18, 93, 94, 95, 90, 61, 23, 175},
	// Dart 3.9.2 - ObjectHeader tag, 5 header fields
	{"", "3.9.2", 4, 1, 16, 20000, TAG_STYLE_OBJECT_HEADER, 5,
		5, 7, 18, 93, 94, 95, 90, 61, 23, 175},
	// Dart 3.10.7 - ObjectHeader tag, 5 header fields
	{"", "3.10.7", 4, 1, 16, 20000, TAG_STYLE_OBJECT_HEADER, 5,
		5, 7, 18, 93, 94, 95, 90, 61, 23, 175},
	{{0}, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

static const char *version_from_hash (const char *hash) {
	if (!hash) {
		return NULL;
	}
	for (int i = 0; known_hashes[i].hash; i++) {
		if (!strncmp (known_hashes[i].hash, hash, 32)) {
			return known_hashes[i].version;
		}
	}
	return NULL;
}

static const DartVerLayout *profile_from_version (const char *version) {
	if (!version) {
		return NULL;
	}
	for (int i = 0; version_profiles[i].dart_version; i++) {
		if (!strcmp (version_profiles[i].dart_version, version)) {
			return &version_profiles[i];
		}
	}
	return NULL;
}

static const DartVerLayout *pick_layout_by_hash (const char *hash) {
	DartVerLayout *dvl = R_NEW0 (DartVerLayout);
	const char *version = version_from_hash (hash);
	const DartVerLayout *profile = version? profile_from_version (version): NULL;
	if (profile) {
		memcpy (dvl, profile, sizeof (DartVerLayout));
		if (hash && *hash) {
			strncpy (dvl->hash, hash, 32);
			dvl->hash[32] = '\0';
		}
		if (G_VERBOSE > 0) {
			fprintf (stderr, "[r2flutter] Detected Dart version: %s (hash=%s)\n",
				profile->dart_version, hash? hash: "(null)");
		}
		return dvl;
	}
	dvl->compressed_word_size = 4;
	dvl->heap_object_tag = 1;
	dvl->max_alignment = 16;
	dvl->it_cap = 20000;
	dvl->tag_style = TAG_STYLE_OBJECT_HEADER;
	dvl->header_fields = 5;
	dvl->cid_class = 5;
	dvl->cid_function = 7;
	dvl->cid_code = 18;
	dvl->cid_string = 93;
	dvl->cid_one_byte_string = 94;
	dvl->cid_two_byte_string = 95;
	dvl->cid_array = 90;
	dvl->cid_mint = 61;
	dvl->cid_object_pool = 23;
	dvl->num_predefined_cids = 175;
	dvl->dart_version = "unknown";
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] Unknown snapshot hash, using v3.9.2 defaults (hash=%s)\n",
			hash? hash: "(null)");
	}
	return dvl;
}

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
	RList *strings; // decoded strings from String clusters
	RList *classes; // decoded class info
	RList *functions; // decoded function info
	void **refs; // reference array for Alloc+Fill phases
	ut64 refs_count;
	ut64 num_base_objects;
	ut64 num_objects;
	ut64 num_clusters;
} DartCtx;

// Predefined Class IDs from Dart VM (class_id.h)
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

// Decoded Dart object types
typedef struct {
	ut64 ref_id;
	char *value;
	int length;
	bool is_two_byte;
} DartString;

typedef struct {
	ut64 ref_id;
	ut64 name_ref; // ref to String
	ut64 library_ref; // ref to Library
	char *name; // resolved name
	int instance_size;
} DartClass;

typedef struct {
	ut64 ref_id;
	ut64 name_ref; // ref to String
	ut64 owner_ref; // ref to Class/Library
	ut64 code_ref; // ref to Code
	ut64 entry_point;
	char *name; // resolved name
} DartFunction;

typedef struct {
	ut64 ref_id;
	ut64 entry_point;
	ut64 owner_ref; // ref to Function
	int state_bits;
} DartCode;

// Debug/diagnostic controls (G_VERBOSE declared at top of file)
static int G_NO_STUBS = 0;
static int G_DUMP_SNAPSHOT_JSON = 0;
static int G_DUMP_IT = 0;
static int G_QUIET = 0;
static int G_DUMP_FNS = 0;
static int G_USE_NAME_POOL = 0;
static int G_DUMP_CLASSES = 0;
static int G_DUMP_FIELDS = 0;

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
void dart_pool_set_dump_classes(int on) {
	G_DUMP_CLASSES = on? 1: 0;
}
int dart_pool_get_dump_classes(void) {
	return G_DUMP_CLASSES;
}
void dart_pool_set_dump_fields(int on) {
	G_DUMP_FIELDS = on? 1: 0;
}
int dart_pool_get_dump_fields(void) {
	return G_DUMP_FIELDS;
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

#define CHUNK_SIZE 4096

static RList *collect_data_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
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

// ============================================================================
// Clustered Snapshot Deserializer - Alloc + Fill Phases
// ============================================================================

// Stream reader context for clustered snapshot
typedef struct {
	RCore *core;
	ut64 cursor;
	ut64 end;
} ClusterStream;

static bool cs_read_u8(ClusterStream *s, ut8 *out) {
	if (!s || !out || s->cursor >= s->end) {
		return false;
	}
	return read_mem (s->core, s->cursor++, out, 1);
}

static bool cs_read_u32(ClusterStream *s, uint32_t *out) {
	if (!s || !out || s->cursor + 4 > s->end) {
		return false;
	}
	bool ok = read_mem (s->core, s->cursor, out, 4);
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
	bool ok = read_mem (s->core, s->cursor, buf, len);
	s->cursor += len;
	return ok;
}

// Free functions for decoded objects
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
	DartFunction *df = (DartFunction *)p;
	if (df) {
		free (df->name);
		free (df);
	}
}

// Decode a String cluster (OneByteString or TwoByteString)
// The encoding packs length and type: bit0 = is_two_byte, rest = length
static int decode_string_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	if (G_VERBOSE > 1) {
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
			if (G_VERBOSE > 0) {
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

// Decode a Class cluster
static int decode_class_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (G_VERBOSE > 1) {
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

// Decode a Function cluster
static int decode_function_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, ut64 iso_instr, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	if (G_VERBOSE > 1) {
		fprintf (stderr, "[r2flutter] Function cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartFunction *df = R_NEW0 (DartFunction);
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

// Read and decode all clusters using Alloc+Fill approach
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
		.core = ctx->core,
		.cursor = cluster_start,
		.end = cluster_end
	};
	ut64 ref_counter = ctx->num_base_objects + 1;
	for (ut64 ci = 0; ci < num_clusters && stream.cursor < stream.end; ci++) {
		uint32_t tags = 0;
		if (!cs_read_u32 (&stream, &tags)) {
			if (G_VERBOSE > 0) {
				fprintf (stderr, "[r2flutter] Failed to read cluster tag at %" PRIu64 "\n", ci);
			}
			break;
		}
		// Dart tag layout (raw_object.h):
		// bits 0-7:   first byte flags (CanonicalBit, DeeplyImmutableBit, etc.)
		// bits 8-11:  SizeTagBits (4 bits)
		// bits 12-31: ClassIdTag (20 bits)
		uint32_t cid = (tags >> 12) & 0xFFFFF;
		bool is_canonical = tags & 1;
		if (G_VERBOSE > 1) {
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
		default: {
			ut64 count = 0;
			if (cs_read_unsigned (&stream, &count)) {
				if (count < 100000) {
					for (ut64 j = 0; j < count; j++) {
						ref_counter++;
						ut64 skip = 0;
						for (int k = 0; k < 8 && stream.cursor < stream.end; k++) {
							if (!cs_read_unsigned (&stream, &skip)) {
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
		break;
		}
		if (rc < 0) {
			if (G_VERBOSE > 0) {
				fprintf (stderr, "[r2flutter] Error decoding cluster cid=%u\n", cid);
			}
		}
	}
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] Decoded: strings=%d classes=%d functions=%d\n",
			ctx->strings? r_list_length (ctx->strings): 0,
			ctx->classes? r_list_length (ctx->classes): 0,
			ctx->functions? r_list_length (ctx->functions): 0);
	}
	return 0;
}

// Resolve string references after Fill phase
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
				}
			}
		}
	}
	if (ctx->functions) {
		RListIter *it;
		DartFunction *df;
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
	// The snapshot header is followed by:
	//   - Version string: 32 bytes (not null-terminated, ASCII hex hash)
	//   - Features string: variable length, null-terminated
	// After the features string comes the clustered data with LEB128 values.
	ut64 cursor = base + 4 + 8 + 8; // after magic + length + kind
	// The version string is exactly 32 ASCII chars
	cursor += 32;
	// Now scan for the NUL terminator of features string
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
		// For debugging, print the features string
		char feat[256];
		memset (feat, 0, sizeof (feat));
		int toshow = scanned > 255? 255: scanned;
		if (read_mem (ctx->core, cursor, (ut8 *)feat, toshow)) {
			eprintf ("[r2flutter] features: %s\n", feat);
		}
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
	// Sanity check: typical Dart snapshots have 100-3000 clusters, rarely >5000
	// If num_clusters is unreasonable, the header parsing likely failed
	bool header_valid = (nc > 0 && nc < 10000 && no > 0 && no < 1000000);
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] snapshot clustered header: base_objs=%" PRIu64 " objs=%" PRIu64 " clusters=%" PRIu64 " it_len=%" PRIu64 " it_data_off=%" PRIu64 " total_len=%" PRIu64 " valid=%d\n", (uint64_t)nb, (uint64_t)no, (uint64_t)nc, (uint64_t)itlen, (uint64_t)itdata, (uint64_t)total_len, header_valid);
	}
	if (!header_valid) {
		if (G_VERBOSE > 0) {
			fprintf (stderr, "[r2flutter] warning: snapshot header values out of expected range, skipping cluster deserialization\n");
		}
		nc = 0; // Skip cluster deserialization
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

	// Store cluster info in context for Alloc+Fill deserialization
	ctx->num_base_objects = nb;
	ctx->num_objects = no;
	ctx->num_clusters = nc;

	// Attempt Alloc+Fill cluster deserialization (new ObjectPool decoding)
	// Note: typical Dart snapshots have 100-2000 clusters; values >10000 indicate parsing error
	ut64 cluster_start = next; // position after the 5 uleb128 header fields
	ut64 cluster_end = base + total_len;
	if (nc > 0 && nc < 5000 && no < 500000 && cluster_start < cluster_end) {
		int deser_rc = deserialize_clusters (ctx, cluster_start, cluster_end, nc, ctx->iso_instr);
		if (deser_rc == 0) {
			resolve_names (ctx);
			// Emit functions from deserialized Function cluster
			if (ctx->functions && on_fn) {
				RListIter *fit;
				DartFunction *df;
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
			// Print decoded strings if verbose
			if (G_VERBOSE > 1 && ctx->strings) {
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
			if (G_VERBOSE > 0) {
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

// ============================================================================
// Class and Field Extraction Implementation
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
		if (ci->fields) {
			r_list_free (ci->fields);
		}
		if (ci->interfaces) {
			r_list_free (ci->interfaces);
		}
		free (ci);
	}
}

void dart_type_info_free(DartTypeInfo *ti) {
	if (ti) {
		free (ti->name);
		if (ti->type_args) {
			r_list_free (ti->type_args);
		}
		free (ti);
	}
}

void dart_class_list_free(RList *list) {
	r_list_free (list);
}

// Internal context for class extraction
typedef struct {
	RCore *core;
	ut64 vm_data;
	ut64 vm_instr;
	ut64 iso_data;
	ut64 iso_instr;
	char snapshot_hash[33];
	const DartVerLayout *layout;
	int compressed_word_size;
	RList *classes;     // DartClassInfo*
	RList *strings;     // DartString* for name resolution
	RList *libraries;   // library objects for URI resolution
	RList *fields;      // DartFieldInfo* (global pool)
	RList *types;       // DartTypeInfo* (global pool)
	void **refs;
	ut64 refs_count;
	ut64 num_base_objects;
	ut64 num_objects;
	ut64 num_clusters;
} ClassExtractCtx;

// CIDs for class-related objects
typedef enum {
	kFieldCid_extract = 10,
	kLibraryCid_extract = 12,
	kTypeArgumentsCid_extract = 115,
} ExtraCids;

// Decode a Field cluster to extract field information
static int decode_field_cluster_ext(ClusterStream *s, ClassExtractCtx *ctx, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (G_VERBOSE > 1) {
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
		if (ctx->fields) {
			r_list_append (ctx->fields, fi);
		}
		if (ctx->refs && ref_id < ctx->refs_count) {
			ctx->refs[ref_id] = fi;
		}
		(void)name_ref;
		(void)owner_ref;
	}
	return 0;
}

// Enhanced Class cluster decoding with hierarchy and type info
static int decode_class_cluster_ext(ClusterStream *s, ClassExtractCtx *ctx, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (G_VERBOSE > 1) {
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
		if (ctx->classes) {
			r_list_append (ctx->classes, ci);
		}
		if (ctx->refs && ci->ref_id < ctx->refs_count) {
			ctx->refs[ci->ref_id] = ci;
		}
		(void)name_ref;
	}
	return 0;
}

// Library cluster decoding for URI resolution
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

static int decode_library_cluster_ext(ClusterStream *s, ClassExtractCtx *ctx, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 10000) {
		return 0;
	}
	if (G_VERBOSE > 1) {
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
		if (ctx->libraries) {
			r_list_append (ctx->libraries, li);
		}
		if (ctx->refs && li->ref_id < ctx->refs_count) {
			ctx->refs[li->ref_id] = li;
		}
	}
	return 0;
}

// Resolve names after fill phase for classes
static void resolve_class_names(ClassExtractCtx *ctx) {
	if (!ctx || !ctx->refs || !ctx->classes) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (ctx->classes, it, ci) {
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

// Main class extraction function
RList *dart_pool_extract_classes(RCore *core) {
	if (!core) {
		return NULL;
	}
	ut64 vm_data = 0, vm_instr = 0, iso_data = 0, iso_instr = 0;
	int ok = find_snapshots_with_r2 (core, &vm_data, &vm_instr, &iso_data, &iso_instr);
	if (ok != 0 || !iso_data) {
		return NULL;
	}
	// Use isolate snapshot for class extraction
	ut64 snapshot_base = iso_data;
	ClassExtractCtx ctx = { 0 };
	ctx.core = core;
	ctx.vm_data = vm_data;
	ctx.vm_instr = vm_instr;
	ctx.iso_data = iso_data;
	ctx.iso_instr = iso_instr;
	extract_snapshot_hash_flags (core, vm_data, ctx.snapshot_hash);
	DartVerLayout layout_tmp;
	bool layout_is_dynamic = false;
	ctx.layout = load_layout_from_json (ctx.snapshot_hash, &layout_tmp);
	if (!ctx.layout) {
		ctx.layout = pick_layout_by_hash (ctx.snapshot_hash);
		layout_is_dynamic = true;
	}
	if (ctx.layout) {
		ctx.compressed_word_size = ctx.layout->compressed_word_size;
	} else {
		ctx.compressed_word_size = 4;
	}
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (core, snapshot_base, hdr, sizeof (hdr))) {
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return NULL;
	}
	uint32_t magic = *(uint32_t *)(hdr + 0);
	if (magic != 0xdcdcf5f5) {
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return NULL;
	}
	uint64_t length_ex_magic = *(uint64_t *)(hdr + 4);
	uint64_t total_len = length_ex_magic + 4;
	ut64 cursor = snapshot_base + 4 + 8 + 8 + 32;
	const int max_scan = 1024;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem (core, cursor + scanned, &b, 1)) {
			break;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	cursor += (ut64)(scanned + 1);
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, next = cursor;
	if (!read_uleb128_at (core, next, &nb, &next)) {
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return NULL;
	}
	if (!read_uleb128_at (core, next, &no, &next)) {
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return NULL;
	}
	if (!read_uleb128_at (core, next, &nc, &next)) {
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return NULL;
	}
	if (!read_uleb128_at (core, next, &itlen, &next)) {
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return NULL;
	}
	if (!read_uleb128_at (core, next, &itdata, &next)) {
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return NULL;
	}
	bool header_valid = (nc > 0 && nc < 10000 && no > 0 && no < 1000000);
	if (!header_valid) {
		if (G_VERBOSE > 0) {
			fprintf (stderr, "[r2flutter] class extraction: invalid header (clusters=%" PRIu64 " objs=%" PRIu64 ")\n", nc, no);
		}
		if (layout_is_dynamic) {
			free ((void *)ctx.layout);
		}
		return r_list_newf ((RListFree)dart_class_info_free);
	}
	ctx.num_base_objects = nb;
	ctx.num_objects = no;
	ctx.num_clusters = nc;
	ctx.classes = r_list_newf ((RListFree)dart_class_info_free);
	ctx.strings = r_list_newf (free_dart_string);
	ctx.libraries = r_list_newf (free_library_info);
	ctx.fields = r_list_newf ((RListFree)dart_field_info_free);
	ut64 total_refs = nb + no + 16;
	ctx.refs_count = total_refs;
	ctx.refs = (void **)calloc (total_refs, sizeof (void *));
	ClusterStream stream = {
		.core = core,
		.cursor = next,
		.end = snapshot_base + total_len
	};
	ut64 ref_counter = nb + 1;
	if (G_VERBOSE > 1) {
		fprintf (stderr, "[r2flutter] class extraction: clusters=%" PRIu64 " cid_class=%d/%d/%d stream=0x%" PFMT64x "-0x%" PFMT64x "\n",
			nc, kClassCid, kFieldCid_extract, kLibraryCid_extract, stream.cursor, stream.end);
	}
	for (ut64 ci2 = 0; ci2 < nc && stream.cursor < stream.end; ci2++) {
		uint32_t tags = 0;
		if (!cs_read_u32 (&stream, &tags)) {
			break;
		}
		uint32_t cid = (tags >> 12) & 0xFFFFF;
		bool is_canonical = tags & 1;
		(void)is_canonical;
		if (G_VERBOSE > 1 && ci2 < 30) {
			fprintf (stderr, "[r2flutter] cluster[%" PRIu64 "] cid=%u tags=0x%08x cursor=0x%" PFMT64x "\n",
				ci2, cid, tags, stream.cursor);
		}
		int rc = 0;
		switch (cid) {
		case kOneByteStringCid:
		case kTwoByteStringCid:
		case kStringCid:
			rc = decode_string_cluster (&stream, (DartCtx *)&ctx, &ref_counter, false);
			break;
		case kClassCid:
			rc = decode_class_cluster_ext (&stream, &ctx, &ref_counter);
			break;
		case kFieldCid_extract:
			rc = decode_field_cluster_ext (&stream, &ctx, &ref_counter);
			break;
		case kLibraryCid_extract:
			rc = decode_library_cluster_ext (&stream, &ctx, &ref_counter);
			break;
		default:
			{
				ut64 count = 0;
				if (cs_read_unsigned (&stream, &count)) {
					if (count < 100000) {
						for (ut64 j = 0; j < count; j++) {
							ref_counter++;
							ut64 skip = 0;
							for (int k = 0; k < 8 && stream.cursor < stream.end; k++) {
								if (!cs_read_unsigned (&stream, &skip)) {
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
			break;
		}
		if (rc < 0) {
			break;
		}
	}
	resolve_class_names (&ctx);
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] Extracted classes from clusters: %d\n",
			ctx.classes? r_list_length (ctx.classes): 0);
	}
	// If no classes found from clusters, try to extract type strings from the const section
	if (!ctx.classes || r_list_length (ctx.classes) == 0) {
		if (G_VERBOSE > 0) {
			fprintf (stderr, "[r2flutter] Falling back to string-based type extraction\n");
		}
		// Scan the const section (between vm_data and iso_data) for type-like strings
		ut64 scan_start = vm_data;
		ut64 scan_end = iso_data;
		if (scan_end > scan_start && (scan_end - scan_start) < 0x100000) {
			ut64 pos = scan_start;
			int class_count = 0;
			while (pos < scan_end - 4 && class_count < 2000) {
				ut8 buf[128];
				int to_read = (scan_end - pos > 127)? 127: (int)(scan_end - pos);
				if (!read_mem (core, pos, buf, to_read)) {
					break;
				}
				// Look for printable strings that look like class names
				int slen = 0;
				while (slen < to_read && buf[slen] >= 0x20 && buf[slen] < 0x7f) {
					slen++;
				}
				if (slen >= 3 && slen < 80 && buf[slen] == 0) {
					// Check if it looks like a class/type name
					// Class names: PascalCase (e.g., ArgumentError) or _PascalCase (e.g., _List)
					// Exclude: function names (_lowercase...), method patterns (get:, set:), etc.
					char *s = (char *)buf;
					bool is_type = false;
					// Skip common non-class prefixes
					if (strncmp (s, "get:", 4) == 0 || strncmp (s, "set:", 4) == 0 ||
					    strncmp (s, "init:", 5) == 0 || strncmp (s, "dyn:", 4) == 0 ||
					    strncmp (s, "vm:", 3) == 0 || strncmp (s, "dart:", 5) == 0 ||
					    strncmp (s, "package:", 8) == 0 || strchr (s, ':') != NULL) {
						// Skip these
					} else if (s[0] >= 'A' && s[0] <= 'Z') {
						// PascalCase: starts with uppercase
						// Verify it's not all uppercase (constants)
						bool has_lower = false;
						for (int i = 1; i < slen && !has_lower; i++) {
							if (s[i] >= 'a' && s[i] <= 'z') {
								has_lower = true;
							}
						}
						is_type = has_lower;
					} else if (s[0] == '_' && slen > 1 && s[1] >= 'A' && s[1] <= 'Z') {
						// _PascalCase: private class
						// Verify it has lowercase after the second char
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
						ci->ref_id = 0; // Unknown ref
						ci->instance_size = 0;
						ci->flags = 0;
						r_list_append (ctx.classes, ci);
						class_count++;
					}
					pos += slen + 1;
				} else {
					pos++;
				}
			}
			if (G_VERBOSE > 0) {
				fprintf (stderr, "[r2flutter] Extracted %d type names from strings\n", class_count);
			}
		}
	}
	RList *result = ctx.classes;
	ctx.classes = NULL;
	free (ctx.refs);
	r_list_free (ctx.strings);
	r_list_free (ctx.libraries);
	r_list_free (ctx.fields);
	if (layout_is_dynamic) {
		free ((void *)ctx.layout);
	}
	return result;
}

// Get class hierarchy as list of ancestor names
RList *dart_pool_get_class_hierarchy(RCore *core, ut64 class_ref) {
	(void)core;
	(void)class_ref;
	return r_list_newf (free);
}

// Extract fields for a specific class
RList *dart_pool_extract_fields(RCore *core, ut64 class_ref) {
	(void)core;
	(void)class_ref;
	return r_list_newf ((RListFree)dart_field_info_free);
}

// Dump classes to JSON
char *dart_pool_dump_classes_json(RCore *core) {
	RList *classes = dart_pool_extract_classes (core);
	if (!classes || r_list_length (classes) == 0) {
		if (classes) {
			dart_class_list_free (classes);
		}
		return strdup ("[]");
	}
	RStrBuf *sb = r_strbuf_new ("[");
	RListIter *it;
	DartClassInfo *ci;
	int first = 1;
	r_list_foreach (classes, it, ci) {
		if (!ci) {
			continue;
		}
		if (!first) {
			r_strbuf_append (sb, ",");
		}
		first = 0;
		r_strbuf_appendf (sb, "{\"ref\":%" PRIu64, ci->ref_id);
		if (ci->name) {
			r_strbuf_appendf (sb, ",\"name\":\"%s\"", ci->name);
		}
		if (ci->library_name) {
			r_strbuf_appendf (sb, ",\"library\":\"%s\"", ci->library_name);
		}
		if (ci->super_class_name) {
			r_strbuf_appendf (sb, ",\"super\":\"%s\"", ci->super_class_name);
		}
		r_strbuf_appendf (sb, ",\"size\":%u", ci->instance_size);
		r_strbuf_appendf (sb, ",\"type_params\":%u", ci->num_type_parameters);
		r_strbuf_appendf (sb, ",\"flags\":%u", ci->flags);
		if (ci->fields && r_list_length (ci->fields) > 0) {
			r_strbuf_append (sb, ",\"fields\":[");
			RListIter *fit;
			DartFieldInfo *fi;
			int ffirst = 1;
			r_list_foreach (ci->fields, fit, fi) {
				if (!fi) {
					continue;
				}
				if (!ffirst) {
					r_strbuf_append (sb, ",");
				}
				ffirst = 0;
				r_strbuf_append (sb, "{");
				if (fi->name) {
					r_strbuf_appendf (sb, "\"name\":\"%s\",", fi->name);
				}
				if (fi->type_name) {
					r_strbuf_appendf (sb, "\"type\":\"%s\",", fi->type_name);
				}
				r_strbuf_appendf (sb, "\"offset\":%u,\"flags\":%u}", fi->offset, fi->flags);
			}
			r_strbuf_append (sb, "]");
		}
		r_strbuf_append (sb, "}");
	}
	r_strbuf_append (sb, "]");
	dart_class_list_free (classes);
	return r_strbuf_drain (sb);
}

// Dump classes to r2 script format
char *dart_pool_dump_classes_r2(RCore *core) {
	RList *classes = dart_pool_extract_classes (core);
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
