// Dart SDK version detection and layout profiles
#ifndef R2C_DART_VERSION_H
#define R2C_DART_VERSION_H

#include <stdint.h>
#include <stdbool.h>

typedef uint64_t ut64;
typedef uint32_t ut32;

#ifdef __cplusplus
extern "C" {
#endif

// Tag encoding styles across Dart versions
typedef enum {
	DART_TAG_STYLE_CID_INT32 = 0, // v2.10-2.13: raw int32 CID
	DART_TAG_STYLE_CID_SHIFT1 = 1, // v2.14-3.3: (cid << 1) | canonical
	DART_TAG_STYLE_OBJECT_HEADER = 2 // v3.4.3+ and known 2.18.2 exception
} DartTagStyle;

// Ordered fields following the snapshot feature string. The field count alone
// is insufficient because the meaning of the five-field layouts changed.
typedef enum {
	DART_HEADER_STYLE_MODERN = 0, // nb, no, nc, itlen, itdata (2.18+)
	DART_HEADER_STYLE_210, // nb, no, nc, field_table_len
	DART_HEADER_STYLE_212, // nb, no, canonical_nc, nc, field_table_len
	DART_HEADER_STYLE_214, // nb, no, nc, field_table_len, itlen
	DART_HEADER_STYLE_216 // nb, no, nc, field_table_len, itlen, itdata
} DartHeaderStyle;

// Object references use the ordinary unsigned stream integer through Dart
// 2.17. Dart 2.18 introduced a distinct big-endian RefId encoding whose
// signed terminal byte is biased by 128.
typedef enum {
	DART_REF_ENCODING_REF_ID128 = 0,
	DART_REF_ENCODING_UNSIGNED
} DartRefEncoding;

// ObjectPool entry type/patch/behavior bit packing changed independently of
// the surrounding cluster layout.
typedef enum {
	DART_POOL_ENCODING_MODERN = 0, // type[0..3], patch[4], behavior[5..7]
	DART_POOL_ENCODING_LOW7, // type[0..6], patch[7], tagged=0, immediate=1
	DART_POOL_ENCODING_LOW7_SWAPPED // type[0..6], patch[7], immediate=0, tagged=1
} DartPoolEncoding;

typedef enum {
	DART_CODE_ALLOC_STATE_DEFERRED = 0, // count, state words, deferred count/state words
	DART_CODE_ALLOC_DEFERRED_ONLY // count, deferred count
} DartCodeAlloc;

// How the Dart version/layout for a snapshot was determined. Reported so users
// can tell whether decoding rests on an exact match or a best-effort guess.
typedef enum {
	DART_VERSION_SOURCE_EXACT = 0, // snapshot hash matched a known SDK release
	DART_VERSION_SOURCE_OVERRIDE = 1, // user forced a profile via -D
	DART_VERSION_SOURCE_FINGERPRINT = 2, // unknown hash, layout inferred from evidence
	DART_VERSION_SOURCE_UNKNOWN = 3 // no snapshot available
} DartVersionSource;

// Version layout information for Dart snapshots
// CID values are stored in dart_cid.c's cid_tables[] and accessed via dart_cid_get()
typedef struct {
	char hash[33];
	const char *dart_version;
	int compressed_word_size;
	int heap_object_tag;
	int max_alignment;
	ut64 it_cap;
	DartTagStyle tag_style;
	int header_fields;
	DartHeaderStyle header_style;
	DartRefEncoding ref_encoding;
	DartPoolEncoding pool_encoding;
	DartCodeAlloc code_alloc;
	int code_refs;
	int code_leading_refs;
	bool code_has_text_offset;
	bool single_snapshot;
	bool class_alloc_fixed;
	bool closure_variable;
	bool class_top_level_cid20;
} DartVerLayout;

// Lookup Dart version from a snapshot hash (MD5)
// Returns NULL if hash is not recognized
const char *dart_version_from_hash(const char *hash);

// Lookup version profile from a Dart version string using floor semantics.
// Returns NULL if the version string is not a dotted numeric version.
const DartVerLayout *dart_profile_from_version(const char *version);

// Pick a layout structure based on hash, with fallback to a compatible baseline
// Returns a newly allocated DartVerLayout (caller must free)
// If hash is unknown, fingerprints against the newest split-snapshot profile.
DartVerLayout *dart_layout_from_hash(const char *hash);

// Newest known layout profile.
const DartVerLayout *dart_newest_profile(void);

// Conservative profile used until an unknown hash can be structurally probed.
// Single-snapshot mechanics require positive evidence and are not inherited.
const DartVerLayout *dart_fingerprint_profile(void);

// Human-readable name for a DartVersionSource value.
const char *dart_version_source_str(int source);

// Free a DartVerLayout allocated by dart_layout_from_hash
void dart_ver_layout_free(DartVerLayout *layout);

void dart_version_set_verbose(int level);

// Compare dotted Dart SDK versions numerically.
// Returns -1, 0, 1, or -2 when either input is not a dotted numeric version.
int dart_version_compare(const char *a, const char *b);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_VERSION_H
