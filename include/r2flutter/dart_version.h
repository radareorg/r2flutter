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
	DART_TAG_STYLE_OBJECT_HEADER = 2 // v3.4.3+: ObjectHeader with ClassIdTag at bits 12-31
} DartTagStyle;

// Version layout information for Dart snapshots
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

// Lookup Dart version from a snapshot hash (MD5)
// Returns NULL if hash is not recognized
const char *dart_version_from_hash(const char *hash);

// Lookup version profile from a Dart version string
// Returns NULL if version is not recognized
const DartVerLayout *dart_profile_from_version(const char *version);

// Pick a layout structure based on hash, with fallback to defaults
// Returns a newly allocated DartVerLayout (caller must free)
// If hash is unknown, uses v3.9.2 defaults
DartVerLayout *dart_pick_layout_by_hash(const char *hash);

// Free a DartVerLayout allocated by dart_pick_layout_by_hash
void dart_ver_layout_free(DartVerLayout *layout);

// Get verbose level for diagnostics
int dart_version_get_verbose(void);
void dart_version_set_verbose(int level);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_VERSION_H