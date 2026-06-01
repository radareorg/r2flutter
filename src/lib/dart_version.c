/* r2flutter - MIT - Copyright 2026 - pancake */

// Dart SDK version detection and layout profiles
//
// Supported Dart SDK versions: 2.10.0 - 3.10.7
// Based on unflutter's version profiles and CID tables.

#include <r_core.h>
#include "../../include/r2flutter/dart_version.h"

static int G_VERBOSE = 0;

int dart_version_get_verbose(void) {
	return G_VERBOSE;
}

void dart_version_set_verbose(int level) {
	G_VERBOSE = level;
}

// Known snapshot hashes mapped to Dart SDK versions
// Sources: unflutter version.go, reFlutter enginehash.csv, blutter precompiled SDKs
static const struct {
	const char *hash;
	const char *version;
} known_hashes[] = {
	// Dart 2.10.x (Flutter 1.22.x)
	{ "8ee4ef7a67df9845fba331734198a953", "2.10.0" },
	// Dart 2.13.x (Flutter 2.2.x - 2.3.x)
	{ "e4a09dbf2bb120fe4674e0576617a0dc", "2.13.0" },
	{ "34f6eec64e9371856eaaa278ccf56538", "2.13.0" },
	{ "7a5b240780941844bae88eca5dbaa7b8", "2.13.0" },
	// Dart 2.14.x (Flutter 2.4.x - 2.5.x)
	{ "9cf77f4405212c45daf608e1cd646852", "2.14.0" },
	{ "659a72e41e3276e882709901c27de33d", "2.14.0" },
	// Dart 2.15.x (Flutter 2.6.x - 2.7.x)
	{ "f10776149bf76be288def3c2ca73bdc1", "2.15.0" },
	{ "24d9d411c2f90c8fbe8907f99e89d4b0", "2.15.0" },
	// Dart 2.16.x (Flutter 2.8.x - 2.16.x)
	{ "d56742caf7b3b3f4bd2df93a9bbb5503", "2.16.0" },
	{ "3318fe66091c0ffbb64faec39976cb7d", "2.16.0" },
	{ "adf563436d12ba0d50ea5beb7f3be1bb", "2.16.0" },
	// Dart 2.17.x (Flutter 2.17.x)
	{ "1441d6b13b8623fa7fbf61433abebd31", "2.17.6" },
	{ "a0cb0c928b23bc17a26e062b351dc44d", "2.17.6" },
	{ "ded6ef11c73fdc638d6ff6d3ad22a67b", "2.17.6" },
	// Dart 2.18.x (Flutter 3.3.x)
	{ "b0e899ec5a90e4661501f0b69e9dd70f", "2.18.0" },
	{ "b6d0a1f034d158b0d37b51d559379697", "2.18.0" },
	{ "8e50e448b241be23b9e990094f4dca39", "2.18.0" },
	{ "6a9b5a03a7e784a4558b10c769f188d9", "2.18.0" },
	// Dart 2.19.x (Flutter 3.7.x)
	{ "adb4292f3ec25074ca70abcd2d5c7251", "2.19.0" },
	{ "501ef5cbd64ca70b6b42672346af6a8a", "2.19.0" },
	// Dart 3.0.x (Flutter 3.10.x - 3.12.x)
	{ "90b56a561f70cd55e972cb49b79b3d8b", "3.0.5" },
	{ "aa64af18e7d086041ac127cc4bc50c5e", "3.0.5" },
	{ "36b0375d284ee2af0d0fffc6e6e48fde", "3.0.5" },
	{ "16ad76edd19b537bf6ea64fdd31977a7", "3.0.5" },
	// Dart 3.1.x (Flutter 3.13.x)
	{ "7dbbeeb8ef7b91338640dca3927636de", "3.1.0" },
	// Dart 3.2.x (Flutter 3.16.x)
	{ "f71c76320d35b65f1164dbaa6d95fe09", "3.2.5" },
	// Dart 3.3.x (Flutter 3.19.x)
	{ "ee1eb666c76a5cb7746faf39d0b97547", "3.3.0" },
	// Dart 3.4.x (Flutter 3.22.x)
	{ "d20a1be77c3d3c41b2a5accaee1ce549", "3.4.3" },
	// Dart 3.5.x (Flutter 3.24.x)
	{ "80a49c7111088100a233b2ae788e1f48", "3.5.0" },
	{ "cda356e9bae476c70de33809fd92e009", "3.5.0" },
	{ "2858c2c0920495f00b9bce9edf6a8cd9", "3.6.2" },
	// Dart 3.6.x (Flutter 3.27.x)
	{ "f956f595844a2f845a55707faaaa51e4", "3.6.2" },
	// Dart 3.7.x (Flutter 3.29.x)
	{ "d91c0e6f35f0eb2e44124e8f42aa44a7", "3.7.0" },
	// Dart 3.8.x (Flutter 3.32.x)
	{ "830f4f59e7969c70b595182826435c19", "3.8.1" },
	// Dart 3.9.x (Flutter 3.35.x)
	{ "97ff04a728735e6b6b098bdf983faaba", "3.9.2" },
	// Dart 3.10.x (Flutter 3.38.x)
	{ "1ce86630892e2dca9a8543fdb8ed8e22", "3.10.7" },
	{ NULL, NULL }
};

// Version profiles with CID tables - based on unflutter's version.go
static const DartVerLayout version_profiles[] = {
	// Dart 2.10.0 - raw int32 tag, 4 header fields, pre-FunctionType split
	{ "", "2.10.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_INT32, 4, 4, 6, 16, 80, 81, 82, 78, 53, 20, 156 },
	// Dart 2.13.0 - raw int32 tag, 5 header fields, split canonical
	{ "", "2.13.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_INT32, 5, 4, 6, 15, 77, 78, 79, 75, 51, 18, 148 },
	// Dart 2.14.0 - shift1 tag, 5 header fields
	{ "", "2.14.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 4, 6, 16, 81, 82, 83, 79, 54, 20, 152 },
	// Dart 2.15.0 - shift1 tag, 5 header fields, NativePointer inserted
	{ "", "2.15.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 5, 7, 17, 82, 83, 84, 79, 55, 21, 153 },
	// Dart 2.16.0 - shift1 tag, 6 header fields, adds ConstMap/ConstSet
	{ "", "2.16.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 6, 5, 7, 17, 84, 85, 86, 81, 55, 21, 154 },
	// Dart 2.17.6 - shift1 tag, 6 header fields
	{ "", "2.17.6", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 6, 5, 7, 17, 89, 90, 91, 86, 59, 21, 158 },
	// Dart 2.18.0 - shift1 tag, 5 header fields, adds SuspendState
	{ "", "2.18.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 5, 7, 17, 90, 91, 92, 87, 59, 21, 159 },
	// Dart 2.19.0 - shift1 tag, 5 header fields, adds RecordType/Record
	{ "", "2.19.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 5, 7, 17, 92, 93, 94, 89, 60, 21, 176 },
	// Dart 3.0.5 - shift1 tag, 5 header fields, adds WeakArray
	{ "", "3.0.5", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 5, 7, 18, 93, 94, 95, 90, 61, 22, 177 },
	// Dart 3.1.0 - shift1 tag, 5 header fields
	{ "", "3.1.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 5, 7, 18, 92, 93, 94, 89, 60, 22, 176 },
	// Dart 3.2.5 - shift1 tag, 5 header fields, PoolType swapped
	{ "", "3.2.5", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 5, 7, 18, 92, 93, 94, 89, 60, 22, 176 },
	// Dart 3.3.0 - shift1 tag, 5 header fields
	{ "", "3.3.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, 5, 7, 18, 92, 93, 94, 89, 60, 22, 176 },
	// Dart 3.4.3 - ObjectHeader tag, 5 header fields
	{ "", "3.4.3", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, 5, 7, 18, 92, 93, 94, 89, 60, 22, 174 },
	// Dart 3.5.0 - ObjectHeader tag, 5 header fields
	{ "", "3.5.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, 5, 7, 18, 92, 93, 94, 89, 60, 22, 174 },
	// Dart 3.6.2 - ObjectHeader tag, 5 header fields
	{ "", "3.6.2", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, 5, 7, 18, 93, 94, 95, 90, 61, 23, 175 },
	// Dart 3.7.0 - ObjectHeader tag, 5 header fields
	{ "", "3.7.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, 5, 7, 18, 93, 94, 95, 90, 61, 23, 175 },
	// Dart 3.8.1 - ObjectHeader tag, 5 header fields
	{ "", "3.8.1", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, 5, 7, 18, 93, 94, 95, 90, 61, 23, 175 },
	// Dart 3.9.2 - ObjectHeader tag, 5 header fields
	{ "", "3.9.2", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, 5, 7, 18, 93, 94, 95, 90, 61, 23, 175 },
	// Dart 3.10.7 - ObjectHeader tag, 5 header fields
	{ "", "3.10.7", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, 5, 7, 18, 93, 94, 95, 90, 61, 23, 175 },
	{ { 0 }, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

const char *dart_version_from_hash(const char *hash) {
	if (!hash) {
		return NULL;
	}
	for (int i = 0; known_hashes[i].hash; i++) {
		if (!strcmp (known_hashes[i].hash, hash)) {
			return known_hashes[i].version;
		}
	}
	return NULL;
}

const DartVerLayout *dart_profile_from_version(const char *version) {
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

DartVerLayout *dart_pick_layout_by_hash(const char *hash) {
	DartVerLayout *dvl = calloc (1, sizeof (DartVerLayout));
	if (!dvl) {
		return NULL;
	}
	const char *version = dart_version_from_hash (hash);
	const DartVerLayout *profile = version? dart_profile_from_version (version): NULL;
	if (profile) {
		memcpy (dvl, profile, sizeof (DartVerLayout));
		if (hash && *hash) {
			strncpy (dvl->hash, hash, 32);
			dvl->hash[32] = '\0';
		}
		if (G_VERBOSE > 0) {
			fprintf (stderr, "[r2flutter] Detected Dart version: %s (hash=%s)\n", profile->dart_version, hash? hash: "(null)");
		}
		return dvl;
	}
	// Default to v3.9.2 layout for unknown hashes
	dvl->compressed_word_size = 4;
	dvl->heap_object_tag = 1;
	dvl->max_alignment = 16;
	dvl->it_cap = 20000;
	dvl->tag_style = DART_TAG_STYLE_OBJECT_HEADER;
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
		fprintf (stderr, "[r2flutter] Unknown snapshot hash, using v3.9.2 defaults (hash=%s)\n", hash? hash: "(null)");
	}
	return dvl;
}

void dart_ver_layout_free(DartVerLayout *layout) {
	free (layout);
}
