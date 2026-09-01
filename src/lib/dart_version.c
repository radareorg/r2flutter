/* r2flutter - MIT - Copyright 2026 - pancake */

// Dart SDK version detection and layout profiles
//
// Supported Dart SDK versions: 2.10.0 - 3.12.2
// Based on Dart SDK source tags plus external snapshot-hash references.

#include <r_core.h>
#include "../../include/r2flutter/dart_version.h"

static int G_VERBOSE = 0;

void dart_version_set_verbose(int level) {
	G_VERBOSE = level;
}

static bool parse_dart_version(const char *version, int *major, int *minor, int *patch) {
	char tail = 0;
	return version && sscanf (version, "%d.%d.%d%c", major, minor, patch, &tail) == 3;
}

int dart_version_compare(const char *a, const char *b) {
	int av[3], bv[3];
	if (!parse_dart_version (a, &av[0], &av[1], &av[2]) || !parse_dart_version (b, &bv[0], &bv[1], &bv[2])) {
		return -2;
	}
	for (int i = 0; i < 3; i++) {
		if (av[i] < bv[i]) {
			return -1;
		}
		if (av[i] > bv[i]) {
			return 1;
		}
	}
	return 0;
}

// Known snapshot hashes mapped to Dart SDK versions
// Sources: unflutter version.go, reFlutter enginehash.csv, blutter precompiled SDKs
static const struct {
	const char *hash;
	const char *version;
} known_hashes[] = {
	// Dart 2.10.x
	{ "8ee4ef7a67df9845fba331734198a953", "2.10.0" },
	{ "d979fa911b038a8682e98cc8c8569261", "2.10.0" },
	// Dart 2.12.x
	{ "5b97292b25f0a715613b7a28e0734f77", "2.12.0" },
	{ "e036be9d5df68283e1a043e348fa7ff4", "2.12.0" },
	// Dart 2.13.x
	{ "0c7f1aa25fc597a7b3b9a19ed390afa1", "2.13.0" },
	{ "34f6eec64e9371856eaaa278ccf56538", "2.13.0" },
	{ "7a5b240780941844bae88eca5dbaa7b8", "2.13.0" },
	{ "e4a09dbf2bb120fe4674e0576617a0dc", "2.13.0" },
	// Dart 2.14.x
	{ "659a72e41e3276e882709901c27de33d", "2.14.0" },
	{ "9cf77f4405212c45daf608e1cd646852", "2.14.0" },
	{ "c03fb294bfdaca2b44c552ad35e52d45", "2.14.0" },
	// Dart 2.15.x
	{ "24d9d411c2f90c8fbe8907f99e89d4b0", "2.15.0" },
	{ "7b96ef6dda75bdd1d70be8c2f7cb814e", "2.15.0" },
	{ "f10776149bf76be288def3c2ca73bdc1", "2.15.0" },
	// Dart 2.16.x
	{ "3318fe66091c0ffbb64faec39976cb7d", "2.16.0" },
	{ "6093345773c65683f60c20c8e62cbe4a", "2.16.0" },
	{ "adf563436d12ba0d50ea5beb7f3be1bb", "2.16.0" },
	{ "d56742caf7b3b3f4bd2df93a9bbb5503", "2.16.0" },
	// Dart 2.17.x
	{ "0eb277b50d6ce4069261c69150ce52c9", "2.17.0" },
	{ "1441d6b13b8623fa7fbf61433abebd31", "2.17.6" },
	{ "a0cb0c928b23bc17a26e062b351dc44d", "2.17.6" },
	{ "ded6ef11c73fdc638d6ff6d3ad22a67b", "2.17.6" },
	// Dart 2.18.x
	{ "287683014dfbd311f6400c655c97a26d", "2.18.6" },
	{ "6a9b5a03a7e784a4558b10c769f188d9", "2.18.0" },
	{ "77bd0a83c49bfc555a44a0740f15003a", "2.18.0" },
	{ "8e50e448b241be23b9e990094f4dca39", "2.18.0" },
	{ "b0e899ec5a90e4661501f0b69e9dd70f", "2.18.0" },
	{ "b6d0a1f034d158b0d37b51d559379697", "2.18.0" },
	{ "f91b8b03bf7f30a5e983fd19b23d978d", "2.18.2" },
	// Dart 2.19.x
	{ "501ef5cbd64ca70b6b42672346af6a8a", "2.19.0" },
	{ "adb4292f3ec25074ca70abcd2d5c7251", "2.19.0" },
	{ "afcf461a16dfa5e88f88a2aa68764c99", "2.19.0" },
	{ "e727fae79fb45aac639252a9453b785e", "2.19.1" },
	// Dart 3.0.x
	{ "16ad76edd19b537bf6ea64fdd31977a7", "3.0.5" },
	{ "36b0375d284ee2af0d0fffc6e6e48fde", "3.0.5" },
	{ "617d044d9faa87a98c29f8aad5d2f220", "3.0.3" },
	{ "90b56a561f70cd55e972cb49b79b3d8b", "3.0.5" },
	{ "aa64af18e7d086041ac127cc4bc50c5e", "3.0.5" },
	{ "ce5d37cf26ea4faac543cd216f3b96d1", "3.0.0" },
	// Dart 3.1.x
	{ "5191d02bb1d36a9f8609aa7495894e76", "3.1.0" },
	{ "7dbbeeb8ef7b91338640dca3927636de", "3.1.3" },
	// Dart 3.2.x
	{ "9d6362266b78e4198f784da1a28fd82b", "3.2.0" },
	{ "f71c76320d35b65f1164dbaa6d95fe09", "3.2.5" },
	// Dart 3.3.x
	{ "77b867742ae1ace67fbbb9a9a0d0334e", "3.3.0" },
	{ "ee1eb666c76a5cb7746faf39d0b97547", "3.3.0" },
	// Dart 3.4.x
	{ "d20a1be77c3d3c41b2a5accaee1ce549", "3.4.3" },
	{ "fe53c4fdba846005b70514aec3840296", "3.4.0" },
	// Dart 3.5.x
	{ "71dcc635f2e5dca494525aa13ca9006b", "3.5.0" },
	{ "80a49c7111088100a233b2ae788e1f48", "3.5.0" },
	{ "cda356e9bae476c70de33809fd92e009", "3.5.0" },
	// Dart 3.6.x
	{ "2858c2c0920495f00b9bce9edf6a8cd9", "3.6.2" },
	{ "30c051cb9192f6d6812be3f0b87a6356", "3.6.0" },
	{ "f956f595844a2f845a55707faaaa51e4", "3.6.2" },
	// Dart 3.7.x
	{ "bae16a6858d8c0fe2c437b275eb807cd", "3.7.0" },
	{ "d91c0e6f35f0eb2e44124e8f42aa44a7", "3.7.0" },
	// Dart 3.8.x
	{ "830f4f59e7969c70b595182826435c19", "3.8.1" },
	{ "fa07b8a2d866963d1117ecdcea9287c8", "3.8.0" },
	// Dart 3.9.x
	{ "97ff04a728735e6b6b098bdf983faaba", "3.9.2" },
	// Dart 3.10.x
	{ "1ce86630892e2dca9a8543fdb8ed8e22", "3.10.7" },
	// Dart 3.11.x
	{ "78da37fed6bf1489361a312568249f3f", "3.11.5" },
	// Dart 3.12.x
	{ "41be3daaabd524b8aa7423bc24584957", "3.12.0" },
	{ "ace654289f5abc240509fc941453ebc5", "3.12.1" },
	{ NULL, NULL }
};

// Range-start version profiles. CID tables are generated in dart_cid.c.
static const DartVerLayout version_profiles[] = {
	{ "", "2.10.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_INT32, 4, DART_HEADER_STYLE_210, DART_REF_ENCODING_UNSIGNED, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_DEFERRED_ONLY, 7, 0, true }, // Dart 2.10.0
	{ "", "2.12.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_INT32, 5, DART_HEADER_STYLE_212, DART_REF_ENCODING_UNSIGNED, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_DEFERRED_ONLY, 7, 0, true }, // Dart 2.12.0
	{ "", "2.13.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_INT32, 5, DART_HEADER_STYLE_212, DART_REF_ENCODING_UNSIGNED, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_DEFERRED_ONLY, 7, 0, true }, // Dart 2.13.0
	{ "", "2.14.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_214, DART_REF_ENCODING_UNSIGNED, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 7, 0, true }, // Dart 2.14.0
	{ "", "2.15.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_214, DART_REF_ENCODING_UNSIGNED, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 7, 0, true }, // Dart 2.15.0
	{ "", "2.16.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 6, DART_HEADER_STYLE_216, DART_REF_ENCODING_UNSIGNED, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 7, 0, false }, // Dart 2.16.0
	{ "", "2.17.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 6, DART_HEADER_STYLE_216, DART_REF_ENCODING_UNSIGNED, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 2.17.0
	{ "", "2.18.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 2.18.0
	{ "", "2.18.2", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 2.18.2
	{ "", "2.18.3", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 2.18.3
	{ "", "2.19.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 2.19.0
	{ "", "3.0.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.0.0
	{ "", "3.1.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_LOW7, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.1.0
	{ "", "3.2.0", 8, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_LOW7_SWAPPED, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.2.0
	{ "", "3.3.0", 4, 1, 16, 20000, DART_TAG_STYLE_CID_SHIFT1, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.3.0
	{ "", "3.4.0", 8, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.4.0
	{ "", "3.5.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.5.0
	{ "", "3.6.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.6.0
	{ "", "3.7.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.7.0
	{ "", "3.8.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.8.0
	{ "", "3.9.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.9.0
	{ "", "3.10.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.10.0
	{ "", "3.11.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.11.0
	{ "", "3.12.0", 4, 1, 16, 20000, DART_TAG_STYLE_OBJECT_HEADER, 5, DART_HEADER_STYLE_MODERN, DART_REF_ENCODING_REF_ID128, DART_POOL_ENCODING_MODERN, DART_CODE_ALLOC_STATE_DEFERRED, 6, 0, false }, // Dart 3.12.0
	{ { 0 }, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
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

const DartVerLayout *dart_newest_profile(void) {
	const DartVerLayout *newest = version_profiles;
	for (int i = 0; version_profiles[i].dart_version; i++) {
		newest = &version_profiles[i];
	}
	return newest;
}

const char *dart_version_source_str(int source) {
	switch (source) {
	case DART_VERSION_SOURCE_EXACT:
		return "exact-hash";
	case DART_VERSION_SOURCE_OVERRIDE:
		return "override";
	case DART_VERSION_SOURCE_FINGERPRINT:
		return "fingerprint";
	default:
		return "unknown";
	}
}

const DartVerLayout *dart_profile_from_version(const char *version) {
	if (!version) {
		return NULL;
	}
	const DartVerLayout *best = NULL;
	for (int i = 0; version_profiles[i].dart_version; i++) {
		const int cmp = dart_version_compare (version, version_profiles[i].dart_version);
		if (cmp == -2) {
			return NULL;
		}
		if (cmp < 0) {
			break;
		}
		best = &version_profiles[i];
	}
	return best? best: version_profiles;
}

DartVerLayout *dart_layout_from_hash(const char *hash) {
	DartVerLayout *dvl = R_NEW0 (DartVerLayout);
	const char *version = dart_version_from_hash (hash);
	const DartVerLayout *profile = version? dart_profile_from_version (version): NULL;
	if (profile) {
		memcpy (dvl, profile, sizeof (DartVerLayout));
		if (hash && *hash) {
			r_str_ncpy (dvl->hash, hash, sizeof (dvl->hash));
		}
		if (G_VERBOSE > 0) {
			fprintf (stderr, "[r2flutter] Detected Dart version: %s (hash=%s)\n", profile->dart_version, hash? hash: "(null)");
		}
		return dvl;
	}
	// Unknown hash: fingerprint against the newest known profile. Snapshot
	// formats (CID tables, tag style) only change at release boundaries, so an
	// unlisted git/dev build almost always matches the most recent release; the
	// caller still refines compressed_word_size from the feature flags.
	const DartVerLayout *newest = dart_newest_profile ();
	memcpy (dvl, newest, sizeof (DartVerLayout));
	if (hash && *hash) {
		r_str_ncpy (dvl->hash, hash, sizeof (dvl->hash));
	}
	if (G_VERBOSE > 0) {
		fprintf (stderr, "[r2flutter] Unknown snapshot hash, fingerprinting as newest known profile %s (hash=%s)\n", newest->dart_version, hash? hash: "(null)");
	}
	return dvl;
}

void dart_ver_layout_free(DartVerLayout *layout) {
	free (layout);
}
