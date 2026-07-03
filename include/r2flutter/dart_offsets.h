// Auto-generated from offsets.json by scripts/update-dart-version
// Hash to compressed_word_size lookup table
#ifndef R2C_DART_OFFSETS_H
#define R2C_DART_OFFSETS_H

#include <stdint.h>

// Hash entry: snapshot MD5 hash (32 hex chars) + compressed_word_size
typedef struct {
	const char hash[33];
	int compressed_word_size;
} DartHashEntry;

static const DartHashEntry dart_hash_entries[] = {
	{ "1441d6b13b8623fa7fbf61433abebd31", 4 },  // Dart 2.17.6
	{ "16ad76edd19b537bf6ea64fdd31977a7", 4 },  // Dart 3.0.5
	{ "1ce86630892e2dca9a8543fdb8ed8e22", 4 },  // Dart 3.10.7
	{ "24d9d411c2f90c8fbe8907f99e89d4b0", 8 },  // Dart 2.15.0
	{ "2858c2c0920495f00b9bce9edf6a8cd9", 4 },  // Dart 3.6.2
	{ "3318fe66091c0ffbb64faec39976cb7d", 8 },  // Dart 2.16.0
	{ "34f6eec64e9371856eaaa278ccf56538", 8 },  // Dart 2.13.0
	{ "36b0375d284ee2af0d0fffc6e6e48fde", 4 },  // Dart 3.0.5
	{ "41be3daaabd524b8aa7423bc24584957", 4 },  // Dart 3.12.0
	{ "501ef5cbd64ca70b6b42672346af6a8a", 4 },  // Dart 2.19.0
	{ "659a72e41e3276e882709901c27de33d", 8 },  // Dart 2.14.0
	{ "6a9b5a03a7e784a4558b10c769f188d9", 4 },  // Dart 2.18.0
	{ "78da37fed6bf1489361a312568249f3f", 4 },  // Dart 3.11.5
	{ "7a5b240780941844bae88eca5dbaa7b8", 8 },  // Dart 2.13.0
	{ "7dbbeeb8ef7b91338640dca3927636de", 4 },  // Dart 3.1.3
	{ "80a49c7111088100a233b2ae788e1f48", 4 },  // Dart 3.5.0
	{ "830f4f59e7969c70b595182826435c19", 4 },  // Dart 3.8.1
	{ "8e50e448b241be23b9e990094f4dca39", 4 },  // Dart 2.18.0
	{ "8ee4ef7a67df9845fba331734198a953", 8 },  // Dart 2.10.0
	{ "90b56a561f70cd55e972cb49b79b3d8b", 4 },  // Dart 3.0.5
	{ "97ff04a728735e6b6b098bdf983faaba", 4 },  // Dart 3.9.2
	{ "9cf77f4405212c45daf608e1cd646852", 8 },  // Dart 2.14.0
	{ "a0cb0c928b23bc17a26e062b351dc44d", 4 },  // Dart 2.17.6
	{ "aa64af18e7d086041ac127cc4bc50c5e", 4 },  // Dart 3.0.5
	{ "ace654289f5abc240509fc941453ebc5", 4 },  // Dart 3.12.1
	{ "adb4292f3ec25074ca70abcd2d5c7251", 4 },  // Dart 2.19.0
	{ "adf563436d12ba0d50ea5beb7f3be1bb", 8 },  // Dart 2.16.0
	{ "b0e899ec5a90e4661501f0b69e9dd70f", 4 },  // Dart 2.18.0
	{ "b6d0a1f034d158b0d37b51d559379697", 4 },  // Dart 2.18.0
	{ "cda356e9bae476c70de33809fd92e009", 4 },  // Dart 3.5.0
	{ "d20a1be77c3d3c41b2a5accaee1ce549", 8 },  // Dart 3.4.3
	{ "d56742caf7b3b3f4bd2df93a9bbb5503", 8 },  // Dart 2.16.0
	{ "d91c0e6f35f0eb2e44124e8f42aa44a7", 4 },  // Dart 3.7.0
	{ "ded6ef11c73fdc638d6ff6d3ad22a67b", 4 },  // Dart 2.17.6
	{ "e4a09dbf2bb120fe4674e0576617a0dc", 8 },  // Dart 2.13.0
	{ "ee1eb666c76a5cb7746faf39d0b97547", 4 },  // Dart 3.3.0
	{ "f10776149bf76be288def3c2ca73bdc1", 8 },  // Dart 2.15.0
	{ "f71c76320d35b65f1164dbaa6d95fe09", 8 },  // Dart 3.2.5
	{ "f91b8b03bf7f30a5e983fd19b23d978d", 4 },  // Dart 2.18.2
	{ "f956f595844a2f845a55707faaaa51e4", 4 },  // Dart 3.6.2
};

#define DART_HASH_ENTRIES_COUNT 40

// Default offset arrays (identical across all known Dart versions)
#define DART_DEFAULT_EP_OFFSETS { 8, 24, 16, 32 }
#define DART_DEFAULT_EP_OFFSETS_COUNT 4
#define DART_DEFAULT_OWNER_OFFSETS { 56 }
#define DART_DEFAULT_OWNER_OFFSETS_COUNT 1
#define DART_DEFAULT_NAME_OFFSETS { 24, 8 }
#define DART_DEFAULT_NAME_OFFSETS_COUNT 2

#endif // R2C_DART_OFFSETS_H
