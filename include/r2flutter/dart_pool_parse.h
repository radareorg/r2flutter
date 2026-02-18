// Simple debug controls for the Dart pool/snapshot parser
#ifndef R2C_DART_POOL_PARSE_H
#define R2C_DART_POOL_PARSE_H

#include <stdint.h>

// Forward declarations to avoid including heavy r2 headers
typedef struct r_core_t RCore;
typedef struct r_list_t RList;
typedef uint64_t ut64;
typedef uint32_t ut32;

#ifdef __cplusplus
extern "C" {
#endif

// Controls verbosity of stderr diagnostics (0=quiet, 1=info, 2=debug)
void dart_pool_set_verbose(int level);

// If true, skip emitting ELF/R2 stub FUNC symbols
void dart_pool_set_no_stubs(int on);

// If true, dump snapshot header + clustered header as a single JSON line to stdout
void dart_pool_set_dump_snapshot_json(int on);

// If true, print resolved InstructionTable entries (index + address) to stderr
void dart_pool_set_dump_it(int on);

// Global quiet flag used by helpers to suppress noisy prints
void dart_pool_set_quiet(int on);
int dart_pool_is_quiet(void);

// Optional: print first N functions (addr+name) after loading
void dart_pool_set_dump_fns(int n);
int dart_pool_get_dump_fns(void);

// If true, map generic entries to human-readable names found in data image
void dart_pool_set_use_name_pool(int on);
int dart_pool_get_use_name_pool(void);

// If true, dump class information after loading
void dart_pool_set_dump_classes(int on);
int dart_pool_get_dump_classes(void);

// If true, dump field information for classes
void dart_pool_set_dump_fields(int on);
int dart_pool_get_dump_fields(void);

// ============================================================================
// Class and Field Information Structures
// ============================================================================

// Field information for a Dart class
typedef struct DartFieldInfo {
	char *name;           // field name
	char *type_name;      // type name (e.g., "int", "String", "List<Widget>")
	ut32 offset;          // offset within object instance
	ut32 flags;           // bitfield: static, final, late, const
	ut64 type_ref;        // reference to type object
} DartFieldInfo;

#define DART_FIELD_STATIC  (1 << 0)
#define DART_FIELD_FINAL   (1 << 1)
#define DART_FIELD_LATE    (1 << 2)
#define DART_FIELD_CONST   (1 << 3)

// Class information extracted from Dart snapshot
typedef struct DartClassInfo {
	ut64 ref_id;              // reference ID in snapshot
	char *name;               // class name
	char *library_name;       // library URI (e.g., "package:flutter/widgets.dart")
	ut64 library_ref;         // reference to library object
	ut64 super_class_ref;     // reference to parent class (0 if none/Object)
	char *super_class_name;   // resolved parent class name
	ut32 instance_size;       // size of instance in bytes
	ut32 type_argument_offset;// offset to type arguments (-1 if none)
	ut32 num_type_parameters; // number of generic type parameters
	ut32 flags;               // bitfield: abstract, enum, mixin, etc.
	RList *fields;            // list of DartFieldInfo*
	RList *interfaces;        // list of interface ref IDs (ut64*)
} DartClassInfo;

#define DART_CLASS_ABSTRACT (1 << 0)
#define DART_CLASS_ENUM     (1 << 1)
#define DART_CLASS_MIXIN    (1 << 2)
#define DART_CLASS_TOPLEVEL (1 << 3)

// Type information for generic parameters
typedef struct DartTypeInfo {
	ut64 ref_id;
	char *name;          // type name
	ut32 kind;           // type kind (Type, FunctionType, RecordType, etc.)
	ut64 type_class_ref; // for Type: reference to the class
	RList *type_args;    // list of type argument refs (ut64*)
} DartTypeInfo;

// ============================================================================
// Class Extraction API
// ============================================================================

// Extract all classes from a loaded Dart snapshot
// Returns a list of DartClassInfo* or NULL on error
// Caller must free with dart_class_list_free()
RList *dart_pool_extract_classes(RCore *core);

// Extract fields for a specific class
// Returns a list of DartFieldInfo* or NULL on error
RList *dart_pool_extract_fields(RCore *core, ut64 class_ref);

// Get the class hierarchy (list of ancestor class names) for a class
// Returns a list of char* (class names) from immediate parent to Object
RList *dart_pool_get_class_hierarchy(RCore *core, ut64 class_ref);

// Dump all classes to JSON format
char *dart_pool_dump_classes_json(RCore *core);

// Dump classes with fields and hierarchy to r2 commands
char *dart_pool_dump_classes_r2(RCore *core);

// Free functions
void dart_field_info_free(DartFieldInfo *fi);
void dart_class_info_free(DartClassInfo *ci);
void dart_type_info_free(DartTypeInfo *ti);
void dart_class_list_free(RList *list);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_POOL_PARSE_H
