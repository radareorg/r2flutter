#ifndef R2C_DART_POOL_PARSE_H
#define R2C_DART_POOL_PARSE_H

#include <stdint.h>
#include "dart_r2.h"

typedef struct r_core_t RCore;
typedef struct r_list_t RList;
typedef uint64_t ut64;
typedef uint32_t ut32;

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// String Information Structures
// ============================================================================

typedef struct DartStringInfo {
	ut64 ref_id;
	char *value;
	ut32 length;
	ut32 flags;
	ut64 address;
	RList *references;
} DartStringInfo;

#define DART_STRING_TWO_BYTE   (1 << 0)
#define DART_STRING_CANONICAL  (1 << 1)
#define DART_STRING_EXTERNAL   (1 << 2)

typedef struct DartStringRef {
	ut64 object_ref;
	ut32 object_type;
	ut32 field_offset;
} DartStringRef;

#define DART_REF_FUNCTION  1
#define DART_REF_CLASS     2
#define DART_REF_FIELD     3
#define DART_REF_LIBRARY   4
#define DART_REF_CODE      5
#define DART_REF_OTHER     0

// ============================================================================
// Class and Field Information Structures
// ============================================================================

typedef struct DartFieldInfo {
	char *name;
	char *type_name;
	ut32 offset;
	ut32 flags;
	ut64 type_ref;
	ut64 ref_id;
	ut64 name_ref;
	ut64 owner_ref;
} DartFieldInfo;

#define DART_FIELD_STATIC  (1 << 0)
#define DART_FIELD_FINAL   (1 << 1)
#define DART_FIELD_LATE    (1 << 2)
#define DART_FIELD_CONST   (1 << 3)

typedef struct DartClassInfo {
	ut64 ref_id;
	char *name;
	char *library_name;
	ut64 library_ref;
	ut64 super_class_ref;
	char *super_class_name;
	ut32 instance_size;
	ut32 type_argument_offset;
	ut32 num_type_parameters;
	ut32 flags;
	RList *fields;
	RList *interfaces;
	ut64 name_ref;
} DartClassInfo;

#define DART_CLASS_ABSTRACT (1 << 0)
#define DART_CLASS_ENUM     (1 << 1)
#define DART_CLASS_MIXIN    (1 << 2)
#define DART_CLASS_TOPLEVEL (1 << 3)

typedef struct DartTypeInfo {
	ut64 ref_id;
	char *name;
	ut32 kind;
	ut64 type_class_ref;
	RList *type_args;
} DartTypeInfo;

// ============================================================================
// Main API - all functions take DartCtx*
// ============================================================================

int dart_pool_enumerate (DartCtx *ctx, const char *libapp_path, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user, unsigned long long *out_base, unsigned long long *out_heap_base);
char *dart_pool_dump_header (DartCtx *ctx);

// ============================================================================
// Class Extraction API
// ============================================================================

RList *dart_pool_extract_classes (DartCtx *ctx);
RList *dart_pool_extract_fields (DartCtx *ctx, ut64 class_ref);
RList *dart_pool_get_class_hierarchy (DartCtx *ctx, ut64 class_ref);
char *dart_pool_dump_classes_json (DartCtx *ctx);
char *dart_pool_dump_classes_r2 (DartCtx *ctx);

// Free functions
void dart_field_info_free (DartFieldInfo *fi);
void dart_class_info_free (DartClassInfo *ci);
void dart_type_info_free (DartTypeInfo *ti);
void dart_class_list_free (RList *list);
void dart_string_info_free (DartStringInfo *si);
void dart_string_ref_free (DartStringRef *sr);

// ============================================================================
// String Extraction API
// ============================================================================

RList *dart_pool_extract_strings (DartCtx *ctx);
char *dart_pool_dump_strings_json (DartCtx *ctx);
char *dart_pool_dump_strings_r2 (DartCtx *ctx);
void dart_string_list_free (RList *list);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_POOL_PARSE_H
