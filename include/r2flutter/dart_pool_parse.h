#ifndef R2C_DART_POOL_PARSE_H
#define R2C_DART_POOL_PARSE_H

#include <stdint.h>
#include <r_vec.h>
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

typedef enum {
	DART_STRING_CAT_UNKNOWN = 0,
	DART_STRING_CAT_APP,
	DART_STRING_CAT_LIBRARY,
	DART_STRING_CAT_RUNTIME
} DartStringCategory;

typedef struct DartStringInfo {
	ut64 ref_id;
	char *value;
	ut32 length;
	ut32 flags;
	ut64 address;
	RList *references;
	DartStringCategory category;
} DartStringInfo;

#define DART_STRING_TWO_BYTE (1 << 0)
#define DART_STRING_CANONICAL (1 << 1)
#define DART_STRING_EXTERNAL (1 << 2)

typedef struct DartStringRef {
	ut64 object_ref;
	ut32 object_type;
	ut32 field_offset;
	char *kind;
	char *object_name;
} DartStringRef;

#define DART_REF_FUNCTION 1
#define DART_REF_CLASS 2
#define DART_REF_FIELD 3
#define DART_REF_LIBRARY 4
#define DART_REF_CODE 5
#define DART_REF_OTHER 0

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

#define DART_FIELD_CONST (1 << 0)
#define DART_FIELD_STATIC (1 << 1)
#define DART_FIELD_FINAL (1 << 2)
#define DART_FIELD_LATE (1 << 10)

typedef struct DartClassInfo {
	ut64 ref_id;
	char *name;
	char *library_name;
	ut64 library_ref;
	ut64 super_class_ref;
	ut64 interfaces_ref;
	char *super_class_name;
	ut32 instance_size;
	ut32 type_argument_offset;
	ut32 num_type_parameters;
	ut32 flags;
	RList *enums;
	RList *fields;
	RList *interfaces;
	RList *methods;
	ut64 name_ref;
} DartClassInfo;

typedef struct DartInterfaceInfo {
	char *name;
	ut64 type_ref;
	ut64 class_ref;
} DartInterfaceInfo;

#define DART_CLASS_ABSTRACT (1 << 0)
#define DART_CLASS_ENUM (1 << 1)
#define DART_CLASS_MIXIN (1 << 2)
#define DART_CLASS_TOPLEVEL (1 << 3)

typedef struct DartTypeInfo {
	ut64 ref_id;
	char *name;
	ut32 kind;
	ut64 type_class_ref;
	ut64 type_args_ref;
	ut64 owner_ref;
	ut64 type_parameters_ref;
	ut64 result_type_ref;
	ut64 parameter_types_ref;
	ut64 named_parameter_names_ref;
	ut32 base;
	ut32 index;
	ut32 packed_parameter_counts;
	ut32 packed_type_parameter_counts;
	ut32 flags;
	RList *type_args;
} DartTypeInfo;

typedef struct DartMethodInfo {
	ut64 ref_id;
	char *name;
	char *owner_name;
	char *signature;
	ut64 owner_ref;
	ut64 name_ref;
	ut64 signature_ref;
	ut64 data_ref;
	ut64 entry_point;
	ut64 code_ref;
	ut64 code_index;
	ut32 kind_tag;
	ut32 flags;
} DartMethodInfo;

typedef struct DartInstructionTableEntry {
	ut64 index;
	ut64 code_index;
	ut64 address;
	ut32 pc_offset;
	ut32 stack_map_offset;
	bool has_code;
	char *name;
} DartInstructionTableEntry;

void dart_instruction_table_entry_fini(DartInstructionTableEntry *ie);
R_VEC_TYPE_WITH_FINI(RVecDartInstructionTableEntry, DartInstructionTableEntry, dart_instruction_table_entry_fini);

typedef void(*DartPoolFunctionCallback)(const char *name, ut64 addr, ut64 size, void *user);

// ============================================================================
// Main API - all functions take DartCtx*
// ============================================================================

int dart_pool_enumerate(DartCtx *ctx, const char *libapp_path, DartPoolFunctionCallback on_fn, void *user, ut64 *out_base, ut64 *out_heap_base);
char *dart_pool_dump_header(DartCtx *ctx, int fmt);
char *dart_pool_dump_header_ext(DartCtx *ctx, int fmt);

// ============================================================================
// Class Extraction API
// ============================================================================

RList *dart_pool_extract_classes(DartCtx *ctx);
char *dart_pool_dump_classes(DartCtx *ctx, int fmt);
int dart_pool_apply_classes_to_core(DartCtx *ctx);

// Free functions
void dart_field_info_free(DartFieldInfo *fi);
void dart_class_info_free(DartClassInfo *ci);
void dart_type_info_free(DartTypeInfo *ti);
void dart_method_info_free(DartMethodInfo *mi);
void dart_class_list_free(RList *list);
void dart_string_info_free(DartStringInfo *si);
void dart_string_ref_free(DartStringRef *sr);

// ============================================================================
// String Extraction API
// ============================================================================

RList *dart_pool_extract_strings(DartCtx *ctx);
char *dart_pool_dump_strings(DartCtx *ctx, int fmt);
void dart_string_list_free(RList *list);
char *dart_pool_dump_xrefs(DartCtx *ctx, int fmt);

// ============================================================================
// InstructionTable extraction API
// ============================================================================

RVecDartInstructionTableEntry *dart_pool_extract_instruction_table(DartCtx *ctx);
char *dart_pool_dump_it(DartCtx *ctx, int fmt);
void dart_instruction_table_entry_free(DartInstructionTableEntry *ie);
void dart_instruction_table_list_free(RVecDartInstructionTableEntry *list);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_POOL_PARSE_H
