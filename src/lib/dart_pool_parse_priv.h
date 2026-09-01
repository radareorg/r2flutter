/* r2flutter - MIT - Copyright 2026 - pancake */

#ifndef R2C_DART_POOL_PARSE_PRIV_H
#define R2C_DART_POOL_PARSE_PRIV_H

#include <r_core.h>
#include "../../include/r2flutter/dart_obf.h"
#include "../../include/r2flutter/dart_pool_parse.h"
#include "../../include/r2flutter/dart_r2.h"
#include "../../include/r2flutter/dart_version.h"

#define DART_SYNTHETIC_PP_BASE 0x100000000ULL

typedef struct {
	DartCtx *ctx;
	ut64 cursor;
	ut64 end;
} ClusterStream;

static inline ut32 dart_cid_from_tags(const DartCtx *ctx, ut64 tags) {
	const DartTagStyle style = ctx && ctx->layout? ctx->layout->tag_style: DART_TAG_STYLE_OBJECT_HEADER;
	switch (style) {
	case DART_TAG_STYLE_CID_INT32:
		return (ut32)tags;
	case DART_TAG_STYLE_CID_SHIFT1:
		return (ut32) (tags >> 1);
	case DART_TAG_STYLE_OBJECT_HEADER:
	default:
		return (ut32) ((tags >> 12) & 0xfffffU);
	}
}

// Which flavour of type a DartTypeInfo holds. Not snapshot class ids: these
// never leave the parser, so they carry no version dependency.
typedef enum {
	DART_TYPE_KIND_TYPE = 1,
	DART_TYPE_KIND_FUNCTION_TYPE,
	DART_TYPE_KIND_TYPE_PARAMETER,
} DartTypeKind;

#define DART_SNAPSHOT_MAGIC 0xdcdcf5f5
#define DART_SNAPSHOT_FIXED_SIZE (4 + 8 + 8)
#define DART_SNAPSHOT_HASH_SIZE 32
#define DART_SNAPSHOT_FEATURES_SCAN_MAX 2048
#define DART_IMAGE_ALIGNMENT 64

static inline ut32 dart_cid_from_object_header(ut64 tags) {
	return (ut32) ((tags >> 12) & 0xfffffU);
}

static inline ut64 dart_snapshot_data_image_base(ut64 snapshot_base, ut64 snapshot_len) {
	return snapshot_base + ((snapshot_len + (DART_IMAGE_ALIGNMENT - 1)) & ~ (DART_IMAGE_ALIGNMENT - 1));
}

typedef struct {
	bool ok;
	ut32 magic;
	ut64 total_len;
	ut64 kind;
	char hash[33];
	char flags[512];
	ut64 nb;
	ut64 no;
	ut64 nc;
	ut64 ncc;
	ut64 field_table_len;
	ut64 itlen;
	ut64 itdata;
	ut64 cluster_start;
} DartSnapshotHeader;

typedef struct {
	ut32 entry_off;
	ut32 unchecked_off;
	ut32 name_off;
	ut32 owner_off;
	ut32 kind_tag_off;
	ut32 class_name_off;
} DartFunctionLayout;

typedef struct {
	char *name;
	char *owner_name;
	ut32 flags;
	ut32 offset;
} DartScannedField;

typedef struct {
	char *name;
	char *owner_name;
	ut64 entry;
	ut32 kind_tag;
} DartScannedMethod;

typedef enum {
	DART_RECOVERY_STRINGS = 1 << 0,
	DART_RECOVERY_CLASSES = 1 << 1,
	DART_RECOVERY_CLASS_FIELDS = 1 << 2,
	DART_RECOVERY_IT = 1 << 3,
	DART_RECOVERY_METHOD_INDEX = 1 << 4,
	DART_RECOVERY_STRING_REFS = 1 << 5,
} DartRecoveryFlags;

typedef struct {
	DartCtx *ctx;
	RList *strings;
	RList *classes;
	RVecDartInstructionTableEntry *it_entries;
	HtPP *string_by_value;
	HtUP *string_by_addr;
	HtPP *class_by_name;
	HtUP *method_by_addr;
} DartRecoveryModel;

typedef struct {
	ut64 base;
	ut64 vaddr;
	ut64 paddr;
	ut64 size;
	ut64 snapshot_base;
	ut64 data_image_base;
	ut64 source_vaddr;
	ut64 source_paddr;
	ut64 cluster_index;
	ut64 pool_ref;
	ut64 pool_index;
	ut64 length;
	ut64 entries_offset;
	ut64 entry_bits_offset;
	int word_size;
	char snapshot_label[16];
	ut8 *image;
} DartPpInfo;

typedef struct {
	bool bits_ok;
	ut64 offset;
	ut64 addr;
	ut64 raw;
	ut64 index;
	ut8 bits;
} DartPpSlotRaw;

typedef struct {
	bool valid;
	ut64 cluster_index;
	ut64 pool_index;
	ut64 pool_ref;
	ut64 length;
	ut64 index;
	ut64 pool_offset;
	ut64 pp_offset;
	ut64 stream_offset;
	ut64 value_offset;
	ut64 ref;
	ut64 raw;
	ut8 bits;
	ut8 type;
	ut8 patch;
	ut8 behavior;
	const char *type_name;
	const char *patch_name;
	const char *behavior_name;
	const char *resolved_kind;
	char *resolved_name;
	int resolved_cid;
	ut64 resolved_code_index;
} ModernPoolSlot;

typedef struct {
	ut64 pp_offset;
	ut64 pool_ref;
	ut64 pool_index;
	ut64 entry_index;
	ut64 target_ref;
	const char *target_kind;
	ut64 field_index;
	ut64 string_ref;
	ut64 string_addr;
	const char *string_value;
} ModernPoolStrRef;

typedef void(*ModernPoolStrRefCb)(const ModernPoolStrRef *info, void *user);

typedef void(*DartInstructionTableEntryCallback)(const DartInstructionTableEntry *entry, void *user);

typedef struct {
	DartCtx *ctx;
	ut64 table_addr;
	ut64 data_image_base;
	ut64 data_image_end;
	ut64 itlen;
	ut64 max_entries;
	bool include_stubs;
	HtUP *sym_by_addr;
	DartPoolFunctionCallback on_fn;
	void *fn_user;
	DartInstructionTableEntryCallback on_it;
	void *it_user;
} DartItEmitRequest;

typedef struct {
	DartCtx *ctx;
	ut64 cluster_start;
	ut64 cluster_end;
	ut64 num_clusters;
	ut64 num_base_objects;
} ModernReq;

typedef struct modern_value_graph_t ModernValueGraph;

typedef struct {
	DartCtx *ctx;
	ut64 cluster_start;
	ut64 cluster_end;
	ut64 num_clusters;
	ut64 num_base_objects;
	int limit;
	int detail;
	const char *r2_scope;
	RStrBuf *sb;
	PJ *pj;
} ModernSummaryReq;

bool read_mem(DartCtx *ctx, ut64 addr, void *buf, int len);
bool read_u32_at(DartCtx *ctx, ut64 addr, ut32 *out);
bool read_u64_at(DartCtx *ctx, ut64 addr, ut64 *out);
bool dart_read_unsigned_at(DartCtx *ctx, ut64 addr, ut64 *out_val, ut64 *out_next);
bool dart_read_unsigned_buf(const ut8 *buf, ut64 size, ut64 pos, ut64 *out_val, ut64 *out_next);
char *dart_utf16le_to_utf8(const ut8 *buf, ut64 size);
bool dart_snapshot_header_read(DartCtx *ctx, ut64 base, DartSnapshotHeader *out);
bool dart_snapshot_header_read_buf(const ut8 *buf, ut64 size, const DartVerLayout *layout, DartSnapshotHeader *out);
DartVerLayout *dart_ctx_init_layout(DartCtx *ctx, DartVerLayout *tmp);
void dart_ctx_fini_layout(DartCtx *ctx, DartVerLayout *owned);
int find_snapshots(DartCtx *ctx);
bool try_read_dart_string(DartCtx *ctx, ut64 addr, char *out, int outsz);
char *try_read_dart_string_dup(DartCtx *ctx, ut64 addr);
void dart_scanned_field_fini(DartScannedField *field);
void dart_scanned_method_fini(DartScannedMethod *method);
HtUP *scan_code_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end);
RList *collect_data_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end);
void collect_data_names_with_r2(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end);

bool dart_recovery_model_load(DartCtx *ctx, DartRecoveryModel *model, int flags);
void dart_recovery_model_fini(DartRecoveryModel *model);
DartStringInfo *dart_recovery_model_string_by_value(DartRecoveryModel *model, const char *value);
DartStringInfo *dart_recovery_model_string_by_addr(DartRecoveryModel *model, ut64 addr);
DartClassInfo *dart_recovery_model_class_by_name(DartRecoveryModel *model, const char *name);
DartMethodInfo *dart_recovery_model_method_by_addr(DartRecoveryModel *model, ut64 addr);

bool cs_read_u8(ClusterStream *s, ut8 *out);
bool cs_read_u32(ClusterStream *s, uint32_t *out);
bool cs_read_unsigned(ClusterStream *s, ut64 *out);
bool cs_read_ref_id(ClusterStream *s, ut64 *out);
bool cs_read_tagged32(ClusterStream *s, ut32 *out);
bool cs_read_tagged64(ClusterStream *s, int64_t *out);
bool cs_read_bytes(ClusterStream *s, ut8 *buf, int len);

void free_dart_string(void *p);
int decode_string_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical);
void skip_generic_cluster(ClusterStream *stream);

bool modern_skip_n_bytes(ClusterStream *s, ut64 len);
bool modern_supported(DartCtx *ctx);
bool modern_emit_summary(const ModernSummaryReq *req);
bool modern_build_pp(const ModernReq *req, DartPpInfo *out);
bool modern_resolve_pp_slot(const ModernReq *req, ut64 pp_off, ModernPoolSlot *out);
void modern_slot_fini(ModernPoolSlot *slot);
ModernValueGraph *modern_value_graph_new(const ModernReq *req, ut64 root_ref);
void modern_value_graph_free(ModernValueGraph *graph);
void modern_value_graph_json(PJ *pj, ModernValueGraph *graph);
void modern_value_graph_text(RStrBuf *sb, ModernValueGraph *graph);
const char *modern_value_graph_root_kind(ModernValueGraph *graph);
bool modern_collect_direct_pool_strrefs(const ModernReq *req, HtUP *pp_offs, ModernPoolStrRefCb cb, void *user);
bool modern_collect_pool_strrefs(const ModernReq *req, HtUP *pp_offs, ModernPoolStrRefCb cb, void *user);
bool modern_extract_pool_strings(const ModernReq *req, RList *strings, HtUP *seen, ut64 *next_ref);
bool modern_scan_names(DartCtx *ctx, ut64 start, ut64 end, ut64 nclusters, ut64 itlen);
bool modern_extract_classes(const ModernReq *req, RList *classes);
DartStringCategory dart_string_classify_value(const char *s);

void init_function_layout(DartCtx *ctx, DartFunctionLayout *fl);
bool read_data_image_field(DartCtx *ctx, ut64 pos, ut64 data_start, ut64 data_end, int fallback_index, bool allow_fallback_name, bool apply_obf, DartScannedField *field);
bool read_data_image_method(DartCtx *ctx, ut64 pos, ut64 data_start, ut64 data_end, const DartFunctionLayout *fl, bool apply_obf, DartScannedMethod *method);
void scan_fields_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end);
void scan_methods_from_data_image(DartCtx *ctx, RList *class_list, ut64 data_start, ut64 data_end);
const char *method_kind_name(uint32_t kind_tag);

int dart_it_emit_linear(const DartItEmitRequest *req);
int dart_it_emit_fixed(const DartItEmitRequest *req);
int dart_it_emit_varint(const DartItEmitRequest *req);

bool dart_resolve_pp_info(DartCtx *ctx, DartPpInfo *info);
bool dart_pp_info_read_slot(const DartPpInfo *info, ut64 offset, DartPpSlotRaw *slot);
void dart_pp_info_fini(DartPpInfo *info);

#endif
