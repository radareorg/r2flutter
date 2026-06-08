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
	kMintCid = 78,
	kDoubleCid = 79,
	kTypedDataBaseCid = 80,
	kTypeCid = 110,
	kFunctionTypeCid = 111,
	kRecordTypeCid = 112,
	kTypeParametersCid = 113,
	kTypeParameterCid = 114,
	kTypeArgumentsCid = 115,
	kNumPredefinedCids = 128
} DartCid;

typedef struct {
	ut64 ref_id;
	ut64 name_ref;
	ut64 library_ref;
	char *name;
	int instance_size;
} DartClass;

typedef struct {
	ut64 ref_id;
	ut64 name_ref;
	ut64 owner_ref;
	ut64 code_ref;
	ut64 entry_point;
	char *name;
} DartPoolFunction;

#define DART_SNAPSHOT_MAGIC 0xdcdcf5f5
#define DART_SNAPSHOT_FIXED_SIZE (4 + 8 + 8)
#define DART_SNAPSHOT_HASH_SIZE 32
#define DART_SNAPSHOT_FEATURES_SCAN_MAX 2048

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
	char name[128];
	char owner_name[128];
	ut32 flags;
	ut32 offset;
} DartScannedField;

typedef struct {
	char name[128];
	char owner_name[128];
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
} DartModernPoolSlotInfo;

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
} DartModernClusterRequest;

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
} DartModernClusterSummaryRequest;

bool read_mem(DartCtx *ctx, ut64 addr, void *buf, int len);
bool read_u32_at(DartCtx *ctx, ut64 addr, ut32 *out);
bool read_u64_at(DartCtx *ctx, ut64 addr, ut64 *out);
bool dart_read_unsigned_at(DartCtx *ctx, ut64 addr, ut64 *out_val, ut64 *out_next);
bool dart_read_unsigned_buf(const ut8 *buf, ut64 size, ut64 pos, ut64 *out_val, ut64 *out_next);
char *dart_utf16le_to_utf8(const ut8 *buf, ut64 size);
bool dart_snapshot_header_read(DartCtx *ctx, ut64 base, DartSnapshotHeader *out);
bool dart_snapshot_header_read_buf(const ut8 *buf, ut64 size, DartSnapshotHeader *out);
DartVerLayout *dart_ctx_init_layout(DartCtx *ctx, DartVerLayout *tmp);
void dart_ctx_fini_layout(DartCtx *ctx, DartVerLayout *owned);
int find_snapshots(DartCtx *ctx);
bool try_read_dart_string(DartCtx *ctx, ut64 addr, char *out, int outsz);
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
void free_dart_class(void *p);
void free_dart_func(void *p);
int decode_string_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical);
int decode_class_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical);
int decode_function_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, ut64 iso_instr, bool is_canonical);
void skip_generic_cluster(ClusterStream *stream);
int deserialize_clusters(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 iso_instr);
void resolve_names(DartCtx *ctx);

bool modern_skip_n_bytes(ClusterStream *s, ut64 len);
bool dart_modern_is_supported_snapshot(DartCtx *ctx);
bool dart_modern_emit_cluster_summary(const DartModernClusterSummaryRequest *req);
bool dart_modern_build_synthetic_pp(const DartModernClusterRequest *req, ut64 snapshot_base, const char *snapshot_label, ut64 data_image_base, DartPpInfo *out);
bool dart_modern_resolve_pp_slot(const DartModernClusterRequest *req, ut64 pp_offset, DartModernPoolSlotInfo *out);
void dart_modern_pool_slot_info_fini(DartModernPoolSlotInfo *info);
bool dart_modern_extract_object_pool_strings_from_clusters(const DartModernClusterRequest *req, RList *strings, HtUP *seen_refs, ut64 *ref_counter);
bool dart_modern_scan_names_from_clusters(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 itlen);
bool dart_modern_extract_classes_from_clusters(const DartModernClusterRequest *req, RList *class_list);
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
