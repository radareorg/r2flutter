/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

typedef enum {
	MODERN_ALLOC_SIMPLE,
	MODERN_ALLOC_CANONICAL_SET,
	MODERN_ALLOC_STRING,
	MODERN_ALLOC_MINT,
	MODERN_ALLOC_ARRAY,
	MODERN_ALLOC_WEAK_ARRAY,
	MODERN_ALLOC_TYPE_ARGUMENTS,
	MODERN_ALLOC_CLASS,
	MODERN_ALLOC_CODE,
	MODERN_ALLOC_OBJECT_POOL,
	MODERN_ALLOC_RODATA,
	MODERN_ALLOC_EXCEPTION_HANDLERS,
	MODERN_ALLOC_CONTEXT,
	MODERN_ALLOC_CONTEXT_SCOPE,
	MODERN_ALLOC_RECORD,
	MODERN_ALLOC_TYPED_DATA,
	MODERN_ALLOC_INSTANCE,
	MODERN_ALLOC_EMPTY,
	MODERN_ALLOC_UNKNOWN,
} ModernAllocKind;

typedef enum {
	MODERN_FILL_NONE,
	MODERN_FILL_REFS,
	MODERN_FILL_CLASS,
	MODERN_FILL_ARRAY,
	MODERN_FILL_WEAK_ARRAY,
	MODERN_FILL_TYPE_ARGUMENTS,
	MODERN_FILL_EXCEPTION_HANDLERS,
	MODERN_FILL_CONTEXT,
	MODERN_FILL_CONTEXT_SCOPE,
	MODERN_FILL_CODE,
	MODERN_FILL_OBJECT_POOL,
	MODERN_FILL_INLINE_BYTES,
	MODERN_FILL_TYPED_DATA,
	MODERN_FILL_RECORD,
	MODERN_FILL_INSTANCE,
	MODERN_FILL_UNKNOWN,
} ModernFillKind;

typedef enum {
	MODERN_SCALAR_UNSIGNED,
	MODERN_SCALAR_TAGGED32,
	MODERN_SCALAR_TAGGED64,
	MODERN_SCALAR_BOOL,
	MODERN_SCALAR_INT8,
	MODERN_SCALAR_UINT8,
	MODERN_SCALAR_REFID,
} ModernScalarOp;

typedef struct {
	ModernFillKind kind;
	int num_refs;
	int name_idx;
	int owner_idx;
	int scalar_count;
	ModernScalarOp scalars[6];
} ModernFillSpec;

typedef struct {
	int cid;
	bool is_canonical;
	bool is_immutable;
	ut64 count;
	ut64 start_ref;
	ut64 main_count;
	ModernAllocKind alloc_kind;
	ModernFillKind fill_kind;
	ut64 tag_offset;
	ut64 alloc_offset;
	ut64 alloc_end;
	ut64 fill_offset;
	ut64 fill_end;
	ut64 alloc_items_total;
	ut64 alloc_items_first;
	ut64 alloc_items_min;
	ut64 alloc_items_max;
	ut64 alloc_items_count;
	ut64 discarded_count;
	bool fill_parsed;
	bool fill_ok;
	int next_field_offset_words;
	ut8 *discarded_codes;
} ModernClusterMeta;

typedef struct {
	const char *op;
	const char *name;
} ModernOpNameMap;

static const ModernOpNameMap modern_op_name_map[] = {
	{ "==", "eq" },
	{ "<", "lt" },
	{ ">", "gt" },
	{ "<=", "lte" },
	{ ">=", "gte" },
	{ "=", "assign" },
	{ "[]", "at" },
	{ "[]=", "at_assign" },
	{ "++", "increment" },
	{ "--", "decrement" },
	{ "+", "add" },
	{ "-", "sub" },
	{ "*", "mul" },
	{ "~/", "div" },
	{ "/", "divf" },
	{ "%", "mod" },
	{ "&", "LAnd" },
	{ "|", "LOr" },
	{ "^", "xor" },
	{ "~", "not" },
	{ ">>", "shr" },
	{ "<<", "shal" },
	{ ">>>", "ushr" },
	{ NULL, NULL }
};

bool dart_modern_is_supported_snapshot(DartCtx *ctx) {
	return ctx && ctx->layout && ctx->layout->tag_style == DART_TAG_STYLE_OBJECT_HEADER && ctx->compressed_word_size == 4;
}

static const char *modern_alloc_kind_name(ModernAllocKind kind) {
	switch (kind) {
	case MODERN_ALLOC_SIMPLE:
		return "simple";
	case MODERN_ALLOC_CANONICAL_SET:
		return "canonical_set";
	case MODERN_ALLOC_STRING:
		return "string";
	case MODERN_ALLOC_MINT:
		return "mint";
	case MODERN_ALLOC_ARRAY:
		return "array";
	case MODERN_ALLOC_WEAK_ARRAY:
		return "weak_array";
	case MODERN_ALLOC_TYPE_ARGUMENTS:
		return "type_arguments";
	case MODERN_ALLOC_CLASS:
		return "class";
	case MODERN_ALLOC_CODE:
		return "code";
	case MODERN_ALLOC_OBJECT_POOL:
		return "object_pool";
	case MODERN_ALLOC_RODATA:
		return "rodata";
	case MODERN_ALLOC_EXCEPTION_HANDLERS:
		return "exception_handlers";
	case MODERN_ALLOC_CONTEXT:
		return "context";
	case MODERN_ALLOC_CONTEXT_SCOPE:
		return "context_scope";
	case MODERN_ALLOC_RECORD:
		return "record";
	case MODERN_ALLOC_TYPED_DATA:
		return "typed_data";
	case MODERN_ALLOC_INSTANCE:
		return "instance";
	case MODERN_ALLOC_EMPTY:
		return "empty";
	case MODERN_ALLOC_UNKNOWN:
	default:
		return "unknown";
	}
}

static const char *modern_fill_kind_name(ModernFillKind kind) {
	switch (kind) {
	case MODERN_FILL_NONE:
		return "none";
	case MODERN_FILL_REFS:
		return "refs";
	case MODERN_FILL_CLASS:
		return "class";
	case MODERN_FILL_ARRAY:
		return "array";
	case MODERN_FILL_WEAK_ARRAY:
		return "weak_array";
	case MODERN_FILL_TYPE_ARGUMENTS:
		return "type_arguments";
	case MODERN_FILL_EXCEPTION_HANDLERS:
		return "exception_handlers";
	case MODERN_FILL_CONTEXT:
		return "context";
	case MODERN_FILL_CONTEXT_SCOPE:
		return "context_scope";
	case MODERN_FILL_CODE:
		return "code";
	case MODERN_FILL_OBJECT_POOL:
		return "object_pool";
	case MODERN_FILL_INLINE_BYTES:
		return "inline_bytes";
	case MODERN_FILL_TYPED_DATA:
		return "typed_data";
	case MODERN_FILL_RECORD:
		return "record";
	case MODERN_FILL_INSTANCE:
		return "instance";
	case MODERN_FILL_UNKNOWN:
	default:
		return "unknown";
	}
}

static void modern_cluster_record_item(ModernClusterMeta *meta, ut64 item) {
	if (!meta->alloc_items_count) {
		meta->alloc_items_first = item;
		meta->alloc_items_min = item;
		meta->alloc_items_max = item;
	} else {
		meta->alloc_items_min = R_MIN (meta->alloc_items_min, item);
		meta->alloc_items_max = R_MAX (meta->alloc_items_max, item);
	}
	meta->alloc_items_total += item;
	meta->alloc_items_count++;
}

static inline int modern_cid_class(DartCtx *ctx) {
	return ctx->layout->cid_class;
}

static inline int modern_cid_function(DartCtx *ctx) {
	return ctx->layout->cid_function;
}

static inline int modern_cid_code(DartCtx *ctx) {
	return ctx->layout->cid_code;
}

static inline int modern_cid_object_pool(DartCtx *ctx) {
	return ctx->layout->cid_object_pool;
}

static inline int modern_cid_string(DartCtx *ctx) {
	return ctx->layout->cid_string;
}

static inline int modern_cid_mint(DartCtx *ctx) {
	return ctx->layout->cid_mint;
}

static inline int modern_cid_double(DartCtx *ctx) {
	return modern_cid_mint (ctx) + 1;
}

static inline int modern_cid_one_byte_string(DartCtx *ctx) {
	return ctx->layout->cid_one_byte_string;
}

static inline int modern_cid_two_byte_string(DartCtx *ctx) {
	return ctx->layout->cid_two_byte_string;
}

static inline int modern_cid_array(DartCtx *ctx) {
	return ctx->layout->cid_array;
}

static inline int modern_cid_immutable_array(DartCtx *ctx) {
	return modern_cid_array (ctx) + 1;
}

static inline int modern_cid_growable_array(DartCtx *ctx) {
	return modern_cid_array (ctx) + 2;
}

static inline int modern_cid_type_arguments(DartCtx *ctx) {
	return modern_cid_array (ctx) - 43;
}

static inline int modern_cid_type(DartCtx *ctx) {
	return modern_cid_type_arguments (ctx) + 2;
}

static inline int modern_cid_function_type(DartCtx *ctx) {
	return modern_cid_type_arguments (ctx) + 3;
}

static inline int modern_cid_record_type(DartCtx *ctx) {
	return modern_cid_type_arguments (ctx) + 4;
}

static inline int modern_cid_type_parameter(DartCtx *ctx) {
	return modern_cid_type_arguments (ctx) + 5;
}

static inline int modern_cid_exception_handlers(DartCtx *ctx) {
	return modern_cid_object_pool (ctx) + 5;
}

static inline int modern_cid_context(DartCtx *ctx) {
	return modern_cid_object_pool (ctx) + 6;
}

static inline int modern_cid_context_scope(DartCtx *ctx) {
	return modern_cid_object_pool (ctx) + 7;
}

static inline int modern_cid_record(DartCtx *ctx) {
	return modern_cid_mint (ctx) + 6;
}

static inline int modern_cid_typed_data(DartCtx *ctx) {
	return modern_cid_string (ctx) - 24;
}

static inline int modern_cid_external_typed_data(DartCtx *ctx) {
	return modern_cid_typed_data (ctx) + 1;
}

static inline int modern_cid_typed_data_view(DartCtx *ctx) {
	return modern_cid_typed_data (ctx) + 2;
}

static inline bool modern_is_string_cid(DartCtx *ctx, int cid) {
	return cid == modern_cid_string (ctx) || cid == modern_cid_one_byte_string (ctx) || cid == modern_cid_two_byte_string (ctx);
}

static inline bool modern_is_array_cid(DartCtx *ctx, int cid) {
	return cid == modern_cid_array (ctx) || cid == modern_cid_immutable_array (ctx);
}

static inline int modern_typed_data_internal_base(DartCtx *ctx) {
	const int predefined_cids = ctx->layout->num_predefined_cids;
	return predefined_cids > 0? predefined_cids - 63: 112;
}

static inline int modern_typed_data_internal_limit(DartCtx *ctx) {
	return modern_typed_data_internal_base (ctx) + (14 * 4);
}

static bool modern_typed_data_internal_kind(DartCtx *ctx, int cid, int *out_rem) {
	int base = modern_typed_data_internal_base (ctx);
	int limit = modern_typed_data_internal_limit (ctx);
	if (cid < base || cid >= limit) {
		return false;
	}
	int rem = (cid - base) % 4;
	if (out_rem) {
		*out_rem = rem;
	}
	return true;
}

static bool modern_is_typed_data_alloc_cid(DartCtx *ctx, int cid) {
	if (cid == 1 || cid == modern_cid_typed_data (ctx)) {
		return true;
	}
	int rem;
	return modern_typed_data_internal_kind (ctx, cid, &rem) && !rem;
}

static bool modern_is_rodata_cid(DartCtx *ctx, int cid) {
	int pc_descriptors = modern_cid_object_pool (ctx) + 1;
	return cid >= pc_descriptors && cid <= pc_descriptors + 2;
}

static int modern_typed_data_element_size(DartCtx *ctx, int cid) {
	if (cid == 1 || cid == modern_cid_typed_data (ctx)) {
		return 1;
	}
	int base = modern_typed_data_internal_base (ctx);
	int limit = modern_typed_data_internal_limit (ctx);
	if (cid < base || cid >= limit) {
		return 1;
	}
	int idx = (cid - base) / 4;
	static const int sizes[] = { 1, 1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 16, 16, 16 };
	if (idx >= 0 && idx < (int) (sizeof (sizes) / sizeof (sizes[0]))) {
		return sizes[idx];
	}
	return 1;
}

static bool modern_is_simple_alloc_cid(int cid) {
	return cid == 46 || cid == 57 || cid == 62 ||
		(cid >= 64 && cid <= 66) ||
		(cid >= 74 && cid <= 81) ||
		(cid >= 83 && cid <= 89) ||
		cid == 92;
}

bool modern_skip_n_bytes(ClusterStream *s, ut64 len) {
	if (!s || s->cursor + len > s->end) {
		return false;
	}
	s->cursor += len;
	return true;
}

static bool modern_skip_scalar(ClusterStream *s, ModernScalarOp op) {
	ut64 uv = 0;
	ut32 u32v = 0;
	int64_t i64v = 0;
	switch (op) {
	case MODERN_SCALAR_UNSIGNED:
		return cs_read_unsigned (s, &uv);
	case MODERN_SCALAR_TAGGED32:
		return cs_read_tagged32 (s, &u32v);
	case MODERN_SCALAR_TAGGED64:
		return cs_read_tagged64 (s, &i64v);
	case MODERN_SCALAR_BOOL:
	case MODERN_SCALAR_INT8:
	case MODERN_SCALAR_UINT8:
		return modern_skip_n_bytes (s, 1);
	case MODERN_SCALAR_REFID:
		return cs_read_ref_id (s, &uv);
	default:
		return false;
	}
}

static bool modern_skip_canonical_set(ClusterStream *s, ut64 count) {
	ut64 table_len = 0;
	ut64 first_element = 0;
	if (!cs_read_unsigned (s, &table_len)) {
		return false;
	}
	if (!cs_read_unsigned (s, &first_element)) {
		return false;
	}
	if (first_element > count) {
		return false;
	}
	for (ut64 i = first_element; i < count; i++) {
		ut64 gap = 0;
		if (!cs_read_unsigned (s, &gap)) {
			return false;
		}
	}
	return true;
}

static ModernAllocKind modern_alloc_kind(DartCtx *ctx, int cid) {
	if (modern_is_string_cid (ctx, cid)) {
		return ctx->compressed_word_size == 8? MODERN_ALLOC_RODATA: MODERN_ALLOC_STRING;
	}
	if (cid == modern_cid_mint (ctx)) {
		return MODERN_ALLOC_MINT;
	}
	if (cid == modern_cid_double (ctx)) {
		return MODERN_ALLOC_SIMPLE;
	}
	if (modern_is_simple_alloc_cid (cid)) {
		return MODERN_ALLOC_SIMPLE;
	}
	if (modern_is_array_cid (ctx, cid)) {
		return MODERN_ALLOC_ARRAY;
	}
	if (cid == 17) {
		return MODERN_ALLOC_WEAK_ARRAY;
	}
	if (cid == modern_cid_type_arguments (ctx)) {
		return MODERN_ALLOC_TYPE_ARGUMENTS;
	}
	if (cid == modern_cid_class (ctx)) {
		return MODERN_ALLOC_CLASS;
	}
	if (cid == modern_cid_code (ctx)) {
		return MODERN_ALLOC_CODE;
	}
	if (cid == modern_cid_object_pool (ctx)) {
		return MODERN_ALLOC_OBJECT_POOL;
	}
	if (modern_is_rodata_cid (ctx, cid)) {
		return MODERN_ALLOC_RODATA;
	}
	if (cid == modern_cid_exception_handlers (ctx)) {
		return MODERN_ALLOC_EXCEPTION_HANDLERS;
	}
	if (cid == modern_cid_context (ctx)) {
		return MODERN_ALLOC_CONTEXT;
	}
	if (cid == modern_cid_context_scope (ctx)) {
		return MODERN_ALLOC_CONTEXT_SCOPE;
	}
	if (cid == modern_cid_record (ctx)) {
		return MODERN_ALLOC_RECORD;
	}
	if (modern_is_typed_data_alloc_cid (ctx, cid)) {
		return MODERN_ALLOC_TYPED_DATA;
	}
	if (cid == modern_cid_type (ctx) || cid == modern_cid_function_type (ctx) || cid == modern_cid_record_type (ctx) || cid == modern_cid_type_parameter (ctx)) {
		return MODERN_ALLOC_CANONICAL_SET;
	}
	if (cid == 16) {
		return MODERN_ALLOC_EMPTY;
	}
	if (cid >= 45) {
		return MODERN_ALLOC_INSTANCE;
	}
	return MODERN_ALLOC_SIMPLE;
}

static bool modern_skip_alloc(ClusterStream *s, DartCtx *ctx, ModernClusterMeta *meta) {
	ut64 count = 0;
	ModernAllocKind kind = modern_alloc_kind (ctx, meta->cid);
	meta->alloc_kind = kind;
	switch (kind) {
	case MODERN_ALLOC_EMPTY:
		meta->count = 0;
		return true;
	case MODERN_ALLOC_SIMPLE:
		if (!cs_read_unsigned (s, &count)) {
			return false;
		}
		meta->count = count;
		return true;
	case MODERN_ALLOC_CANONICAL_SET:
		if (!cs_read_unsigned (s, &count)) {
			return false;
		}
		meta->count = count;
		if (meta->is_canonical) {
			return modern_skip_canonical_set (s, count);
		}
		return true;
	case MODERN_ALLOC_STRING:
		if (!cs_read_unsigned (s, &count)) {
			return false;
		}
		meta->count = count;
		for (ut64 i = 0; i < count; i++) {
			ut64 encoded = 0;
			if (!cs_read_unsigned (s, &encoded)) {
				return false;
			}
			modern_cluster_record_item (meta, encoded >> 1);
		}
		if (meta->is_canonical) {
			return modern_skip_canonical_set (s, count);
		}
		return true;
	case MODERN_ALLOC_MINT:
		if (!cs_read_unsigned (s, &count)) {
			return false;
		}
		meta->count = count;
		for (ut64 i = 0; i < count; i++) {
			int64_t value = 0;
			if (!cs_read_tagged64 (s, &value)) {
				return false;
			}
		}
		return true;
	case MODERN_ALLOC_ARRAY:
	case MODERN_ALLOC_WEAK_ARRAY:
	case MODERN_ALLOC_TYPE_ARGUMENTS:
	case MODERN_ALLOC_OBJECT_POOL:
	case MODERN_ALLOC_RODATA:
	case MODERN_ALLOC_EXCEPTION_HANDLERS:
	case MODERN_ALLOC_CONTEXT:
	case MODERN_ALLOC_CONTEXT_SCOPE:
	case MODERN_ALLOC_RECORD:
	case MODERN_ALLOC_TYPED_DATA:
		if (!cs_read_unsigned (s, &count)) {
			return false;
		}
		meta->count = count;
		for (ut64 i = 0; i < count; i++) {
			ut64 item = 0;
			if (!cs_read_unsigned (s, &item)) {
				return false;
			}
			modern_cluster_record_item (meta, item);
		}
		if ((kind == MODERN_ALLOC_STRING || kind == MODERN_ALLOC_TYPE_ARGUMENTS || kind == MODERN_ALLOC_RODATA) && meta->is_canonical) {
			return modern_skip_canonical_set (s, count);
		}
		return true;
	case MODERN_ALLOC_CLASS:
		{
			ut64 predefined = 0;
			if (!cs_read_unsigned (s, &predefined)) {
				return false;
			}
			const int predefined_cids = ctx->layout->num_predefined_cids;
			if (predefined_cids > 0 && predefined > (ut64)predefined_cids) {
				if (!cs_read_unsigned (s, &predefined)) {
					return false;
				}
			}
			meta->main_count = predefined;
			for (ut64 i = 0; i < predefined; i++) {
				ut32 cidv = 0;
				if (!cs_read_tagged32 (s, &cidv)) {
					return false;
				}
			}
			ut64 new_count = 0;
			if (!cs_read_unsigned (s, &new_count)) {
				return false;
			}
			meta->count = predefined + new_count;
			return true;
		}
	case MODERN_ALLOC_CODE:
		{
			if (!cs_read_unsigned (s, &count)) {
				return false;
			}
			meta->main_count = count;
			meta->discarded_codes = (ut8 *)calloc ((size_t)count + 1, 1);
			for (ut64 i = 0; i < count; i++) {
				ut32 state_bits = 0;
				if (!cs_read_tagged32 (s, &state_bits)) {
					return false;
				}
				if (meta->discarded_codes && ((state_bits >> 3) & 1)) {
					meta->discarded_codes[i] = 1;
					meta->discarded_count++;
				}
			}
			ut64 deferred = 0;
			if (!cs_read_unsigned (s, &deferred)) {
				return false;
			}
			meta->count = count + deferred;
			for (ut64 i = 0; i < deferred; i++) {
				ut32 state_bits = 0;
				if (!cs_read_tagged32 (s, &state_bits)) {
					return false;
				}
			}
			return true;
		}
	case MODERN_ALLOC_INSTANCE:
		{
			ut32 nfo = 0;
			ut32 instance_size = 0;
			if (!cs_read_unsigned (s, &count)) {
				return false;
			}
			meta->count = count;
			if (!cs_read_tagged32 (s, &nfo)) {
				return false;
			}
			if (!cs_read_tagged32 (s, &instance_size)) {
				return false;
			}
			meta->next_field_offset_words = (int)nfo;
			return true;
		}
	case MODERN_ALLOC_UNKNOWN:
	default:
		return false;
	}
}

static ModernFillSpec modern_fill_spec_make(ModernFillKind kind, int num_refs, int name_idx, int owner_idx, int scalar_count, ModernScalarOp a, ModernScalarOp b, ModernScalarOp c, ModernScalarOp d) {
	ModernFillSpec spec = { 0 };
	spec.kind = kind;
	spec.num_refs = num_refs;
	spec.name_idx = name_idx;
	spec.owner_idx = owner_idx;
	spec.scalar_count = scalar_count;
	if (scalar_count > 0) {
		spec.scalars[0] = a;
	}
	if (scalar_count > 1) {
		spec.scalars[1] = b;
	}
	if (scalar_count > 2) {
		spec.scalars[2] = c;
	}
	if (scalar_count > 3) {
		spec.scalars[3] = d;
	}
	return spec;
}

static ModernFillSpec modern_fill_spec_kind(ModernFillKind kind) {
	return modern_fill_spec_make (kind, 0, -1, -1, 0, 0, 0, 0, 0);
}

static ModernFillSpec modern_fill_spec_unknown(void) {
	return modern_fill_spec_kind (MODERN_FILL_UNKNOWN);
}

static ModernFillSpec modern_fill_spec_refs(int num_refs, int name_idx, int owner_idx, int scalar_count, ModernScalarOp a, ModernScalarOp b, ModernScalarOp c, ModernScalarOp d) {
	return modern_fill_spec_make (MODERN_FILL_REFS, num_refs, name_idx, owner_idx, scalar_count, a, b, c, d);
}

typedef struct {
	int cid;
	ModernFillKind kind;
	int num_refs;
	int name_idx;
	int owner_idx;
	int scalar_count;
	ModernScalarOp scalars[4];
} ModernFillSpecRule;

static ModernFillSpec modern_fill_spec_from_rule(const ModernFillSpecRule *rule) {
	return modern_fill_spec_make (rule->kind, rule->num_refs, rule->name_idx, rule->owner_idx, rule->scalar_count, rule->scalars[0], rule->scalars[1], rule->scalars[2], rule->scalars[3]);
}

static ModernFillSpec modern_get_fill_spec(DartCtx *ctx, int cid) {
	if (modern_is_string_cid (ctx, cid)) {
		return modern_fill_spec_kind (MODERN_FILL_NONE);
	}
	if (cid == modern_cid_class (ctx)) {
		return modern_fill_spec_make (MODERN_FILL_CLASS, 13, 0, -1, 0, 0, 0, 0, 0);
	}
	if (cid == modern_cid_function (ctx)) {
		return modern_fill_spec_refs (4, 0, 1, 2, MODERN_SCALAR_UNSIGNED, MODERN_SCALAR_TAGGED32, 0, 0);
	}
	if (cid == modern_cid_mint (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_NONE);
	}
	if (cid == modern_cid_double (ctx)) {
		return modern_fill_spec_refs (0, -1, -1, 1, MODERN_SCALAR_TAGGED64, 0, 0, 0);
	}
	if (cid == modern_cid_code (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_CODE);
	}
	if (cid == modern_cid_object_pool (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_OBJECT_POOL);
	}
	if (modern_is_rodata_cid (ctx, cid)) {
		return modern_fill_spec_kind (MODERN_FILL_INLINE_BYTES);
	}
	if (modern_is_array_cid (ctx, cid)) {
		return modern_fill_spec_kind (MODERN_FILL_ARRAY);
	}
	if (cid == modern_cid_typed_data_view (ctx)) {
		return modern_fill_spec_refs (3, -1, -1, 0, 0, 0, 0, 0);
	}
	if (cid == modern_cid_external_typed_data (ctx)) {
		return modern_fill_spec_refs (1, -1, -1, 0, 0, 0, 0, 0);
	}
	if (cid == modern_cid_typed_data (ctx) || cid == 1) {
		return modern_fill_spec_kind (MODERN_FILL_TYPED_DATA);
	}
	int typed_rem = 0;
	if (modern_typed_data_internal_kind (ctx, cid, &typed_rem)) {
		if (typed_rem == 0) {
			return modern_fill_spec_kind (MODERN_FILL_TYPED_DATA);
		}
		if (typed_rem == 1) {
			return modern_fill_spec_refs (3, -1, -1, 0, 0, 0, 0, 0);
		}
		return modern_fill_spec_refs (1, -1, -1, 0, 0, 0, 0, 0);
	}
	if (cid == modern_cid_growable_array (ctx)) {
		return modern_fill_spec_refs (3, -1, -1, 0, 0, 0, 0, 0);
	}
	if (cid == modern_cid_type_arguments (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_TYPE_ARGUMENTS);
	}
	if (cid == modern_cid_exception_handlers (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_EXCEPTION_HANDLERS);
	}
	if (cid == modern_cid_context (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_CONTEXT);
	}
	if (cid == modern_cid_context_scope (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_CONTEXT_SCOPE);
	}
	if (cid == modern_cid_record (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_RECORD);
	}
	static const ModernFillSpecRule rules[] = {
		{ 6, MODERN_FILL_REFS, 2, -1, -1, 0, { 0 } },
		{ 8, MODERN_FILL_REFS, 4, -1, -1, 0, { 0 } },
		{ 9, MODERN_FILL_REFS, 2, -1, -1, 1, { MODERN_SCALAR_UNSIGNED } },
		{ 10, MODERN_FILL_REFS, 4, -1, -1, 2, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_UINT8 } },
		{ 11, MODERN_FILL_REFS, 4, 0, 1, 2, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_REFID } },
		{ 12, MODERN_FILL_REFS, 1, 0, -1, 1, { MODERN_SCALAR_TAGGED32 } },
		{ 13, MODERN_FILL_REFS, 10, 0, -1, 4, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_INT8, MODERN_SCALAR_UINT8 } },
		{ 14, MODERN_FILL_REFS, 1, -1, -1, 0, { 0 } },
		{ 15, MODERN_FILL_REFS, 9, -1, -1, 0, { 0 } },
		{ 16, MODERN_FILL_REFS, 1, -1, -1, 0, { 0 } },
		{ 17, MODERN_FILL_WEAK_ARRAY, 0, -1, -1, 0, { 0 } },
		{ 24, MODERN_FILL_INLINE_BYTES, 0, -1, -1, 0, { 0 } },
		{ 25, MODERN_FILL_INLINE_BYTES, 0, -1, -1, 0, { 0 } },
		{ 26, MODERN_FILL_INLINE_BYTES, 0, -1, -1, 0, { 0 } },
		{ 28, MODERN_FILL_EXCEPTION_HANDLERS, 0, -1, -1, 0, { 0 } },
		{ 29, MODERN_FILL_CONTEXT, 0, -1, -1, 0, { 0 } },
		{ 30, MODERN_FILL_CONTEXT_SCOPE, 0, -1, -1, 0, { 0 } },
		{ 31, MODERN_FILL_NONE, 0, -1, -1, 0, { 0 } },
		{ 32, MODERN_FILL_REFS, 1, -1, -1, 2, { MODERN_SCALAR_TAGGED64, MODERN_SCALAR_TAGGED64 } },
		{ 33, MODERN_FILL_REFS, 2, 0, -1, 1, { MODERN_SCALAR_BOOL } },
		{ 34, MODERN_FILL_REFS, 0, -1, -1, 2, { MODERN_SCALAR_TAGGED64, MODERN_SCALAR_TAGGED64 } },
		{ 35, MODERN_FILL_REFS, 2, 0, -1, 1, { MODERN_SCALAR_BOOL } },
		{ 36, MODERN_FILL_REFS, 3, -1, -1, 1, { MODERN_SCALAR_TAGGED32 } },
		{ 37, MODERN_FILL_REFS, 4, -1, -1, 1, { MODERN_SCALAR_TAGGED32 } },
		{ 38, MODERN_FILL_REFS, 1, -1, -1, 2, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32 } },
		{ 39, MODERN_FILL_REFS, 1, -1, -1, 1, { MODERN_SCALAR_TAGGED32 } },
		{ 42, MODERN_FILL_REFS, 4, -1, -1, 3, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_BOOL, MODERN_SCALAR_INT8 } },
		{ 43, MODERN_FILL_REFS, 2, -1, -1, 0, { 0 } },
		{ 46, MODERN_FILL_REFS, 2, 0, -1, 2, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_BOOL } },
		{ 47, MODERN_FILL_TYPE_ARGUMENTS, 0, -1, -1, 0, { 0 } },
		{ 48, MODERN_FILL_REFS, 3, -1, -1, 1, { MODERN_SCALAR_UNSIGNED } },
		{ 49, MODERN_FILL_REFS, 3, -1, -1, 1, { MODERN_SCALAR_UNSIGNED } },
		{ 50, MODERN_FILL_REFS, 6, -1, -1, 3, { MODERN_SCALAR_UINT8, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32 } },
		{ 51, MODERN_FILL_REFS, 4, -1, -1, 1, { MODERN_SCALAR_UINT8 } },
		{ 52, MODERN_FILL_REFS, 3, -1, -1, 3, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_UINT8 } },
		{ 57, MODERN_FILL_REFS, 6, -1, -1, 0, { 0 } },
		{ 62, MODERN_FILL_REFS, 0, -1, -1, 1, { MODERN_SCALAR_TAGGED64 } },
		{ 64, MODERN_FILL_REFS, 0, -1, -1, 4, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32 } },
		{ 65, MODERN_FILL_REFS, 0, -1, -1, 4, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32 } },
		{ 66, MODERN_FILL_REFS, 0, -1, -1, 2, { MODERN_SCALAR_TAGGED64, MODERN_SCALAR_TAGGED64 } },
		{ 67, MODERN_FILL_RECORD, 0, -1, -1, 0, { 0 } },
		{ 68, MODERN_FILL_TYPED_DATA, 0, -1, -1, 0, { 0 } },
		{ 74, MODERN_FILL_REFS, 0, -1, -1, 1, { MODERN_SCALAR_TAGGED64 } },
		{ 75, MODERN_FILL_REFS, 1, -1, -1, 1, { MODERN_SCALAR_TAGGED64 } },
		{ 76, MODERN_FILL_REFS, 0, -1, -1, 2, { MODERN_SCALAR_TAGGED64, MODERN_SCALAR_TAGGED64 } },
		{ 77, MODERN_FILL_REFS, 2, -1, -1, 0, { 0 } },
		{ 78, MODERN_FILL_REFS, 2, -1, -1, 1, { MODERN_SCALAR_TAGGED32 } },
		{ 79, MODERN_FILL_REFS, 6, -1, -1, 3, { MODERN_SCALAR_TAGGED32, MODERN_SCALAR_TAGGED32, MODERN_SCALAR_INT8 } },
		{ 80, MODERN_FILL_REFS, 2, -1, -1, 0, { 0 } },
		{ 81, MODERN_FILL_REFS, 2, -1, -1, 0, { 0 } },
		{ 83, MODERN_FILL_REFS, 2, -1, -1, 0, { 0 } },
		{ 84, MODERN_FILL_REFS, 1, 0, -1, 1, { MODERN_SCALAR_TAGGED64 } },
		{ 85, MODERN_FILL_NONE, 0, -1, -1, 0, { 0 } },
		{ 86, MODERN_FILL_REFS, 5, -1, -1, 0, { 0 } },
		{ 87, MODERN_FILL_REFS, 5, -1, -1, 0, { 0 } },
		{ 88, MODERN_FILL_REFS, 5, -1, -1, 0, { 0 } },
		{ 89, MODERN_FILL_REFS, 5, -1, -1, 0, { 0 } },
};
	for (size_t i = 0; i < R_ARRAY_SIZE (rules); i++) {
		if (rules[i].cid == cid) {
			return modern_fill_spec_from_rule (&rules[i]);
		}
	}
	if (cid >= 45) {
		return modern_fill_spec_kind (MODERN_FILL_INSTANCE);
	}
	return modern_fill_spec_unknown ();
}

static bool modern_skip_fill_refs(ClusterStream *s, const ModernClusterMeta *meta, const ModernFillSpec *spec) {
	for (ut64 i = 0; i < meta->count; i++) {
		for (int j = 0; j < spec->num_refs; j++) {
			ut64 ref = 0;
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
		for (int j = 0; j < spec->scalar_count; j++) {
			if (!modern_skip_scalar (s, spec->scalars[j])) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_array(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		ut64 ref = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		if (!cs_read_ref_id (s, &ref)) {
			return false;
		}
		for (ut64 j = 0; j < length; j++) {
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_weak_array(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		ut64 ref = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		for (ut64 j = 0; j < length; j++) {
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_type_arguments(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		ut64 ref = 0;
		ut32 tmp32 = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		if (!cs_read_tagged32 (s, &tmp32)) {
			return false;
		}
		if (!cs_read_unsigned (s, &ref)) {
			return false;
		}
		if (!cs_read_ref_id (s, &ref)) {
			return false;
		}
		for (ut64 j = 0; j < length; j++) {
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_exception_handlers(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 raw = 0;
		ut64 ref = 0;
		ut32 tmp32 = 0;
		if (!cs_read_unsigned (s, &raw)) {
			return false;
		}
		ut64 length = raw >> 1;
		if (!cs_read_ref_id (s, &ref)) {
			return false;
		}
		for (ut64 j = 0; j < length; j++) {
			if (!cs_read_tagged32 (s, &tmp32)) {
				return false;
			}
			if (!cs_read_tagged32 (s, &tmp32)) {
				return false;
			}
			if (!modern_skip_n_bytes (s, 3)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_context(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		ut64 ref = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		if (!cs_read_ref_id (s, &ref)) {
			return false;
		}
		for (ut64 j = 0; j < length; j++) {
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_context_scope(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		ut64 ref = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		if (!modern_skip_n_bytes (s, 1)) {
			return false;
		}
		for (ut64 j = 0; j < length * 7; j++) {
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_inline_bytes(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		if (!modern_skip_n_bytes (s, length)) {
			return false;
		}
	}
	return true;
}

static bool modern_skip_fill_typed_data(ClusterStream *s, DartCtx *ctx, const ModernClusterMeta *meta) {
	int elem_size = modern_typed_data_element_size (ctx, meta->cid);
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		if (!modern_skip_n_bytes (s, length *(ut64)elem_size)) {
			return false;
		}
	}
	return true;
}

static bool modern_skip_fill_record(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 shape = 0;
		ut64 ref = 0;
		if (!cs_read_unsigned (s, &shape)) {
			return false;
		}
		ut64 fields = shape & 0xffffULL;
		for (ut64 j = 0; j < fields; j++) {
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_string(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 encoded = 0;
		if (!cs_read_unsigned (s, &encoded)) {
			return false;
		}
		ut64 length = encoded >> 1;
		bool is_two_byte = (encoded & 1) != 0;
		ut64 nbytes = is_two_byte? length * 2: length;
		if (!modern_skip_n_bytes (s, nbytes)) {
			return false;
		}
	}
	return true;
}

static int modern_target_word_size(DartCtx *ctx) {
	(void)ctx;
	return 8;
}

static ut64 modern_pool_entry_pool_offset(DartCtx *ctx, ut64 index) {
	ut64 word_size = (ut64)modern_target_word_size (ctx);
	return (2 * word_size) - 1 + (index * word_size);
}

static ut64 modern_pool_entry_pp_offset(DartCtx *ctx, ut64 index) {
	return modern_pool_entry_pool_offset (ctx, index) + 1;
}

static bool modern_read_raw_word(ClusterStream *s, DartCtx *ctx, ut64 *out) {
	ut8 buf[8] = { 0 };
	int word_size = modern_target_word_size (ctx);
	if (word_size == 4) {
		if (!cs_read_bytes (s, buf, 4)) {
			return false;
		}
		if (out) {
			*out = r_read_le32 (buf);
		}
		return true;
	}
	if (!cs_read_bytes (s, buf, 8)) {
		return false;
	}
	if (out) {
		*out = r_read_le64 (buf);
	}
	return true;
}

static bool modern_skip_fill_instance(ClusterStream *s, const ModernClusterMeta *meta) {
	ut64 bitmap = 0;
	if (!cs_read_unsigned (s, &bitmap)) {
		return false;
	}
	int header_words = 2;
	int num_fields = meta->next_field_offset_words - header_words;
	if (num_fields < 0) {
		num_fields = 0;
	}
	for (ut64 i = 0; i < meta->count; i++) {
		for (int j = 0; j < num_fields; j++) {
			int field_word_idx = header_words + j;
			bool is_unboxed = ((bitmap >> field_word_idx) & 1ULL) != 0;
			if (is_unboxed) {
				ut32 tmp32 = 0;
				if (!cs_read_tagged32 (s, &tmp32) || !cs_read_tagged32 (s, &tmp32)) {
					return false;
				}
			} else {
				ut64 ref = 0;
				if (!cs_read_ref_id (s, &ref)) {
					return false;
				}
			}
		}
	}
	return true;
}

static bool modern_skip_fill_code(ClusterStream *s, const ModernClusterMeta *meta) {
	const int num_refs = 6;
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 ref = 0;
		if (i < meta->main_count) {
			ut64 payload = 0;
			if (!cs_read_unsigned (s, &payload)) {
				return false;
			}
			if (meta->discarded_codes && meta->discarded_codes[i]) {
				if (!cs_read_ref_id (s, &ref)) {
					return false;
				}
				continue;
			}
		}
		for (int j = 0; j < num_refs; j++) {
			if (!cs_read_ref_id (s, &ref)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_object_pool(ClusterStream *s, const ModernClusterMeta *meta) {
	for (ut64 i = 0; i < meta->count; i++) {
		ut64 length = 0;
		if (!cs_read_unsigned (s, &length)) {
			return false;
		}
		for (ut64 j = 0; j < length; j++) {
			ut8 entry_bits = 0;
			if (!cs_read_u8 (s, &entry_bits)) {
				return false;
			}
			ut8 behavior = entry_bits >> 5;
			ut8 type = entry_bits & 0x0f;
			if (behavior == 0) {
				if (type == 0) {
					int64_t imm = 0;
					if (!cs_read_tagged64 (s, &imm)) {
						return false;
					}
				} else if (type == 1) {
					ut64 ref = 0;
					if (!cs_read_ref_id (s, &ref)) {
						return false;
					}
				} else if (type != 2) {
					return false;
				}
			}
		}
	}
	return true;
}

static bool modern_skip_fill_class(ClusterStream *s, const ModernClusterMeta *meta, const ModernFillSpec *spec) {
	for (ut64 j = 0; j < meta->count; j++) {
		ut32 class_id = 0;
		ut32 tmp32 = 0;
		for (int k = 0; k < spec->num_refs; k++) {
			ut64 rv = 0;
			if (!cs_read_ref_id (s, &rv)) {
				return false;
			}
		}
		if (!cs_read_tagged32 (s, &class_id) || !cs_read_tagged32 (s, &tmp32) || !cs_read_tagged32 (s, &tmp32) || !cs_read_tagged32 (s, &tmp32) || !cs_read_tagged32 (s, &tmp32) || !cs_read_tagged32 (s, &tmp32) || !cs_read_tagged32 (s, &tmp32)) {
			return false;
		}
		bool is_predefined = j < meta->main_count;
		bool is_top_level = class_id >= (1U << 20);
		if (is_predefined || !is_top_level) {
			ut64 bitmap = 0;
			if (!cs_read_unsigned (s, &bitmap)) {
				return false;
			}
		}
	}
	return true;
}

static bool modern_skip_fill_by_kind(ClusterStream *s, DartCtx *ctx, const ModernClusterMeta *meta, const ModernFillSpec *spec) {
	switch (spec->kind) {
	case MODERN_FILL_REFS:
		return modern_skip_fill_refs (s, meta, spec);
	case MODERN_FILL_CLASS:
		return modern_skip_fill_class (s, meta, spec);
	case MODERN_FILL_ARRAY:
		return modern_skip_fill_array (s, meta);
	case MODERN_FILL_WEAK_ARRAY:
		return modern_skip_fill_weak_array (s, meta);
	case MODERN_FILL_TYPE_ARGUMENTS:
		return modern_skip_fill_type_arguments (s, meta);
	case MODERN_FILL_EXCEPTION_HANDLERS:
		return modern_skip_fill_exception_handlers (s, meta);
	case MODERN_FILL_CONTEXT:
		return modern_skip_fill_context (s, meta);
	case MODERN_FILL_CONTEXT_SCOPE:
		return modern_skip_fill_context_scope (s, meta);
	case MODERN_FILL_CODE:
		return modern_skip_fill_code (s, meta);
	case MODERN_FILL_OBJECT_POOL:
		return modern_skip_fill_object_pool (s, meta);
	case MODERN_FILL_INLINE_BYTES:
		return modern_skip_fill_inline_bytes (s, meta);
	case MODERN_FILL_TYPED_DATA:
		return modern_skip_fill_typed_data (s, ctx, meta);
	case MODERN_FILL_RECORD:
		return modern_skip_fill_record (s, meta);
	case MODERN_FILL_INSTANCE:
		return modern_skip_fill_instance (s, meta);
	case MODERN_FILL_NONE:
		return true;
	default:
		return false;
	}
}

static bool modern_read_cluster_tags(ClusterStream *s, DartCtx *ctx, ut32 *out) {
	(void)ctx;
	return cs_read_tagged32 (s, out);
}

static const char *modern_pool_entry_type_name(ut8 type) {
	switch (type) {
	case 0:
		return "immediate";
	case 1:
		return "tagged_object";
	case 2:
		return "native_function";
	case 3:
		return "immediate128";
	default:
		return "unknown";
	}
}

static const char *modern_pool_entry_patch_name(ut8 patch) {
	return patch? "not_patchable": "patchable";
}

static const char *modern_pool_entry_behavior_name(ut8 behavior) {
	switch (behavior) {
	case 0:
		return "snapshotable";
	case 1:
		return "not_snapshotable";
	case 2:
		return "reset_to_bootstrap_native";
	case 3:
		return "reset_to_switchable_call_miss";
	case 4:
		return "set_to_zero";
	default:
		return "unknown";
	}
}

static bool modern_decode_pool_entry(ClusterStream *s, DartCtx *ctx, ut8 type, ut8 behavior, ut64 *out_ref, ut64 *out_raw) {
	if (behavior != 0) {
		return true;
	}
	switch (type) {
	case 0:
		return modern_read_raw_word (s, ctx, out_raw);
	case 1:
		return cs_read_ref_id (s, out_ref);
	case 2:
		return true;
	default:
		return false;
	}
}

static void modern_emit_pool_entry_json(PJ *pj, DartCtx *ctx, ut64 index, ut64 stream_offset, ut64 value_offset, ut8 bits, ut8 type, ut8 patch, ut8 behavior, ut64 ref, ut64 raw) {
	pj_o (pj);
	pj_kn (pj, "index", index);
	pj_kn (pj, "pool_offset", modern_pool_entry_pool_offset (ctx, index));
	pj_kn (pj, "pp_offset", modern_pool_entry_pp_offset (ctx, index));
	pj_kn (pj, "stream_offset", stream_offset);
	pj_kn (pj, "value_offset", value_offset);
	pj_ki (pj, "bits", bits);
	pj_ks (pj, "type", modern_pool_entry_type_name (type));
	pj_ks (pj, "patch", modern_pool_entry_patch_name (patch));
	pj_ks (pj, "behavior", modern_pool_entry_behavior_name (behavior));
	if (behavior == 0 && type == 1) {
		pj_kn (pj, "ref", ref);
	} else if (behavior == 0 && type == 0) {
		pj_kn (pj, "raw", raw);
	}
	pj_end (pj);
}

static void modern_emit_pool_entry_text(RStrBuf *sb, DartCtx *ctx, ut64 index, ut64 stream_offset, ut64 value_offset, ut8 bits, ut8 type, ut8 patch, ut8 behavior, ut64 ref, ut64 raw) {
	r_strbuf_appendf (sb,
		"      [%" PRIu64 "] pool_off=0x%" PFMT64x " pp_off=0x%" PFMT64x " bits=0x%02x type=%s patch=%s behavior=%s stream=0x%" PFMT64x,
		(uint64_t)index,
		(ut64)modern_pool_entry_pool_offset (ctx, index),
		(ut64)modern_pool_entry_pp_offset (ctx, index),
		(unsigned int)bits,
		modern_pool_entry_type_name (type),
		modern_pool_entry_patch_name (patch),
		modern_pool_entry_behavior_name (behavior),
		(ut64)stream_offset);
	if (behavior == 0 && type == 1) {
		r_strbuf_appendf (sb, " value=0x%" PFMT64x " ref=%" PRIu64, (ut64)value_offset, (uint64_t)ref);
	} else if (behavior == 0 && type == 0) {
		r_strbuf_appendf (sb, " value=0x%" PFMT64x " raw=0x%" PFMT64x, (ut64)value_offset, (ut64)raw);
	}
	r_strbuf_append (sb, "\n");
}

static void modern_emit_pool_entry_r2(RStrBuf *sb, const char *scope, ut64 cluster_index, ut64 pool_index, ut64 pool_ref, DartCtx *ctx, ut64 index, ut64 stream_offset, ut64 value_offset, ut8 bits, ut8 type, ut8 patch, ut8 behavior, ut64 ref, ut64 raw) {
	r_strbuf_appendf (sb, "'f dart.%s.cluster.%" PRIu64 ".pool.%" PRIu64 ".entry.%" PRIu64 ".bits = 0x%02x\n", scope, (uint64_t)cluster_index, (uint64_t)pool_index, (uint64_t)index, (unsigned int)bits);
	r_strbuf_appendf (sb,
		"'@0x%" PFMT64x "'CC Dart %s ObjectPool ref=%" PRIu64 " entry=%" PRIu64 " pool_off=0x%" PFMT64x " pp_off=0x%" PFMT64x " type=%s patch=%s behavior=%s",
		(ut64)stream_offset,
		scope,
		(uint64_t)pool_ref,
		(uint64_t)index,
		(ut64)modern_pool_entry_pool_offset (ctx, index),
		(ut64)modern_pool_entry_pp_offset (ctx, index),
		modern_pool_entry_type_name (type),
		modern_pool_entry_patch_name (patch),
		modern_pool_entry_behavior_name (behavior));
	if (behavior == 0 && type == 1) {
		r_strbuf_appendf (sb, " value=0x%" PFMT64x " target_ref=%" PRIu64, (ut64)value_offset, (uint64_t)ref);
	} else if (behavior == 0 && type == 0) {
		r_strbuf_appendf (sb, " value=0x%" PFMT64x " raw=0x%" PFMT64x, (ut64)value_offset, (ut64)raw);
	}
	r_strbuf_append (sb, "\n");
}

static bool modern_emit_object_pool_details(DartCtx *ctx, const ModernClusterMeta *meta, ut64 cluster_index, int limit, const char *r2_scope, RStrBuf *sb, PJ *pj) {
	if (!ctx || !meta || meta->fill_kind != MODERN_FILL_OBJECT_POOL || !meta->fill_parsed || !meta->fill_ok || meta->fill_offset >= meta->fill_end) {
		return false;
	}
	ClusterStream s = {
		.ctx = ctx,
		.cursor = meta->fill_offset,
		.end = meta->fill_end,
};
	bool ok = true;
	if (pj) {
		pj_ka (pj, "object_pools");
	}
	for (ut64 i = 0; i < meta->count && ok; i++) {
		ut64 pool_ref = meta->start_ref + i;
		ut64 pool_stream = s.cursor;
		ut64 length = 0;
		if (!cs_read_unsigned (&s, &length)) {
			ok = false;
			break;
		}
		ut64 emit_count = length;
		if (limit > 0 && (ut64)limit < emit_count) {
			emit_count = (ut64)limit;
		}
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "ref", pool_ref);
			pj_kn (pj, "index", i);
			pj_kn (pj, "length", length);
			pj_kn (pj, "stream_offset", pool_stream);
			pj_ka (pj, "entries");
		} else if (sb && r2_scope) {
			r_strbuf_appendf (sb, "'f dart.%s.cluster.%" PRIu64 ".pool.%" PRIu64 ".length = %" PRIu64 "\n", r2_scope, (uint64_t)cluster_index, (uint64_t)i, (uint64_t)length);
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart %s ObjectPool ref=%" PRIu64 " length=%" PRIu64 "\n", (ut64)pool_stream, r2_scope, (uint64_t)pool_ref, (uint64_t)length);
		} else if (sb) {
			r_strbuf_appendf (sb, "    object_pool ref=%" PRIu64 " index=%" PRIu64 " length=%" PRIu64 " stream=0x%" PFMT64x "\n", (uint64_t)pool_ref, (uint64_t)i, (uint64_t)length, (ut64)pool_stream);
		}
		for (ut64 j = 0; j < length; j++) {
			ut64 entry_stream = s.cursor;
			ut8 bits = 0;
			if (!cs_read_u8 (&s, &bits)) {
				ok = false;
				break;
			}
			ut8 type = bits & 0x0f;
			ut8 patch = (bits >> 4) & 1;
			ut8 behavior = bits >> 5;
			ut64 value_offset = s.cursor;
			ut64 ref = 0;
			ut64 raw = 0;
			if (!modern_decode_pool_entry (&s, ctx, type, behavior, &ref, &raw)) {
				ok = false;
				break;
			}
			if (j >= emit_count) {
				continue;
			}
			if (pj) {
				modern_emit_pool_entry_json (pj, ctx, j, entry_stream, value_offset, bits, type, patch, behavior, ref, raw);
			} else if (sb && r2_scope) {
				modern_emit_pool_entry_r2 (sb, r2_scope, cluster_index, i, pool_ref, ctx, j, entry_stream, value_offset, bits, type, patch, behavior, ref, raw);
			} else if (sb) {
				modern_emit_pool_entry_text (sb, ctx, j, entry_stream, value_offset, bits, type, patch, behavior, ref, raw);
			}
		}
		if (pj) {
			pj_end (pj);
			if (emit_count < length) {
				pj_kn (pj, "entries_omitted", length - emit_count);
			}
			pj_kb (pj, "decode_ok", ok);
			pj_end (pj);
		} else if (sb && !r2_scope && emit_count < length) {
			r_strbuf_appendf (sb, "      ... %" PRIu64 " object pool entries omitted by -l\n", (uint64_t) (length - emit_count));
		} else if (sb && r2_scope && emit_count < length) {
			r_strbuf_appendf (sb, "'# dart.%s.cluster.%" PRIu64 ".pool.%" PRIu64 ".entries.omitted=%" PRIu64 " by -l\n", r2_scope, (uint64_t)cluster_index, (uint64_t)i, (uint64_t) (length - emit_count));
		}
	}
	if (pj) {
		pj_end (pj);
	}
	if (!ok && sb) {
		if (r2_scope) {
			r_strbuf_appendf (sb, "'# Dart %s ObjectPool decode failed near 0x%" PFMT64x "\n", r2_scope, (ut64)s.cursor);
		} else {
			r_strbuf_appendf (sb, "    object_pool_decode: failed near 0x%" PFMT64x "\n", (ut64)s.cursor);
		}
	}
	return ok && s.cursor == meta->fill_end;
}

static const char *modern_object_pool_decode_status(const ModernClusterMeta *meta) {
	if (!meta || meta->alloc_kind != MODERN_ALLOC_OBJECT_POOL) {
		return NULL;
	}
	if (!meta->fill_parsed) {
		return "fill_not_parsed";
	}
	if (!meta->fill_ok) {
		return "fill_failed";
	}
	if (meta->fill_kind != MODERN_FILL_OBJECT_POOL) {
		return "not_object_pool_fill";
	}
	if (!meta->fill_offset || meta->fill_offset >= meta->fill_end) {
		return "empty_fill_range";
	}
	return "decoded";
}

static void modern_emit_object_pool_text_status(RStrBuf *sb, const ModernClusterMeta *meta) {
	const char *status = modern_object_pool_decode_status (meta);
	if (status && strcmp (status, "decoded")) {
		r_strbuf_appendf (sb, "    object_pool_decode: %s\n", status);
	}
}

static void modern_emit_object_pool_r2_status(RStrBuf *sb, const char *scope, ut64 cluster_index, const ModernClusterMeta *meta) {
	const char *status = modern_object_pool_decode_status (meta);
	if (status && strcmp (status, "decoded")) {
		r_strbuf_appendf (sb, "'# dart.%s.cluster.%" PRIu64 ".object_pool_decode=%s\n", scope, (uint64_t)cluster_index, status);
	}
}

static void modern_emit_cluster_json(DartCtx *ctx, PJ *pj, ut64 index, const ModernClusterMeta *meta, int limit, int detail) {
	pj_o (pj);
	pj_kn (pj, "index", index);
	pj_kn (pj, "cid", meta->cid);
	pj_ks (pj, "alloc", modern_alloc_kind_name (meta->alloc_kind));
	pj_ks (pj, "fill", modern_fill_kind_name (meta->fill_kind));
	pj_kb (pj, "canonical", meta->is_canonical);
	pj_kb (pj, "immutable", meta->is_immutable);
	pj_kn (pj, "count", meta->count);
	pj_kn (pj, "ref_start", meta->start_ref);
	pj_kn (pj, "ref_end", meta->start_ref + meta->count);
	pj_kn (pj, "tag_offset", meta->tag_offset);
	pj_kn (pj, "alloc_offset", meta->alloc_offset);
	pj_kn (pj, "alloc_end", meta->alloc_end);
	pj_kn (pj, "fill_offset", meta->fill_offset);
	pj_kn (pj, "fill_end", meta->fill_end);
	pj_ks (pj, "fill_status", meta->fill_parsed? (meta->fill_ok? "ok": "failed"): "not_parsed");
	if (meta->main_count) {
		pj_kn (pj, "main_count", meta->main_count);
	}
	if (meta->discarded_count) {
		pj_kn (pj, "discarded_count", meta->discarded_count);
	}
	if (meta->next_field_offset_words) {
		pj_ki (pj, "next_field_offset_words", meta->next_field_offset_words);
	}
	if (meta->alloc_items_count) {
		pj_k (pj, "items");
		pj_o (pj);
		pj_kn (pj, "count", meta->alloc_items_count);
		pj_kn (pj, "first", meta->alloc_items_first);
		pj_kn (pj, "min", meta->alloc_items_min);
		pj_kn (pj, "max", meta->alloc_items_max);
		pj_kn (pj, "total", meta->alloc_items_total);
		pj_end (pj);
	}
	if (detail >= 3) {
		const char *status = modern_object_pool_decode_status (meta);
		if (status) {
			pj_ks (pj, "object_pool_decode", status);
		}
		if (status && !strcmp (status, "decoded")) {
			(void)modern_emit_object_pool_details (ctx, meta, index, limit, NULL, NULL, pj);
		}
	}
	pj_end (pj);
}

static void modern_emit_cluster_text(DartCtx *ctx, RStrBuf *sb, ut64 index, const ModernClusterMeta *meta, int limit, int detail) {
	r_strbuf_appendf (sb,
		"  %" PRIu64 " cid=%d alloc=%s fill=%s count=%" PRIu64 " refs=%" PRIu64 "..%" PRIu64 " flags=%s%s alloc=0x%" PFMT64x "..0x%" PFMT64x " fill=0x%" PFMT64x "..0x%" PFMT64x,
		(uint64_t)index,
		meta->cid,
		modern_alloc_kind_name (meta->alloc_kind),
		modern_fill_kind_name (meta->fill_kind),
		(uint64_t)meta->count,
		(uint64_t)meta->start_ref,
		(uint64_t) (meta->start_ref + meta->count),
		meta->is_canonical? "canonical": "-",
		meta->is_immutable? ",immutable": "",
		(ut64)meta->alloc_offset,
		(ut64)meta->alloc_end,
		(ut64)meta->fill_offset,
		(ut64)meta->fill_end);
	r_strbuf_appendf (sb, " fill_status=%s", meta->fill_parsed? (meta->fill_ok? "ok": "failed"): "not_parsed");
	if (meta->main_count) {
		r_strbuf_appendf (sb, " main=%" PRIu64, (uint64_t)meta->main_count);
	}
	if (meta->discarded_count) {
		r_strbuf_appendf (sb, " discarded=%" PRIu64, (uint64_t)meta->discarded_count);
	}
	if (meta->next_field_offset_words) {
		r_strbuf_appendf (sb, " next_field_words=%d", meta->next_field_offset_words);
	}
	if (meta->alloc_items_count) {
		r_strbuf_appendf (sb,
			" items=count:%" PRIu64 ",first:%" PRIu64 ",min:%" PRIu64 ",max:%" PRIu64 ",total:%" PRIu64,
			(uint64_t)meta->alloc_items_count,
			(uint64_t)meta->alloc_items_first,
			(uint64_t)meta->alloc_items_min,
			(uint64_t)meta->alloc_items_max,
			(uint64_t)meta->alloc_items_total);
	}
	r_strbuf_append (sb, "\n");
	if (detail >= 3) {
		const char *status = modern_object_pool_decode_status (meta);
		if (status && !strcmp (status, "decoded")) {
			(void)modern_emit_object_pool_details (ctx, meta, index, limit, NULL, sb, NULL);
		} else {
			modern_emit_object_pool_text_status (sb, meta);
		}
	}
}

static void modern_emit_cluster_r2(DartCtx *ctx, RStrBuf *sb, const char *scope, ut64 index, const ModernClusterMeta *meta, int limit, int detail) {
	const char *status = meta->fill_parsed? (meta->fill_ok? "ok": "failed"): "not_parsed";
	ut64 alloc_size = meta->alloc_end > meta->alloc_offset? meta->alloc_end - meta->alloc_offset: 0;
	ut64 fill_size = meta->fill_end > meta->fill_offset? meta->fill_end - meta->fill_offset: 0;
	r_strbuf_appendf (sb, "'f dart.%s.cluster.%" PRIu64 ".tag = 0x%" PFMT64x "\n", scope, (uint64_t)index, (ut64)meta->tag_offset);
	if (alloc_size > 0) {
		r_strbuf_appendf (sb, "'f dart.%s.cluster.%" PRIu64 ".alloc 0x%" PFMT64x " @ 0x%" PFMT64x "\n", scope, (uint64_t)index, (ut64)alloc_size, (ut64)meta->alloc_offset);
	}
	if (fill_size > 0) {
		r_strbuf_appendf (sb, "'f dart.%s.cluster.%" PRIu64 ".fill 0x%" PFMT64x " @ 0x%" PFMT64x "\n", scope, (uint64_t)index, (ut64)fill_size, (ut64)meta->fill_offset);
	}
	r_strbuf_appendf (sb,
		"'@0x%" PFMT64x "'CC Dart %s cluster %" PRIu64 " cid=%d alloc=%s fill=%s count=%" PRIu64 " refs=%" PRIu64 "..%" PRIu64 " fill_status=%s\n",
		(ut64)meta->tag_offset,
		scope,
		(uint64_t)index,
		meta->cid,
		modern_alloc_kind_name (meta->alloc_kind),
		modern_fill_kind_name (meta->fill_kind),
		(uint64_t)meta->count,
		(uint64_t)meta->start_ref,
		(uint64_t) (meta->start_ref + meta->count),
		status);
	if (detail >= 3) {
		const char *pool_status = modern_object_pool_decode_status (meta);
		if (pool_status && !strcmp (pool_status, "decoded")) {
			(void)modern_emit_object_pool_details (ctx, meta, index, limit, scope, sb, NULL);
		} else {
			modern_emit_object_pool_r2_status (sb, scope, index, meta);
		}
	}
}

#define DART_SYNTHETIC_PP_BASE 0x100000000ULL
#define DART_SYNTHETIC_PP_MAX_SIZE (64ULL << 20)

static ut64 modern_align_up(ut64 value, ut64 align) {
	if (!align) {
		return value;
	}
	return (value + align - 1) & ~ (align - 1);
}

static void modern_write_target_word(ut8 *buf, ut64 off, int word_size, ut64 value) {
	if (word_size == 4) {
		r_write_le32 (buf + off, (ut32)value);
		return;
	}
	r_write_le64 (buf + off, value);
}

static ut64 modern_vaddr_to_paddr(DartCtx *ctx, ut64 vaddr) {
	if (!ctx || !ctx->core || !ctx->core->io) {
		return vaddr;
	}
	ut64 paddr = r_io_v2p (ctx->core->io, vaddr);
	return paddr == UT64_MAX? vaddr: paddr;
}

static bool modern_decode_pool_entry_for_pp(ClusterStream *s, ut8 type, ut8 behavior, ut64 *out_ref, ut64 *out_raw);

static bool modern_skip_pool_payload_for_pp(ClusterStream *s) {
	ut64 length = 0;
	if (!cs_read_unsigned (s, &length)) {
		return false;
	}
	for (ut64 j = 0; j < length; j++) {
		ut8 bits = 0;
		if (!cs_read_u8 (s, &bits)) {
			return false;
		}
		ut8 type = bits & 0x0f;
		ut8 behavior = bits >> 5;
		ut64 ref = 0;
		ut64 raw = 0;
		if (!modern_decode_pool_entry_for_pp (s, type, behavior, &ref, &raw)) {
			return false;
		}
		(void)ref;
		(void)raw;
	}
	return true;
}

static bool modern_build_pp_image_from_pool(DartCtx *ctx, const ModernClusterMeta *meta, ut64 cluster_index, ut64 pool_index, ut64 pool_ref, ut64 pool_stream, DartPpInfo *out) {
	if (!ctx || !meta || !out || meta->fill_offset >= meta->fill_end) {
		return false;
	}
	ClusterStream s = {
		.ctx = ctx,
		.cursor = pool_stream,
		.end = meta->fill_end,
};
	ut64 length = 0;
	if (!cs_read_unsigned (&s, &length) || length == 0) {
		return false;
	}
	int word_size = modern_target_word_size (ctx);
	ut64 entries_offset = (ut64)word_size * 2;
	ut64 word_size64 = (ut64)word_size;
	if (length > DART_SYNTHETIC_PP_MAX_SIZE / word_size64) {
		return false;
	}
	ut64 entries_size = length * word_size64;
	ut64 entry_bits_offset = entries_offset + entries_size;
	if (entry_bits_offset < entries_offset || entry_bits_offset > DART_SYNTHETIC_PP_MAX_SIZE || length > DART_SYNTHETIC_PP_MAX_SIZE - entry_bits_offset) {
		return false;
	}
	ut64 image_size = modern_align_up (entry_bits_offset + length, (ut64)word_size);
	if (image_size == 0 || image_size > DART_SYNTHETIC_PP_MAX_SIZE || image_size < entry_bits_offset) {
		return false;
	}
	ut8 *image = (ut8 *)calloc ((size_t)image_size, 1);
	if (!image) {
		return false;
	}
	modern_write_target_word (image, (ut64)word_size, word_size, length);
	for (ut64 j = 0; j < length; j++) {
		ut8 bits = 0;
		if (!cs_read_u8 (&s, &bits)) {
			free (image);
			return false;
		}
		ut8 type = bits & 0x0f;
		ut8 behavior = bits >> 5;
		ut64 ref = 0;
		ut64 raw = 0;
		if (!modern_decode_pool_entry_for_pp (&s, type, behavior, &ref, &raw)) {
			free (image);
			return false;
		}
		(void)ref;
		ut64 value = 0;
		if (behavior == 0 && type == 0) {
			value = raw;
		}
		modern_write_target_word (image, entries_offset + (j *(ut64)word_size), word_size, value);
		image[entry_bits_offset + j] = bits;
	}
	memset (out, 0, sizeof (*out));
	out->base = DART_SYNTHETIC_PP_BASE;
	out->vaddr = DART_SYNTHETIC_PP_BASE;
	out->paddr = modern_vaddr_to_paddr (ctx, pool_stream);
	out->size = image_size;
	out->source_vaddr = pool_stream;
	out->source_paddr = out->paddr;
	out->cluster_index = cluster_index;
	out->pool_ref = pool_ref;
	out->pool_index = pool_index;
	out->length = length;
	out->entries_offset = entries_offset;
	out->entry_bits_offset = entry_bits_offset;
	out->word_size = word_size;
	out->image = image;
	return true;
}

static bool modern_decode_pool_entry_for_pp(ClusterStream *s, ut8 type, ut8 behavior, ut64 *out_ref, ut64 *out_raw) {
	if (out_ref) {
		*out_ref = 0;
	}
	if (out_raw) {
		*out_raw = 0;
	}
	if (behavior != 0) {
		return true;
	}
	if (type == 0) {
		int64_t imm = 0;
		if (!cs_read_tagged64 (s, &imm)) {
			return false;
		}
		if (out_raw) {
			*out_raw = (ut64)imm;
		}
		return true;
	}
	if (type == 1) {
		return cs_read_ref_id (s, out_ref);
	}
	return type == 2;
}

static void modern_cluster_meta_free(ModernClusterMeta *meta, ut64 num_clusters) {
	if (!meta) {
		return;
	}
	for (ut64 i = 0; i < num_clusters; i++) {
		free (meta[i].discarded_codes);
	}
	free (meta);
}

static ModernClusterMeta *modern_parse_cluster_meta(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 num_base_objects) {
	if (!ctx || !ctx->layout || ctx->layout->tag_style != DART_TAG_STYLE_OBJECT_HEADER || cluster_start >= cluster_end || num_clusters == 0 || num_clusters > 100000) {
		return NULL;
	}
	ModernClusterMeta *meta = (ModernClusterMeta *)calloc ((size_t)num_clusters, sizeof (ModernClusterMeta));
	if (!meta) {
		return NULL;
	}
	ClusterStream s = {
		.ctx = ctx,
		.cursor = cluster_start,
		.end = cluster_end,
};
	ut64 next_ref = num_base_objects + 1;
	for (ut64 i = 0; i < num_clusters; i++) {
		ut32 tags = 0;
		meta[i].tag_offset = s.cursor;
		if (!modern_read_cluster_tags (&s, ctx, &tags)) {
			goto fail;
		}
		meta[i].cid = (int) ((tags >> 12) & 0xFFFFF);
		meta[i].is_canonical = ((tags >> 1) & 1) != 0;
		meta[i].is_immutable = (tags & (1 << 6)) != 0;
		meta[i].start_ref = next_ref;
		meta[i].alloc_offset = s.cursor;
		if (!modern_skip_alloc (&s, ctx, &meta[i])) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] cluster summary alloc failed cid=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, (uint64_t)i, s.cursor);
			}
			goto fail;
		}
		meta[i].alloc_end = s.cursor;
		next_ref += meta[i].count;
	}
	for (ut64 i = 0; i < num_clusters; i++) {
		ModernFillSpec spec = modern_get_fill_spec (ctx, meta[i].cid);
		meta[i].fill_kind = spec.kind;
		meta[i].fill_offset = s.cursor;
		bool ok = true;
		if (spec.kind == MODERN_FILL_UNKNOWN && meta[i].count == 0) {
			meta[i].fill_kind = MODERN_FILL_NONE;
		} else {
			ok = modern_is_string_cid (ctx, meta[i].cid) && ctx->compressed_word_size != 8
				? modern_skip_fill_string (&s, &meta[i])
				: modern_skip_fill_by_kind (&s, ctx, &meta[i], &spec);
		}
		meta[i].fill_parsed = true;
		meta[i].fill_ok = ok;
		meta[i].fill_end = s.cursor;
		if (!ok) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] cluster summary fill failed cid=%d kind=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, spec.kind, (uint64_t)i, s.cursor);
			}
			break;
		}
	}
	return meta;
fail:
	modern_cluster_meta_free (meta, num_clusters);
	return NULL;
}

bool dart_modern_emit_cluster_summary(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 num_base_objects, int limit, int detail, const char *r2_scope, RStrBuf *sb, PJ *pj) {
	ModernClusterMeta *meta = modern_parse_cluster_meta (ctx, cluster_start, cluster_end, num_clusters, num_base_objects);
	if (!meta) {
		return false;
	}
	ut64 emit_count = num_clusters;
	if (limit > 0 && (ut64)limit < emit_count) {
		emit_count = (ut64)limit;
	}
	for (ut64 i = 0; i < emit_count; i++) {
		if (pj) {
			modern_emit_cluster_json (ctx, pj, i, &meta[i], limit, detail);
		} else if (sb && r2_scope) {
			modern_emit_cluster_r2 (ctx, sb, r2_scope, i, &meta[i], limit, detail);
		} else if (sb) {
			modern_emit_cluster_text (ctx, sb, i, &meta[i], limit, detail);
		}
	}
	if (sb && emit_count < num_clusters) {
		if (r2_scope) {
			r_strbuf_appendf (sb, "'# dart.%s.clusters.omitted=%" PRIu64 " by -l\n", r2_scope, (uint64_t) (num_clusters - emit_count));
		} else {
			r_strbuf_appendf (sb, "  ... %" PRIu64 " clusters omitted by -l\n", (uint64_t) (num_clusters - emit_count));
		}
	}
	modern_cluster_meta_free (meta, num_clusters);
	return true;
}

bool dart_modern_build_synthetic_pp(DartCtx *ctx, ut64 snapshot_base, const char *snapshot_label, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 num_base_objects, ut64 data_image_base, DartPpInfo *out) {
	if (!out) {
		return false;
	}
	memset (out, 0, sizeof (*out));
	ModernClusterMeta *meta = modern_parse_cluster_meta (ctx, cluster_start, cluster_end, num_clusters, num_base_objects);
	if (!meta) {
		return false;
	}
	bool ok = false;
	for (ut64 i = 0; i < num_clusters && !ok; i++) {
		ModernClusterMeta *m = &meta[i];
		if (m->fill_kind != MODERN_FILL_OBJECT_POOL || !m->fill_parsed || !m->fill_ok || m->fill_offset >= m->fill_end || m->count == 0) {
			continue;
		}
		ClusterStream s = {
			.ctx = ctx,
			.cursor = m->fill_offset,
			.end = m->fill_end,
};
		for (ut64 pool_index = 0; pool_index < m->count && !ok; pool_index++) {
			ut64 pool_stream = s.cursor;
			ok = modern_build_pp_image_from_pool (ctx, m, i, pool_index, m->start_ref + pool_index, pool_stream, out);
			if (ok) {
				out->snapshot_base = snapshot_base;
				out->data_image_base = data_image_base;
				r_str_ncpy (out->snapshot_label, snapshot_label? snapshot_label: "snapshot", sizeof (out->snapshot_label));
				break;
			}
			if (!modern_skip_pool_payload_for_pp (&s)) {
				break;
			}
		}
	}
	modern_cluster_meta_free (meta, num_clusters);
	return ok;
}

static int modern_name_quality(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return 0;
	}
	if (strstr (name, "AnonymousClosure")) {
		return 20;
	}
	if (r_str_startswith (name, "method.")) {
		return 100;
	}
	if (strchr (name, '.')) {
		return 60;
	}
	return 40;
}

static void modern_set_name_for_code_index(DartCtx *ctx, ut64 code_index, char *name) {
	if (!ctx->name_by_code_index || code_index >= ctx->name_by_code_index_count || R_STR_ISEMPTY (name)) {
		free (name);
		return;
	}
	char *old = ctx->name_by_code_index[code_index];
	if (!old || modern_name_quality (name) > modern_name_quality (old) || strlen (name) > strlen (old)) {
		free (old);
		ctx->name_by_code_index[code_index] = name;
		return;
	}
	free (name);
}

static const char *modern_lookup_operator_name(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	for (int i = 0; modern_op_name_map[i].op; i++) {
		if (!strcmp (name, modern_op_name_map[i].op)) {
			return modern_op_name_map[i].name;
		}
	}
	return NULL;
}

static const char *modern_resolve_ref_name(char **strings_by_ref, ut64 *class_name_ref, ut64 *library_name_ref, ut64 *patch_wrapped_ref, ut64 *function_name_ref, ut64 refs_count, ut64 ref, int depth) {
	if (!ref || ref >= refs_count || depth > 8) {
		return NULL;
	}
	if (class_name_ref[ref] && class_name_ref[ref] < refs_count) {
		return strings_by_ref[class_name_ref[ref]];
	}
	if (library_name_ref[ref] && library_name_ref[ref] < refs_count) {
		return strings_by_ref[library_name_ref[ref]];
	}
	if (patch_wrapped_ref[ref]) {
		return modern_resolve_ref_name (strings_by_ref, class_name_ref, library_name_ref, patch_wrapped_ref, function_name_ref, refs_count, patch_wrapped_ref[ref], depth + 1);
	}
	if (function_name_ref[ref] && function_name_ref[ref] < refs_count) {
		return strings_by_ref[function_name_ref[ref]];
	}
	return NULL;
}

static char *modern_build_full_name(DartCtx *ctx, const char *owner_name, const char *method_name) {
	if (R_STR_ISEMPTY (method_name)) {
		return NULL;
	}
	char *owner_dup = owner_name? strdup (owner_name): NULL;
	char *method_dup = strdup (method_name);
	if (owner_dup) {
		dart_obf_apply (ctx, &owner_dup);
		if (!strcmp (owner_dup, "::")) {
			free (owner_dup);
			owner_dup = NULL;
		}
	}
	dart_obf_apply (ctx, &method_dup);
	if (method_dup && !strcmp (method_dup, "AnonymousClosure")) {
		free (method_dup);
		method_dup = strdup ("_anon_closure");
	}
	const char *op_name = modern_lookup_operator_name (method_dup);
	if (op_name) {
		free (method_dup);
		method_dup = r_str_newf ("op_%s", op_name);
	}
	char *full = owner_dup && *owner_dup
		? r_str_newf ("method.%s.%s", owner_dup, method_dup)
		: r_str_newf ("method.%s", method_dup);
	r_name_filter (full, 0);
	free (owner_dup);
	free (method_dup);
	return full;
}

static bool modern_read_cluster_string(ClusterStream *s, char **out) {
	ut64 encoded = 0;
	if (!cs_read_unsigned (s, &encoded)) {
		return false;
	}
	ut64 length = encoded >> 1;
	bool is_two_byte = (encoded & 1) != 0;
	if (length == 0) {
		*out = strdup ("");
		return true;
	}
	if (is_two_byte) {
		ut64 nbytes = length * 2;
		if (nbytes > INT32_MAX) {
			return false;
		}
		ut8 *raw = (ut8 *)calloc ((size_t)nbytes + 1, 1);
		if (!raw || !cs_read_bytes (s, raw, (int)nbytes)) {
			free (raw);
			return false;
		}
		*out = dart_utf16le_to_utf8 (raw, nbytes);
		free (raw);
		return true;
	}
	if (length > INT32_MAX) {
		return false;
	}
	char *value = (char *)calloc ((size_t)length + 1, 1);
	if (!value || !cs_read_bytes (s, (ut8 *)value, (int)length)) {
		free (value);
		return false;
	}
	*out = value;
	return true;
}

static bool modern_load_vm_base_strings(DartCtx *ctx, char **strings_by_ref, ut64 refs_count) {
	if (!ctx->vm_data || refs_count == 0) {
		return false;
	}
	DartSnapshotHeader sh = { 0 };
	if (!dart_snapshot_header_read (ctx, ctx->vm_data, &sh) || !sh.ok || sh.nc == 0 || sh.nc > 10000) {
		return false;
	}
	ut64 cluster_start = sh.cluster_start;
	ut64 cluster_end = ctx->vm_data + sh.total_len;
	if (cluster_start >= cluster_end || sh.no == 0 || sh.no >= refs_count) {
		return false;
	}
	ModernClusterMeta *meta = (ModernClusterMeta *)calloc ((size_t)sh.nc, sizeof (ModernClusterMeta));
	if (!meta) {
		return false;
	}
	ClusterStream s = {
		.ctx = ctx,
		.cursor = cluster_start,
		.end = cluster_end,
};
	ut64 next_ref = sh.nb + 1;
	for (ut64 i = 0; i < sh.nc; i++) {
		ut32 tags = 0;
		if (!cs_read_tagged32 (&s, &tags)) {
			goto fail;
		}
		meta[i].cid = (int) ((tags >> 12) & 0xFFFFF);
		meta[i].is_canonical = ((tags >> 1) & 1) != 0;
		meta[i].is_immutable = (tags & (1 << 6)) != 0;
		meta[i].start_ref = next_ref;
		if (modern_is_string_cid (ctx, meta[i].cid)) {
			ut64 count = 0;
			if (!cs_read_unsigned (&s, &count)) {
				goto fail;
			}
			meta[i].count = count;
			for (ut64 j = 0; j < count; j++) {
				ut64 encoded = 0;
				if (!cs_read_unsigned (&s, &encoded)) {
					goto fail;
				}
			}
		} else if (!modern_skip_alloc (&s, ctx, &meta[i])) {
			goto fail;
		}
		next_ref += meta[i].count;
	}
	for (ut64 i = 0; i < sh.nc; i++) {
		ut64 ref = meta[i].start_ref;
		if (modern_is_string_cid (ctx, meta[i].cid)) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				char *value = NULL;
				if (!modern_read_cluster_string (&s, &value)) {
					goto fail;
				}
				if (ref < refs_count && !strings_by_ref[ref]) {
					strings_by_ref[ref] = value;
				} else {
					free (value);
				}
			}
			continue;
		}
		ModernFillSpec spec = modern_get_fill_spec (ctx, meta[i].cid);
		if (!modern_skip_fill_by_kind (&s, ctx, &meta[i], &spec)) {
			goto fail;
		}
	}
	for (ut64 i = 0; i < sh.nc; i++) {
		free (meta[i].discarded_codes);
	}
	free (meta);
	return true;
fail:
	for (ut64 i = 0; i < sh.nc; i++) {
		free (meta[i].discarded_codes);
	}
	free (meta);
	return false;
}

static bool modern_can_extract_classes(DartCtx *ctx) {
	if (!ctx || !ctx->layout || ctx->layout->tag_style != DART_TAG_STYLE_OBJECT_HEADER) {
		return false;
	}
	return ctx->compressed_word_size == 4;
}

static inline int modern_cid_field(DartCtx *ctx) {
	(void)ctx;
	return 11;
}

static char *modern_dup_ref_name(DartCtx *ctx, char **strings_by_ref, ut64 refs_count, ut64 ref, const char *fallback, ut64 id) {
	char *name = NULL;
	if (ref > 0 && ref < refs_count && R_STR_ISNOTEMPTY (strings_by_ref[ref])) {
		name = strdup (strings_by_ref[ref]);
		dart_obf_apply (ctx, &name);
	}
	if (R_STR_ISEMPTY (name)) {
		free (name);
		name = r_str_newf ("%s_%" PFMT64u, fallback, id);
	}
	return name;
}

static DartClassInfo *modern_class_by_ref(DartClassInfo **class_by_ref, ut64 refs_count, RList *classes, ut64 ref) {
	if (ref > 0 && ref < refs_count && class_by_ref && class_by_ref[ref]) {
		return class_by_ref[ref];
	}
	if (!classes) {
		return NULL;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (classes, it, ci) {
		if (ci && ci->ref_id == ref) {
			return ci;
		}
	}
	return NULL;
}

static void modern_finalize_class_names(DartCtx *ctx, RList *classes, char **strings_by_ref, ut64 refs_count) {
	RListIter *cit;
	DartClassInfo *ci;
	r_list_foreach (classes, cit, ci) {
		if (!ci) {
			continue;
		}
		if (!ci->name) {
			ci->name = modern_dup_ref_name (ctx, strings_by_ref, refs_count, ci->name_ref, "class", ci->ref_id);
		}
		if (ci->fields) {
			RListIter *fit;
			DartFieldInfo *fi;
			r_list_foreach (ci->fields, fit, fi) {
				if (!fi) {
					continue;
				}
				if (!fi->name) {
					fi->name = modern_dup_ref_name (ctx, strings_by_ref, refs_count, fi->name_ref, "field", fi->ref_id);
				}
				if (!fi->type_name) {
					fi->type_name = strdup ("dynamic");
				}
			}
		}
		if (ci->methods) {
			RListIter *mit;
			DartMethodInfo *mi;
			r_list_foreach (ci->methods, mit, mi) {
				if (!mi) {
					continue;
				}
				if (!mi->name) {
					mi->name = modern_dup_ref_name (ctx, strings_by_ref, refs_count, mi->name_ref, "method", mi->ref_id);
				}
				if (!mi->owner_name) {
					mi->owner_name = strdup (ci->name);
				}
			}
		}
	}
}

static bool modern_read_mint_alloc(ClusterStream *s, ModernClusterMeta *meta, int64_t *mint_values, ut8 *mint_ok, ut64 refs_count) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return false;
	}
	if (count > 1000000) {
		return false;
	}
	meta->count = count;
	for (ut64 i = 0; i < count; i++) {
		int64_t value = 0;
		if (!cs_read_tagged64 (s, &value)) {
			return false;
		}
		ut64 ref = meta->start_ref + i;
		if (ref < refs_count) {
			mint_values[ref] = value;
			mint_ok[ref] = 1;
		}
	}
	return true;
}

static bool modern_read_class_fill(DartCtx *ctx, ClusterStream *s, const ModernClusterMeta *meta, RList *classes, DartClassInfo **class_by_ref, ut64 refs_count) {
	const int word_size = ctx->compressed_word_size? ctx->compressed_word_size: 4;
	ut64 ref = meta->start_ref;
	for (ut64 j = 0; j < meta->count; j++, ref++) {
		ut64 refs[13] = { 0 };
		ut32 class_id = 0;
		ut32 instance_size_words = 0;
		ut32 next_field_offset_words = 0;
		ut32 type_args_offset_words = 0;
		ut32 num_type_args = 0;
		ut32 num_native_fields = 0;
		ut32 state_bits = 0;
		for (int k = 0; k < 13; k++) {
			if (!cs_read_ref_id (s, &refs[k])) {
				return false;
			}
		}
		if (!cs_read_tagged32 (s, &class_id) ||
			!cs_read_tagged32 (s, &instance_size_words) ||
			!cs_read_tagged32 (s, &next_field_offset_words) ||
			!cs_read_tagged32 (s, &type_args_offset_words) ||
			!cs_read_tagged32 (s, &num_type_args) ||
			!cs_read_tagged32 (s, &num_native_fields) ||
			!cs_read_tagged32 (s, &state_bits)) {
			return false;
		}
		bool is_predefined = j < meta->main_count;
		bool is_top_level = class_id >= (1U << 20);
		if (is_predefined || !is_top_level) {
			ut64 bitmap = 0;
			if (!cs_read_unsigned (s, &bitmap)) {
				return false;
			}
		}
		(void)next_field_offset_words;
		(void)num_native_fields;
		(void)state_bits;
		DartClassInfo *ci = R_NEW0 (DartClassInfo);
		ci->ref_id = ref;
		ci->name_ref = refs[0];
		ci->instance_size = instance_size_words * word_size;
		ci->type_argument_offset = type_args_offset_words? type_args_offset_words * word_size: 0;
		ci->num_type_parameters = num_type_args;
		if (is_top_level) {
			ci->flags |= DART_CLASS_TOPLEVEL;
		}
		ci->fields = r_list_newf ((RListFree)dart_field_info_free);
		ci->interfaces = r_list_newf (NULL);
		ci->methods = r_list_newf ((RListFree)dart_method_info_free);
		r_list_append (classes, ci);
		if (ref < refs_count) {
			class_by_ref[ref] = ci;
		}
	}
	return true;
}

static void modern_field_flags_from_kind(ut32 kind_bits, ut32 *out_flags) {
	ut32 flags = 0;
	if (kind_bits & (1U << 0)) {
		flags |= DART_FIELD_CONST;
	}
	if (kind_bits & (1U << 1)) {
		flags |= DART_FIELD_STATIC;
	}
	if (kind_bits & (1U << 2)) {
		flags |= DART_FIELD_FINAL;
	}
	if (kind_bits & (1U << 10)) {
		flags |= DART_FIELD_LATE;
	}
	*out_flags = flags;
}

static bool modern_read_field_fill(DartCtx *ctx, ClusterStream *s, const ModernClusterMeta *meta, RList *classes, DartClassInfo **class_by_ref, int64_t *mint_values, ut8 *mint_ok, ut64 refs_count) {
	const int word_size = ctx->compressed_word_size? ctx->compressed_word_size: 4;
	ut64 ref = meta->start_ref;
	for (ut64 j = 0; j < meta->count; j++, ref++) {
		ut64 name_ref = 0;
		ut64 owner_ref = 0;
		ut64 type_ref = 0;
		ut64 initializer_ref = 0;
		ut32 kind_bits = 0;
		ut64 offset_ref = 0;
		if (!cs_read_ref_id (s, &name_ref) ||
			!cs_read_ref_id (s, &owner_ref) ||
			!cs_read_ref_id (s, &type_ref) ||
			!cs_read_ref_id (s, &initializer_ref) ||
			!cs_read_tagged32 (s, &kind_bits) ||
			!cs_read_ref_id (s, &offset_ref)) {
			return false;
		}
		(void)initializer_ref;
		DartClassInfo *owner = modern_class_by_ref (class_by_ref, refs_count, classes, owner_ref);
		if (!owner || !owner->fields) {
			continue;
		}
		DartFieldInfo *fi = R_NEW0 (DartFieldInfo);
		fi->ref_id = ref;
		fi->name_ref = name_ref;
		fi->owner_ref = owner_ref;
		fi->type_ref = type_ref;
		modern_field_flags_from_kind (kind_bits, &fi->flags);
		if (! (fi->flags & DART_FIELD_STATIC) && offset_ref < refs_count && mint_ok[offset_ref]) {
			int64_t word_off = mint_values[offset_ref];
			if (word_off > 0 && word_off < INT32_MAX / word_size) {
				fi->offset = (ut32) (word_off * word_size);
			}
		}
		r_list_append (owner->fields, fi);
	}
	return true;
}

static bool modern_read_function_fill(ClusterStream *s, const ModernClusterMeta *meta, RList *methods) {
	ut64 ref = meta->start_ref;
	for (ut64 j = 0; j < meta->count; j++, ref++) {
		ut64 name_ref = 0;
		ut64 owner_ref = 0;
		ut64 sig_ref = 0;
		ut64 data_ref = 0;
		ut64 code_index = 0;
		ut32 kind_tag = 0;
		if (!cs_read_ref_id (s, &name_ref) ||
			!cs_read_ref_id (s, &owner_ref) ||
			!cs_read_ref_id (s, &sig_ref) ||
			!cs_read_ref_id (s, &data_ref) ||
			!cs_read_unsigned (s, &code_index) ||
			!cs_read_tagged32 (s, &kind_tag)) {
			return false;
		}
		DartMethodInfo *mi = R_NEW0 (DartMethodInfo);
		mi->ref_id = ref;
		mi->name_ref = name_ref;
		mi->owner_ref = owner_ref;
		mi->signature_ref = sig_ref;
		mi->data_ref = data_ref;
		mi->code_index = code_index? code_index - 1: UT64_MAX;
		mi->kind_tag = kind_tag;
		r_list_append (methods, mi);
	}
	return true;
}

static void modern_attach_methods(RList *methods, RList *classes, DartClassInfo **class_by_ref, ut64 refs_count) {
	while (!r_list_empty (methods)) {
		DartMethodInfo *mi = (DartMethodInfo *)r_list_pop_head (methods);
		DartClassInfo *owner = modern_class_by_ref (class_by_ref, refs_count, classes, mi->owner_ref);
		if (owner && owner->methods) {
			r_list_append (owner->methods, mi);
		} else {
			dart_method_info_free (mi);
		}
	}
}

static void modern_free_strings(char **strings_by_ref, ut64 refs_count) {
	if (!strings_by_ref) {
		return;
	}
	for (ut64 i = 0; i < refs_count; i++) {
		free (strings_by_ref[i]);
	}
	free (strings_by_ref);
}

bool dart_modern_extract_classes_from_clusters(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, RList *class_list) {
	if (!modern_can_extract_classes (ctx) || !class_list || cluster_start >= cluster_end || num_clusters == 0 || num_clusters > 100000) {
		return false;
	}
	ut64 total_refs = ctx->num_base_objects + ctx->num_objects + 16;
	ModernClusterMeta *meta = (ModernClusterMeta *)calloc ((size_t)num_clusters, sizeof (ModernClusterMeta));
	char **strings_by_ref = (char **)calloc ((size_t)total_refs, sizeof (char *));
	DartClassInfo **class_by_ref = (DartClassInfo **)calloc ((size_t)total_refs, sizeof (DartClassInfo *));
	int64_t *mint_values = (int64_t *)calloc ((size_t)total_refs, sizeof (int64_t));
	ut8 *mint_ok = (ut8 *)calloc ((size_t)total_refs, 1);
	RList *tmp_classes = r_list_newf ((RListFree)dart_class_info_free);
	RList *tmp_methods = r_list_newf ((RListFree)dart_method_info_free);
	if (!meta || !strings_by_ref || !class_by_ref || !mint_values || !mint_ok) {
		free (meta);
		modern_free_strings (strings_by_ref, total_refs);
		free (class_by_ref);
		free (mint_values);
		free (mint_ok);
		r_list_free (tmp_classes);
		r_list_free (tmp_methods);
		return false;
	}
	modern_load_vm_base_strings (ctx, strings_by_ref, total_refs);
	ClusterStream s = {
		.ctx = ctx,
		.cursor = cluster_start,
		.end = cluster_end,
};
	ut64 next_ref = ctx->num_base_objects + 1;
	for (ut64 i = 0; i < num_clusters; i++) {
		ut32 tags = 0;
		if (!cs_read_tagged32 (&s, &tags)) {
			goto fail;
		}
		meta[i].cid = (int) ((tags >> 12) & 0xFFFFF);
		meta[i].is_canonical = ((tags >> 1) & 1) != 0;
		meta[i].is_immutable = (tags & (1 << 6)) != 0;
		meta[i].start_ref = next_ref;
		if (meta[i].cid == modern_cid_mint (ctx)) {
			if (!modern_read_mint_alloc (&s, &meta[i], mint_values, mint_ok, total_refs)) {
				goto fail;
			}
		} else if (!modern_skip_alloc (&s, ctx, &meta[i])) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] modern classes alloc: failed cid=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, i, s.cursor);
			}
			goto fail;
		}
		next_ref += meta[i].count;
	}
	for (ut64 i = 0; i < num_clusters; i++) {
		ModernFillSpec spec = modern_get_fill_spec (ctx, meta[i].cid);
		ut64 ref = meta[i].start_ref;
		if (modern_is_string_cid (ctx, meta[i].cid)) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				char *value = NULL;
				if (!modern_read_cluster_string (&s, &value)) {
					goto fail;
				}
				if (ref < total_refs) {
					free (strings_by_ref[ref]);
					strings_by_ref[ref] = value;
				} else {
					free (value);
				}
			}
			continue;
		}
		if (spec.kind == MODERN_FILL_CLASS) {
			if (!modern_read_class_fill (ctx, &s, &meta[i], tmp_classes, class_by_ref, total_refs)) {
				goto fail;
			}
			continue;
		}
		if (meta[i].cid == modern_cid_field (ctx)) {
			if (!modern_read_field_fill (ctx, &s, &meta[i], tmp_classes, class_by_ref, mint_values, mint_ok, total_refs)) {
				goto fail;
			}
			continue;
		}
		if (meta[i].cid == modern_cid_function (ctx)) {
			if (!modern_read_function_fill (&s, &meta[i], tmp_methods)) {
				goto fail;
			}
			continue;
		}
		if (!modern_skip_fill_by_kind (&s, ctx, &meta[i], &spec)) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] modern classes fill: failed cid=%d kind=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, spec.kind, i, s.cursor);
			}
			goto fail;
		}
	}
	modern_attach_methods (tmp_methods, tmp_classes, class_by_ref, total_refs);
	modern_finalize_class_names (ctx, tmp_classes, strings_by_ref, total_refs);
	if (r_list_length (tmp_classes) == 0) {
		goto fail;
	}
	while (!r_list_empty (tmp_classes)) {
		DartClassInfo *ci = (DartClassInfo *)r_list_pop_head (tmp_classes);
		r_list_append (class_list, ci);
	}
	for (ut64 i = 0; i < num_clusters; i++) {
		free (meta[i].discarded_codes);
	}
	free (meta);
	modern_free_strings (strings_by_ref, total_refs);
	free (class_by_ref);
	free (mint_values);
	free (mint_ok);
	r_list_free (tmp_classes);
	r_list_free (tmp_methods);
	return true;
fail:
	for (ut64 i = 0; i < num_clusters; i++) {
		free (meta[i].discarded_codes);
	}
	free (meta);
	modern_free_strings (strings_by_ref, total_refs);
	free (class_by_ref);
	free (mint_values);
	free (mint_ok);
	r_list_free (tmp_classes);
	r_list_free (tmp_methods);
	return false;
}

bool dart_modern_scan_names_from_clusters(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 itlen) {
	if (!dart_modern_is_supported_snapshot (ctx) || !itlen || cluster_start >= cluster_end) {
		return false;
	}
	ModernClusterMeta *meta = (ModernClusterMeta *)calloc ((size_t)num_clusters, sizeof (ModernClusterMeta));
	if (!meta) {
		return false;
	}
	ut64 total_refs = ctx->num_base_objects + ctx->num_objects + 16;
	char **strings_by_ref = (char **)calloc ((size_t)total_refs, sizeof (char *));
	ut64 *class_name_ref = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *library_name_ref = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *patch_wrapped_ref = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *function_name_ref = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *function_owner_ref = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *function_data_ref = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *function_code_index = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *closure_parent_ref = (ut64 *)calloc ((size_t)total_refs, sizeof (ut64));
	ut64 *code_owner_ref_by_index = (ut64 *)calloc ((size_t)itlen, sizeof (ut64));
	// Per-slot owner cid: used to distinguish Function/Class/AbstractType/null
	// owners so we can synthesize AllocateXStub / TypeStub / VMStub names
	// instead of letting the name_pool fallback shift every later entry.
	int *code_owner_cid_by_index = (int *)calloc ((size_t)itlen, sizeof (int));
	if (!strings_by_ref || !class_name_ref || !library_name_ref || !patch_wrapped_ref || !function_name_ref || !function_owner_ref || !function_data_ref || !function_code_index || !closure_parent_ref || !code_owner_ref_by_index || !code_owner_cid_by_index) {
		free (meta);
		free (strings_by_ref);
		free (class_name_ref);
		free (library_name_ref);
		free (patch_wrapped_ref);
		free (function_name_ref);
		free (function_owner_ref);
		free (function_data_ref);
		free (function_code_index);
		free (closure_parent_ref);
		free (code_owner_ref_by_index);
		free (code_owner_cid_by_index);
		return false;
	}
	modern_load_vm_base_strings (ctx, strings_by_ref, total_refs);
	ClusterStream s = {
		.ctx = ctx,
		.cursor = cluster_start,
		.end = cluster_end,
};
	ut64 current_cluster = UT64_MAX;
	int current_cid = -1;
	ut64 next_code_index = 0;
	ut64 next_ref = ctx->num_base_objects + 1;
	for (ut64 i = 0; i < num_clusters; i++) {
		current_cluster = i;
		ut32 tags = 0;
		if (!cs_read_tagged32 (&s, &tags)) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] modern alloc: failed reading cluster tag at %" PRIu64 " off=0x%" PFMT64x "\n", i, s.cursor);
			}
			goto fail;
		}
		meta[i].cid = (int) ((tags >> 12) & 0xFFFFF);
		current_cid = meta[i].cid;
		meta[i].is_canonical = ((tags >> 1) & 1) != 0;
		meta[i].is_immutable = (tags & (1 << 6)) != 0;
		meta[i].start_ref = next_ref;
		if (!modern_skip_alloc (&s, ctx, &meta[i])) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] modern alloc: failed skipping cid=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, i, s.cursor);
			}
			goto fail;
		}
		next_ref += meta[i].count;
	}
	if (!ctx->name_by_code_index || ctx->name_by_code_index_count != itlen) {
		if (ctx->name_by_code_index) {
			for (ut64 i = 0; i < ctx->name_by_code_index_count; i++) {
				free (ctx->name_by_code_index[i]);
			}
			free (ctx->name_by_code_index);
		}
		ctx->name_by_code_index = (char **)calloc ((size_t)itlen, sizeof (char *));
		ctx->name_by_code_index_count = itlen;
	}
	if (!ctx->owner_kind_by_code_index || ctx->owner_kind_by_code_index_count != itlen) {
		free (ctx->owner_kind_by_code_index);
		ctx->owner_kind_by_code_index = (ut8 *)calloc ((size_t)itlen, sizeof (ut8));
		ctx->owner_kind_by_code_index_count = itlen;
	} else {
		memset (ctx->owner_kind_by_code_index, 0, (size_t)itlen * sizeof (ut8));
	}
	for (ut64 i = 0; i < num_clusters; i++) {
		current_cluster = i;
		current_cid = meta[i].cid;
		ModernFillSpec spec = modern_get_fill_spec (ctx, meta[i].cid);
		ut64 ref = meta[i].start_ref;
		if (modern_is_string_cid (ctx, meta[i].cid)) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				char *value = NULL;
				if (!modern_read_cluster_string (&s, &value)) {
					if (ctx->verbose > 0) {
						fprintf (stderr, "[r2flutter] modern fill: failed string cid=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, i, s.cursor);
					}
					goto fail;
				}
				strings_by_ref[ref] = value;
			}
			continue;
		}
		if (spec.kind == MODERN_FILL_CLASS) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				ut64 name_ref = 0;
				ut32 class_id = 0;
				ut32 tmp32 = 0;
				for (int k = 0; k < spec.num_refs; k++) {
					ut64 rv = 0;
					if (!cs_read_ref_id (&s, &rv)) {
						goto fail;
					}
					if (k == 0) {
						name_ref = rv;
					}
				}
				if (!cs_read_tagged32 (&s, &class_id) || !cs_read_tagged32 (&s, &tmp32) || !cs_read_tagged32 (&s, &tmp32) || !cs_read_tagged32 (&s, &tmp32) || !cs_read_tagged32 (&s, &tmp32) || !cs_read_tagged32 (&s, &tmp32) || !cs_read_tagged32 (&s, &tmp32)) {
					goto fail;
				}
				bool is_predefined = j < meta[i].main_count;
				bool is_top_level = class_id >= (1U << 20);
				if (is_predefined || !is_top_level) {
					ut64 bitmap = 0;
					if (!cs_read_unsigned (&s, &bitmap)) {
						goto fail;
					}
				}
				class_name_ref[ref] = name_ref;
			}
			continue;
		}
		if (meta[i].cid == modern_cid_function (ctx)) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				ut64 name_ref = 0;
				ut64 owner_ref = 0;
				ut64 sig_ref = 0;
				ut64 data_ref = 0;
				ut64 code_index = 0;
				ut32 kind_tag = 0;
				if (!cs_read_ref_id (&s, &name_ref) || !cs_read_ref_id (&s, &owner_ref) || !cs_read_ref_id (&s, &sig_ref) || !cs_read_ref_id (&s, &data_ref) || !cs_read_unsigned (&s, &code_index) || !cs_read_tagged32 (&s, &kind_tag)) {
					goto fail;
				}
				function_name_ref[ref] = name_ref;
				function_owner_ref[ref] = owner_ref;
				function_data_ref[ref] = data_ref;
				function_code_index[ref] = code_index? code_index - 1: UT64_MAX;
			}
			continue;
		}
		if (meta[i].cid == modern_cid_code (ctx)) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				ut64 owner_ref = 0;
				ut64 tmp_ref = 0;
				ut64 slot = UT64_MAX;
				if (j < meta[i].main_count) {
					ut64 payload = 0;
					if (!cs_read_unsigned (&s, &payload)) {
						goto fail;
					}
					slot = next_code_index++;
					if (meta[i].discarded_codes && meta[i].discarded_codes[j]) {
						if (!cs_read_ref_id (&s, &tmp_ref)) {
							goto fail;
						}
						continue;
					}
				}
				for (int k = 0; k < 6; k++) {
					if (!cs_read_ref_id (&s, &tmp_ref)) {
						goto fail;
					}
					if (k == 0) {
						owner_ref = tmp_ref;
					}
				}
				if (slot != UT64_MAX && slot < itlen) {
					code_owner_ref_by_index[slot] = owner_ref;
					// Resolve the owner ref back to the cluster cid that
					// allocated it; this tells us if the slot is a regular
					// function, an allocate stub (owner is a Class), a type
					// test stub (owner is an AbstractType), or a VM stub
					// (owner_ref == 0, not in any cluster).
					int owner_cid = 0;
					if (owner_ref > 0) {
						for (ut64 m = 0; m < num_clusters; m++) {
							if (meta[m].count == 0) {
								continue;
							}
							ut64 lo = meta[m].start_ref;
							ut64 hi = lo + meta[m].count;
							if (owner_ref >= lo && owner_ref < hi) {
								owner_cid = meta[m].cid;
								break;
							}
						}
					}
					code_owner_cid_by_index[slot] = owner_cid;
				}
			}
			continue;
		}
		if (meta[i].cid == 9) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				ut64 parent_function_ref = 0;
				ut64 closure_ref = 0;
				ut64 default_kind = 0;
				if (!cs_read_ref_id (&s, &parent_function_ref) || !cs_read_ref_id (&s, &closure_ref) || !cs_read_unsigned (&s, &default_kind)) {
					goto fail;
				}
				closure_parent_ref[ref] = parent_function_ref;
			}
			continue;
		}
		if (meta[i].cid == 13) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				ut64 name_ref = 0;
				for (int k = 0; k < 10; k++) {
					ut64 rv = 0;
					if (!cs_read_ref_id (&s, &rv)) {
						goto fail;
					}
					if (k == 0) {
						name_ref = rv;
					}
				}
				for (int k = 0; k < 4; k++) {
					if (!modern_skip_scalar (&s, spec.scalars[k])) {
						goto fail;
					}
				}
				library_name_ref[ref] = name_ref;
			}
			continue;
		}
		if (meta[i].cid == 6) {
			for (ut64 j = 0; j < meta[i].count; j++, ref++) {
				ut64 wrapped_ref = 0;
				ut64 script_ref = 0;
				if (!cs_read_ref_id (&s, &wrapped_ref) || !cs_read_ref_id (&s, &script_ref)) {
					goto fail;
				}
				patch_wrapped_ref[ref] = wrapped_ref;
			}
			continue;
		}
		if (!modern_skip_fill_by_kind (&s, ctx, &meta[i], &spec)) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] modern fill: failed skipping cid=%d kind=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, spec.kind, i, s.cursor);
			}
			goto fail;
		}
	}
	ut64 mapped = 0;
	const int cid_class_v = modern_cid_class (ctx);
	const int cid_function_v = modern_cid_function (ctx);
	// Cluster cids for abstract-type owners (Type/FunctionType/RecordType).
	// These live just past the Class/Function predefined cids; on Dart 3.8.x
	// they are 112/113/114 in the VM but in the snapshot cluster-cid space
	// they appear as modern_cid_function + N. Rather than hardcode, treat any
	// non-Class non-Function owner as a type-test-like stub.
	for (ut64 code_index = 0; code_index < itlen; code_index++) {
		ut64 owner_ref = code_owner_ref_by_index[code_index];
		int owner_cid = code_owner_cid_by_index[code_index];
		ut8 kind = DART_OWNER_UNKNOWN;
		char *full = NULL;
		if (owner_ref == 0) {
			// Code object with no owner in the cluster graph: these are
			// precompiled VM stubs (runtime helpers). Mark the slot so the
			// IT resolver doesn't burn a name-pool entry on it.
			kind = DART_OWNER_VM_STUB;
		} else if (owner_ref >= total_refs) {
			// Out of range, leave unknown.
		} else if (owner_cid == cid_function_v && function_name_ref[owner_ref]) {
			const char *method_name = function_name_ref[owner_ref] < total_refs? strings_by_ref[function_name_ref[owner_ref]]: NULL;
			ut64 data_ref = function_data_ref[owner_ref];
			if (data_ref < total_refs && closure_parent_ref[data_ref]) {
				method_name = "_anon_closure";
			}
			const char *owner_name = modern_resolve_ref_name (strings_by_ref, class_name_ref, library_name_ref, patch_wrapped_ref, function_name_ref, total_refs, function_owner_ref[owner_ref], 0);
			full = modern_build_full_name (ctx, owner_name, method_name);
			kind = DART_OWNER_FUNCTION;
		} else if (owner_cid == cid_class_v) {
			// Allocate stub for a user class. Name it like blutter's
			// Allocate<ClassName>Stub so cross-tool diffs line up.
			const char *cls_name = class_name_ref[owner_ref] && class_name_ref[owner_ref] < total_refs
				? strings_by_ref[class_name_ref[owner_ref]]
				: NULL;
			if (R_STR_ISNOTEMPTY (cls_name)) {
				full = r_str_newf ("stub.Allocate%sStub", cls_name);
				if (full) {
					r_name_filter (full, 0);
				}
			}
			kind = DART_OWNER_CLASS;
		} else if (owner_cid > 0) {
			// Non-Function, non-Class owner: most commonly a Type or
			// FunctionType (type-test stub). Try to recover a readable name
			// via modern_resolve_ref_name (walks class_name/library_name
			// chains) and fall back to a generic tag.
			const char *t_name = modern_resolve_ref_name (strings_by_ref, class_name_ref, library_name_ref, patch_wrapped_ref, function_name_ref, total_refs, owner_ref, 0);
			if (R_STR_ISNOTEMPTY (t_name)) {
				full = r_str_newf ("stub.TypeTest_%s", t_name);
				if (full) {
					r_name_filter (full, 0);
				}
			}
			kind = DART_OWNER_TYPE;
		}
		if (ctx->owner_kind_by_code_index && code_index < ctx->owner_kind_by_code_index_count) {
			ctx->owner_kind_by_code_index[code_index] = kind;
		}
		if (full) {
			modern_set_name_for_code_index (ctx, code_index, full);
		}
	}
	for (ut64 ref = 1; ref < total_refs; ref++) {
		if (!function_name_ref[ref] || function_code_index[ref] >= ctx->name_by_code_index_count) {
			continue;
		}
		ut64 ci = function_code_index[ref];
		if (ctx->name_by_code_index[ci]) {
			continue;
		}
		const char *method_name = function_name_ref[ref] < total_refs? strings_by_ref[function_name_ref[ref]]: NULL;
		ut64 data_ref = function_data_ref[ref];
		if (data_ref < total_refs && closure_parent_ref[data_ref]) {
			method_name = "_anon_closure";
		}
		const char *owner_name = modern_resolve_ref_name (strings_by_ref, class_name_ref, library_name_ref, patch_wrapped_ref, function_name_ref, total_refs, function_owner_ref[ref], 0);
		char *full = modern_build_full_name (ctx, owner_name, method_name);
		modern_set_name_for_code_index (ctx, ci, full);
		if (ctx->owner_kind_by_code_index && ci < ctx->owner_kind_by_code_index_count) {
			ctx->owner_kind_by_code_index[ci] = DART_OWNER_FUNCTION;
		}
	}
	for (ut64 i = 0; i < ctx->name_by_code_index_count; i++) {
		if (R_STR_ISNOTEMPTY (ctx->name_by_code_index[i])) {
			mapped++;
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] modern cluster naming mapped=%" PRIu64 "\n", mapped);
	}
	for (ut64 i = 0; i < total_refs; i++) {
		free (strings_by_ref[i]);
	}
	for (ut64 i = 0; i < num_clusters; i++) {
		free (meta[i].discarded_codes);
	}
	free (meta);
	free (strings_by_ref);
	free (class_name_ref);
	free (library_name_ref);
	free (patch_wrapped_ref);
	free (function_name_ref);
	free (function_owner_ref);
	free (function_data_ref);
	free (function_code_index);
	free (closure_parent_ref);
	free (code_owner_ref_by_index);
	free (code_owner_cid_by_index);
	return true;
fail:
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] modern scan failed cluster=%" PRIu64 " cid=%d off=0x%" PFMT64x "\n", current_cluster, current_cid, s.cursor);
	}
	for (ut64 i = 0; i < total_refs; i++) {
		free (strings_by_ref[i]);
	}
	for (ut64 i = 0; i < num_clusters; i++) {
		free (meta[i].discarded_codes);
	}
	free (meta);
	free (strings_by_ref);
	free (class_name_ref);
	free (library_name_ref);
	free (patch_wrapped_ref);
	free (function_name_ref);
	free (function_owner_ref);
	free (function_data_ref);
	free (function_code_index);
	free (closure_parent_ref);
	free (code_owner_ref_by_index);
	free (code_owner_cid_by_index);
	return false;
}
