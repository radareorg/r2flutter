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

static int modern_cid_class(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_class: 5;
}

static int modern_cid_function(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_function: 7;
}

static int modern_cid_code(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_code: 18;
}

static int modern_cid_object_pool(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_object_pool: 23;
}

static int modern_cid_string(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_string: 93;
}

static int modern_cid_mint(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_mint: 61;
}

static int modern_cid_one_byte_string(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_one_byte_string: 94;
}

static int modern_cid_two_byte_string(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_two_byte_string: 95;
}

static int modern_cid_array(DartCtx *ctx) {
	return ctx && ctx->layout? ctx->layout->cid_array: 90;
}

static int modern_cid_immutable_array(DartCtx *ctx) {
	return modern_cid_array (ctx) + 1;
}

static int modern_cid_growable_array(DartCtx *ctx) {
	return modern_cid_array (ctx) + 2;
}

static int modern_cid_typed_data(DartCtx *ctx) {
	return modern_cid_string (ctx) - 24;
}

static int modern_cid_external_typed_data(DartCtx *ctx) {
	return modern_cid_typed_data (ctx) + 1;
}

static int modern_cid_typed_data_view(DartCtx *ctx) {
	return modern_cid_typed_data (ctx) + 2;
}

static int modern_typed_data_internal_base(DartCtx *ctx) {
	if (ctx && ctx->layout && ctx->layout->num_predefined_cids > 0) {
		return ctx->layout->num_predefined_cids - 63;
	}
	return 112;
}

static int modern_typed_data_internal_limit(DartCtx *ctx) {
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
	int rem = 0;
	return modern_typed_data_internal_kind (ctx, cid, &rem) && rem == 0;
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
	if (cid == modern_cid_string (ctx) || cid == modern_cid_one_byte_string (ctx) || cid == modern_cid_two_byte_string (ctx)) {
		return MODERN_ALLOC_STRING;
	}
	if (cid == modern_cid_mint (ctx)) {
		return MODERN_ALLOC_MINT;
	}
	if (modern_is_simple_alloc_cid (cid)) {
		return MODERN_ALLOC_SIMPLE;
	}
	if (cid == modern_cid_array (ctx) || cid == modern_cid_immutable_array (ctx)) {
		return MODERN_ALLOC_ARRAY;
	}
	if (cid == 17) {
		return MODERN_ALLOC_WEAK_ARRAY;
	}
	if (cid == 47) {
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
	if (cid == 24 || cid == 25 || cid == 26) {
		return MODERN_ALLOC_RODATA;
	}
	if (cid == 28) {
		return MODERN_ALLOC_EXCEPTION_HANDLERS;
	}
	if (cid == 29) {
		return MODERN_ALLOC_CONTEXT;
	}
	if (cid == 30) {
		return MODERN_ALLOC_CONTEXT_SCOPE;
	}
	if (cid == 67) {
		return MODERN_ALLOC_RECORD;
	}
	if (modern_is_typed_data_alloc_cid (ctx, cid)) {
		return MODERN_ALLOC_TYPED_DATA;
	}
	if (cid == 49 || cid == 50 || cid == 51 || cid == 52) {
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
	if (!s || !meta) {
		return false;
	}
	ut64 count = 0;
	ModernAllocKind kind = modern_alloc_kind (ctx, meta->cid);
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
			if (ctx->layout && ctx->layout->num_predefined_cids > 0 && predefined > (ut64)ctx->layout->num_predefined_cids) {
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
	if (cid == modern_cid_string (ctx) || cid == modern_cid_one_byte_string (ctx) || cid == modern_cid_two_byte_string (ctx)) {
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
	if (cid == modern_cid_code (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_CODE);
	}
	if (cid == modern_cid_object_pool (ctx)) {
		return modern_fill_spec_kind (MODERN_FILL_OBJECT_POOL);
	}
	if (cid == modern_cid_array (ctx) || cid == modern_cid_immutable_array (ctx)) {
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
	if (!s || !meta || !spec) {
		return false;
	}
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
	if (!ctx || !ctx->name_by_code_index || code_index >= ctx->name_by_code_index_count || R_STR_ISEMPTY (name)) {
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
	if (!ctx || !ctx->vm_data || !strings_by_ref || refs_count == 0) {
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
		if (meta[i].cid == modern_cid_string (ctx) || meta[i].cid == modern_cid_one_byte_string (ctx) || meta[i].cid == modern_cid_two_byte_string (ctx)) {
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
		if (meta[i].cid == modern_cid_string (ctx) || meta[i].cid == modern_cid_one_byte_string (ctx) || meta[i].cid == modern_cid_two_byte_string (ctx)) {
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
		switch (spec.kind) {
		case MODERN_FILL_REFS:
			if (!modern_skip_fill_refs (&s, &meta[i], &spec)) {
				goto fail;
			}
			break;
		case MODERN_FILL_CLASS:
		case MODERN_FILL_ARRAY:
		case MODERN_FILL_WEAK_ARRAY:
		case MODERN_FILL_TYPE_ARGUMENTS:
		case MODERN_FILL_EXCEPTION_HANDLERS:
		case MODERN_FILL_CONTEXT:
		case MODERN_FILL_CONTEXT_SCOPE:
		case MODERN_FILL_CODE:
		case MODERN_FILL_OBJECT_POOL:
		case MODERN_FILL_INLINE_BYTES:
		case MODERN_FILL_TYPED_DATA:
		case MODERN_FILL_RECORD:
		case MODERN_FILL_INSTANCE:
		case MODERN_FILL_NONE:
			if (!modern_skip_fill_by_kind (&s, ctx, &meta[i], &spec)) {
				goto fail;
			}
			break;
		default:
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
		if (meta[i].cid == modern_cid_string (ctx) || meta[i].cid == modern_cid_one_byte_string (ctx) || meta[i].cid == modern_cid_two_byte_string (ctx)) {
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
		switch (spec.kind) {
		case MODERN_FILL_REFS:
			if (!modern_skip_fill_refs (&s, &meta[i], &spec)) {
				goto fail;
			}
			break;
		case MODERN_FILL_ARRAY:
			if (!modern_skip_fill_array (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_WEAK_ARRAY:
			if (!modern_skip_fill_weak_array (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_TYPE_ARGUMENTS:
			if (!modern_skip_fill_type_arguments (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_EXCEPTION_HANDLERS:
			if (!modern_skip_fill_exception_handlers (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_CONTEXT:
			if (!modern_skip_fill_context (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_CONTEXT_SCOPE:
			if (!modern_skip_fill_context_scope (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_CODE:
			if (!modern_skip_fill_code (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_OBJECT_POOL:
			if (!modern_skip_fill_object_pool (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_INLINE_BYTES:
			if (!modern_skip_fill_inline_bytes (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_TYPED_DATA:
			if (!modern_skip_fill_typed_data (&s, ctx, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_RECORD:
			if (!modern_skip_fill_record (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_INSTANCE:
			if (!modern_skip_fill_instance (&s, &meta[i])) {
				goto fail;
			}
			break;
		case MODERN_FILL_NONE:
			break;
		default:
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] modern fill: unsupported cid=%d kind=%d cluster=%" PRIu64 " off=0x%" PFMT64x "\n", meta[i].cid, spec.kind, i, s.cursor);
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
