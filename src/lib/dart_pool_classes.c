/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

static DartFieldInfo *dart_field_info_clone(const DartFieldInfo *fi) {
	if (!fi) {
		return NULL;
	}
	DartFieldInfo *out = R_NEW0 (DartFieldInfo);
	out->name = fi->name? strdup (fi->name): NULL;
	out->type_name = fi->type_name? strdup (fi->type_name): NULL;
	out->offset = fi->offset;
	out->flags = fi->flags;
	out->type_ref = fi->type_ref;
	out->ref_id = fi->ref_id;
	out->name_ref = fi->name_ref;
	out->owner_ref = fi->owner_ref;
	return out;
}

static DartMethodInfo *dart_method_info_clone(const DartMethodInfo *mi) {
	if (!mi) {
		return NULL;
	}
	DartMethodInfo *out = R_NEW0 (DartMethodInfo);
	out->ref_id = mi->ref_id;
	out->name = mi->name? strdup (mi->name): NULL;
	out->owner_name = mi->owner_name? strdup (mi->owner_name): NULL;
	out->signature = mi->signature? strdup (mi->signature): NULL;
	out->owner_ref = mi->owner_ref;
	out->name_ref = mi->name_ref;
	out->signature_ref = mi->signature_ref;
	out->data_ref = mi->data_ref;
	out->entry_point = mi->entry_point;
	out->code_ref = mi->code_ref;
	out->code_index = mi->code_index;
	out->kind_tag = mi->kind_tag;
	out->flags = mi->flags;
	return out;
}

static void dart_interface_info_free(void *p) {
	DartInterfaceInfo *ii = (DartInterfaceInfo *)p;
	if (ii) {
		free (ii->name);
		free (ii);
	}
}

typedef enum {
	kFieldCid_extract = 10,
	kLibraryCid_extract = 12,
} ExtraCids;

#define DART_TYPE_CLASS_ID_SHIFT 3
#define DART_TYPE_CLASS_ID_MASK ((1U << 20) - 1)
#define DART_TYPE_RESOLVE_MAX_DEPTH 8
#define DART_TYPE_PARAMETER_FUNCTION_FLAG (1 << 3)

typedef struct {
	ut64 ref_id;
	ut64 length;
	ut64 *type_refs;
} DartTypeArgumentsInfo;

typedef struct {
	ut64 ref_id;
	ut64 length;
	ut64 type_args_ref;
	ut64 *refs;
} DartArrayInfo;

static void free_type_arguments_info(void *p) {
	DartTypeArgumentsInfo *tai = (DartTypeArgumentsInfo *)p;
	if (tai) {
		free (tai->type_refs);
		free (tai);
	}
}

static void free_array_info(void *p) {
	DartArrayInfo *ai = (DartArrayInfo *)p;
	if (ai) {
		free (ai->refs);
		free (ai);
	}
}

static void free_method_info_items(DartMethodInfo **items, ut64 count);

static int decode_field_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *field_list, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Field cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartFieldInfo *fi = R_NEW0 (DartFieldInfo);
		fi->ref_id = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		fi->name_ref = name_ref;
		ut64 owner_ref = 0;
		cs_read_ref_id (s, &owner_ref);
		fi->owner_ref = owner_ref;
		ut64 type_ref = 0;
		cs_read_ref_id (s, &type_ref);
		fi->type_ref = type_ref;
		ut64 initializer_ref = 0;
		cs_read_ref_id (s, &initializer_ref);
		uint32_t kind_bits = 0;
		cs_read_u32 (s, &kind_bits);
		fi->flags = kind_bits;
		ut64 offset_or_id = 0;
		cs_read_ref_id (s, &offset_or_id);
		fi->offset = (ut32)offset_or_id;
		r_list_append (field_list, fi);
		if (ctx->refs && fi->ref_id < ctx->refs_count) {
			ctx->refs[fi->ref_id] = fi;
		}
	}
	return 0;
}

static int decode_function_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *method_list, ut64 *ref_counter) {
	if (!s || !ctx || !method_list || !ref_counter) {
		return -1;
	}
	ut64 start = s->cursor;
	ut64 start_ref = *ref_counter;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (count == 0) {
		return 0;
	}
	if (count > 100000) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Function cluster (ext): count=%" PRIu64 "\n", count);
	}
	DartMethodInfo **items = (DartMethodInfo **)calloc ((size_t)count, sizeof (DartMethodInfo *));
	if (!items) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	for (ut64 i = 0; i < count; i++) {
		DartMethodInfo *mi = R_NEW0 (DartMethodInfo);
		mi->ref_id = (*ref_counter)++;
		if (!cs_read_ref_id (s, &mi->name_ref) || !cs_read_ref_id (s, &mi->owner_ref) || !cs_read_ref_id (s, &mi->signature_ref) || !cs_read_ref_id (s, &mi->data_ref) || !cs_read_unsigned (s, &mi->code_index) || !cs_read_u32 (s, &mi->kind_tag)) {
			dart_method_info_free (mi);
			free_method_info_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		if (mi->code_index > 0 && ctx->iso_instr > 0) {
			mi->entry_point = ctx->iso_instr + (mi->code_index - 1) * 4;
		}
		mi->code_ref = mi->code_index;
		items[i] = mi;
	}
	for (ut64 i = 0; i < count; i++) {
		r_list_append (method_list, items[i]);
		if (ctx->refs && items[i]->ref_id < ctx->refs_count) {
			ctx->refs[items[i]->ref_id] = items[i];
		}
		items[i] = NULL;
	}
	free_method_info_items (items, count);
	return 0;
}

static void free_type_arguments_items(DartTypeArgumentsInfo **items, ut64 count) {
	if (!items) {
		return;
	}
	for (ut64 i = 0; i < count; i++) {
		free_type_arguments_info (items[i]);
	}
	free (items);
}

static void free_array_items(DartArrayInfo **items, ut64 count) {
	if (!items) {
		return;
	}
	for (ut64 i = 0; i < count; i++) {
		free_array_info (items[i]);
	}
	free (items);
}

static void free_type_info_items(DartTypeInfo **items, ut64 count) {
	if (!items) {
		return;
	}
	for (ut64 i = 0; i < count; i++) {
		dart_type_info_free (items[i]);
	}
	free (items);
}

static void free_method_info_items(DartMethodInfo **items, ut64 count) {
	if (!items) {
		return;
	}
	for (ut64 i = 0; i < count; i++) {
		dart_method_info_free (items[i]);
	}
	free (items);
}

static int decode_type_arguments_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *type_args_list, ut64 *ref_counter) {
	if (!s || !ctx || !type_args_list || !ref_counter) {
		return -1;
	}
	ut64 start = s->cursor;
	ut64 start_ref = *ref_counter;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (count == 0) {
		return 0;
	}
	if (count > 50000) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] TypeArguments cluster: count=%" PRIu64 "\n", count);
	}
	ut64 *lengths = (ut64 *)calloc ((size_t)count, sizeof (ut64));
	DartTypeArgumentsInfo **items = (DartTypeArgumentsInfo **)calloc ((size_t)count, sizeof (DartTypeArgumentsInfo *));
	if (!lengths || !items) {
		free (lengths);
		free_type_arguments_items (items, count);
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 length = 0;
		if (!cs_read_unsigned (s, &length) || length > 1024) {
			free (lengths);
			free_type_arguments_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		lengths[i] = length;
		DartTypeArgumentsInfo *tai = R_NEW0 (DartTypeArgumentsInfo);
		tai->ref_id = (*ref_counter)++;
		tai->length = length;
		items[i] = tai;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 length = 0;
		ut32 hash = 0;
		ut64 nullability = 0;
		ut64 instantiations_ref = 0;
		if (!cs_read_unsigned (s, &length) || length != lengths[i] || !cs_read_tagged32 (s, &hash) || !cs_read_unsigned (s, &nullability) || !cs_read_ref_id (s, &instantiations_ref)) {
			free (lengths);
			free_type_arguments_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		(void)hash;
		(void)nullability;
		(void)instantiations_ref;
		if (length > 0) {
			items[i]->type_refs = (ut64 *)calloc ((size_t)length, sizeof (ut64));
			if (!items[i]->type_refs) {
				free (lengths);
				free_type_arguments_items (items, count);
				s->cursor = start;
				*ref_counter = start_ref;
				return -1;
			}
		}
		for (ut64 j = 0; j < length; j++) {
			if (!cs_read_ref_id (s, &items[i]->type_refs[j])) {
				free (lengths);
				free_type_arguments_items (items, count);
				s->cursor = start;
				*ref_counter = start_ref;
				return -1;
			}
		}
	}
	free (lengths);
	for (ut64 i = 0; i < count; i++) {
		r_list_append (type_args_list, items[i]);
		items[i] = NULL;
	}
	free_type_arguments_items (items, count);
	return 0;
}

static int decode_array_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *array_list, ut64 *ref_counter) {
	if (!s || !ctx || !array_list || !ref_counter) {
		return -1;
	}
	ut64 start = s->cursor;
	ut64 start_ref = *ref_counter;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (count == 0) {
		return 0;
	}
	if (count > 50000) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Array cluster: count=%" PRIu64 "\n", count);
	}
	ut64 *lengths = (ut64 *)calloc ((size_t)count, sizeof (ut64));
	DartArrayInfo **items = (DartArrayInfo **)calloc ((size_t)count, sizeof (DartArrayInfo *));
	if (!lengths || !items) {
		free (lengths);
		free_array_items (items, count);
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 length = 0;
		if (!cs_read_unsigned (s, &length) || length > 4096) {
			free (lengths);
			free_array_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		lengths[i] = length;
		DartArrayInfo *ai = R_NEW0 (DartArrayInfo);
		ai->ref_id = (*ref_counter)++;
		ai->length = length;
		items[i] = ai;
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 length = 0;
		ut64 type_args_ref = 0;
		if (!cs_read_unsigned (s, &length) || length != lengths[i] || !cs_read_ref_id (s, &type_args_ref)) {
			free (lengths);
			free_array_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		items[i]->type_args_ref = type_args_ref;
		if (length > 0) {
			items[i]->refs = (ut64 *)calloc ((size_t)length, sizeof (ut64));
			if (!items[i]->refs) {
				free (lengths);
				free_array_items (items, count);
				s->cursor = start;
				*ref_counter = start_ref;
				return -1;
			}
		}
		for (ut64 j = 0; j < length; j++) {
			if (!cs_read_ref_id (s, &items[i]->refs[j])) {
				free (lengths);
				free_array_items (items, count);
				s->cursor = start;
				*ref_counter = start_ref;
				return -1;
			}
		}
	}
	free (lengths);
	for (ut64 i = 0; i < count; i++) {
		r_list_append (array_list, items[i]);
		items[i] = NULL;
	}
	free_array_items (items, count);
	return 0;
}

static int decode_type_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *type_list, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Type cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartTypeInfo *ti = R_NEW0 (DartTypeInfo);
		ti->ref_id = (*ref_counter)++;
		ti->kind = kTypeCid;
		ut64 type_test_stub_ref = 0;
		ut64 hash_ref = 0;
		ut64 args_ref = 0;
		cs_read_ref_id (s, &type_test_stub_ref);
		cs_read_ref_id (s, &hash_ref);
		cs_read_ref_id (s, &args_ref);
		(void)type_test_stub_ref;
		(void)hash_ref;
		ti->type_args_ref = args_ref;
		ut64 flags = 0;
		cs_read_unsigned (s, &flags);
		ti->flags = (ut32)flags;
		ti->type_class_ref = (flags >> DART_TYPE_CLASS_ID_SHIFT) & DART_TYPE_CLASS_ID_MASK;
		r_list_append (type_list, ti);
		if (ctx->refs && ti->ref_id < ctx->refs_count) {
			ctx->refs[ti->ref_id] = ti;
		}
	}
	return 0;
}

static int decode_type_parameter_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *type_list, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] TypeParameter cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartTypeInfo *ti = R_NEW0 (DartTypeInfo);
		ti->ref_id = (*ref_counter)++;
		ti->kind = kTypeParameterCid;
		ut64 type_test_stub_ref = 0;
		ut64 hash_ref = 0;
		ut64 owner_ref = 0;
		cs_read_ref_id (s, &type_test_stub_ref);
		cs_read_ref_id (s, &hash_ref);
		cs_read_ref_id (s, &owner_ref);
		(void)type_test_stub_ref;
		(void)hash_ref;
		ti->owner_ref = owner_ref;
		ut8 raw16[2] = { 0 };
		if (!cs_read_bytes (s, raw16, sizeof (raw16))) {
			dart_type_info_free (ti);
			return -1;
		}
		ti->base = r_read_le16 (raw16);
		if (!cs_read_bytes (s, raw16, sizeof (raw16))) {
			dart_type_info_free (ti);
			return -1;
		}
		ti->index = r_read_le16 (raw16);
		ut8 flags = 0;
		if (!cs_read_u8 (s, &flags)) {
			dart_type_info_free (ti);
			return -1;
		}
		ti->flags = flags;
		r_list_append (type_list, ti);
		if (ctx->refs && ti->ref_id < ctx->refs_count) {
			ctx->refs[ti->ref_id] = ti;
		}
	}
	return 0;
}

static int decode_function_type_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *type_list, ut64 *ref_counter) {
	if (!s || !ctx || !type_list || !ref_counter) {
		return -1;
	}
	ut64 start = s->cursor;
	ut64 start_ref = *ref_counter;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (count == 0) {
		return 0;
	}
	if (count > 50000) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] FunctionType cluster: count=%" PRIu64 "\n", count);
	}
	DartTypeInfo **items = (DartTypeInfo **)calloc ((size_t)count, sizeof (DartTypeInfo *));
	if (!items) {
		s->cursor = start;
		*ref_counter = start_ref;
		return -1;
	}
	for (ut64 i = 0; i < count; i++) {
		DartTypeInfo *ti = R_NEW0 (DartTypeInfo);
		ti->ref_id = (*ref_counter)++;
		ti->kind = kFunctionTypeCid;
		ut64 type_test_stub_ref = 0;
		ut64 hash_ref = 0;
		if (!cs_read_ref_id (s, &type_test_stub_ref) || !cs_read_ref_id (s, &hash_ref) || !cs_read_ref_id (s, &ti->type_parameters_ref) || !cs_read_ref_id (s, &ti->result_type_ref) || !cs_read_ref_id (s, &ti->parameter_types_ref) || !cs_read_ref_id (s, &ti->named_parameter_names_ref)) {
			dart_type_info_free (ti);
			free_type_info_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		(void)type_test_stub_ref;
		(void)hash_ref;
		ut8 flags = 0;
		if (!cs_read_u8 (s, &flags) || !cs_read_u32 (s, &ti->packed_parameter_counts)) {
			dart_type_info_free (ti);
			free_type_info_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		ti->flags = flags;
		ut8 raw16[2] = { 0 };
		if (!cs_read_bytes (s, raw16, sizeof (raw16))) {
			dart_type_info_free (ti);
			free_type_info_items (items, count);
			s->cursor = start;
			*ref_counter = start_ref;
			return -1;
		}
		ti->packed_type_parameter_counts = r_read_le16 (raw16);
		items[i] = ti;
	}
	for (ut64 i = 0; i < count; i++) {
		r_list_append (type_list, items[i]);
		if (ctx->refs && items[i]->ref_id < ctx->refs_count) {
			ctx->refs[items[i]->ref_id] = items[i];
		}
		items[i] = NULL;
	}
	free_type_info_items (items, count);
	return 0;
}

static int decode_class_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *class_list, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Class cluster (ext): count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartClassInfo *ci = R_NEW0 (DartClassInfo);
		ci->ref_id = (*ref_counter)++;
		ci->fields = r_list_newf ((RListFree)dart_field_info_free);
		ci->interfaces = r_list_newf (dart_interface_info_free);
		uint32_t instance_size = 0;
		cs_read_u32 (s, &instance_size);
		ci->instance_size = instance_size;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		ci->name_ref = name_ref;
		ut64 library_ref = 0;
		cs_read_ref_id (s, &library_ref);
		ci->library_ref = library_ref;
		ut64 super_class_ref = 0;
		cs_read_ref_id (s, &super_class_ref);
		ci->super_class_ref = super_class_ref;
		ut64 type_args_ref = 0;
		cs_read_ref_id (s, &type_args_ref);
		uint32_t num_type_params = 0;
		cs_read_u32 (s, &num_type_params);
		ci->num_type_parameters = num_type_params;
		uint32_t type_arg_offset = 0;
		cs_read_u32 (s, &type_arg_offset);
		ci->type_argument_offset = type_arg_offset;
		uint32_t flags = 0;
		cs_read_u32 (s, &flags);
		ci->flags = 0;
		if (flags & (1 << 0)) {
			ci->flags |= DART_CLASS_ABSTRACT;
		}
		if (flags & (1 << 1)) {
			ci->flags |= DART_CLASS_ENUM;
		}
		if (flags & (1 << 2)) {
			ci->flags |= DART_CLASS_MIXIN;
		}
		ut64 interfaces_ref = 0;
		cs_read_ref_id (s, &interfaces_ref);
		ci->interfaces_ref = interfaces_ref;
		ut64 skip_refs = 3;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		r_list_append (class_list, ci);
		if (ctx->refs && ci->ref_id < ctx->refs_count) {
			ctx->refs[ci->ref_id] = ci;
		}
	}
	return 0;
}

typedef struct {
	ut64 ref_id;
	char *uri;
	ut64 name_ref;
} LibraryInfo;

static void free_library_info(void *p) {
	LibraryInfo *li = (LibraryInfo *)p;
	if (li) {
		free (li->uri);
		free (li);
	}
}

static char *dup_ref_string(DartCtx *ctx, ut64 ref) {
	if (!ctx || !ctx->refs || ref == 0 || ref >= ctx->refs_count) {
		return NULL;
	}
	DartString *ds = (DartString *)ctx->refs[ref];
	if (!ds || R_STR_ISEMPTY (ds->value)) {
		return NULL;
	}
	return strdup (ds->value);
}

static char *dup_ref_string_obf(DartCtx *ctx, ut64 ref) {
	char *value = dup_ref_string (ctx, ref);
	if (value) {
		dart_obf_apply (ctx, &value);
	}
	return value;
}

static const char *builtin_type_name(ut64 cid) {
	switch (cid) {
	case kStringCid:
	case kOneByteStringCid:
	case kTwoByteStringCid:
		return "String";
	case kArrayCid:
	case kImmutableArrayCid:
	case kGrowableObjectArrayCid:
		return "List";
	case kMintCid:
		return "int";
	case kDoubleCid:
		return "double";
	default:
		return NULL;
	}
}

static DartTypeInfo *find_type_by_ref(RList *type_list, ut64 ref) {
	if (!type_list || ref == 0) {
		return NULL;
	}
	RListIter *it;
	DartTypeInfo *ti;
	r_list_foreach (type_list, it, ti) {
		if (ti && ti->ref_id == ref) {
			return ti;
		}
	}
	return NULL;
}

static DartTypeArgumentsInfo *find_type_arguments_by_ref(RList *type_args_list, ut64 ref) {
	if (!type_args_list || ref == 0) {
		return NULL;
	}
	RListIter *it;
	DartTypeArgumentsInfo *tai;
	r_list_foreach (type_args_list, it, tai) {
		if (tai && tai->ref_id == ref) {
			return tai;
		}
	}
	return NULL;
}

static DartArrayInfo *find_array_by_ref(RList *array_list, ut64 ref) {
	if (!array_list || ref == 0) {
		return NULL;
	}
	RListIter *it;
	DartArrayInfo *ai;
	r_list_foreach (array_list, it, ai) {
		if (ai && ai->ref_id == ref) {
			return ai;
		}
	}
	return NULL;
}

static DartClassInfo *find_class_by_ref(RList *class_list, ut64 ref) {
	if (!class_list || ref == 0) {
		return NULL;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (ci && ci->ref_id == ref) {
			return ci;
		}
	}
	return NULL;
}

static char *dup_class_name_by_ref(RList *class_list, ut64 ref) {
	DartClassInfo *ci = find_class_by_ref (class_list, ref);
	if (ci && R_STR_ISNOTEMPTY (ci->name)) {
		return strdup (ci->name);
	}
	return NULL;
}

static ut32 function_type_num_implicit(const DartTypeInfo *ti) {
	return ti? (ti->packed_parameter_counts & 1): 0;
}

static bool function_type_has_named_optional(const DartTypeInfo *ti) {
	return ti && ((ti->packed_parameter_counts >> 1) & 1);
}

static ut32 function_type_num_fixed(const DartTypeInfo *ti) {
	return ti? ((ti->packed_parameter_counts >> 2) & 0x3fff): 0;
}

static ut32 function_type_num_optional(const DartTypeInfo *ti) {
	return ti? ((ti->packed_parameter_counts >> 16) & 0x3fff): 0;
}

static ut32 function_type_num_type_parameters(const DartTypeInfo *ti) {
	return ti? ((ti->packed_type_parameter_counts >> 8) & 0xff): 0;
}

static char *resolve_type_name_depth(DartCtx *ctx, RList *class_list, RList *type_list, RList *type_args_list, RList *array_list, ut64 type_ref, int depth);

static void append_function_parameter_type(RStrBuf *sb, DartCtx *ctx, RList *class_list, RList *type_list, RList *type_args_list, RList *array_list, const DartArrayInfo *parameter_types, ut32 index, int depth) {
	char *name = NULL;
	if (parameter_types && index < parameter_types->length && parameter_types->refs) {
		name = resolve_type_name_depth (ctx, class_list, type_list, type_args_list, array_list, parameter_types->refs[index], depth + 1);
	}
	r_strbuf_append (sb, R_STR_ISNOTEMPTY (name)? name: "dynamic");
	free (name);
}

static void append_function_parameter_name(RStrBuf *sb, DartCtx *ctx, const DartArrayInfo *names, ut32 index) {
	char *name = NULL;
	if (names && index < names->length && names->refs) {
		name = dup_ref_string_obf (ctx, names->refs[index]);
	}
	if (R_STR_ISNOTEMPTY (name)) {
		r_strbuf_appendf (sb, " %s", name);
	} else {
		r_strbuf_appendf (sb, " arg%u", index);
	}
	free (name);
}

static char *resolve_function_type_name(DartCtx *ctx, RList *class_list, RList *type_list, RList *type_args_list, RList *array_list, DartTypeInfo *ti, int depth) {
	if (!ti) {
		return NULL;
	}
	RStrBuf sb;
	r_strbuf_init (&sb);
	ut32 num_type_params = function_type_num_type_parameters (ti);
	if (num_type_params > 0) {
		r_strbuf_append (&sb, "<");
		for (ut32 i = 0; i < num_type_params; i++) {
			if (i > 0) {
				r_strbuf_append (&sb, ", ");
			}
			r_strbuf_appendf (&sb, "Y%u", i);
		}
		r_strbuf_append (&sb, ">");
	}
	r_strbuf_append (&sb, "(");
	const DartArrayInfo *parameter_types = find_array_by_ref (array_list, ti->parameter_types_ref);
	const DartArrayInfo *names = find_array_by_ref (array_list, ti->named_parameter_names_ref);
	ut32 implicit = function_type_num_implicit (ti);
	ut32 fixed = function_type_num_fixed (ti);
	ut32 optional = function_type_num_optional (ti);
	ut32 total = fixed + optional;
	bool need_comma = false;
	for (ut32 i = implicit; i < fixed && i < total; i++) {
		if (need_comma) {
			r_strbuf_append (&sb, ", ");
		}
		append_function_parameter_type (&sb, ctx, class_list, type_list, type_args_list, array_list, parameter_types, i, depth);
		need_comma = true;
	}
	if (optional > 0) {
		if (need_comma) {
			r_strbuf_append (&sb, ", ");
		}
		bool has_named = function_type_has_named_optional (ti);
		r_strbuf_append (&sb, has_named? "{": "[");
		for (ut32 i = fixed; i < total; i++) {
			if (i > fixed) {
				r_strbuf_append (&sb, ", ");
			}
			append_function_parameter_type (&sb, ctx, class_list, type_list, type_args_list, array_list, parameter_types, i, depth);
			if (has_named) {
				append_function_parameter_name (&sb, ctx, names, i - fixed);
			}
		}
		r_strbuf_append (&sb, has_named? "}": "]");
	}
	r_strbuf_append (&sb, ") => ");
	char *result = resolve_type_name_depth (ctx, class_list, type_list, type_args_list, array_list, ti->result_type_ref, depth + 1);
	r_strbuf_append (&sb, R_STR_ISNOTEMPTY (result)? result: "dynamic");
	free (result);
	const char *resolved = r_strbuf_get (&sb);
	char *name = resolved? strdup (resolved): NULL;
	r_strbuf_fini (&sb);
	return name;
}

static char *resolve_type_name_depth(DartCtx *ctx, RList *class_list, RList *type_list, RList *type_args_list, RList *array_list, ut64 type_ref, int depth) {
	if (depth > DART_TYPE_RESOLVE_MAX_DEPTH) {
		return NULL;
	}
	DartTypeInfo *ti = find_type_by_ref (type_list, type_ref);
	if (!ti) {
		return NULL;
	}
	if (R_STR_ISNOTEMPTY (ti->name)) {
		return strdup (ti->name);
	}
	if (ti->kind == kTypeParameterCid) {
		bool is_function_param = (ti->flags & DART_TYPE_PARAMETER_FUNCTION_FLAG) != 0;
		const char *base_prefix = is_function_param? "F": "C";
		const char *index_prefix = is_function_param? "Y": "X";
		ut32 index = ti->index >= ti->base? ti->index - ti->base: ti->index;
		char *name = ti->base > 0
			? r_str_newf ("%s%u%s%u", base_prefix, ti->base, index_prefix, index)
			: r_str_newf ("%s%u", index_prefix, index);
		if (name) {
			ti->name = strdup (name);
		}
		return name;
	}
	if (ti->kind == kFunctionTypeCid) {
		char *name = resolve_function_type_name (ctx, class_list, type_list, type_args_list, array_list, ti, depth);
		if (name) {
			ti->name = strdup (name);
		}
		return name;
	}
	char *name = NULL;
	const char *builtin = builtin_type_name (ti->type_class_ref);
	if (builtin) {
		name = strdup (builtin);
	} else {
		name = dup_class_name_by_ref (class_list, ti->type_class_ref);
	}
	if (name) {
		dart_obf_apply (ctx, &name);
		DartTypeArgumentsInfo *tai = find_type_arguments_by_ref (type_args_list, ti->type_args_ref);
		if (tai && tai->length > 0) {
			RStrBuf sb;
			r_strbuf_init (&sb);
			r_strbuf_append (&sb, name);
			r_strbuf_append (&sb, "<");
			for (ut64 i = 0; i < tai->length; i++) {
				if (i > 0) {
					r_strbuf_append (&sb, ", ");
				}
				char *arg_name = resolve_type_name_depth (ctx, class_list, type_list, type_args_list, array_list, tai->type_refs? tai->type_refs[i]: 0, depth + 1);
				r_strbuf_append (&sb, R_STR_ISNOTEMPTY (arg_name)? arg_name: "dynamic");
				free (arg_name);
			}
			r_strbuf_append (&sb, ">");
			free (name);
			const char *resolved = r_strbuf_get (&sb);
			name = resolved? strdup (resolved): NULL;
			r_strbuf_fini (&sb);
		}
		if (name) {
			ti->name = strdup (name);
		}
	}
	return name;
}

static char *resolve_type_name(DartCtx *ctx, RList *class_list, RList *type_list, RList *type_args_list, RList *array_list, ut64 type_ref) {
	return resolve_type_name_depth (ctx, class_list, type_list, type_args_list, array_list, type_ref, 0);
}

typedef struct {
	char *name;
	bool saw_plain_name;
	bool saw_trailing_dot;
	RList *values;
} DartEnumCandidate;

static void free_enum_candidate(void *p) {
	DartEnumCandidate *ec = (DartEnumCandidate *)p;
	if (ec) {
		free (ec->name);
		r_list_free (ec->values);
		free (ec);
	}
}
static bool has_lowercase_after(const char *s, int start) {
	for (int i = start; s[i]; i++) {
		if (islower ((ut8)s[i])) {
			return true;
		}
	}
	return false;
}

static bool is_type_name_candidate(const char *s) {
	static const char *const skip_prefixes[] = {
		"get:",
		"set:",
		"init:",
		"dyn:",
		"vm:",
		"dart:",
		"package:",
		NULL
	};
	if (R_STR_ISEMPTY (s)) {
		return false;
	}
	const char *const *prefix = skip_prefixes;
	while (*prefix) {
		if (r_str_startswith (s, *prefix)) {
			return false;
		}
		prefix++;
	}
	if (strchr (s, ':') != NULL) {
		return false;
	}
	if (isupper ((ut8)s[0])) {
		return has_lowercase_after (s, 1);
	}
	if (s[0] == '_' && isupper ((ut8)s[1])) {
		return has_lowercase_after (s, 2);
	}
	return false;
}

static bool is_enum_value_candidate(const char *s) {
	if (!R_STR_ISNOTEMPTY (s) || !isalpha ((ut8)s[0]) || !islower ((ut8)s[0])) {
		return false;
	}
	for (const ut8 *p = (const ut8 *)s + 1; *p; p++) {
		if (isalpha (*p) || isdigit (*p) || *p == '_') {
			continue;
		}
		return false;
	}
	return true;
}

static DartEnumCandidate *enum_candidate_get_or_add(RList *list, HtPP *by_name, const char *name) {
	if (!R_STR_ISNOTEMPTY (name)) {
		return NULL;
	}
	DartEnumCandidate *ec = ht_pp_find (by_name, name, NULL);
	if (ec) {
		return ec;
	}
	ec = R_NEW0 (DartEnumCandidate);
	ec->name = strdup (name);
	ec->values = r_list_newf (free);
	if (!ec->name) {
		free_enum_candidate (ec);
		return NULL;
	}
	r_list_append (list, ec);
	ht_pp_insert (by_name, ec->name, ec);
	return ec;
}

static void enum_candidate_add_value(DartEnumCandidate *ec, const char *value) {
	if (!R_STR_ISNOTEMPTY (value)) {
		return;
	}
	if (r_list_find (ec->values, value, (RListComparator)strcmp)) {
		return;
	}
	r_list_append (ec->values, strdup (value));
}

static bool has_enum_like_suffix(const char *name) {
	static const char *suffixes[] = {
		"Action",
		"Affinity",
		"Alignment",
		"Behavior",
		"Direction",
		"Kind",
		"Mode",
		"Platform",
		"Side",
		"Size",
		"State",
		"Status",
		"Style"
	};
	for (size_t i = 0; i < sizeof (suffixes) / sizeof (suffixes[0]); i++) {
		if (r_str_endswith (name, suffixes[i])) {
			return true;
		}
	}
	return false;
}

static bool is_factory_like_value(const char *value) {
	static const char *bad_values[] = {
		"builder",
		"child",
		"compose",
		"copy",
		"current",
		"dark",
		"delayed",
		"directory",
		"empty",
		"error",
		"exit",
		"fallback",
		"filled",
		"file",
		"from",
		"generate",
		"identity",
		"inverted",
		"light",
		"matrix",
		"microtask",
		"now",
		"of",
		"parse",
		"root",
		"separated",
		"spawn",
		"sync",
		"timestamp",
		"unmodifiable",
		"utc",
		"value",
		"zero"
	};
	for (size_t i = 0; i < sizeof (bad_values) / sizeof (bad_values[0]); i++) {
		if (!strcmp (value, bad_values[i])) {
			return true;
		}
	}
	return false;
}

static int enum_candidate_score(const DartEnumCandidate *ec) {
	if (!ec || !ec->name) {
		return 0;
	}
	int score = 0;
	int count = ec->values? r_list_length (ec->values): 0;
	if (count >= 4) {
		score += 2;
	} else if (count >= 3) {
		score += 1;
	}
	if (has_enum_like_suffix (ec->name)) {
		score += 3;
	}
	if (ec->values) {
		RListIter *it;
		char *value;
		r_list_foreach (ec->values, it, value) {
			if (is_factory_like_value (value)) {
				score -= 2;
				break;
			}
		}
	}
	return score;
}

static int cmp_cstr_ptr(const void *a, const void *b) {
	const char *const *sa = (const char *const *)a;
	const char *const *sb = (const char *const *)b;
	return strcmp (*sa, *sb);
}

static void class_info_add_enum_values(DartClassInfo *ci, RList *values) {
	if (r_list_length (values) == 0) {
		return;
	}
	if (!ci->enums) {
		ci->enums = r_list_newf (free);
	}
	int count = r_list_length (values);
	char **sorted = calloc ((size_t)count, sizeof (char *));
	if (!sorted) {
		return;
	}
	int idx = 0;
	RListIter *it;
	char *value;
	r_list_foreach (values, it, value) {
		if (value && idx < count) {
			sorted[idx++] = value;
		}
	}
	if (idx > 1) {
		qsort (sorted, (size_t)idx, sizeof (char *), cmp_cstr_ptr);
	}
	for (int i = 0; i < idx; i++) {
		if (!sorted[i] || r_list_find (ci->enums, sorted[i], (RListComparator)strcmp)) {
			continue;
		}
		r_list_append (ci->enums, strdup (sorted[i]));
	}
	free (sorted);
}

static void recover_enum_types_from_strings(DartCtx *ctx, RList *class_list) {
	if (!ctx || !ctx->core || !class_list) {
		return;
	}
	RList *strings = dart_pool_extract_strings (ctx);
	if (!strings || r_list_length (strings) == 0) {
		dart_string_list_free (strings);
		return;
	}
	HtPP *class_by_name = ht_pp_new0 ();
	HtPP *candidate_by_name = ht_pp_new0 ();
	RList *candidates = r_list_newf (free_enum_candidate);
	if (!class_by_name || !candidate_by_name) {
		ht_pp_free (class_by_name);
		ht_pp_free (candidate_by_name);
		dart_string_list_free (strings);
		r_list_free (candidates);
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (ci && ci->name) {
			ht_pp_insert (class_by_name, ci->name, ci);
		}
	}
	DartStringInfo *si;
	r_list_foreach (strings, it, si) {
		if (!si || R_STR_ISEMPTY (si->value)) {
			continue;
		}
		const char *s = si->value;
		size_t len = strlen (s);
		if (len > 1 && s[len - 1] == '.') {
			char *prefix = r_str_ndup (s, len - 1);
			if (prefix && is_type_name_candidate (prefix)) {
				DartEnumCandidate *ec = enum_candidate_get_or_add (candidates, candidate_by_name, prefix);
				if (ec) {
					ec->saw_trailing_dot = true;
				}
			}
			free (prefix);
			continue;
		}
		const char *dot = strchr (s, '.');
		if (dot && dot != s && dot[1] && !strchr (dot + 1, '.')) {
			char *prefix = r_str_ndup (s, (size_t) (dot - s));
			if (!prefix) {
				continue;
			}
			if (is_type_name_candidate (prefix) && is_enum_value_candidate (dot + 1)) {
				DartEnumCandidate *ec = enum_candidate_get_or_add (candidates, candidate_by_name, prefix);
				if (ec) {
					enum_candidate_add_value (ec, dot + 1);
				}
			}
			free (prefix);
			continue;
		}
		if (is_type_name_candidate (s)) {
			DartEnumCandidate *ec = enum_candidate_get_or_add (candidates, candidate_by_name, s);
			if (ec) {
				ec->saw_plain_name = true;
			}
		}
	}
	DartEnumCandidate *ec;
	int recovered = 0;
	r_list_foreach (candidates, it, ec) {
		if (!ec || !ec->name || r_list_length (ec->values) < 2) {
			continue;
		}
		int score = enum_candidate_score (ec);
		if (!ec->saw_trailing_dot || score < 3) {
			continue;
		}
		DartClassInfo *eci = ht_pp_find (class_by_name, ec->name, NULL);
		if (!eci) {
			eci = R_NEW0 (DartClassInfo);
			eci->name = strdup (ec->name);
			eci->fields = r_list_newf ((RListFree)dart_field_info_free);
			eci->interfaces = r_list_newf (dart_interface_info_free);
			if (!eci->name) {
				dart_class_info_free (eci);
				continue;
			}
			r_list_append (class_list, eci);
			ht_pp_insert (class_by_name, eci->name, eci);
		}
		eci->flags |= DART_CLASS_ENUM;
		class_info_add_enum_values (eci, ec->values);
		recovered++;
		if (ctx->verbose > 1) {
			fprintf (stderr, "[r2flutter] recovered enum %s (%d values, score=%d)\n", ec->name, r_list_length (ec->values), score);
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Recovered %d enums from strings\n", recovered);
	}
	r_list_free (candidates);
	ht_pp_free (candidate_by_name);
	ht_pp_free (class_by_name);
	dart_string_list_free (strings);
}

static int decode_library_cluster_ext(ClusterStream *s, DartCtx *ctx, RList *libraries, ut64 *ref_counter) {
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 10000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Library cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		LibraryInfo *li = R_NEW0 (LibraryInfo);
		li->ref_id = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		li->name_ref = name_ref;
		ut64 skip_refs = 5;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		r_list_append (libraries, li);
		if (ctx->refs && li->ref_id < ctx->refs_count) {
			ctx->refs[li->ref_id] = li;
		}
	}
	return 0;
}

static bool class_has_interface(const DartClassInfo *ci, const char *name, ut64 type_ref) {
	if (!ci || !ci->interfaces) {
		return false;
	}
	RListIter *it;
	DartInterfaceInfo *ii;
	r_list_foreach (ci->interfaces, it, ii) {
		if (!ii) {
			continue;
		}
		if (type_ref > 0 && ii->type_ref == type_ref) {
			return true;
		}
		if (R_STR_ISNOTEMPTY (name) && R_STR_ISNOTEMPTY (ii->name) && !strcmp (name, ii->name)) {
			return true;
		}
	}
	return false;
}

static void resolve_class_interfaces(DartCtx *ctx, RList *class_list, RList *type_list, RList *type_args_list, RList *array_list, DartClassInfo *ci) {
	if (!ci || !ci->interfaces || ci->interfaces_ref == 0) {
		return;
	}
	DartArrayInfo *interfaces = find_array_by_ref (array_list, ci->interfaces_ref);
	if (!interfaces || interfaces->length == 0 || !interfaces->refs) {
		return;
	}
	for (ut64 i = 0; i < interfaces->length; i++) {
		ut64 type_ref = interfaces->refs[i];
		if (type_ref == 0) {
			continue;
		}
		char *name = resolve_type_name (ctx, class_list, type_list, type_args_list, array_list, type_ref);
		ut64 class_ref = 0;
		DartTypeInfo *ti = find_type_by_ref (type_list, type_ref);
		if (ti && ti->kind == kTypeCid) {
			DartClassInfo *target_ci = find_class_by_ref (class_list, ti->type_class_ref);
			if (target_ci) {
				class_ref = target_ci->ref_id;
			}
		} else {
			DartClassInfo *direct_ci = find_class_by_ref (class_list, type_ref);
			if (direct_ci) {
				class_ref = direct_ci->ref_id;
				if (!name && R_STR_ISNOTEMPTY (direct_ci->name)) {
					name = strdup (direct_ci->name);
				}
			}
		}
		if (R_STR_ISEMPTY (name) || class_has_interface (ci, name, type_ref)) {
			free (name);
			continue;
		}
		DartInterfaceInfo *ii = R_NEW0 (DartInterfaceInfo);
		ii->name = name;
		ii->type_ref = type_ref;
		ii->class_ref = class_ref;
		r_list_append (ci->interfaces, ii);
	}
}

static void resolve_class_and_field_names(DartCtx *ctx, RList *class_list, RList *field_list, RList *method_list, RList *type_list, RList *type_args_list, RList *array_list) {
	if (!ctx || !ctx->refs || !class_list) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (!ci) {
			continue;
		}
		if (!ci->name && ci->name_ref > 0 && ci->name_ref < ctx->refs_count) {
			ci->name = dup_ref_string_obf (ctx, ci->name_ref);
		}
		if (ci->super_class_ref > 0 && ci->super_class_ref < ctx->refs_count) {
			void *ref = ctx->refs[ci->super_class_ref];
			if (ref) {
				DartClassInfo *parent = (DartClassInfo *)ref;
				if (parent->name) {
					ci->super_class_name = strdup (parent->name);
					dart_obf_apply (ctx, &ci->super_class_name);
				}
			}
		}
		if (ci->library_ref > 0 && ci->library_ref < ctx->refs_count) {
			void *ref = ctx->refs[ci->library_ref];
			if (ref) {
				LibraryInfo *lib = (LibraryInfo *)ref;
				if (!lib->uri) {
					lib->uri = dup_ref_string_obf (ctx, lib->name_ref);
				}
				if (lib->uri) {
					ci->library_name = strdup (lib->uri);
				}
			}
		}
	}
	r_list_foreach (class_list, it, ci) {
		resolve_class_interfaces (ctx, class_list, type_list, type_args_list, array_list, ci);
	}
	if (method_list) {
		DartMethodInfo *mi;
		r_list_foreach (method_list, it, mi) {
			if (!mi) {
				continue;
			}
			if (!mi->name && mi->name_ref > 0 && mi->name_ref < ctx->refs_count) {
				mi->name = dup_ref_string_obf (ctx, mi->name_ref);
			}
			if (!mi->signature && mi->signature_ref > 0) {
				mi->signature = resolve_type_name (ctx, class_list, type_list, type_args_list, array_list, mi->signature_ref);
			}
			DartClassInfo *owner = find_class_by_ref (class_list, mi->owner_ref);
			if (!owner) {
				continue;
			}
			if (!mi->owner_name && owner->name) {
				mi->owner_name = strdup (owner->name);
			}
			if (!owner->methods) {
				owner->methods = r_list_newf ((RListFree)dart_method_info_free);
			}
			DartMethodInfo *mi_copy = dart_method_info_clone (mi);
			r_list_append (owner->methods, mi_copy);
		}
	}
	if (!field_list) {
		return;
	}
	DartFieldInfo *fi;
	r_list_foreach (field_list, it, fi) {
		if (!fi) {
			continue;
		}
		if (!fi->name && fi->name_ref > 0 && fi->name_ref < ctx->refs_count) {
			fi->name = dup_ref_string_obf (ctx, fi->name_ref);
		}
		if (!fi->type_name && fi->type_ref > 0) {
			fi->type_name = resolve_type_name (ctx, class_list, type_list, type_args_list, array_list, fi->type_ref);
		}
		DartClassInfo *owner = find_class_by_ref (class_list, fi->owner_ref);
		if (owner && owner->fields) {
			DartFieldInfo *fi_copy = dart_field_info_clone (fi);
			r_list_append (owner->fields, fi_copy);
		}
	}
}

int parse_snapshot_header(DartCtx *ctx, ut64 snapshot_base, ut64 *out_nb, ut64 *out_no, ut64 *out_nc, ut64 *out_itlen, ut64 *out_itdata, ut64 *out_total_len, ut64 *out_cluster_start) {
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read (ctx, snapshot_base, &hdr)) {
		return -1;
	}
	*out_nb = hdr.nb;
	*out_no = hdr.no;
	*out_nc = hdr.nc;
	*out_itlen = hdr.itlen;
	*out_itdata = hdr.itdata;
	*out_total_len = hdr.total_len;
	*out_cluster_start = hdr.cluster_start;
	return 0;
}

RList *dart_pool_extract_classes(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	if (find_snapshots (ctx) != 0 || !ctx->iso_data) {
		return NULL;
	}
	ut64 snapshot_base = ctx->iso_data;
	DartVerLayout layout_tmp;
	DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, total_len = 0, cluster_start = 0;
	if (parse_snapshot_header (ctx, snapshot_base, &nb, &no, &nc, &itlen, &itdata, &total_len, &cluster_start) != 0) {
		dart_ctx_fini_layout (ctx, layout_owned);
		return NULL;
	}
	bool header_valid = (nc > 0 && nc < 1000000 && no > 0 && no < 10000000);
	RList *class_list = r_list_newf ((RListFree)dart_class_info_free);
	RList *field_list = r_list_newf ((RListFree)dart_field_info_free);
	RList *method_list = r_list_newf ((RListFree)dart_method_info_free);
	RList *type_list = r_list_newf ((RListFree)dart_type_info_free);
	RList *type_args_list = r_list_newf (free_type_arguments_info);
	RList *array_list = r_list_newf (free_array_info);
	ctx->strings = r_list_newf (free_dart_string);
	RList *libraries = r_list_newf (free_library_info);
	bool modern_classes = false;
	if (header_valid) {
		ctx->num_base_objects = nb;
		ctx->num_objects = no;
		ctx->num_clusters = nc;
		ut64 total_refs = nb + no + 16;
		ctx->refs_count = total_refs;
		ctx->refs = (void **)calloc (total_refs, sizeof (void *));
		modern_classes = dart_modern_extract_classes_from_clusters (ctx, cluster_start, snapshot_base + total_len, nc, class_list);
		if (modern_classes) {
			if (ctx->verbose > 0) {
				int modern_fields = 0;
				int modern_methods = 0;
				RListIter *cit;
				DartClassInfo *mci;
				r_list_foreach (class_list, cit, mci) {
					modern_fields += mci->fields? r_list_length (mci->fields): 0;
					modern_methods += mci->methods? r_list_length (mci->methods): 0;
				}
				fprintf (stderr, "[r2flutter] Extracted classes from modern fill: %d fields=%d methods=%d\n", r_list_length (class_list), modern_fields, modern_methods);
			}
		}
	}
	bool synthetic_legacy_parse = ctx->layout &&
		ctx->layout->tag_style == DART_TAG_STYLE_OBJECT_HEADER &&
		ctx->compressed_word_size == 8 &&
		itlen == 0 &&
		no < 1000 &&
		nc < 100;
	if (synthetic_legacy_parse) {
		for (int i = 0; i < 32; i++) {
			if (ctx->snapshot_hash[i] != '0') {
				synthetic_legacy_parse = false;
				break;
			}
		}
	}
	bool legacy_class_parse = !ctx->layout ||
		ctx->layout->tag_style != DART_TAG_STYLE_OBJECT_HEADER ||
		synthetic_legacy_parse;
	if (header_valid && !modern_classes && legacy_class_parse) {
		ClusterStream stream = {
			.ctx = ctx,
			.cursor = cluster_start,
			.end = snapshot_base + total_len
		};
		ut64 ref_counter = nb + 1;
		for (ut64 ci2 = 0; ci2 < nc && stream.cursor < stream.end; ci2++) {
			uint32_t tags = 0;
			if (!cs_read_u32 (&stream, &tags)) {
				break;
			}
			uint32_t cid = (tags >> 12) & 0xFFFFF;
			bool is_canonical = ((tags >> 1) & 1) != 0;
			(void)is_canonical;
			if (ctx->verbose > 1) {
				fprintf (stderr, "[r2flutter] Cluster %" PRIu64 ": cid=%u (Class=%d,Field=%d,String=%d)\n", ci2, cid, kClassCid, kFieldCid_extract, kOneByteStringCid);
			}
			int rc = 0;
			switch (cid) {
			case kOneByteStringCid:
			case kTwoByteStringCid:
			case kStringCid:
				rc = decode_string_cluster (&stream, ctx, &ref_counter, false);
				break;
			case kClassCid:
				rc = decode_class_cluster_ext (&stream, ctx, class_list, &ref_counter);
				break;
			case kFieldCid_extract:
				rc = decode_field_cluster_ext (&stream, ctx, field_list, &ref_counter);
				break;
			case kFunctionCid:
				rc = decode_function_cluster_ext (&stream, ctx, method_list, &ref_counter);
				if (rc < 0) {
					rc = 0;
					skip_generic_cluster (&stream);
				}
				break;
			case kTypeCid:
				rc = decode_type_cluster_ext (&stream, ctx, type_list, &ref_counter);
				break;
			case kFunctionTypeCid:
				rc = decode_function_type_cluster_ext (&stream, ctx, type_list, &ref_counter);
				if (rc < 0) {
					rc = 0;
					skip_generic_cluster (&stream);
				}
				break;
			case kTypeParameterCid:
				rc = decode_type_parameter_cluster_ext (&stream, ctx, type_list, &ref_counter);
				break;
			case kTypeArgumentsCid:
				rc = decode_type_arguments_cluster_ext (&stream, ctx, type_args_list, &ref_counter);
				if (rc < 0) {
					rc = 0;
					skip_generic_cluster (&stream);
				}
				break;
			case kArrayCid:
			case kImmutableArrayCid:
				rc = decode_array_cluster_ext (&stream, ctx, array_list, &ref_counter);
				if (rc < 0) {
					rc = 0;
					skip_generic_cluster (&stream);
				}
				break;
			case kLibraryCid_extract:
				rc = decode_library_cluster_ext (&stream, ctx, libraries, &ref_counter);
				break;
			default:
				skip_generic_cluster (&stream);
				break;
			}
			if (rc < 0) {
				break;
			}
		}
		resolve_class_and_field_names (ctx, class_list, field_list, method_list, type_list, type_args_list, array_list);
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] Extracted fields from clusters: %d\n", r_list_length (field_list));
		}
	} else if (header_valid && !modern_classes && ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] class extraction: ObjectHeader fill parser unavailable for cws=%d, using string fallback\n", ctx->compressed_word_size);
	} else if (!header_valid) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] class extraction: skipping cluster parse (clusters=%" PRIu64 " objs=%" PRIu64 ")\n", nc, no);
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Extracted classes from clusters: %d\n", r_list_length (class_list));
	}
	if (r_list_length (class_list) == 0) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] Falling back to string-based type extraction\n");
		}
		ut64 scan_start = ctx->vm_data;
		ut64 scan_end = ctx->iso_data;
		if (scan_end > scan_start && (scan_end - scan_start) < 0x1000000) {
			ut64 pos = scan_start;
			int class_count = 0;
			while (pos < scan_end - 4 && class_count < 4000) {
				ut8 buf[128];
				int to_read = (scan_end - pos > 127)? 127: (int) (scan_end - pos);
				if (!read_mem (ctx, pos, buf, to_read)) {
					break;
				}
				int slen = 0;
				while (slen < to_read && IS_PRINTABLE (buf[slen])) {
					slen++;
				}
				if (slen >= 3 && slen < to_read && slen < 80 && !IS_PRINTABLE (buf[slen])) {
					char saved = buf[slen];
					buf[slen] = 0;
					char *s = (char *)buf;
					if (is_type_name_candidate (s)) {
						DartClassInfo *ci = R_NEW0 (DartClassInfo);
						ci->name = strdup (s);
						dart_obf_apply (ctx, &ci->name);
						ci->ref_id = 0;
						ci->instance_size = 0;
						ci->flags = 0;
						ci->fields = r_list_newf ((RListFree)dart_field_info_free);
						ci->interfaces = r_list_newf (dart_interface_info_free);
						r_list_append (class_list, ci);
						class_count++;
					}
					buf[slen] = saved;
					pos += slen + 1;
				} else {
					pos++;
				}
			}
		}
	}
	free (ctx->refs);
	ctx->refs = NULL;
	ctx->refs_count = 0;
	r_list_free (ctx->strings);
	ctx->strings = NULL;
	r_list_free (libraries);
	r_list_free (array_list);
	r_list_free (type_args_list);
	r_list_free (type_list);
	r_list_free (method_list);
	r_list_free (field_list);
	if (ctx->dump_fields && r_list_length (class_list) > 0) {
		ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
		ut64 data_image_base = snapshot_base + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
		ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: (data_image_base + (4ULL << 20));
		scan_fields_from_data_image (ctx, class_list, data_image_base, data_image_end);
		scan_methods_from_data_image (ctx, class_list, data_image_base, data_image_end);
		if (ctx->vm_data) {
			ut64 vm_nb = 0, vm_no = 0, vm_nc = 0, vm_itlen = 0, vm_itdata = 0, vm_total = 0, vm_cluster = 0;
			if (parse_snapshot_header (ctx, ctx->vm_data, &vm_nb, &vm_no, &vm_nc, &vm_itlen, &vm_itdata, &vm_total, &vm_cluster) == 0) {
				ut64 vm_data_base = ctx->vm_data + ((vm_total + (kAlign - 1)) & ~ (kAlign - 1));
				ut64 vm_data_end = ctx->vm_instr? ctx->vm_instr: (vm_data_base + (4ULL << 20));
				scan_fields_from_data_image (ctx, class_list, vm_data_base, vm_data_end);
				scan_methods_from_data_image (ctx, class_list, vm_data_base, vm_data_end);
			}
		}
	}
	dart_ctx_fini_layout (ctx, layout_owned);
	return class_list;
}

static void dump_class_json(PJ *pj, const DartClassInfo *ci) {
	pj_o (pj);
	pj_kn (pj, "ref", ci->ref_id);
	if (ci->name) {
		pj_ks (pj, "name", ci->name);
	}
	if (ci->library_name || ci->library_ref) {
		pj_k (pj, "library");
		pj_o (pj);
		pj_kn (pj, "ref", ci->library_ref);
		if (ci->library_name) {
			pj_ks (pj, "name", ci->library_name);
		}
		pj_end (pj);
	}
	if (ci->super_class_name || ci->super_class_ref) {
		pj_k (pj, "super");
		pj_o (pj);
		pj_kn (pj, "ref", ci->super_class_ref);
		if (ci->super_class_name) {
			pj_ks (pj, "name", ci->super_class_name);
		}
		pj_end (pj);
	}
	if (ci->interfaces && r_list_length (ci->interfaces) > 0) {
		pj_ka (pj, "interfaces");
		RListIter *iit;
		DartInterfaceInfo *ii;
		r_list_foreach (ci->interfaces, iit, ii) {
			if (!ii) {
				continue;
			}
			pj_o (pj);
			if (ii->type_ref > 0) {
				pj_kn (pj, "ref", ii->type_ref);
			}
			if (ii->class_ref > 0) {
				pj_kn (pj, "class_ref", ii->class_ref);
			}
			if (ii->name) {
				pj_ks (pj, "name", ii->name);
			}
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_k (pj, "layout");
	pj_o (pj);
	pj_ki (pj, "instance_size", ci->instance_size);
	pj_ki (pj, "type_params", ci->num_type_parameters);
	pj_ki (pj, "type_arg_offset", ci->type_argument_offset);
	pj_end (pj);
	pj_k (pj, "flags");
	pj_o (pj);
	pj_kb (pj, "abstract", (ci->flags & DART_CLASS_ABSTRACT) != 0);
	pj_kb (pj, "enum", (ci->flags & DART_CLASS_ENUM) != 0);
	pj_kb (pj, "mixin", (ci->flags & DART_CLASS_MIXIN) != 0);
	pj_kb (pj, "toplevel", (ci->flags & DART_CLASS_TOPLEVEL) != 0);
	pj_end (pj);
	if (ci->enums && r_list_length (ci->enums) > 0) {
		pj_ka (pj, "enums");
		RListIter *eit;
		char *value;
		r_list_foreach (ci->enums, eit, value) {
			if (value) {
				pj_s (pj, value);
			}
		}
		pj_end (pj);
	}
	if (ci->fields && r_list_length (ci->fields) > 0) {
		pj_ka (pj, "fields");
		RListIter *fit;
		DartFieldInfo *fi;
		r_list_foreach (ci->fields, fit, fi) {
			pj_o (pj);
			if (fi->name) {
				pj_ks (pj, "name", fi->name);
			}
			if (fi->type_name) {
				pj_ks (pj, "type", fi->type_name);
			}
			pj_ki (pj, "offset", fi->offset);
			pj_k (pj, "flags");
			pj_o (pj);
			pj_kb (pj, "static", (fi->flags & DART_FIELD_STATIC) != 0);
			pj_kb (pj, "final", (fi->flags & DART_FIELD_FINAL) != 0);
			pj_kb (pj, "const", (fi->flags & DART_FIELD_CONST) != 0);
			pj_kb (pj, "late", (fi->flags & DART_FIELD_LATE) != 0);
			pj_end (pj);
			pj_end (pj);
		}
		pj_end (pj);
	}
	if (ci->methods && r_list_length (ci->methods) > 0) {
		pj_ka (pj, "methods");
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			pj_o (pj);
			if (mi->name) {
				pj_ks (pj, "name", mi->name);
			}
			pj_kn (pj, "entry", mi->entry_point);
			if (mi->owner_name) {
				pj_ks (pj, "owner", mi->owner_name);
			}
			if (mi->signature) {
				pj_ks (pj, "signature", mi->signature);
			}
			pj_kn (pj, "kind_tag", mi->kind_tag);
			pj_ks (pj, "kind", method_kind_name (mi->kind_tag));
			pj_end (pj);
		}
		pj_end (pj);
	}
	pj_end (pj);
}

static void append_enum_values(RStrBuf *sb, const DartClassInfo *ci) {
	if (!sb || !ci || !ci->enums || r_list_length (ci->enums) == 0) {
		return;
	}
	char *joined = r_str_list_join (ci->enums, ", ");
	if (!joined) {
		return;
	}
	r_strbuf_append (sb, " { ");
	r_strbuf_append (sb, joined);
	r_strbuf_append (sb, " }");
	free (joined);
}

static void append_interfaces_text(RStrBuf *sb, const DartClassInfo *ci) {
	if (!sb || !ci || !ci->interfaces || r_list_length (ci->interfaces) == 0) {
		return;
	}
	bool first = true;
	RListIter *it;
	DartInterfaceInfo *ii;
	r_list_foreach (ci->interfaces, it, ii) {
		if (!ii || R_STR_ISEMPTY (ii->name)) {
			continue;
		}
		if (first) {
			r_strbuf_append (sb, " implements ");
			first = false;
		} else {
			r_strbuf_append (sb, ", ");
		}
		r_strbuf_append (sb, ii->name);
	}
}

static char *class_export_name(const char *name) {
	char *safe = r_str_newf ("dart_%s", R_STR_ISNOTEMPTY (name)? name: "unknown");
	r_name_filter (safe, 0);
	for (char *p = safe; *p; p++) {
		if (*p == '.' || *p == ':') {
			*p = '_';
		}
	}
	if (R_STR_ISEMPTY (safe)) {
		free (safe);
		return strdup ("dart_unknown");
	}
	return safe;
}

static char *member_export_name(const char *name, const char *fallback) {
	char *safe = strdup (R_STR_ISNOTEMPTY (name)? name: fallback);
	r_name_filter (safe, 0);
	for (char *p = safe; *p; p++) {
		if (*p == '.' || *p == ':') {
			*p = '_';
		}
	}
	if (isdigit ((ut8)*safe)) {
		char *prefixed = r_str_newf ("%s_%s", fallback, safe);
		free (safe);
		safe = prefixed;
	}
	if (R_STR_ISEMPTY (safe)) {
		free (safe);
		return strdup (fallback);
	}
	return safe;
}

static ut64 method_export_addr(const DartMethodInfo *mi) {
	if (!mi || !mi->entry_point) {
		return 0;
	}
	return mi->entry_point & 1ULL? mi->entry_point - 1: mi->entry_point;
}

#define DART_FUNCTION_STATIC_BIT (1U << 16)

static bool method_is_static(const DartMethodInfo *mi) {
	if (!mi) {
		return false;
	}
	if (mi->kind_tag & DART_FUNCTION_STATIC_BIT) {
		return true;
	}
	return !strcmp (method_kind_name (mi->kind_tag), "ImplicitStaticGetter");
}

static bool method_has_receiver(const DartClassInfo *ci, const DartMethodInfo *mi) {
	if (!ci || !mi || method_is_static (mi)) {
		return false;
	}
	switch (mi->kind_tag & 0x1f) {
	case 0: /* RegularFunction */
	case 3: /* GetterFunction */
	case 4: /* SetterFunction */
	case 5: /* Constructor */
	case 6: /* ImplicitGetter */
	case 7: /* ImplicitSetter */
	case 10: /* MethodExtractor */
	case 11: /* NoSuchMethodDispatcher */
	case 12: /* InvokeFieldDispatcher */
	case 14: /* DynamicInvocationForwarder */
	case 16: /* RecordFieldGetter */
		return true;
	default:
		return false;
	}
}

static const char *method_mode_name(const DartMethodInfo *mi) {
	if (!mi) {
		return "unknown";
	}
	const bool is_static = method_is_static (mi);
	const char *kind = method_kind_name (mi->kind_tag);
	if (!strcmp (kind, "Constructor")) {
		return is_static? "factory": "constructor";
	}
	return is_static? "static": "instance";
}

static char *method_dyncc(const DartClassInfo *ci, const DartMethodInfo *mi) {
	return r_str_newf ("dyncc:x0+8,^:x0%s", method_has_receiver (ci, mi)? "!T0": "");
}

static const char *field_c_type(const DartFieldInfo *fi) {
	if (!fi || R_STR_ISEMPTY (fi->type_name)) {
		return "uint64_t";
	}
	if (!strcmp (fi->type_name, "double")) {
		return "double";
	}
	if (!strcmp (fi->type_name, "int")) {
		return "int64_t";
	}
	return "void *";
}

static void append_c_padding(RStrBuf *sb, ut32 *cursor, ut32 target, int *pad_idx) {
	if (!sb || !cursor || !pad_idx || target <= *cursor) {
		return;
	}
	r_strbuf_appendf (sb, " uint8_t _pad%d[0x%x];", *pad_idx, target - *cursor);
	(*pad_idx)++;
	*cursor = target;
}

static void append_class_struct_members(RStrBuf *sb, const DartClassInfo *ci) {
	if (!sb || !ci || !ci->fields || r_list_length (ci->fields) == 0) {
		return;
	}
	ut32 cursor = 0;
	int pad_idx = 0;
	RListIter *fit;
	DartFieldInfo *fi;
	r_list_foreach (ci->fields, fit, fi) {
		if (!fi || R_STR_ISEMPTY (fi->name) || (fi->flags & DART_FIELD_STATIC)) {
			continue;
		}
		if (ci->instance_size > 0 && fi->offset >= ci->instance_size) {
			continue;
		}
		if (fi->offset < cursor) {
			continue;
		}
		append_c_padding (sb, &cursor, fi->offset, &pad_idx);
		char *field_name = member_export_name (fi->name, "field");
		r_strbuf_appendf (sb, " %s %s;", field_c_type (fi), field_name);
		cursor = fi->offset + 8;
		free (field_name);
	}
}

static void append_comment_cmd(RStrBuf *sb, ut64 addr, const char *msg) {
	if (!sb || !addr || R_STR_ISEMPTY (msg)) {
		return;
	}
	char *b64 = r_base64_encode_dyn ((const ut8 *)msg, strlen (msg));
	if (!b64) {
		return;
	}
	r_strbuf_appendf (sb, "CCu base64:%s @ 0x%" PFMT64x "\n", b64, addr);
	free (b64);
}

static void append_ic_inheritance_cmd(RStrBuf *sb, const char *class_name, const char *base_name) {
	if (!sb || R_STR_ISEMPTY (class_name) || R_STR_ISEMPTY (base_name)) {
		return;
	}
	r_strbuf_appendf (sb, "ic+%s @ 0\n", base_name);
	r_strbuf_appendf (sb, "ic+%s:%s\n", class_name, base_name);
}

static void append_ic_field_cmd(RStrBuf *sb, const char *class_name, const DartFieldInfo *fi) {
	if (!sb || R_STR_ISEMPTY (class_name) || !fi || R_STR_ISEMPTY (fi->name)) {
		return;
	}
	char *field_name = member_export_name (fi->name, "field");
	r_strbuf_appendf (sb, "ic+%s..%s %s @ 0x%x\n", class_name, field_name, field_c_type (fi), fi->offset);
	free (field_name);
}

static void append_ic_method_cmd(RStrBuf *sb, const char *class_name, const char *method_name, ut64 addr) {
	if (!sb || R_STR_ISEMPTY (class_name) || R_STR_ISEMPTY (method_name)) {
		return;
	}
	r_strbuf_appendf (sb, "ic+%s.%s @ 0x%" PFMT64x "\n", class_name, method_name, addr);
}

static void dump_class_r2_metadata(RStrBuf *sb, const DartClassInfo *ci, bool quiet) {
	if (!sb || !ci || R_STR_ISEMPTY (ci->name)) {
		return;
	}
	char *class_name = class_export_name (ci->name);
	if (!quiet) {
		r_strbuf_appendf (sb, "# r2 class %s original=%s\n", class_name, ci->name);
	}
	r_strbuf_appendf (sb, "ic+%s @ 0\n", class_name);
	r_strbuf_appendf (sb, "ac %s\n", class_name);
#if 0
	// TOO SLOW
	r_strbuf_appendf (sb, "af @ 0x%" PFMT64x "\n", addr);
	r_strbuf_appendf (sb, "afc %s @ 0x%" PFMT64x "\n", cc, addr);
#endif
	if (R_STR_ISNOTEMPTY (ci->super_class_name)) {
		char *super_name = class_export_name (ci->super_class_name);
		append_ic_inheritance_cmd (sb, class_name, super_name);
		r_strbuf_appendf (sb, "ac %s\n", super_name);
		r_strbuf_appendf (sb, "acb %s %s 0\n", class_name, super_name);
		free (super_name);
	}
	if (ci->interfaces) {
		RListIter *iit;
		DartInterfaceInfo *ii;
		r_list_foreach (ci->interfaces, iit, ii) {
			if (!ii || R_STR_ISEMPTY (ii->name)) {
				continue;
			}
			char *iface_name = class_export_name (ii->name);
			if (!quiet) {
				r_strbuf_appendf (sb, "# interface %s implements %s\n", class_name, ii->name);
			}
			append_ic_inheritance_cmd (sb, class_name, iface_name);
			r_strbuf_appendf (sb, "ac %s\n", iface_name);
			r_strbuf_appendf (sb, "acb %s %s 0\n", class_name, iface_name);
			free (iface_name);
		}
	}
	if (ci->fields) {
		RListIter *fit;
		DartFieldInfo *fi;
		r_list_foreach (ci->fields, fit, fi) {
			if (!fi || R_STR_ISEMPTY (fi->name)) {
				continue;
			}
			if (!quiet) {
				r_strbuf_appendf (sb, "# field %s.%s +0x%x type=%s %s%s%s%s\n", class_name, fi->name, fi->offset, R_STR_ISNOTEMPTY (fi->type_name)? fi->type_name: "dynamic", (fi->flags & DART_FIELD_STATIC)? "static": "instance", (fi->flags & DART_FIELD_FINAL)? " final": "", (fi->flags & DART_FIELD_CONST)? " const": "", (fi->flags & DART_FIELD_LATE)? " late": "");
			}
			append_ic_field_cmd (sb, class_name, fi);
		}
	}
	if (ci->methods) {
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			if (!mi || R_STR_ISEMPTY (mi->name)) {
				continue;
			}
			char *method_name = member_export_name (mi->name, "method");
			char *cc = method_dyncc (ci, mi);
			ut64 addr = method_export_addr (mi);
			append_ic_method_cmd (sb, class_name, method_name, addr);
			if (!quiet) {
				r_strbuf_appendf (sb, "# method %s.%s kind=%s mode=%s cc=%s", class_name, method_name, method_kind_name (mi->kind_tag), method_mode_name (mi), cc);
				if (R_STR_ISNOTEMPTY (mi->signature)) {
					r_strbuf_appendf (sb, " signature=%s", mi->signature);
				}
				r_strbuf_append (sb, "\n");
			}
			if (addr) {
				r_strbuf_appendf (sb, "acm %s %s 0x%" PFMT64x "\n", class_name, method_name, addr);
				if (!quiet) {
					char *msg = r_str_newf ("dart: method %s.%s kind=%s mode=%s cc=%s%s%s",
						ci->name,
						mi->name,
						method_kind_name (mi->kind_tag),
						method_mode_name (mi),
						cc,
						R_STR_ISNOTEMPTY (mi->signature)? " signature=": "",
						R_STR_ISNOTEMPTY (mi->signature)? mi->signature: "");
					append_comment_cmd (sb, addr, msg);
					free (msg);
				}
			}
			free (cc);
			free (method_name);
		}
	}
	free (class_name);
}

static void dump_class_text(RStrBuf *sb, const DartClassInfo *ci, int fmt, bool type_view, bool quiet) {
	if (!ci || !ci->name) {
		return;
	}
	const bool emit_r2 = fmt == 'r';
	const bool emit_enum_literal = type_view &&
		(ci->flags & DART_CLASS_ENUM) &&
		ci->enums &&
		r_list_length (ci->enums) > 0;
	if (emit_r2) {
		char *safe_name = class_export_name (ci->name);
		if (emit_enum_literal) {
			if (!quiet) {
				r_strbuf_appendf (sb, "# enum %s", ci->name);
				append_enum_values (sb, ci);
				r_strbuf_append (sb, "\n");
			}
			r_strbuf_appendf (sb, "\"td struct %s { };\"\n", safe_name);
			free (safe_name);
			return;
		}
		if (!quiet) {
			r_strbuf_appendf (sb, "# class %s", ci->name);
			if (ci->super_class_name) {
				r_strbuf_appendf (sb, " extends %s", ci->super_class_name);
			}
			append_interfaces_text (sb, ci);
			r_strbuf_appendf (sb, " (size=%u", ci->instance_size);
			if (ci->flags & DART_CLASS_ABSTRACT) {
				r_strbuf_append (sb, " abstract");
			}
			if (ci->flags & DART_CLASS_ENUM) {
				r_strbuf_append (sb, " enum");
			}
			if (ci->flags & DART_CLASS_MIXIN) {
				r_strbuf_append (sb, " mixin");
			}
			r_strbuf_append (sb, ")\n");
			if (ci->library_name) {
				r_strbuf_appendf (sb, "#   library: %s\n", ci->library_name);
			}
			if (ci->num_type_parameters > 0) {
				r_strbuf_appendf (sb, "#   type_params: %u\n", ci->num_type_parameters);
			}
		}
		r_strbuf_appendf (sb, "\"td struct %s {", safe_name);
		append_class_struct_members (sb, ci);
		r_strbuf_append (sb, " };\"\n");
		if (!quiet && ci->methods && r_list_length (ci->methods) > 0) {
			RListIter *mit;
			DartMethodInfo *mi;
			r_list_foreach (ci->methods, mit, mi) {
				r_strbuf_appendf (sb, "#   method 0x%08" PFMT64x " %s", (ut64)mi->entry_point, r_str_get (mi->name));
				if (R_STR_ISNOTEMPTY (mi->signature)) {
					r_strbuf_appendf (sb, " %s", mi->signature);
				}
				r_strbuf_appendf (sb, " (%s)\n", method_kind_name (mi->kind_tag));
			}
		}
		free (safe_name);
		return;
	}
	if (emit_enum_literal) {
		r_strbuf_appendf (sb, "enum %s", ci->name);
		append_enum_values (sb, ci);
		r_strbuf_append (sb, "\n");
		return;
	}
	r_strbuf_appendf (sb, "class %s", ci->name);
	if (ci->super_class_name) {
		r_strbuf_appendf (sb, " extends %s", ci->super_class_name);
	}
	append_interfaces_text (sb, ci);
	r_strbuf_appendf (sb, " (size=%u", ci->instance_size);
	if (ci->flags & DART_CLASS_ABSTRACT) {
		r_strbuf_append (sb, " abstract");
	}
	if (ci->flags & DART_CLASS_ENUM) {
		r_strbuf_append (sb, " enum");
	}
	if (ci->flags & DART_CLASS_MIXIN) {
		r_strbuf_append (sb, " mixin");
	}
	r_strbuf_append (sb, ")\n");
	if (quiet) {
		return;
	}
	if (ci->library_name) {
		r_strbuf_appendf (sb, "  library: %s\n", ci->library_name);
	}
	if (ci->fields && r_list_length (ci->fields) > 0) {
		r_strbuf_append (sb, "  fields:\n");
		RListIter *fit;
		DartFieldInfo *fi;
		r_list_foreach (ci->fields, fit, fi) {
			r_strbuf_appendf (sb, "    +0x%x %s %s", fi->offset, r_str_get (fi->type_name), r_str_get (fi->name));
			if (fi->flags & DART_FIELD_STATIC) {
				r_strbuf_append (sb, " static");
			}
			if (fi->flags & DART_FIELD_FINAL) {
				r_strbuf_append (sb, " final");
			}
			if (fi->flags & DART_FIELD_CONST) {
				r_strbuf_append (sb, " const");
			}
			r_strbuf_append (sb, "\n");
		}
	}
	if (ci->methods && r_list_length (ci->methods) > 0) {
		r_strbuf_append (sb, "  methods:\n");
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			r_strbuf_appendf (sb, "    0x%08" PFMT64x " %s", (ut64)mi->entry_point, r_str_get (mi->name));
			if (R_STR_ISNOTEMPTY (mi->signature)) {
				r_strbuf_appendf (sb, " %s", mi->signature);
			}
			r_strbuf_appendf (sb, " (%s)\n", method_kind_name (mi->kind_tag));
		}
	}
}

char *dart_pool_dump_classes(DartCtx *ctx, int fmt) {
	RList *classes = dart_pool_extract_classes (ctx);
	const bool type_view = ctx && ctx->dump_classes == 3;
	if (!classes && type_view) {
		classes = r_list_newf ((RListFree)dart_class_info_free);
	}
	if (classes && type_view) {
		recover_enum_types_from_strings (ctx, classes);
	}
	if (fmt == 'j') {
		if (!classes || r_list_length (classes) == 0) {
			dart_class_list_free (classes);
			return strdup ("[]");
		}
		PJ *pj = pj_new ();
		pj_a (pj);
		RListIter *it;
		DartClassInfo *ci;
		r_list_foreach (classes, it, ci) {
			if (ci) {
				dump_class_json (pj, ci);
			}
		}
		pj_end (pj);
		dart_class_list_free (classes);
		return pj_drain (pj);
	}
	if (!classes) {
		return strdup ("# No classes found\n");
	}
	const bool quiet = ctx && ctx->quiet;
	RStrBuf *sb = r_strbuf_new (fmt == 'r' && !quiet? "# Dart classes extracted from snapshot\n": "");
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (classes, it, ci) {
		dump_class_text (sb, ci, fmt, type_view, quiet);
	}
	if (fmt == 'r') {
		if (!quiet) {
			r_strbuf_append (sb, "# Dart class symbols and analysis metadata\n");
		}
		r_list_foreach (classes, it, ci) {
			dump_class_r2_metadata (sb, ci, quiet);
		}
	}
	dart_class_list_free (classes);
	return r_strbuf_drain (sb);
}

static RBinClass *core_bin_get_class(RCore *core, const char *class_name) {
	if (!core || R_STR_ISEMPTY (class_name)) {
		return NULL;
	}
	RList *klasses = r_bin_get_classes (core->bin);
	if (!klasses) {
		return NULL;
	}
	RListIter *it;
	RBinClass *klass;
	r_list_foreach (klasses, it, klass) {
		if (!klass || !klass->name) {
			continue;
		}
		const char *name = r_bin_name_tostring (klass->name);
		if (name && !strcmp (name, class_name)) {
			return klass;
		}
	}
	return NULL;
}

static RBinClass *core_bin_get_or_add_class(RCore *core, const char *class_name, const DartClassInfo *ci) {
	RBinClass *klass = core_bin_get_class (core, class_name);
	if (klass) {
		return klass;
	}
	RList *klasses = r_bin_get_classes (core->bin);
	if (!klasses) {
		return NULL;
	}
	klass = r_bin_class_new (class_name, NULL, 0);
	if (!klass) {
		return NULL;
	}
	klass->origin = R_BIN_CLASS_ORIGIN_USER;
	klass->addr = 0;
	klass->instance_size = ci? ci->instance_size: 0;
	klass->index = r_list_length (klasses);
	r_list_append (klasses, klass);
	return klass;
}

static bool bin_class_has_method(RBinClass *klass, const char *method_name) {
	if (!klass || R_STR_ISEMPTY (method_name)) {
		return false;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (&klass->methods, sym) {
		if (!sym || !sym->name) {
			continue;
		}
		const char *name = r_bin_name_tostring (sym->name);
		if (name && !strcmp (name, method_name)) {
			return true;
		}
	}
	return false;
}

static bool bin_class_has_field(RBinClass *klass, const char *field_name) {
	if (!klass || R_STR_ISEMPTY (field_name)) {
		return false;
	}
	RBinField *field;
	R_VEC_FOREACH (&klass->fields, field) {
		if (!field || !field->name) {
			continue;
		}
		const char *name = r_bin_name_tostring (field->name);
		if (name && !strcmp (name, field_name)) {
			return true;
		}
	}
	return false;
}

static void core_apply_bin_field(RBinClass *klass, const DartFieldInfo *fi, int *count) {
	if (!klass || !fi || R_STR_ISEMPTY (fi->name)) {
		return;
	}
	char *field_name = member_export_name (fi->name, "field");
	if (bin_class_has_field (klass, field_name)) {
		free (field_name);
		return;
	}
	char *comment = r_str_newf ("dart field type=%s offset=0x%x%s%s%s%s",
		R_STR_ISNOTEMPTY (fi->type_name)? fi->type_name: "dynamic",
		fi->offset,
		(fi->flags & DART_FIELD_STATIC)? " static": "",
		(fi->flags & DART_FIELD_FINAL)? " final": "",
		(fi->flags & DART_FIELD_CONST)? " const": "",
		(fi->flags & DART_FIELD_LATE)? " late": "");
	RBinField *field = RVecRBinField_emplace_back (&klass->fields);
	if (field) {
		memset (field, 0, sizeof (*field));
		field->name = r_bin_name_new (field_name);
		field->comment = comment;
		comment = NULL;
		field->vaddr = fi->offset;
		field->paddr = fi->offset;
		field->value = fi->offset;
		field->size = 8;
		field->offset = fi->offset;
		field->kind = R_BIN_FIELD_KIND_FIELD;
		field->type = r_bin_name_new (R_STR_ISNOTEMPTY (fi->type_name)? fi->type_name: "dynamic");
		(*count)++;
	}
	free (comment);
	free (field_name);
}

static void core_apply_bin_method(RBinClass *klass, const DartMethodInfo *mi, int *count) {
	ut64 addr = method_export_addr (mi);
	if (!klass || !mi || R_STR_ISEMPTY (mi->name)) {
		return;
	}
	char *method_name = member_export_name (mi->name, "method");
	if (bin_class_has_method (klass, method_name)) {
		free (method_name);
		return;
	}
	RBinSymbol *sym = RVecRBinSymbol_emplace_back (&klass->methods);
	if (sym) {
		memset (sym, 0, sizeof (*sym));
		sym->name = r_bin_name_new (method_name);
		sym->classname = strdup (r_bin_name_tostring (klass->name));
		sym->type = "method";
		sym->paddr = addr;
		sym->vaddr = addr;
		sym->size = 0;
		(*count)++;
	}
	free (method_name);
}

static void core_apply_anal_class(RCore *core, const DartClassInfo *ci, const char *class_name, int *method_count) {
	if (!core || !ci || R_STR_ISEMPTY (class_name)) {
		return;
	}
	if (!r_anal_class_exists (core->anal, class_name)) {
		r_anal_class_create (core->anal, class_name);
	}
	if (R_STR_ISNOTEMPTY (ci->super_class_name)) {
		char *super_name = class_export_name (ci->super_class_name);
		if (!r_anal_class_exists (core->anal, super_name)) {
			r_anal_class_create (core->anal, super_name);
		}
		RAnalBaseClass base = {
			.id = strdup (super_name),
			.offset = 0,
			.class_name = strdup (super_name),
};
		r_anal_class_base_set (core->anal, class_name, &base);
		r_anal_class_base_fini (&base);
		free (super_name);
	}
	if (ci->interfaces) {
		RListIter *iit;
		DartInterfaceInfo *ii;
		r_list_foreach (ci->interfaces, iit, ii) {
			if (!ii || R_STR_ISEMPTY (ii->name)) {
				continue;
			}
			char *iface_name = class_export_name (ii->name);
			if (!r_anal_class_exists (core->anal, iface_name)) {
				r_anal_class_create (core->anal, iface_name);
			}
			RAnalBaseClass base = {
				.id = strdup (iface_name),
				.offset = 0,
				.class_name = strdup (iface_name),
};
			r_anal_class_base_set (core->anal, class_name, &base);
			r_anal_class_base_fini (&base);
			free (iface_name);
		}
	}
	if (ci->methods) {
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			ut64 addr = method_export_addr (mi);
			if (!mi || R_STR_ISEMPTY (mi->name) || !addr) {
				continue;
			}
			char *method_name = member_export_name (mi->name, "method");
			RAnalMethod method = {
				.name = method_name,
				.addr = addr,
				.vtable_offset = -1,
};
			if (r_anal_class_method_set (core->anal, class_name, &method) == R_ANAL_CLASS_ERR_SUCCESS) {
				(*method_count)++;
			}
			free (method_name);
		}
	}
}

static void core_apply_type(RCore *core, const DartClassInfo *ci, const char *class_name, int *field_count) {
	if (!core || !ci || R_STR_ISEMPTY (class_name)) {
		return;
	}
	RAnalBaseType *type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	if (!type) {
		return;
	}
	type->name = strdup (class_name);
	type->size = ci->instance_size;
	if (ci->fields) {
		RListIter *fit;
		DartFieldInfo *fi;
		r_list_foreach (ci->fields, fit, fi) {
			if (!fi || R_STR_ISEMPTY (fi->name) || (fi->flags & DART_FIELD_STATIC)) {
				continue;
			}
			if (ci->instance_size > 0 && fi->offset >= ci->instance_size) {
				continue;
			}
			char *field_name = member_export_name (fi->name, "field");
			RAnalStructMember member = {
				.name = field_name,
				.type = strdup (field_c_type (fi)),
				.offset = fi->offset,
				.size = 64,
};
			RAnalStructMember *slot = RVecAnalStructMember_emplace_back (&type->struct_data.members);
			if (slot) {
				*slot = member;
				(*field_count)++;
			} else {
				anal_struct_member_fini (&member);
			}
		}
	}
	r_anal_save_base_type (core->anal, type);
	r_anal_base_type_free (type);
}

static void core_apply_method_comments(RCore *core, const DartClassInfo *ci, const char *class_name) {
	if (!core || !ci || !ci->methods) {
		return;
	}
	RListIter *mit;
	DartMethodInfo *mi;
	r_list_foreach (ci->methods, mit, mi) {
		ut64 addr = method_export_addr (mi);
		if (!mi || R_STR_ISEMPTY (mi->name) || !addr) {
			continue;
		}
		char *cc = method_dyncc (ci, mi);
		char *msg = r_str_newf ("dart: method %s.%s kind=%s mode=%s cc=%s%s%s",
			R_STR_ISNOTEMPTY (class_name)? class_name: ci->name,
			mi->name,
			method_kind_name (mi->kind_tag),
			method_mode_name (mi),
			cc,
			R_STR_ISNOTEMPTY (mi->signature)? " signature=": "",
			R_STR_ISNOTEMPTY (mi->signature)? mi->signature: "");
		r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, msg);
		free (msg);
		free (cc);
	}
}

static void core_apply_ic_command(RCore *core, char *cmd) {
	if (!core || R_STR_ISEMPTY (cmd)) {
		free (cmd);
		return;
	}
	r_core_cmd0 (core, cmd);
	free (cmd);
}

static void core_apply_ic_inheritance(RCore *core, const char *class_name, const char *base_name) {
	if (!core || R_STR_ISEMPTY (class_name) || R_STR_ISEMPTY (base_name)) {
		return;
	}
	core_apply_ic_command (core, r_str_newf ("ic+%s @ 0", base_name));
	core_apply_ic_command (core, r_str_newf ("ic+%s:%s", class_name, base_name));
}

static void core_apply_ic_field(RCore *core, const char *class_name, const DartFieldInfo *fi) {
	if (!core || R_STR_ISEMPTY (class_name) || !fi || R_STR_ISEMPTY (fi->name)) {
		return;
	}
	char *field_name = member_export_name (fi->name, "field");
	core_apply_ic_command (core, r_str_newf ("ic+%s..%s %s @ 0x%x", class_name, field_name, field_c_type (fi), fi->offset));
	free (field_name);
}

static void core_apply_ic_method(RCore *core, const char *class_name, const DartMethodInfo *mi) {
	if (!core || R_STR_ISEMPTY (class_name) || !mi || R_STR_ISEMPTY (mi->name)) {
		return;
	}
	char *method_name = member_export_name (mi->name, "method");
	ut64 addr = method_export_addr (mi);
	core_apply_ic_command (core, r_str_newf ("ic+%s.%s @ 0x%" PFMT64x, class_name, method_name, addr));
	free (method_name);
}

static void core_apply_ic_class(RCore *core, const DartClassInfo *ci, const char *class_name) {
	if (!core || !ci || R_STR_ISEMPTY (class_name)) {
		return;
	}
	core_apply_ic_command (core, r_str_newf ("ic+%s @ 0", class_name));
	if (R_STR_ISNOTEMPTY (ci->super_class_name)) {
		char *super_name = class_export_name (ci->super_class_name);
		core_apply_ic_inheritance (core, class_name, super_name);
		free (super_name);
	}
	if (ci->interfaces) {
		RListIter *iit;
		DartInterfaceInfo *ii;
		r_list_foreach (ci->interfaces, iit, ii) {
			if (!ii || R_STR_ISEMPTY (ii->name)) {
				continue;
			}
			char *iface_name = class_export_name (ii->name);
			core_apply_ic_inheritance (core, class_name, iface_name);
			free (iface_name);
		}
	}
	if (ci->fields) {
		RListIter *fit;
		DartFieldInfo *fi;
		r_list_foreach (ci->fields, fit, fi) {
			core_apply_ic_field (core, class_name, fi);
		}
	}
	if (ci->methods) {
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			core_apply_ic_method (core, class_name, mi);
		}
	}
}

int dart_pool_apply_classes_to_core(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return 0;
	}
	RList *classes = dart_pool_extract_classes (ctx);
	if (!classes) {
		return 0;
	}
	int class_count = 0;
	int field_count = 0;
	int method_count = 0;
	int type_field_count = 0;
	int anal_method_count = 0;
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (classes, it, ci) {
		if (!ci || R_STR_ISEMPTY (ci->name)) {
			continue;
		}
		char *class_name = class_export_name (ci->name);
		RBinClass *bin_class = core_bin_get_or_add_class (ctx->core, class_name, ci);
		if (bin_class && ci->fields) {
			RListIter *fit;
			DartFieldInfo *fi;
			r_list_foreach (ci->fields, fit, fi) {
				core_apply_bin_field (bin_class, fi, &field_count);
			}
		}
		if (bin_class && ci->methods) {
			RListIter *mit;
			DartMethodInfo *mi;
			r_list_foreach (ci->methods, mit, mi) {
				core_apply_bin_method (bin_class, mi, &method_count);
			}
		}
		core_apply_anal_class (ctx->core, ci, class_name, &anal_method_count);
		core_apply_type (ctx->core, ci, class_name, &type_field_count);
		core_apply_method_comments (ctx->core, ci, ci->name);
		core_apply_ic_class (ctx->core, ci, class_name);
		class_count++;
		free (class_name);
	}
	dart_class_list_free (classes);
	if (!ctx->quiet) {
		R_LOG_INFO ("Applied %d Dart classes, %d fields, %d methods", class_count, field_count, method_count);
	}
	return class_count;
}
