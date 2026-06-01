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

typedef enum {
	kFieldCid_extract = 10,
	kLibraryCid_extract = 12,
} ExtraCids;

#define DART_TYPE_CLASS_ID_SHIFT 3
#define DART_TYPE_CLASS_ID_MASK ((1U << 20) - 1)

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
		ci->interfaces = r_list_newf (free);
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

static char *dup_class_name_by_ref(RList *class_list, ut64 ref) {
	if (!class_list || ref == 0) {
		return NULL;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (class_list, it, ci) {
		if (ci && ci->ref_id == ref && R_STR_ISNOTEMPTY (ci->name)) {
			return strdup (ci->name);
		}
	}
	return NULL;
}

static char *resolve_type_name(DartCtx *ctx, RList *class_list, RList *type_list, ut64 type_ref) {
	DartTypeInfo *ti = find_type_by_ref (type_list, type_ref);
	if (!ti) {
		return NULL;
	}
	if (R_STR_ISNOTEMPTY (ti->name)) {
		return strdup (ti->name);
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
		ti->name = strdup (name);
	}
	return name;
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
			eci->interfaces = r_list_newf (free);
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

static void resolve_class_and_field_names(DartCtx *ctx, RList *class_list, RList *field_list, RList *type_list) {
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
			fi->type_name = resolve_type_name (ctx, class_list, type_list, fi->type_ref);
		}
		if (fi->owner_ref > 0 && fi->owner_ref < ctx->refs_count) {
			void *ref = ctx->refs[fi->owner_ref];
			if (ref) {
				DartClassInfo *owner = (DartClassInfo *)ref;
				if (owner->fields) {
					DartFieldInfo *fi_copy = dart_field_info_clone (fi);
					r_list_append (owner->fields, fi_copy);
				}
			}
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
	RList *type_list = r_list_newf ((RListFree)dart_type_info_free);
	ctx->strings = r_list_newf (free_dart_string);
	RList *libraries = r_list_newf (free_library_info);
	if (header_valid) {
		ctx->num_base_objects = nb;
		ctx->num_objects = no;
		ctx->num_clusters = nc;
		ut64 total_refs = nb + no + 16;
		ctx->refs_count = total_refs;
		ctx->refs = (void **)calloc (total_refs, sizeof (void *));
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
			case kTypeCid:
				rc = decode_type_cluster_ext (&stream, ctx, type_list, &ref_counter);
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
		resolve_class_and_field_names (ctx, class_list, field_list, type_list);
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] Extracted fields from clusters: %d\n", r_list_length (field_list));
		}
	} else {
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
						ci->interfaces = r_list_newf (free);
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
	r_list_free (type_list);
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

static void dump_class_text(RStrBuf *sb, const DartClassInfo *ci, int fmt, bool type_view) {
	if (!ci || !ci->name) {
		return;
	}
	const bool emit_r2 = fmt == 'r';
	const bool emit_enum_literal = type_view &&
		(ci->flags & DART_CLASS_ENUM) &&
		ci->enums &&
		r_list_length (ci->enums) > 0;
	if (emit_r2) {
		char safe_name[256];
		snprintf (safe_name, sizeof (safe_name), "%s", ci->name);
		r_name_filter (safe_name, 0);
		if (emit_enum_literal) {
			r_strbuf_appendf (sb, "# enum %s", ci->name);
			append_enum_values (sb, ci);
			r_strbuf_append (sb, "\n");
			r_strbuf_appendf (sb, "\"td struct.dart.%s { };\"\n", safe_name);
			return;
		}
		r_strbuf_appendf (sb, "# class %s", ci->name);
		if (ci->super_class_name) {
			r_strbuf_appendf (sb, " extends %s", ci->super_class_name);
		}
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
		r_strbuf_appendf (sb, "\"td struct.dart.%s {", safe_name);
		if (ci->fields && r_list_length (ci->fields) > 0) {
			RListIter *fit;
			DartFieldInfo *fi;
			r_list_foreach (ci->fields, fit, fi) {
				r_strbuf_appendf (sb, " %s %s @ 0x%x;", r_str_get (fi->type_name), r_str_get (fi->name), fi->offset);
			}
		}
		r_strbuf_append (sb, " };\"\n");
		if (ci->methods && r_list_length (ci->methods) > 0) {
			RListIter *mit;
			DartMethodInfo *mi;
			r_list_foreach (ci->methods, mit, mi) {
				r_strbuf_appendf (sb, "#   method 0x%08" PFMT64x " %s (%s)\n", (ut64)mi->entry_point, r_str_get (mi->name), method_kind_name (mi->kind_tag));
			}
		}
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
			r_strbuf_appendf (sb, "    0x%08" PFMT64x " %s (%s)\n", (ut64)mi->entry_point, r_str_get (mi->name), method_kind_name (mi->kind_tag));
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
	RStrBuf *sb = r_strbuf_new (fmt == 'r'? "# Dart classes extracted from snapshot\n": "");
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (classes, it, ci) {
		dump_class_text (sb, ci, fmt, type_view);
	}
	dart_class_list_free (classes);
	return r_strbuf_drain (sb);
}
