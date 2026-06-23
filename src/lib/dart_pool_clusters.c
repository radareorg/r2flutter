/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

// ============================================================================
// Clustered Snapshot Deserializer
// ============================================================================

// Modern cluster naming lives in dart_pool_modern.c.

void free_dart_string(void *p) {
	DartString *ds = (DartString *)p;
	if (ds) {
		free (ds->value);
		free (ds);
	}
}

static void free_dart_class(void *p) {
	DartClass *dc = (DartClass *)p;
	if (dc) {
		free (dc->name);
		free (dc);
	}
}

static void free_dart_func(void *p) {
	DartPoolFunction *df = (DartPoolFunction *)p;
	if (df) {
		free (df->name);
		free (df);
	}
}

int decode_string_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] String cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		ut64 encoded = 0;
		if (!cs_read_unsigned (s, &encoded)) {
			return -1;
		}
		bool is_two_byte = (encoded & 1) != 0;
		ut64 length = encoded >> 1;
		if (length > 65536) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] String too long: %" PRIu64 "\n", length);
			}
			ut64 skip_len = is_two_byte? length * 2: length;
			if (!modern_skip_n_bytes (s, skip_len)) {
				return -1;
			}
			continue;
		}
		DartString *ds = R_NEW0 (DartString);
		ds->ref_id = (*ref_counter)++;
		ds->is_two_byte = is_two_byte;
		ds->length = (int)length;
		if (length > 0) {
			if (is_two_byte) {
				ut64 nbytes = length * 2;
				ut8 *raw = (ut8 *)malloc ((size_t)nbytes);
				if (!raw) {
					return -1;
				}
				if (cs_read_bytes (s, raw, (int)nbytes)) {
					ds->value = dart_utf16le_to_utf8 (raw, nbytes);
				}
				free (raw);
			} else {
				ds->value = (char *)malloc (length + 1);
				if (ds->value) {
					if (cs_read_bytes (s, (ut8 *)ds->value, (int)length)) {
						ds->value[length] = '\0';
					} else {
						free (ds->value);
						ds->value = NULL;
					}
				}
			}
		}
		if (ctx->strings) {
			r_list_append (ctx->strings, ds);
		}
		if (ctx->refs && ds->ref_id < ctx->refs_count) {
			ctx->refs[ds->ref_id] = ds;
		}
	}
	return 0;
}

static int decode_class_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 50000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Class cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartClass *dc = R_NEW0 (DartClass);
		dc->ref_id = (*ref_counter)++;
		uint32_t instance_size = 0;
		cs_read_u32 (s, &instance_size);
		dc->instance_size = (int)instance_size;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		dc->name_ref = name_ref;
		ut64 library_ref = 0;
		cs_read_ref_id (s, &library_ref);
		dc->library_ref = library_ref;
		ut64 skip_count = 6;
		for (ut64 j = 0; j < skip_count; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		if (ctx->classes) {
			r_list_append (ctx->classes, dc);
		}
		if (ctx->refs && dc->ref_id < ctx->refs_count) {
			ctx->refs[dc->ref_id] = dc;
		}
	}
	return 0;
}

static int decode_function_cluster(ClusterStream *s, DartCtx *ctx, ut64 *ref_counter, ut64 iso_instr, bool is_canonical) {
	(void)is_canonical;
	ut64 count = 0;
	if (!cs_read_unsigned (s, &count)) {
		return -1;
	}
	if (count == 0 || count > 100000) {
		return 0;
	}
	if (ctx->verbose > 1) {
		fprintf (stderr, "[r2flutter] Function cluster: count=%" PRIu64 "\n", count);
	}
	for (ut64 i = 0; i < count; i++) {
		DartPoolFunction *df = R_NEW0 (DartPoolFunction);
		df->ref_id = (*ref_counter)++;
		ut64 name_ref = 0;
		cs_read_ref_id (s, &name_ref);
		df->name_ref = name_ref;
		ut64 owner_ref = 0;
		cs_read_ref_id (s, &owner_ref);
		df->owner_ref = owner_ref;
		ut64 code_idx = 0;
		cs_read_unsigned (s, &code_idx);
		if (code_idx > 0 && iso_instr > 0) {
			df->entry_point = iso_instr + (code_idx - 1) * 4;
		}
		ut64 skip_refs = 4;
		for (ut64 j = 0; j < skip_refs; j++) {
			ut64 dummy = 0;
			cs_read_ref_id (s, &dummy);
		}
		uint32_t kind_tag = 0;
		cs_read_u32 (s, &kind_tag);
		if (ctx->functions) {
			r_list_append (ctx->functions, df);
		}
		if (ctx->refs && df->ref_id < ctx->refs_count) {
			ctx->refs[df->ref_id] = df;
		}
	}
	return 0;
}

void skip_generic_cluster(ClusterStream *stream) {
	ut64 count = 0;
	if (cs_read_unsigned (stream, &count)) {
		if (count < 100000) {
			for (ut64 j = 0; j < count; j++) {
				ut64 skip = 0;
				for (int k = 0; k < 8 && stream->cursor < stream->end; k++) {
					if (!cs_read_unsigned (stream, &skip)) {
						break;
					}
					if (skip == 0) {
						break;
					}
				}
			}
		}
	}
}

int deserialize_clusters(DartCtx *ctx, ut64 cluster_start, ut64 cluster_end, ut64 num_clusters, ut64 iso_instr) {
	if (!ctx || !ctx->core || cluster_start >= cluster_end) {
		return -1;
	}
	ctx->strings = r_list_newf (free_dart_string);
	ctx->classes = r_list_newf (free_dart_class);
	ctx->functions = r_list_newf (free_dart_func);
	ut64 total_refs = ctx->num_base_objects + ctx->num_objects + 16;
	ctx->refs_count = total_refs;
	ctx->refs = (void **)calloc (total_refs, sizeof (void *));
	ClusterStream stream = {
		.ctx = ctx,
		.cursor = cluster_start,
		.end = cluster_end
	};
	ut64 ref_counter = ctx->num_base_objects + 1;
	for (ut64 ci = 0; ci < num_clusters && stream.cursor < stream.end; ci++) {
		uint32_t tags = 0;
		if (!cs_read_u32 (&stream, &tags)) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] Failed to read cluster tag at %" PRIu64 "\n", ci);
			}
			break;
		}
		uint32_t cid = (tags >> 12) & 0xFFFFF;
		bool is_canonical = ((tags >> 1) & 1) != 0;
		if (ctx->verbose > 1) {
			fprintf (stderr, "[r2flutter] Cluster %" PRIu64 ": cid=%u canonical=%d cursor=0x%" PFMT64x "\n", ci, cid, is_canonical, stream.cursor);
		}
		int rc = 0;
		switch (cid) {
		case kOneByteStringCid:
		case kTwoByteStringCid:
		case kStringCid:
			rc = decode_string_cluster (&stream, ctx, &ref_counter, is_canonical);
			break;
		case kClassCid:
			rc = decode_class_cluster (&stream, ctx, &ref_counter, is_canonical);
			break;
		case kFunctionCid:
			rc = decode_function_cluster (&stream, ctx, &ref_counter, iso_instr, is_canonical);
			break;
		default:
			skip_generic_cluster (&stream);
			break;
		}
		if (rc < 0) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] Error decoding cluster cid=%u\n", cid);
			}
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Decoded: strings=%d classes=%d functions=%d\n", ctx->strings? r_list_length (ctx->strings): 0, ctx->classes? r_list_length (ctx->classes): 0, ctx->functions? r_list_length (ctx->functions): 0);
	}
	return 0;
}

void resolve_names(DartCtx *ctx) {
	if (!ctx || !ctx->refs) {
		return;
	}
	if (ctx->classes) {
		RListIter *it;
		DartClass *dc;
		r_list_foreach (ctx->classes, it, dc) {
			if (!dc || dc->name) {
				continue;
			}
			if (dc->name_ref > 0 && dc->name_ref < ctx->refs_count) {
				DartString *ds = (DartString *)ctx->refs[dc->name_ref];
				if (ds && ds->value) {
					dc->name = strdup (ds->value);
					dart_obf_apply (ctx, &dc->name);
				}
			}
		}
	}
	if (ctx->functions) {
		RListIter *it;
		DartPoolFunction *df;
		r_list_foreach (ctx->functions, it, df) {
			if (!df || df->name) {
				continue;
			}
			if (df->name_ref > 0 && df->name_ref < ctx->refs_count) {
				DartString *ds = (DartString *)ctx->refs[df->name_ref];
				if (ds && ds->value) {
					df->name = strdup (ds->value);
					dart_obf_apply (ctx, &df->name);
				}
			}
		}
	}
}
