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

