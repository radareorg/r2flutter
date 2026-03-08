/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_core.h>
#include <r_util/r_file.h>
#include <r_util/r_json.h>
#include <r_util/r_str.h>
#include <sdb/ht_pp.h>
#include "../../include/r2flutter/dart_obf.h"

static void free_obf_kv(HtPPKv *kv) {
	free (kv->key);
	free (kv->value);
}

static char *dup_n(const char *s, size_t len) {
	char *out = malloc (len + 1);
	memcpy (out, s, len);
	out[len] = '\0';
	return out;
}

static char *resolve_dot_pieces(DartCtx *ctx, const char *name) {
	size_t out_cap = strlen (name) + 1;
	char *out = malloc (out_cap);
	size_t out_len = 0;
	bool changed = false;
	const char *cur = name;

	while (*cur) {
		const char *dot = strchr (cur, '.');
		size_t piece_len = dot? (size_t) (dot - cur): strlen (cur);
		char *piece = dup_n (cur, piece_len);
		const char *mapped = (const char *)ht_pp_find (ctx->obf_by_obfuscated, piece, NULL);
		const char *emit = mapped? mapped: piece;
		size_t emit_len = strlen (emit);
		size_t need = out_len + emit_len + (dot? 1: 0) + 1;
		if (need > out_cap) {
			out_cap = need * 2;
			out = realloc (out, out_cap);
		}
		memcpy (out + out_len, emit, emit_len);
		out_len += emit_len;
		if (mapped && strcmp (mapped, piece)) {
			changed = true;
		}
		free (piece);
		if (!dot) {
			break;
		}
		out[out_len++] = '.';
		cur = dot + 1;
	}
	out[out_len] = '\0';
	if (!changed) {
		free (out);
		return strdup (name);
	}
	return out;
}

bool dart_obf_load(DartCtx *ctx) {
	if (!ctx || R_STR_ISEMPTY (ctx->obf_map_path)) {
		return true;
	}
	if (ctx->obf_map_tried) {
		return ctx->obf_by_obfuscated != NULL;
	}
	ctx->obf_map_tried = true;

	char *json = r_file_slurp (ctx->obf_map_path, NULL);
	if (!json) {
		R_LOG_ERROR ("Cannot read obfuscation map: %s", ctx->obf_map_path);
		return false;
	}
	RJson *root = r_json_parse (json);
	if (!root) {
		R_LOG_ERROR ("Invalid obfuscation map JSON: %s", ctx->obf_map_path);
		free (json);
		return false;
	}
	if (root->type != R_JSON_ARRAY) {
		R_LOG_ERROR ("Obfuscation map must be a JSON array: %s", ctx->obf_map_path);
		r_json_free (root);
		free (json);
		return false;
	}

	ctx->obf_by_obfuscated = ht_pp_new (NULL, (HtPPKvFreeFunc)free_obf_kv, NULL);
	for (size_t i = 0; i + 1 < root->children.count; i += 2) {
		const RJson *orig = r_json_item (root, i);
		const RJson *obf = r_json_item (root, i + 1);
		if (!orig || !obf || orig->type != R_JSON_STRING || obf->type != R_JSON_STRING) {
			continue;
		}
		if (R_STR_ISEMPTY (orig->str_value) || R_STR_ISEMPTY (obf->str_value)) {
			continue;
		}
		if (!ht_pp_find (ctx->obf_by_obfuscated, (void *)obf->str_value, NULL)) {
			ht_pp_insert (ctx->obf_by_obfuscated, strdup (obf->str_value), strdup (orig->str_value));
		}
	}

	r_json_free (root);
	free (json);
	return true;
}

void dart_obf_fini(DartCtx *ctx) {
	if (!ctx) {
		return;
	}
	ht_pp_free (ctx->obf_by_obfuscated);
	ctx->obf_by_obfuscated = NULL;
	ctx->obf_map_tried = false;
}

char *dart_obf_resolve(DartCtx *ctx, const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return name? strdup (name): NULL;
	}
	if (!ctx || !dart_obf_load (ctx) || !ctx->obf_by_obfuscated) {
		return strdup (name);
	}
	const char *mapped = (const char *)ht_pp_find (ctx->obf_by_obfuscated, (void *)name, NULL);
	if (mapped) {
		return strdup (mapped);
	}
	if (!strchr (name, '.')) {
		return strdup (name);
	}
	return resolve_dot_pieces (ctx, name);
}

void dart_obf_apply(DartCtx *ctx, char **name) {
	if (!name || R_STR_ISEMPTY (*name)) {
		return;
	}
	char *resolved = dart_obf_resolve (ctx, *name);
	if (!resolved) {
		return;
	}
	if (strcmp (resolved, *name)) {
		free (*name);
		*name = resolved;
		return;
	}
	free (resolved);
}

void dart_obf_apply_buf(DartCtx *ctx, char *buf, size_t buf_len) {
	if (!buf || buf_len < 2 || R_STR_ISEMPTY (buf)) {
		return;
	}
	char *resolved = dart_obf_resolve (ctx, buf);
	if (!resolved) {
		return;
	}
	snprintf (buf, buf_len, "%s", resolved);
	free (resolved);
}
