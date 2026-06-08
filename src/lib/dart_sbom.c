/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

typedef struct {
	char *name;
	char *version;
	char *type;
	char *source;
	char *evidence;
	int confidence;
	int occurrences;
} DartSbomComponent;

static void sbom_component_free(void *p) {
	DartSbomComponent *c = (DartSbomComponent *)p;
	if (c) {
		free (c->name);
		free (c->version);
		free (c->type);
		free (c->source);
		free (c->evidence);
		free (c);
	}
}

static int sbom_component_cmp(const void *a, const void *b) {
	const DartSbomComponent *ca = (const DartSbomComponent *)a;
	const DartSbomComponent *cb = (const DartSbomComponent *)b;
	int rc = strcmp (ca->type? ca->type: "", cb->type? cb->type: "");
	if (rc) {
		return rc;
	}
	rc = strcmp (ca->name? ca->name: "", cb->name? cb->name: "");
	if (rc) {
		return rc;
	}
	return strcmp (ca->version? ca->version: "", cb->version? cb->version: "");
}

static bool same_str_or_empty(const char *a, const char *b) {
	return !strcmp (a? a: "", b? b: "");
}

static DartSbomComponent *sbom_find_component(RList *components, const char *type, const char *name) {
	RListIter *it;
	DartSbomComponent *c;
	r_list_foreach (components, it, c) {
		if (c && same_str_or_empty (c->type, type) && same_str_or_empty (c->name, name)) {
			return c;
		}
	}
	return NULL;
}

static char *sbom_strdup_evidence(const char *s) {
	if (R_STR_ISEMPTY (s)) {
		return NULL;
	}
	const char *p = s;
	while (*p && isspace ((ut8)*p)) {
		p++;
	}
	const char *e = p;
	int len = 0;
	while (*e && len < 240) {
		if (*e == '"' || *e == '\'' || *e == ',' || *e == ']' || *e == '}' || *e == '\n' || *e == '\r') {
			break;
		}
		e++;
		len++;
	}
	return e > p? r_str_ndup (p, (int) (e - p)): NULL;
}

static void sbom_add_component(RList *components, const char *type, const char *name, const char *version, const char *source, int confidence, const char *evidence) {
	if (!components || R_STR_ISEMPTY (type) || R_STR_ISEMPTY (name)) {
		return;
	}
	if (strlen (name) > 160) {
		return;
	}
	DartSbomComponent *c = sbom_find_component (components, type, name);
	if (!c) {
		c = R_NEW0 (DartSbomComponent);
		c->type = strdup (type);
		c->name = strdup (name);
		c->version = R_STR_ISNOTEMPTY (version)? strdup (version): NULL;
		c->source = R_STR_ISNOTEMPTY (source)? strdup (source): NULL;
		c->evidence = sbom_strdup_evidence (evidence);
		c->confidence = confidence;
		c->occurrences = 1;
		r_list_append (components, c);
		return;
	}
	c->occurrences++;
	if (!c->version && R_STR_ISNOTEMPTY (version)) {
		c->version = strdup (version);
	}
	if (confidence > c->confidence) {
		c->confidence = confidence;
		free (c->source);
		free (c->evidence);
		c->source = R_STR_ISNOTEMPTY (source)? strdup (source): NULL;
		c->evidence = sbom_strdup_evidence (evidence);
	}
}

static bool sbom_package_char(char ch) {
	return isalnum ((ut8)ch) || ch == '_' || ch == '-';
}

static char *sbom_dup_package_segment(const char *s) {
	if (R_STR_ISEMPTY (s) || !sbom_package_char (*s)) {
		return NULL;
	}
	const char *p = s;
	while (*p && sbom_package_char (*p)) {
		p++;
	}
	if (p == s || (size_t) (p - s) > 128) {
		return NULL;
	}
	return r_str_ndup (s, (int) (p - s));
}

static char *sbom_dup_dart_uri(const char *s) {
	if (!r_str_startswith (s, "dart:")) {
		return NULL;
	}
	const char *p = s + 5;
	while (*p && (isalnum ((ut8)*p) || *p == '_' || *p == '.')) {
		p++;
	}
	if (p == s + 5 || (size_t) (p - s) > 96) {
		return NULL;
	}
	return r_str_ndup (s, (int) (p - s));
}

static void sbom_scan_text_for_uris(RList *components, const char *text, const char *source, int confidence) {
	if (!components || R_STR_ISEMPTY (text)) {
		return;
	}
	const char *p = text;
	while ((p = strstr (p, "package:"))) {
		char *name = sbom_dup_package_segment (p + 8);
		if (name) {
			sbom_add_component (components, "dart-package", name, NULL, source, confidence, p);
			free (name);
		}
		p += 8;
	}
	p = text;
	while ((p = strstr (p, "packages/"))) {
		char *name = sbom_dup_package_segment (p + 9);
		if (name) {
			sbom_add_component (components, "dart-package", name, NULL, source, confidence - 10, p);
			free (name);
		}
		p += 9;
	}
	p = text;
	while ((p = strstr (p, "dart:"))) {
		char *name = sbom_dup_dart_uri (p);
		if (name) {
			sbom_add_component (components, "dart-library", name, NULL, source, confidence - 20, p);
			free (name);
		}
		p += 5;
	}
}

static void sbom_add_snapshot_runtime(DartCtx *ctx, RList *components) {
	if (!ctx || !components || !ctx->core) {
		return;
	}
	if (!ctx->vm_data) {
		find_snapshots (ctx);
	}
	if (ctx->vm_data && R_STR_ISEMPTY (ctx->snapshot_hash)) {
		DartSnapshotHeader hdr;
		if (dart_snapshot_header_read (ctx, ctx->vm_data, &hdr)) {
			memcpy (ctx->snapshot_hash, hdr.hash, 32);
			ctx->snapshot_hash[32] = '\0';
		}
	}
	const char *version = dart_version_from_hash (ctx->snapshot_hash);
	char evidence[96];
	snprintf (evidence, sizeof (evidence), "snapshot_hash=%s", ctx->snapshot_hash[0]? ctx->snapshot_hash: "unknown");
	sbom_add_component (components, "runtime", "dart-sdk", version, "snapshot_header", version? 100: 70, evidence);
}

static void sbom_add_model_components(DartRecoveryModel *model, RList *components) {
	if (!model || !components) {
		return;
	}
	if (model->classes) {
		RListIter *it;
		DartClassInfo *ci;
		r_list_foreach (model->classes, it, ci) {
			if (ci && R_STR_ISNOTEMPTY (ci->library_name)) {
				sbom_scan_text_for_uris (components, ci->library_name, "library_cluster", 90);
			}
		}
	}
	if (model->strings) {
		RListIter *it;
		DartStringInfo *si;
		r_list_foreach (model->strings, it, si) {
			if (si && R_STR_ISNOTEMPTY (si->value) &&
				(strstr (si->value, "package:") || strstr (si->value, "packages/") || strstr (si->value, "dart:"))) {
				sbom_scan_text_for_uris (components, si->value, "snapshot_string", 70);
			}
		}
	}
}

static char *sbom_plist_string_for_key(const char *text, const char *key) {
	if (R_STR_ISEMPTY (text) || R_STR_ISEMPTY (key)) {
		return NULL;
	}
	char *needle = r_str_newf ("<key>%s</key>", key);
	const char *p = strstr (text, needle);
	free (needle);
	if (!p) {
		return NULL;
	}
	p = strstr (p, "<string>");
	if (!p) {
		return NULL;
	}
	p += 8;
	const char *e = strstr (p, "</string>");
	if (!e || e <= p || (size_t) (e - p) > 128) {
		return NULL;
	}
	return r_str_ndup (p, (int) (e - p));
}

static char *sbom_framework_name_from_path(const char *path) {
	const char *end = strstr (path, ".framework");
	if (!end) {
		return NULL;
	}
	const char *start = end;
	while (start > path && start[-1] != '/') {
		start--;
	}
	if (start == end || (size_t) (end - start) > 160) {
		return NULL;
	}
	return r_str_ndup (start, (int) (end - start));
}

static void sbom_add_native_path(RList *components, const char *path) {
	if (R_STR_ISEMPTY (path)) {
		return;
	}
	char *fw = sbom_framework_name_from_path (path);
	if (fw) {
		sbom_add_component (components, "native-framework", fw, NULL, "bundle_framework", 85, path);
		free (fw);
	}
	const char *base = r_file_basename (path);
	if (R_STR_ISEMPTY (base)) {
		return;
	}
	if (r_str_endswith (base, ".so") || r_str_endswith (base, ".dylib")) {
		char *name = strdup (base);
		char *dot = strrchr (name, '.');
		if (dot) {
			*dot = '\0';
		}
		if (r_str_startswith (name, "lib") && name[3]) {
			memmove (name, name + 3, strlen (name + 3) + 1);
		}
		sbom_add_component (components, "native-library", name, NULL, "bundle_file", 75, path);
		free (name);
	}
}

static void sbom_scan_package_config(RList *components, const char *path) {
	char *json = r_file_slurp (path, NULL);
	if (!json) {
		return;
	}
	const char *p = json;
	while ((p = strstr (p, "\"name\""))) {
		const char *colon = strchr (p, ':');
		const char *quote = colon? strchr (colon, '"'): NULL;
		if (!quote) {
			break;
		}
		quote++;
		const char *end = strchr (quote, '"');
		if (!end || end <= quote || (size_t) (end - quote) > 128) {
			p = quote;
			continue;
		}
		char *name = r_str_ndup (quote, (int) (end - quote));
		sbom_add_component (components, "dart-package", name, NULL, "package_config", 80, path);
		free (name);
		p = end + 1;
	}
	free (json);
}

static char *sbom_extract_yaml_version(const char *line) {
	const char *p = strstr (line, "version:");
	if (!p) {
		return NULL;
	}
	p += 8;
	while (*p && isspace ((ut8)*p)) {
		p++;
	}
	if (*p == '"' || *p == '\'') {
		const char quote = *p++;
		const char *end = strchr (p, quote);
		if (end && end > p) {
			return r_str_ndup (p, (int) (end - p));
		}
		return NULL;
	}
	const char *end = p;
	while (*end && !isspace ((ut8)*end)) {
		end++;
	}
	return end > p? r_str_ndup (p, (int) (end - p)): NULL;
}

static char *sbom_extract_yaml_package_key(const char *line) {
	if (!r_str_startswith (line, "  ") || r_str_startswith (line, "    ")) {
		return NULL;
	}
	const char *p = line + 2;
	if (!sbom_package_char (*p)) {
		return NULL;
	}
	const char *end = p;
	while (*end && sbom_package_char (*end)) {
		end++;
	}
	if (*end != ':') {
		return NULL;
	}
	return r_str_ndup (p, (int) (end - p));
}

static void sbom_scan_pubspec_lock(RList *components, const char *path) {
	char *yaml = r_file_slurp (path, NULL);
	if (!yaml) {
		return;
	}
	bool in_packages = false;
	char *current = NULL;
	char *saveptr = NULL;
	for (char *line = strtok_r (yaml, "\n", &saveptr); line; line = strtok_r (NULL, "\n", &saveptr)) {
		if (!strcmp (line, "packages:")) {
			in_packages = true;
			continue;
		}
		if (!in_packages) {
			continue;
		}
		if (*line && !isspace ((ut8)*line)) {
			break;
		}
		char *pkg = sbom_extract_yaml_package_key (line);
		if (pkg) {
			free (current);
			current = pkg;
			continue;
		}
		if (current) {
			char *version = sbom_extract_yaml_version (line);
			if (version) {
				sbom_add_component (components, "dart-package", current, version, "pubspec.lock", 100, path);
				free (version);
			}
		}
	}
	free (current);
	free (yaml);
}

static void sbom_scan_manifest_file(RList *components, const char *path) {
	char *text = r_file_slurp (path, NULL);
	if (!text) {
		return;
	}
	sbom_scan_text_for_uris (components, text, "flutter_assets", 75);
	free (text);
}

static void sbom_scan_framework_plist(RList *components, const char *path) {
	char *fw = sbom_framework_name_from_path (path);
	if (!fw) {
		return;
	}
	char *plist = r_file_slurp (path, NULL);
	if (!plist) {
		free (fw);
		return;
	}
	char *version = sbom_plist_string_for_key (plist, "CFBundleShortVersionString");
	if (!version) {
		version = sbom_plist_string_for_key (plist, "CFBundleVersion");
	}
	sbom_add_component (components, "native-framework", fw, version, "Info.plist", version? 95: 85, path);
	free (version);
	free (plist);
	free (fw);
}

static void sbom_scan_bundle_files(RList *components, const char *root) {
	if (R_STR_ISEMPTY (root) || !r_file_is_directory (root)) {
		return;
	}
	RList *files = r_file_lsrf (root);
	if (!files) {
		return;
	}
	RListIter *it;
	char *path;
	int scanned = 0;
	r_list_foreach (files, it, path) {
		if (R_STR_ISEMPTY (path) || scanned++ > 50000) {
			continue;
		}
		sbom_scan_text_for_uris (components, path, "bundle_path", 60);
		sbom_add_native_path (components, path);
		const char *base = r_file_basename (path);
		if (!strcmp (base, "AssetManifest.json") || !strcmp (base, "FontManifest.json")) {
			sbom_scan_manifest_file (components, path);
		} else if (!strcmp (base, "package_config.json")) {
			sbom_scan_package_config (components, path);
		} else if (!strcmp (base, "pubspec.lock")) {
			sbom_scan_pubspec_lock (components, path);
		} else if (!strcmp (base, "Info.plist") && strstr (path, ".framework/")) {
			sbom_scan_framework_plist (components, path);
		}
	}
	r_list_free (files);
}

static void sbom_dump_component_json(PJ *pj, const DartSbomComponent *c) {
	pj_o (pj);
	pj_ks (pj, "type", c->type);
	pj_ks (pj, "name", c->name);
	if (c->version) {
		pj_ks (pj, "version", c->version);
	} else {
		pj_k (pj, "version");
		pj_null (pj);
	}
	pj_ki (pj, "confidence", c->confidence);
	pj_ki (pj, "occurrences", c->occurrences);
	if (c->source) {
		pj_ks (pj, "source", c->source);
	}
	if (c->evidence) {
		pj_ks (pj, "evidence", c->evidence);
	}
	pj_end (pj);
}

static char *sbom_dump_json(DartCtx *ctx, RList *components, const char *input_path) {
	const char *version = dart_version_from_hash (ctx->snapshot_hash);
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "format", "r2flutter-recovered-sbom");
	pj_kb (pj, "complete", false);
	pj_ks (pj, "note", "Best-effort component report. Dart package versions are null unless explicit packaged metadata is present.");
	if (input_path) {
		pj_ks (pj, "input", input_path);
	}
	pj_k (pj, "snapshot");
	pj_o (pj);
	pj_ks (pj, "hash", ctx->snapshot_hash[0]? ctx->snapshot_hash: "");
	if (version) {
		pj_ks (pj, "dart_version", version);
	} else {
		pj_ks (pj, "dart_version", "unknown");
	}
	pj_kn (pj, "vm_data", ctx->vm_data);
	pj_kn (pj, "iso_data", ctx->iso_data);
	pj_end (pj);
	pj_ki (pj, "count", r_list_length (components));
	pj_ka (pj, "components");
	RListIter *it;
	DartSbomComponent *c;
	int emitted = 0;
	const int limit = ctx->dump_fns_limit;
	r_list_foreach (components, it, c) {
		if (limit > 0 && emitted >= limit) {
			break;
		}
		sbom_dump_component_json (pj, c);
		emitted++;
	}
	pj_end (pj);
	if (limit > 0 && r_list_length (components) > limit) {
		pj_ki (pj, "omitted", r_list_length (components) - limit);
	}
	pj_end (pj);
	return pj_drain (pj);
}

static void sbom_append_component_text(RStrBuf *sb, const DartSbomComponent *c, bool quiet) {
	if (quiet) {
		r_strbuf_appendf (sb, "%s\t%s\t%s\t%s\t%d\n", c->type, c->name, c->version? c->version: "-", c->source? c->source: "-", c->confidence);
		return;
	}
	r_strbuf_appendf (sb, "%s %s %s confidence=%d source=%s", c->type, c->name, c->version? c->version: "-", c->confidence, c->source? c->source: "unknown");
	if (c->occurrences > 1) {
		r_strbuf_appendf (sb, " occurrences=%d", c->occurrences);
	}
	if (c->evidence) {
		r_strbuf_appendf (sb, " evidence=%s", c->evidence);
	}
	r_strbuf_append (sb, "\n");
}

static char *sbom_dump_text(DartCtx *ctx, RList *components) {
	const bool quiet = ctx && ctx->quiet;
	RStrBuf *sb = r_strbuf_new ("");
	if (!quiet) {
		const char *version = dart_version_from_hash (ctx->snapshot_hash);
		r_strbuf_append (sb, "# Dart/Flutter Recovered Components\n");
		r_strbuf_append (sb, "# complete: false\n");
		r_strbuf_append (sb, "# versions: explicit metadata only; AOT snapshots usually do not serialize pub package versions\n");
		r_strbuf_appendf (sb, "snapshot_hash: %s\n", ctx->snapshot_hash[0]? ctx->snapshot_hash: "unknown");
		r_strbuf_appendf (sb, "dart_version: %s\n", version? version: "unknown");
		r_strbuf_appendf (sb, "components: %d\n", r_list_length (components));
	}
	RListIter *it;
	DartSbomComponent *c;
	int emitted = 0;
	const int limit = ctx->dump_fns_limit;
	r_list_foreach (components, it, c) {
		if (limit > 0 && emitted >= limit) {
			break;
		}
		sbom_append_component_text (sb, c, quiet);
		emitted++;
	}
	if (!quiet && limit > 0 && r_list_length (components) > limit) {
		r_strbuf_appendf (sb, "omitted: %d\n", r_list_length (components) - limit);
	}
	return r_strbuf_drain (sb);
}

static char *sbom_dump_r2(DartCtx *ctx, RList *components) {
	const bool quiet = ctx && ctx->quiet;
	RStrBuf *sb = r_strbuf_new (quiet? "": "# Dart/Flutter recovered components\n");
	RListIter *it;
	DartSbomComponent *c;
	int emitted = 0;
	const int limit = ctx->dump_fns_limit;
	r_list_foreach (components, it, c) {
		if (limit > 0 && emitted >= limit) {
			break;
		}
		char *type = strdup (c->type);
		char *name = strdup (c->name);
		r_name_filter (type, 0);
		r_name_filter (name, 0);
		r_strbuf_appendf (sb, "f dart.sbom.%s.%s 1 @ 0\n", type, name);
		if (!quiet) {
			r_strbuf_appendf (sb, "# component %s %s version=%s confidence=%d source=%s\n", c->type, c->name, c->version? c->version: "-", c->confidence, c->source? c->source: "unknown");
		}
		free (type);
		free (name);
		emitted++;
	}
	return r_strbuf_drain (sb);
}

char *dart_pool_dump_sbom(DartCtx *ctx, const char *input_path, int fmt) {
	if (!ctx || !ctx->core) {
		return fmt == 'j'? strdup ("{\"error\":\"Dart context unavailable\"}"): strdup ("Error: Dart context unavailable\n");
	}
	RList *components = r_list_newf (sbom_component_free);
	sbom_add_snapshot_runtime (ctx, components);
	DartRecoveryModel model;
	if (dart_recovery_model_load (ctx, &model, DART_RECOVERY_STRINGS | DART_RECOVERY_CLASSES)) {
		sbom_add_model_components (&model, components);
		dart_recovery_model_fini (&model);
	}
	if (R_STR_ISNOTEMPTY (input_path) && r_file_is_directory (input_path)) {
		sbom_scan_bundle_files (components, input_path);
	}
	r_list_sort (components, (RListComparator)sbom_component_cmp);
	char *out = NULL;
	if (fmt == 'j') {
		out = sbom_dump_json (ctx, components, input_path);
	} else if (fmt == 'r') {
		out = sbom_dump_r2 (ctx, components);
	} else {
		out = sbom_dump_text (ctx, components);
	}
	r_list_free (components);
	return out;
}
