/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

static const char *dart_tag_style_names[] = {
	"CID_INT32", // DART_TAG_STYLE_CID_INT32 = 0
	"CID_SHIFT1", // DART_TAG_STYLE_CID_SHIFT1 = 1
	"OBJECT_HEADER", // DART_TAG_STYLE_OBJECT_HEADER = 2
};

static inline const char *dart_tag_style_to_string(DartTagStyle style) {
	if (style >= 0 && style < (sizeof (dart_tag_style_names) / sizeof (dart_tag_style_names[0]))) {
		return dart_tag_style_names[style];
	}
	return "unknown";
}

static inline const char *dart_tag_style_to_string_verbose(DartTagStyle style) {
	switch (style) {
	case DART_TAG_STYLE_CID_INT32:
		return "CID_INT32 (v2.10-2.13)";
	case DART_TAG_STYLE_CID_SHIFT1:
		return "CID_SHIFT1 (v2.14-3.3)";
	case DART_TAG_STYLE_OBJECT_HEADER:
		return "OBJECT_HEADER (v3.4+)";
	default:
		return "unknown";
	}
}

static const DartVerLayout *load_layout_from_json(const char *hash, DartVerLayout *out) {
	if (!hash || !out) {
		return NULL;
	}
	char *s = r_file_slurp ("r2flutter/offsets.json", NULL);
	if (!s) {
		s = r_file_slurp ("offsets.json", NULL);
	}
	if (!s) {
		return NULL;
	}
	RJson *j = r_json_parse (s);
	if (!j) {
		free (s);
		return NULL;
	}
	const RJson *hashes = r_json_get (j, "hashes");
	const RJson *item = r_json_get (hashes, hash);
	if (!item) {
		r_json_free (j);
		free (s);
		return NULL;
	}
	const char *version = dart_version_from_hash (hash);
	const DartVerLayout *base_profile = version? dart_profile_from_version (version): NULL;
	if (base_profile) {
		memcpy (out, base_profile, sizeof (*out));
	} else {
		memset (out, 0, sizeof (*out));
		out->tag_style = DART_TAG_STYLE_OBJECT_HEADER;
		out->cid_class = 5;
		out->cid_function = 7;
		out->cid_code = 18;
		out->cid_string = 93;
		out->cid_one_byte_string = 94;
		out->cid_two_byte_string = 95;
		out->cid_array = 90;
		out->cid_mint = 61;
		out->cid_object_pool = 23;
		out->num_predefined_cids = 175;
	}
	const char *h = r_json_get_str (item, "hash");
	if (h && *h) {
		strncpy (out->hash, h, 32);
	} else {
		strncpy (out->hash, hash, 32);
	}
	out->hash[32] = '\0';
	int cws = (int)r_json_get_num (item, "compressed_word_size");
	if (cws > 0) {
		out->compressed_word_size = cws;
	}
	int hot = (int)r_json_get_num (item, "heap_object_tag");
	if (hot > 0) {
		out->heap_object_tag = hot;
	}
	int mal = (int)r_json_get_num (item, "max_alignment");
	if (mal > 0) {
		out->max_alignment = mal;
	}
	ut64 cap = (ut64)r_json_get_num (item, "it_cap");
	if (cap > 0) {
		out->it_cap = cap;
	}
	r_json_free (j);
	free (s);
	return out;
}

static void extract_snapshot_hash_flags(DartCtx *ctx, ut64 vm_data) {
	if (!ctx || !vm_data) {
		return;
	}
	ctx->snapshot_hash[0] = '\0';
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read (ctx, vm_data, &hdr)) {
		return;
	}
	memcpy (ctx->snapshot_hash, hdr.hash, 32);
	ctx->snapshot_hash[32] = '\0';
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] snapshot_hash=%.*s flags=%.128s\n", 32, hdr.hash, hdr.flags);
	}
}

static void derive_layout_from_flags(DartCtx *ctx) {
	if (!ctx || !ctx->vm_data) {
		return;
	}
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read (ctx, ctx->vm_data, &hdr)) {
		return;
	}
	const char *flags = hdr.flags;
	bool has_compressed = strstr (flags, "compressed-pointer") != NULL;
	bool has_no_compressed = strstr (flags, "no-compressed-pointer") != NULL ||
		strstr (flags, "no-compressed") != NULL;
	if (has_compressed && !has_no_compressed) {
		ctx->compressed_word_size = 4;
	} else {
		ctx->compressed_word_size = 8;
	}
	if (ctx->layout && ctx->compressed_word_size == 4) {
		int major = 0;
		int minor = 0;
		const char *version = dart_version_from_hash (ctx->snapshot_hash);
		bool use_64_alignment = ctx->layout->tag_style == DART_TAG_STYLE_OBJECT_HEADER;
		if (!use_64_alignment && version && sscanf (version, "%d.%d", &major, &minor) == 2) {
			use_64_alignment = major > 2 || (major == 2 && minor >= 19);
		}
		if (use_64_alignment && ctx->layout->max_alignment < 64) {
			((DartVerLayout *)ctx->layout)->max_alignment = 64;
		}
	} else if (ctx->layout && ctx->layout->max_alignment != 16) {
		((DartVerLayout *)ctx->layout)->max_alignment = 16;
	}
}

DartVerLayout *dart_ctx_init_layout(DartCtx *ctx, DartVerLayout *tmp) {
	extract_snapshot_hash_flags (ctx, ctx->vm_data);
	ctx->layout = load_layout_from_json (ctx->snapshot_hash, tmp);
	DartVerLayout *owned = NULL;
	if (!ctx->layout) {
		owned = dart_pick_layout_by_hash (ctx->snapshot_hash);
		ctx->layout = owned;
	}
	derive_layout_from_flags (ctx);
	return owned;
}

void dart_ctx_fini_layout(DartCtx *ctx, DartVerLayout *owned) {
	dart_ver_layout_free (owned);
	ctx->layout = NULL;
}

static int decode_pool_and_emit(DartCtx *ctx,
	DartPoolFunctionCallback on_fn,
	void *fn_user,
	DartInstructionTableEntryCallback on_it,
	void *it_user,
	bool include_stubs,
	ut64 it_limit) {
	if (!ctx || !ctx->iso_data) {
		return -1;
	}
	if (!ctx->layout) {
		fprintf (stderr, "[r2flutter] No layout for snapshot hash %s. Populate known_layouts.\n", ctx->snapshot_hash);
		return -1;
	}
	const ut64 base = ctx->iso_data;
	DartSnapshotHeader sh;
	if (!dart_snapshot_header_read (ctx, base, &sh)) {
		eprintf ("Cannot read head\n");
		return -1;
	}
	if (ctx->verbose > 1 && sh.flags[0]) {
		eprintf ("[r2flutter] features: %s\n", sh.flags);
	}
	ut64 total_len = sh.total_len;
	ut64 kind = sh.kind;
	ut64 nb = sh.nb;
	ut64 no = sh.no;
	ut64 nc = sh.nc;
	ut64 itlen = sh.itlen;
	ut64 itdata = sh.itdata;
	bool header_valid = (nc > 0 && nc < 1000000 && no > 0 && no < 10000000);
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] snapshot clustered header: base_objs=%" PRIu64 " objs=%" PRIu64 " clusters=%" PRIu64 " it_len=%" PRIu64 " it_data_off=%" PRIu64 " total_len=%" PRIu64 " valid=%d\n", (uint64_t)nb, (uint64_t)no, (uint64_t)nc, (uint64_t)itlen, (uint64_t)itdata, (uint64_t)total_len, header_valid);
	}
	if (!header_valid) {
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] warning: snapshot header values out of expected range, skipping cluster deserialization\n");
		}
		nc = 0;
	}

	if (ctx->dump_snapshot_json) {
		printf ("{\"kind\":%" PFMT64u ",\"hash\":\"%s\",\"vm_data\":%" PFMT64u ",\"vm_instr\":%" PFMT64u ",\"iso_data\":%" PFMT64u ",\"iso_instr\":%" PFMT64u ",\"cluster\":{\"base\":%" PFMT64u ",\"objs\":%" PFMT64u ",\"clusters\":%" PFMT64u ",\"it_len\":%" PFMT64u ",\"it_off\":%" PFMT64u ",\"total\":%" PFMT64u "},\"cws\":%d}\n",
			(ut64)kind,
			ctx->snapshot_hash,
			(ut64)ctx->vm_data,
			(ut64)ctx->vm_instr,
			(ut64)ctx->iso_data,
			(ut64)ctx->iso_instr,
			(ut64)nb,
			(ut64)no,
			(ut64)nc,
			(ut64)itlen,
			(ut64)itdata,
			(ut64)total_len,
			ctx->compressed_word_size);
	}

	ctx->num_base_objects = nb;
	ctx->num_objects = no;
	ctx->num_clusters = nc;
	ctx->it_length = 0;
	ctx->it_first_with_code = 0;
	ctx->it_canonical_stack_map_offset = 0;

	ut64 cluster_start = sh.cluster_start;
	ut64 cluster_end = base + total_len;
	if (nc > 0 && nc < 5000 && no < 500000 && cluster_start < cluster_end) {
		int deser_rc = deserialize_clusters (ctx, cluster_start, cluster_end, nc, ctx->iso_instr);
		if (deser_rc == 0) {
			resolve_names (ctx);
			if (ctx->functions && on_fn) {
				RListIter *fit;
				DartPoolFunction *df;
				r_list_foreach (ctx->functions, fit, df) {
					if (!df || df->entry_point == 0) {
						continue;
					}
					const char *fname = df->name? df->name: "method.unknown";
					char clean_name[256];
					snprintf (clean_name, sizeof (clean_name), "%s", fname);
					r_name_filter (clean_name, 0);
					on_fn (clean_name, df->entry_point, 0, fn_user);
				}
			}
			if (ctx->verbose > 1 && ctx->strings) {
				RListIter *sit;
				DartString *ds;
				int str_count = 0;
				r_list_foreach (ctx->strings, sit, ds) {
					if (ds && ds->value && str_count < 50) {
						fprintf (stderr, "[r2flutter] String[%" PRIu64 "]: %s\n", ds->ref_id, ds->value);
						str_count++;
					}
				}
			}
		}
	}

	HtUP *sym_by_addr = ht_up_new0 ();
	if (ctx->core && ctx->core->bin && sym_by_addr) {
		RVecRBinSymbol *v = r_bin_get_symbols_vec (ctx->core->bin);
		if (v) {
			RBinSymbol *sym;
			R_VEC_FOREACH (v, sym) {
				if (!sym) {
					continue;
				}
				if (sym->type && strcmp (sym->type, R_BIN_TYPE_FUNC_STR)) {
					continue;
				}
				if (sym->vaddr) {
					ht_up_insert (sym_by_addr, sym->vaddr, sym);
				}
			}
		}
	}
	if (!ctx->iso_instr) {
		if (sym_by_addr) {
			ht_up_free (sym_by_addr);
		}
		return 0;
	}
	ut64 kAlign = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	ut64 data_image_base = base + ((total_len + (kAlign - 1)) & ~ (kAlign - 1));
	ut64 data_image_end = ctx->iso_instr? ctx->iso_instr: (data_image_base + (1ULL << 22));
	if (data_image_end < data_image_base) {
		data_image_end = data_image_base + (1ULL << 22);
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] data_image_base=0x%" PFMT64x " data_image_end=0x%" PFMT64x "\n", (ut64)data_image_base, (ut64)data_image_end);
	}
	if (dart_modern_is_supported_snapshot (ctx)) {
		dart_modern_scan_names_from_clusters (ctx, cluster_start, cluster_end, nc, itlen);
	}
	ctx->name_by_ep = scan_code_names (ctx, data_image_base, data_image_end);
	ctx->name_pool = collect_data_names (ctx, data_image_base, data_image_end);
	if (r_list_length (ctx->name_pool) == 0) {
		collect_data_names_with_r2 (ctx, data_image_base, data_image_end);
		if (ctx->verbose > 0) {
			fprintf (stderr, "[r2flutter] name_pool(r2)=%d\n", r_list_length (ctx->name_pool));
		}
	}
	ctx->name_pool_idx = 0;
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] name_pool=%d\n", r_list_length (ctx->name_pool));
	}
	if (itlen == 0) {
		goto cleanup;
	}
	ut64 max_entries = 0;
	if (it_limit > 0) {
		max_entries = it_limit;
	} else if (on_it) {
		max_entries = itlen;
	} else {
		max_entries = ctx->layout && ctx->layout->it_cap? ctx->layout->it_cap: 20000;
	}
	if (itdata == 0) {
		(void)dart_it_emit_linear (ctx, itlen, max_entries, on_fn, fn_user, on_it, it_user);
		goto cleanup;
	}
	ut64 table_addr = data_image_base + itdata;
	if (dart_it_emit_fixed (ctx, table_addr, data_image_base, itlen, max_entries, include_stubs, sym_by_addr, on_fn, fn_user, on_it, it_user) == 0) {
		goto cleanup;
	}
	for (int delta = -64; delta <= 64; delta += 4) {
		if (dart_it_emit_varint (ctx, table_addr + delta, data_image_base, max_entries, include_stubs, sym_by_addr, on_fn, fn_user, on_it, it_user) == 0) {
			goto cleanup;
		}
	}
	if (ctx->verbose > 0) {
		fprintf (stderr, "[r2flutter] Could not decode InstructionsTable::Data at 0x%" PFMT64x ", using sequential fallback\n", (ut64) (data_image_base + itdata));
	}
	(void)dart_it_emit_linear (ctx, itlen, max_entries, on_fn, fn_user, on_it, it_user);
cleanup:
	if (ctx->name_by_code_index) {
		for (ut64 i = 0; i < ctx->name_by_code_index_count; i++) {
			free (ctx->name_by_code_index[i]);
		}
		free (ctx->name_by_code_index);
		ctx->name_by_code_index = NULL;
		ctx->name_by_code_index_count = 0;
	}
	if (ctx->owner_kind_by_code_index) {
		free (ctx->owner_kind_by_code_index);
		ctx->owner_kind_by_code_index = NULL;
		ctx->owner_kind_by_code_index_count = 0;
	}
	if (ctx->name_by_ep) {
		ht_up_free (ctx->name_by_ep);
		ctx->name_by_ep = NULL;
	}
	if (sym_by_addr) {
		ht_up_free (sym_by_addr);
	}
	r_list_free (ctx->name_pool);
	ctx->name_pool = NULL;
	return 0;
}

static void emit_stub_symbols(DartCtx *ctx,
	DartPoolFunctionCallback on_fn,
	void *user) {
	if (!ctx || !ctx->core || !ctx->core->bin || !on_fn) {
		return;
	}
	RVecRBinSymbol *v = r_bin_get_symbols_vec (ctx->core->bin);
	if (!v) {
		return;
	}
	RBinSymbol *sym;
	R_VEC_FOREACH (v, sym) {
		if (!sym) {
			continue;
		}
		if (sym->type && strcmp (sym->type, R_BIN_TYPE_FUNC_STR)) {
			continue;
		}
		ut64 addr = sym->vaddr;
		if (!addr) {
			continue;
		}
		ut64 size = sym->size;
		const char *nm = sym->name? r_bin_name_tostring2 (sym->name, 'o'): NULL;
		if (!nm) {
			nm = "sym.func";
		}
		char tmp[512];
		snprintf (tmp, sizeof (tmp), "%s", nm);
		for (char *p = tmp; *p; p++) {
			if (*p == ' ') {
				*p = '.';
			}
		}
		on_fn (tmp, addr, size, user);
	}
}

int dart_pool_enumerate(DartCtx *ctx, const char *libapp_path, DartPoolFunctionCallback on_fn, void *user, ut64 *out_base, ut64 *out_heap_base) {
	(void)libapp_path;
	if (!ctx || !ctx->core) {
		return -1;
	}
	int ok = find_snapshots (ctx);
	if (ok == 0) {
		if (out_base) {
			*out_base = r_bin_get_baddr (ctx->core->bin);
		}
		if (out_heap_base) {
			*out_heap_base = 0;
		}
		if (ctx->verbose > 0) {
			eprintf ("[r2flutter] Found Dart snapshots: vm_data=0x%" PFMT64x " vm_instr=0x%" PFMT64x " iso_data=0x%" PFMT64x " iso_instr=0x%" PFMT64x "\n",
				(ut64)ctx->vm_data,
				(ut64)ctx->vm_instr,
				(ut64)ctx->iso_data,
				(ut64)ctx->iso_instr);
		}
		DartVerLayout layout_tmp;
		DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
		if (ctx->verbose > 1) {
			ut8 peek[32] = { 0 };
			if (read_mem (ctx, ctx->iso_data, peek, sizeof (peek))) {
				fprintf (stderr, "[r2flutter] iso_data[0..32]: ");
				for (int i = 0; i < 32; i++) {
					fprintf (stderr, "%02x", (unsigned int)peek[i]);
				}
				fprintf (stderr, "\n");
			}
		}
		if (!ctx->no_stubs) {
			emit_stub_symbols (ctx, on_fn, user);
		}
		int rc = decode_pool_and_emit (ctx, on_fn, user, NULL, NULL, false, 0);
		dart_ctx_fini_layout (ctx, layout_owned);
		return rc;
	}
	if (out_base) {
		*out_base = 0;
	}
	if (out_heap_base) {
		*out_heap_base = 0;
	}
	eprintf ("[r2flutter] Dart snapshots not found in symbols (file=%s).\n", libapp_path? libapp_path: "(null)");
	return -1;
}

// ============================================================================
// Class and Field Extraction
// ============================================================================

void dart_field_info_free(DartFieldInfo *fi) {
	if (fi) {
		free (fi->name);
		free (fi->type_name);
		free (fi);
	}
}

void dart_class_info_free(DartClassInfo *ci) {
	if (ci) {
		free (ci->name);
		free (ci->library_name);
		free (ci->super_class_name);
		r_list_free (ci->enums);
		r_list_free (ci->fields);
		r_list_free (ci->interfaces);
		r_list_free (ci->methods);
		free (ci);
	}
}

void dart_type_info_free(DartTypeInfo *ti) {
	if (ti) {
		free (ti->name);
		r_list_free (ti->type_args);
		free (ti);
	}
}

void dart_method_info_free(DartMethodInfo *mi) {
	if (mi) {
		free (mi->name);
		free (mi->owner_name);
		free (mi->signature);
		free (mi);
	}
}

void dart_instruction_table_entry_fini(DartInstructionTableEntry *ie) {
	if (!ie) {
		return;
	}
	R_FREE (ie->name);
}

void dart_instruction_table_entry_free(DartInstructionTableEntry *ie) {
	if (!ie) {
		return;
	}
	dart_instruction_table_entry_fini (ie);
	free (ie);
}

void dart_instruction_table_list_free(RVecDartInstructionTableEntry *list) {
	RVecDartInstructionTableEntry_free (list);
}

void dart_class_list_free(RList *list) {
	r_list_free (list);
}

static int prepare_header_data(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return -1;
	}
	int ok = find_snapshots (ctx);
	if (ok != 0) {
		return -1;
	}
	extract_snapshot_hash_flags (ctx, ctx->vm_data);
	ctx->layout = dart_pick_layout_by_hash (ctx->snapshot_hash);
	derive_layout_from_flags (ctx);
	return 0;
}

char *dart_pool_dump_header(DartCtx *ctx, int fmt) {
	if (prepare_header_data (ctx) != 0) {
		if (fmt == 'j') {
			return strdup ("{\"error\":\"Dart snapshots not found\"}");
		}
		return fmt == 'r'? strdup ("# Error: Dart snapshots not found\n"): strdup ("Error: Dart snapshots not found\n");
	}
	const bool quiet = ctx && ctx->quiet;
	const char *version = dart_version_from_hash (ctx->snapshot_hash);
	if (fmt == 'j') {
		ut64 header_addr = ctx->iso_data? ctx->iso_data: ctx->vm_data;
		DartSnapshotHeader sh = { 0 };
		dart_snapshot_header_read (ctx, header_addr, &sh);
		PJ *pj = pj_new ();
		if (!pj) {
			return strdup ("{\"error\":\"Failed to create JSON\"}");
		}
		pj_o (pj);
		pj_kn (pj, "kind", sh.kind);
		pj_ks (pj, "hash", r_str_get (ctx->snapshot_hash));
		pj_kn (pj, "vm_data", ctx->vm_data);
		pj_kn (pj, "vm_instr", ctx->vm_instr);
		pj_kn (pj, "iso_data", ctx->iso_data);
		pj_kn (pj, "iso_instr", ctx->iso_instr);
		if (ctx->container_kind[0]) {
			pj_k (pj, "container");
			pj_o (pj);
			pj_ks (pj, "kind", ctx->container_kind);
			pj_ks (pj, "note_owner", ctx->container_note_owner);
			pj_kn (pj, "payload_offset", ctx->container_payload_offset);
			pj_kn (pj, "payload_size", ctx->container_payload_size);
			pj_kn (pj, "macho_offset", ctx->container_macho_offset);
			pj_end (pj);
		}
		pj_k (pj, "cluster");
		pj_o (pj);
		pj_kn (pj, "base", sh.nb);
		pj_kn (pj, "objs", sh.no);
		pj_kn (pj, "clusters", sh.nc);
		pj_kn (pj, "it_len", sh.itlen);
		pj_kn (pj, "it_off", sh.itdata);
		pj_kn (pj, "total", sh.total_len);
		pj_end (pj);
		pj_ki (pj, "cws", ctx->compressed_word_size);
		pj_ks (pj, "dart_version", version? version: "unknown");
		if (ctx->layout) {
			const DartVerLayout *l = ctx->layout;
			pj_ks (pj, "tag_style", dart_tag_style_to_string (l->tag_style));
			pj_ki (pj, "alignment", l->max_alignment);
			pj_ki (pj, "header_fields", l->header_fields);
			pj_kn (pj, "it_capacity", l->it_cap);
			pj_k (pj, "cid_table");
			pj_o (pj);
			pj_ki (pj, "cid_class", l->cid_class);
			pj_ki (pj, "cid_function", l->cid_function);
			pj_ki (pj, "cid_code", l->cid_code);
			pj_ki (pj, "cid_string", l->cid_string);
			pj_ki (pj, "cid_one_byte_string", l->cid_one_byte_string);
			pj_ki (pj, "cid_two_byte_string", l->cid_two_byte_string);
			pj_ki (pj, "cid_array", l->cid_array);
			pj_ki (pj, "cid_mint", l->cid_mint);
			pj_ki (pj, "cid_object_pool", l->cid_object_pool);
			pj_ki (pj, "num_predefined", l->num_predefined_cids);
			pj_end (pj);
		}
		pj_end (pj);
		return pj_drain (pj);
	}
	if (fmt == 'r') {
		RStrBuf *sb = r_strbuf_new (quiet? "": "'# Dart AOT Snapshot Info\n");
		// Create flags for snapshot addresses
		r_strbuf_appendf (sb, "'fs dart\n");
		r_strbuf_appendf (sb, "'f dart.vm_data = 0x%" PFMT64x "\n", (ut64)ctx->vm_data);
		r_strbuf_appendf (sb, "'f dart.vm_instr = 0x%" PFMT64x "\n", (ut64)ctx->vm_instr);
		r_strbuf_appendf (sb, "'f dart.iso_data = 0x%" PFMT64x "\n", (ut64)ctx->iso_data);
		r_strbuf_appendf (sb, "'f dart.iso_instr = 0x%" PFMT64x "\n", (ut64)ctx->iso_instr);
		if (ctx->container_kind[0]) {
			r_strbuf_appendf (sb, "'f dart.container_payload = 0x%" PFMT64x "\n", (ut64)ctx->container_payload_offset);
			r_strbuf_appendf (sb, "'f dart.container_payload_size = 0x%" PFMT64x "\n", (ut64)ctx->container_payload_size);
		}
		if (!quiet) {
			// Add comments with metadata
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart snapshot hash: %s\n", (ut64)ctx->vm_data, ctx->snapshot_hash[0]? ctx->snapshot_hash: "(unknown)");
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart version: %s\n", (ut64)ctx->vm_data, version? version: "unknown");
			if (ctx->layout) {
				const DartVerLayout *l = ctx->layout;
				r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Tag style: %s\n", (ut64)ctx->vm_data, dart_tag_style_to_string (l->tag_style));
				r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Alignment: %d, CWS: %d\n", (ut64)ctx->vm_data, l->max_alignment, ctx->compressed_word_size);
			}
		}
		return r_strbuf_drain (sb);
	}

	RStrBuf *sb = r_strbuf_new ("");
	if (quiet) {
		r_strbuf_appendf (sb, "snapshot_hash=%s dart_version=%s vm_data=0x%" PFMT64x " vm_instr=0x%" PFMT64x " iso_data=0x%" PFMT64x " iso_instr=0x%" PFMT64x " cws=%d", ctx->snapshot_hash[0]? ctx->snapshot_hash: "(unknown)", version? version: "unknown", (ut64)ctx->vm_data, (ut64)ctx->vm_instr, (ut64)ctx->iso_data, (ut64)ctx->iso_instr, ctx->compressed_word_size);
		if (ctx->layout) {
			const DartVerLayout *l = ctx->layout;
			r_strbuf_appendf (sb, " tag_style=%s alignment=%d", dart_tag_style_to_string (l->tag_style), l->max_alignment);
		}
		return r_strbuf_drain (sb);
	}
	r_strbuf_appendf (sb, "# Dart AOT Snapshot Header\n\n");
	r_strbuf_appendf (sb, "snapshot_hash: %s\n", ctx->snapshot_hash[0]? ctx->snapshot_hash: "(unknown)");
	r_strbuf_appendf (sb, "dart_version:  %s\n", version? version: "unknown");
	if (ctx->layout) {
		const DartVerLayout *l = ctx->layout;
		r_strbuf_appendf (sb, "tag_style:     %s\n", dart_tag_style_to_string_verbose (l->tag_style));
		r_strbuf_appendf (sb, "cws:           %d\n", ctx->compressed_word_size);
		r_strbuf_appendf (sb, "alignment:     %d\n", l->max_alignment);
		r_strbuf_appendf (sb, "header_fields: %d\n", l->header_fields);
		r_strbuf_appendf (sb, "it_capacity:   %" PRIu64 "\n", (uint64_t)l->it_cap);
	}

	r_strbuf_appendf (sb, "\n## Snapshot Addresses\n");
	r_strbuf_appendf (sb, "vm_data:       0x%" PFMT64x "\n", (ut64)ctx->vm_data);
	r_strbuf_appendf (sb, "vm_instr:      0x%" PFMT64x "\n", (ut64)ctx->vm_instr);
	r_strbuf_appendf (sb, "iso_data:      0x%" PFMT64x "\n", (ut64)ctx->iso_data);
	r_strbuf_appendf (sb, "iso_instr:     0x%" PFMT64x "\n", (ut64)ctx->iso_instr);
	if (ctx->container_kind[0]) {
		r_strbuf_appendf (sb, "\n## Container\n");
		r_strbuf_appendf (sb, "kind:          %s\n", ctx->container_kind);
		r_strbuf_appendf (sb, "note_owner:    %s\n", ctx->container_note_owner[0]? ctx->container_note_owner: "(unknown)");
		r_strbuf_appendf (sb, "payload_off:   0x%" PFMT64x "\n", (ut64)ctx->container_payload_offset);
		r_strbuf_appendf (sb, "payload_size:  %" PRIu64 " bytes\n", (uint64_t)ctx->container_payload_size);
		r_strbuf_appendf (sb, "macho_off:     0x%" PFMT64x "\n", (ut64)ctx->container_macho_offset);
	}

	ut64 addrs[2] = { ctx->vm_data, ctx->iso_data };
	const char *labels[2] = { "VM", "Isolate" };
	for (int si = 0; si < 2; si++) {
		if (!addrs[si]) {
			continue;
		}
		DartSnapshotHeader sh = { 0 };
		dart_snapshot_header_read (ctx, addrs[si], &sh);
		r_strbuf_appendf (sb, "\n## %s Snapshot (0x%" PFMT64x ")\n", labels[si], (ut64)addrs[si]);
		if (!sh.ok) {
			r_strbuf_appendf (sb, "  failed_to_read_header: true\n");
			continue;
		}
		r_strbuf_appendf (sb, "  magic:       0x%08x\n", sh.magic);
		r_strbuf_appendf (sb, "  total_len:   %" PRIu64 " bytes\n", sh.total_len);
		r_strbuf_appendf (sb, "  kind:        %" PRIu64 "\n", sh.kind);
		r_strbuf_appendf (sb, "  hash:        %s\n", sh.hash[0]? sh.hash: "(empty)");
		r_strbuf_appendf (sb, "  flags:       %s\n", sh.flags[0]? sh.flags: "(none)");
		r_strbuf_appendf (sb, "  base_objects: %" PRIu64 "\n", (uint64_t)sh.nb);
		r_strbuf_appendf (sb, "  objects:     %" PRIu64 "\n", (uint64_t)sh.no);
		r_strbuf_appendf (sb, "  clusters:    %" PRIu64 "\n", (uint64_t)sh.nc);
		r_strbuf_appendf (sb, "  it_length:   %" PRIu64 "\n", (uint64_t)sh.itlen);
		r_strbuf_appendf (sb, "  it_data_off: %" PRIu64 "\n", (uint64_t)sh.itdata);
	}

	if (ctx->layout) {
		const DartVerLayout *l = ctx->layout;
		r_strbuf_appendf (sb, "\n## Class IDs (CID Table)\n");
		r_strbuf_appendf (sb, "  cid_class:          %d\n", l->cid_class);
		r_strbuf_appendf (sb, "  cid_function:       %d\n", l->cid_function);
		r_strbuf_appendf (sb, "  cid_code:           %d\n", l->cid_code);
		r_strbuf_appendf (sb, "  cid_string:         %d\n", l->cid_string);
		r_strbuf_appendf (sb, "  cid_one_byte_string: %d\n", l->cid_one_byte_string);
		r_strbuf_appendf (sb, "  cid_two_byte_string: %d\n", l->cid_two_byte_string);
		r_strbuf_appendf (sb, "  cid_array:          %d\n", l->cid_array);
		r_strbuf_appendf (sb, "  cid_mint:           %d\n", l->cid_mint);
		r_strbuf_appendf (sb, "  cid_object_pool:    %d\n", l->cid_object_pool);
		r_strbuf_appendf (sb, "  num_predefined:     %d\n", l->num_predefined_cids);
	}

	return r_strbuf_drain (sb);
}

static void dump_header_snapshot_json(DartCtx *ctx, PJ *pj, const char *label, ut64 addr, int detail) {
	pj_o (pj);
	pj_ks (pj, "label", label);
	pj_kn (pj, "base", addr);
	DartSnapshotHeader sh = { 0 };
	if (!addr || !dart_snapshot_header_read (ctx, addr, &sh) || !sh.ok) {
		pj_kb (pj, "ok", false);
		pj_end (pj);
		return;
	}
	pj_kb (pj, "ok", true);
	pj_kn (pj, "magic", sh.magic);
	pj_kn (pj, "total_len", sh.total_len);
	pj_kn (pj, "kind", sh.kind);
	pj_ks (pj, "hash", sh.hash[0]? sh.hash: "");
	pj_ks (pj, "flags", sh.flags[0]? sh.flags: "");
	pj_kn (pj, "base_objects", sh.nb);
	pj_kn (pj, "objects", sh.no);
	pj_kn (pj, "clusters_count", sh.nc);
	pj_kn (pj, "it_length", sh.itlen);
	pj_kn (pj, "it_data_off", sh.itdata);
	pj_kn (pj, "cluster_start", sh.cluster_start);
	ut64 cluster_end = addr + sh.total_len;
	pj_kn (pj, "cluster_end", cluster_end);
	if (ctx->layout) {
		ut64 align = ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
		ut64 data_image_base = addr + ((sh.total_len + (align - 1)) & ~ (align - 1));
		pj_kn (pj, "data_image_base", data_image_base);
		pj_kn (pj, "instruction_table_addr", data_image_base + sh.itdata);
	}
	pj_ka (pj, "clusters");
	bool parsed = dart_modern_emit_cluster_summary (ctx, sh.cluster_start, cluster_end, sh.nc, sh.nb, ctx->dump_fns_limit, detail, NULL, NULL, pj);
	pj_end (pj);
	pj_kb (pj, "clusters_parsed", parsed);
	if (!parsed) {
		pj_ks (pj, "clusters_error", "unsupported or failed cluster stream");
	}
	if (ctx->dump_fns_limit > 0 && sh.nc > (ut64)ctx->dump_fns_limit) {
		pj_kn (pj, "clusters_omitted", sh.nc - (ut64)ctx->dump_fns_limit);
	}
	pj_end (pj);
}

static char *dump_header_ext_json(DartCtx *ctx, int detail) {
	const char *version = dart_version_from_hash (ctx->snapshot_hash);
	DartSnapshotHeader iso = { 0 };
	if (ctx->iso_data) {
		dart_snapshot_header_read (ctx, ctx->iso_data, &iso);
	}
	PJ *pj = pj_new ();
	if (!pj) {
		return strdup ("{\"error\":\"Failed to create JSON\"}");
	}
	pj_o (pj);
	pj_kn (pj, "kind", iso.kind);
	pj_ks (pj, "hash", r_str_get (ctx->snapshot_hash));
	pj_kn (pj, "vm_data", ctx->vm_data);
	pj_kn (pj, "vm_instr", ctx->vm_instr);
	pj_kn (pj, "iso_data", ctx->iso_data);
	pj_kn (pj, "iso_instr", ctx->iso_instr);
	pj_ki (pj, "cws", ctx->compressed_word_size);
	pj_ks (pj, "dart_version", version? version: "unknown");
	pj_ki (pj, "detail", detail);
	if (ctx->container_kind[0]) {
		pj_k (pj, "container");
		pj_o (pj);
		pj_ks (pj, "kind", ctx->container_kind);
		pj_ks (pj, "note_owner", ctx->container_note_owner);
		pj_kn (pj, "payload_offset", ctx->container_payload_offset);
		pj_kn (pj, "payload_size", ctx->container_payload_size);
		pj_kn (pj, "macho_offset", ctx->container_macho_offset);
		pj_end (pj);
	}
	if (ctx->layout) {
		const DartVerLayout *l = ctx->layout;
		pj_ks (pj, "tag_style", dart_tag_style_to_string (l->tag_style));
		pj_ki (pj, "alignment", l->max_alignment);
		pj_ki (pj, "header_fields", l->header_fields);
		pj_kn (pj, "it_capacity", l->it_cap);
		pj_k (pj, "cid_table");
		pj_o (pj);
		pj_ki (pj, "cid_class", l->cid_class);
		pj_ki (pj, "cid_function", l->cid_function);
		pj_ki (pj, "cid_code", l->cid_code);
		pj_ki (pj, "cid_string", l->cid_string);
		pj_ki (pj, "cid_one_byte_string", l->cid_one_byte_string);
		pj_ki (pj, "cid_two_byte_string", l->cid_two_byte_string);
		pj_ki (pj, "cid_array", l->cid_array);
		pj_ki (pj, "cid_mint", l->cid_mint);
		pj_ki (pj, "cid_object_pool", l->cid_object_pool);
		pj_ki (pj, "num_predefined", l->num_predefined_cids);
		pj_end (pj);
	}
	pj_ka (pj, "snapshots");
	dump_header_snapshot_json (ctx, pj, "VM", ctx->vm_data, detail);
	dump_header_snapshot_json (ctx, pj, "Isolate", ctx->iso_data, detail);
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

static void dump_header_ext_snapshot_text(DartCtx *ctx, RStrBuf *sb, const char *label, ut64 addr, int detail) {
	if (!addr) {
		return;
	}
	DartSnapshotHeader sh = { 0 };
	dart_snapshot_header_read (ctx, addr, &sh);
	r_strbuf_appendf (sb, "\n## %s Clusters\n", label);
	if (!sh.ok) {
		r_strbuf_appendf (sb, "  failed_to_read_header: true\n");
		return;
	}
	ut64 cluster_end = addr + sh.total_len;
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	ut64 data_image_base = addr + ((sh.total_len + (align - 1)) & ~ (align - 1));
	r_strbuf_appendf (sb, "  cluster_start: 0x%" PFMT64x "\n", (ut64)sh.cluster_start);
	r_strbuf_appendf (sb, "  cluster_end:   0x%" PFMT64x "\n", (ut64)cluster_end);
	r_strbuf_appendf (sb, "  data_image:    0x%" PFMT64x "\n", (ut64)data_image_base);
	r_strbuf_appendf (sb, "  it_data:       0x%" PFMT64x "\n", (ut64) (data_image_base + sh.itdata));
	if (detail >= 3) {
		r_strbuf_appendf (sb, "  detail: object_pool_entries\n");
	}
	r_strbuf_appendf (sb, "  columns: idx cid alloc fill count refs flags alloc_range fill_range extras\n");
	bool parsed = dart_modern_emit_cluster_summary (ctx, sh.cluster_start, cluster_end, sh.nc, sh.nb, ctx->dump_fns_limit, detail, NULL, sb, NULL);
	if (!parsed) {
		r_strbuf_appendf (sb, "  parser: unsupported or failed cluster stream\n");
	}
}

static void dump_header_ext_snapshot_r2(DartCtx *ctx, RStrBuf *sb, const char *label, const char *scope, ut64 addr, int detail) {
	if (!addr) {
		return;
	}
	DartSnapshotHeader sh = { 0 };
	dart_snapshot_header_read (ctx, addr, &sh);
	r_strbuf_appendf (sb, "'# Dart %s clusters\n", label);
	if (!sh.ok) {
		r_strbuf_appendf (sb, "'# Dart %s clusters: failed to read snapshot header\n", label);
		return;
	}
	ut64 cluster_end = addr + sh.total_len;
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	ut64 data_image_base = addr + ((sh.total_len + (align - 1)) & ~ (align - 1));
	r_strbuf_appendf (sb, "'f dart.%s.cluster_start = 0x%" PFMT64x "\n", scope, (ut64)sh.cluster_start);
	r_strbuf_appendf (sb, "'f dart.%s.cluster_end = 0x%" PFMT64x "\n", scope, (ut64)cluster_end);
	r_strbuf_appendf (sb, "'f dart.%s.data_image = 0x%" PFMT64x "\n", scope, (ut64)data_image_base);
	r_strbuf_appendf (sb, "'f dart.%s.it_data = 0x%" PFMT64x "\n", scope, (ut64) (data_image_base + sh.itdata));
	if (detail >= 3) {
		r_strbuf_appendf (sb, "'# Dart %s cluster detail: object_pool_entries\n", label);
	}
	bool parsed = dart_modern_emit_cluster_summary (ctx, sh.cluster_start, cluster_end, sh.nc, sh.nb, ctx->dump_fns_limit, detail, scope, sb, NULL);
	if (!parsed) {
		r_strbuf_appendf (sb, "'# Dart %s cluster parser: unsupported or failed cluster stream\n", label);
	}
}

static char *dart_pool_dump_header_ext_level(DartCtx *ctx, int fmt, int detail) {
	if (prepare_header_data (ctx) != 0) {
		if (fmt == 'j') {
			return strdup ("{\"error\":\"Dart snapshots not found\"}");
		}
		return fmt == 'r'? strdup ("# Error: Dart snapshots not found\n"): strdup ("Error: Dart snapshots not found\n");
	}
	if (fmt == 'j') {
		return dump_header_ext_json (ctx, detail);
	}
	if (fmt == 'r') {
		char *header = dart_pool_dump_header (ctx, fmt);
		RStrBuf *sb = r_strbuf_new (header? header: "");
		free (header);
		dump_header_ext_snapshot_r2 (ctx, sb, "VM", "vm", ctx->vm_data, detail);
		dump_header_ext_snapshot_r2 (ctx, sb, "Isolate", "isolate", ctx->iso_data, detail);
		return r_strbuf_drain (sb);
	}
	char *header = dart_pool_dump_header (ctx, fmt);
	RStrBuf *sb = r_strbuf_new (header? header: "");
	free (header);
	dump_header_ext_snapshot_text (ctx, sb, "VM", ctx->vm_data, detail);
	dump_header_ext_snapshot_text (ctx, sb, "Isolate", ctx->iso_data, detail);
	return r_strbuf_drain (sb);
}

char *dart_pool_dump_header_ext(DartCtx *ctx, int fmt) {
	return dart_pool_dump_header_ext_level (ctx, fmt, 2);
}

char *dart_pool_dump_header_deep(DartCtx *ctx, int fmt) {
	return dart_pool_dump_header_ext_level (ctx, fmt, 3);
}

static void dart_pp_info_fini(DartPpInfo *info) {
	if (!info) {
		return;
	}
	free (info->image);
	memset (info, 0, sizeof (*info));
}

static bool resolve_pp_from_snapshot(DartCtx *ctx, ut64 snapshot_base, const char *label, DartPpInfo *info) {
	if (!ctx || !snapshot_base || !info) {
		return false;
	}
	DartSnapshotHeader sh = { 0 };
	if (!dart_snapshot_header_read (ctx, snapshot_base, &sh) || !sh.ok) {
		return false;
	}
	ut64 align = ctx->layout && ctx->layout->max_alignment? (ut64)ctx->layout->max_alignment: 16;
	ut64 data_image_base = snapshot_base + ((sh.total_len + (align - 1)) & ~ (align - 1));
	return dart_modern_build_synthetic_pp (ctx, snapshot_base, label, sh.cluster_start, snapshot_base + sh.total_len, sh.nc, sh.nb, data_image_base, info);
}

static bool resolve_pp_info(DartCtx *ctx, DartPpInfo *info) {
	if (!ctx || !ctx->core || !info) {
		return false;
	}
	memset (info, 0, sizeof (*info));
	if (find_snapshots (ctx) != 0) {
		return false;
	}
	DartVerLayout layout_tmp;
	DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
	bool ok = resolve_pp_from_snapshot (ctx, ctx->iso_data, "Isolate", info);
	if (!ok) {
		ok = resolve_pp_from_snapshot (ctx, ctx->vm_data, "VM", info);
	}
	dart_ctx_fini_layout (ctx, layout_owned);
	return ok;
}

static char *dump_pp_json(const DartPpInfo *info) {
	PJ *pj = pj_new ();
	if (!pj) {
		return strdup ("{\"error\":\"Failed to create JSON\"}");
	}
	pj_o (pj);
	pj_kn (pj, "pp", info->vaddr);
	pj_kn (pj, "base", info->vaddr);
	pj_kn (pj, "vaddr", info->vaddr);
	pj_kn (pj, "paddr", info->paddr);
	pj_ks (pj, "kind", "synthetic");
	pj_ks (pj, "source", "object_pool_fill");
	pj_ko (pj, "pp_addr");
	pj_kn (pj, "vaddr", info->vaddr);
	pj_kn (pj, "paddr", info->paddr);
	pj_end (pj);
	pj_ko (pj, "source_addr");
	pj_kn (pj, "vaddr", info->source_vaddr);
	pj_kn (pj, "paddr", info->source_paddr);
	pj_end (pj);
	pj_ks (pj, "snapshot", info->snapshot_label);
	pj_kn (pj, "snapshot_base", info->snapshot_base);
	pj_kn (pj, "data_image_base", info->data_image_base);
	pj_kn (pj, "cluster_index", info->cluster_index);
	pj_kn (pj, "pool_ref", info->pool_ref);
	pj_kn (pj, "pool_index", info->pool_index);
	pj_kn (pj, "length", info->length);
	pj_kn (pj, "size", info->size);
	pj_kn (pj, "entries_offset", info->entries_offset);
	pj_kn (pj, "entry_bits_offset", info->entry_bits_offset);
	pj_ki (pj, "word_size", info->word_size);
	pj_ks (pj, "note", "runtime PP is not serialized; this is a reconstructed static ObjectPool image");
	pj_end (pj);
	return pj_drain (pj);
}

static char *dump_pp_r2(const DartPpInfo *info, bool quiet) {
	if (info->size > 0x7fffffffULL) {
		return strdup ("# Error: synthetic ObjectPool image is too large\n");
	}
	char *hex = r_hex_bin2strdup (info->image, (int)info->size);
	if (!hex) {
		return strdup ("# Error: failed to encode synthetic ObjectPool image\n");
	}
	RStrBuf *sb = r_strbuf_new (quiet? "": "# Dart synthetic ObjectPool PP\n");
	if (!quiet) {
		r_strbuf_appendf (sb, "# runtime PP is not serialized; mapping reconstructed ObjectPool cluster %" PRIu64 "\n", (uint64_t)info->cluster_index);
	}
	r_strbuf_appendf (sb, "o malloc://0x%" PFMT64x " 0x%" PFMT64x " rw\n", info->size, info->base);
	r_strbuf_appendf (sb, "s 0x%" PFMT64x "\n", info->base);
	r_strbuf_appendf (sb, "wx %s\n", hex);
	r_strbuf_appendf (sb, "e anal.gp=0x%" PFMT64x "\n", info->base);
	r_strbuf_appendf (sb, "dr x27=0x%" PFMT64x "\n", info->base);
	r_strbuf_appendf (sb, "f PP = 0x%" PFMT64x "\n", info->base);
	r_strbuf_appendf (sb, "f dart.pp 0x%" PFMT64x " @ 0x%" PFMT64x "\n", info->size, info->base);
	r_strbuf_appendf (sb, "f dart.pp.entries 0x%" PFMT64x " @ 0x%" PFMT64x "\n", info->entry_bits_offset - info->entries_offset, info->base + info->entries_offset);
	r_strbuf_appendf (sb, "f dart.pp.entry_bits 0x%" PFMT64x " @ 0x%" PFMT64x "\n", info->length, info->base + info->entry_bits_offset);
	if (!quiet) {
		r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC Dart synthetic ObjectPool PP length=%" PRIu64 " ref=%" PRIu64 " source=%s cluster=%" PRIu64 "\n", info->base, (uint64_t)info->length, (uint64_t)info->pool_ref, info->snapshot_label, (uint64_t)info->cluster_index);
	}
	free (hex);
	return r_strbuf_drain (sb);
}

static char *dump_pp_text(const DartPpInfo *info, bool quiet) {
	if (quiet) {
		return r_str_newf ("vaddr=0x%" PFMT64x " paddr=0x%" PFMT64x, info->vaddr, info->paddr);
	}
	RStrBuf *sb = r_strbuf_new ("# Dart ObjectPool PP\n\n");
	r_strbuf_appendf (sb, "pp.vaddr:        0x%" PFMT64x "\n", info->vaddr);
	r_strbuf_appendf (sb, "pp.paddr:        0x%" PFMT64x "\n", info->paddr);
	r_strbuf_appendf (sb, "kind:            synthetic\n");
	r_strbuf_appendf (sb, "source:          %s ObjectPool cluster %" PRIu64 "\n", info->snapshot_label, (uint64_t)info->cluster_index);
	r_strbuf_appendf (sb, "source_vaddr:    0x%" PFMT64x "\n", info->source_vaddr);
	r_strbuf_appendf (sb, "source_paddr:    0x%" PFMT64x "\n", info->source_paddr);
	r_strbuf_appendf (sb, "pool_ref:        %" PRIu64 "\n", (uint64_t)info->pool_ref);
	r_strbuf_appendf (sb, "pool_index:      %" PRIu64 "\n", (uint64_t)info->pool_index);
	r_strbuf_appendf (sb, "length:          %" PRIu64 " entries\n", (uint64_t)info->length);
	r_strbuf_appendf (sb, "image_size:      0x%" PFMT64x "\n", info->size);
	r_strbuf_appendf (sb, "entries_offset:  0x%" PFMT64x "\n", info->entries_offset);
	r_strbuf_appendf (sb, "entry_bits_off:  0x%" PFMT64x "\n", info->entry_bits_offset);
	r_strbuf_appendf (sb, "note:            runtime PP is not serialized; use -r -p to map this reconstructed pool and set anal.gp\n");
	return r_strbuf_drain (sb);
}

char *dart_pool_dump_pp(DartCtx *ctx, int fmt) {
	DartPpInfo info = { 0 };
	if (!resolve_pp_info (ctx, &info)) {
		if (fmt == 'j') {
			return strdup ("{\"error\":\"PP not resolved\",\"reason\":\"ObjectPool fill payload was not decoded\"}");
		}
		return fmt == 'r'? strdup ("# Error: PP not resolved; ObjectPool fill payload was not decoded\n"): strdup ("Error: PP not resolved; ObjectPool fill payload was not decoded\n");
	}
	char *out = NULL;
	if (fmt == 'j') {
		out = dump_pp_json (&info);
	} else if (fmt == 'r') {
		out = dump_pp_r2 (&info, ctx && ctx->quiet);
	} else {
		out = dump_pp_text (&info, ctx && ctx->quiet);
	}
	dart_pp_info_fini (&info);
	return out;
}

static void collect_it_entry_cb(const DartInstructionTableEntry *entry, void *user) {
	RVecDartInstructionTableEntry *list = (RVecDartInstructionTableEntry *)user;
	if (!entry || !list) {
		return;
	}
	DartInstructionTableEntry *dup = RVecDartInstructionTableEntry_emplace_back (list);
	if (!dup) {
		return;
	}
	*dup = *entry;
	dup->name = entry->name? strdup (entry->name): NULL;
}

RVecDartInstructionTableEntry *dart_pool_extract_instruction_table(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	RVecDartInstructionTableEntry *list = RVecDartInstructionTableEntry_new ();
	int ok = find_snapshots (ctx);
	if (ok != 0) {
		RVecDartInstructionTableEntry_free (list);
		return NULL;
	}
	if (ctx->verbose > 0) {
		eprintf ("[r2flutter] Found Dart snapshots: vm_data=0x%" PFMT64x " vm_instr=0x%" PFMT64x " iso_data=0x%" PFMT64x " iso_instr=0x%" PFMT64x "\n",
			(ut64)ctx->vm_data,
			(ut64)ctx->vm_instr,
			(ut64)ctx->iso_data,
			(ut64)ctx->iso_instr);
	}
	DartVerLayout layout_tmp;
	DartVerLayout *layout_owned = dart_ctx_init_layout (ctx, &layout_tmp);
	if (decode_pool_and_emit (ctx, NULL, NULL, collect_it_entry_cb, list, true, ctx->dump_fns_limit > 0? (ut64)ctx->dump_fns_limit: 0) != 0) {
		RVecDartInstructionTableEntry_free (list);
		list = NULL;
	}
	dart_ctx_fini_layout (ctx, layout_owned);
	return list;
}

char *dart_pool_dump_it(DartCtx *ctx, int fmt) {
	RVecDartInstructionTableEntry *entries = dart_pool_extract_instruction_table (ctx);
	if (!entries) {
		return fmt == 'j'? strdup ("{\"error\":\"Dart snapshots not found\"}"): strdup ("Error: Dart snapshots not found\n");
	}
	if (fmt == 'j') {
		PJ *pj = pj_new ();
		if (!pj) {
			dart_instruction_table_list_free (entries);
			return strdup ("{\"error\":\"Failed to create JSON\"}");
		}
		pj_o (pj);
		pj_kn (pj, "length", ctx->it_length);
		pj_kn (pj, "first_entry_with_code", ctx->it_first_with_code);
		pj_kn (pj, "canonical_stack_map_entries_offset", ctx->it_canonical_stack_map_offset);
		pj_ka (pj, "entries");
		DartInstructionTableEntry *entry;
		R_VEC_FOREACH (entries, entry) {
			pj_o (pj);
			pj_kn (pj, "index", entry->index);
			if (entry->has_code) {
				pj_kn (pj, "code_index", entry->code_index);
			}
			pj_kn (pj, "address", entry->address);
			pj_ki (pj, "pc_offset", entry->pc_offset);
			pj_ki (pj, "stack_map_offset", entry->stack_map_offset);
			pj_ks (pj, "kind", entry->has_code? "code": "stub");
			if (entry->name && *entry->name) {
				pj_ks (pj, "name", entry->name);
			}
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
		dart_instruction_table_list_free (entries);
		return pj_drain (pj);
	}
	const bool quiet = ctx && ctx->quiet;
	RStrBuf *sb = fmt == 'r' && !quiet? r_strbuf_new ("# Dart InstructionTable entries\n"): r_strbuf_new ("");
	if (!quiet) {
		r_strbuf_appendf (sb, "# length=%" PRIu64 " first_entry_with_code=%" PRIu64 " canonical_stack_map_entries_offset=%" PRIu64 "\n", (uint64_t)ctx->it_length, (uint64_t)ctx->it_first_with_code, (uint64_t)ctx->it_canonical_stack_map_offset);
	}
	DartInstructionTableEntry *entry;
	R_VEC_FOREACH (entries, entry) {
		if (fmt == 'r') {
			if (!quiet && entry->name && *entry->name) {
				r_strbuf_appendf (sb, "# it[%" PRIu64 "] %s\n", (uint64_t)entry->index, entry->name);
			}
			r_strbuf_appendf (sb, "f it.%s_%" PRIu64 " = 0x%" PFMT64x "\n", entry->has_code? "code": "stub", (uint64_t)entry->index, (ut64)entry->address);
			continue;
		}
		r_strbuf_appendf (sb, "%" PRIu64 " 0x%" PFMT64x " %s", (uint64_t)entry->index, (ut64)entry->address, entry->has_code? "code": "stub");
		if (entry->name && *entry->name) {
			r_strbuf_appendf (sb, " %s", entry->name);
		}
		r_strbuf_append (sb, "\n");
	}
	dart_instruction_table_list_free (entries);
	char *out = r_strbuf_drain (sb);
	size_t len = strlen (out);
	if (len > 0 && out[len - 1] == '\n') {
		out[len - 1] = '\0';
	}
	return out;
}
