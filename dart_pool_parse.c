#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <r_core.h>
#include <r_io.h>
#include <r_util/r_json.h>
#include <r_util/r_file.h>
#include "dart_pool_parse.h"

// Minimal, standalone AOT snapshot/ObjectPool decoder scaffolding.
// This file will progressively implement decoding without Dart VM deps.

typedef struct {
	char hash[33]; // snapshot hash as ASCII (32 chars)
	int compressed_word_size; // 4 or 8
	int heap_object_tag;      // usually 1
	int max_alignment;        // alignment for DataImage rounding (default 16)
	ut64 it_cap;              // cap for instruction table entries to emit
				  // Future: offsets for Code.entry_point, Code.size, Function.name, etc.
} DartVerLayout;

#if 0
static const DartVerLayout known_layouts[] = {
	// Known snapshot hashes may be added here.
	//{"0123456789abcdef0123456789abcdef", 4, 1},
};

static const DartVerLayout* pick_layout_by_hash(const char* hash) {
	if (!hash) return NULL;
	for (size_t i = 0; i < sizeof(known_layouts)/sizeof(known_layouts[0]); i++) {
		if (!strncmp(known_layouts[i].hash, hash, 32)) return &known_layouts[i];
	}
	return NULL;
}
#else
static const DartVerLayout* pick_layout_by_hash(const char* hash) {
	DartVerLayout *dvl = R_NEW0 (DartVerLayout);
	dvl->compressed_word_size = 4;
	dvl->heap_object_tag = 4;
	dvl->max_alignment = 16;
	dvl->it_cap = 20000;
	(void)hash;
	return dvl;
}
#endif

typedef struct {
	RCore *core;
	ut64 vm_data;
	ut64 vm_instr;
	ut64 iso_data;
	ut64 iso_instr;
	char snapshot_hash[33];
	const DartVerLayout *layout;
	int compressed_word_size; // derived from flags or layout
} DartCtx;

// Debug/diagnostic controls
static int G_VERBOSE = 0;
static int G_NO_STUBS = 0;
static int G_DUMP_SNAPSHOT_JSON = 0;
static int G_DUMP_IT = 0;
static int G_QUIET = 0;
static int G_DUMP_FNS = 0;

void dart_pool_set_verbose(int level) { G_VERBOSE = level; }
void dart_pool_set_no_stubs(int on) { G_NO_STUBS = on ? 1 : 0; }
void dart_pool_set_dump_snapshot_json(int on) { G_DUMP_SNAPSHOT_JSON = on ? 1 : 0; }
void dart_pool_set_dump_it(int on) { G_DUMP_IT = on ? 1 : 0; }
void dart_pool_set_quiet(int on) { G_QUIET = on ? 1 : 0; }
int dart_pool_is_quiet(void) { return G_QUIET; }
void dart_pool_set_dump_fns(int n) { G_DUMP_FNS = n; }
int dart_pool_get_dump_fns(void) { return G_DUMP_FNS; }

static bool read_mem(RCore *core, ut64 addr, void *buf, int len) {
	if (!core || !buf || len <= 0) return false;
	int r = r_io_read_at(core->io, addr, (ut8*)buf, len);
	return r > 0;
}

static RJson* load_offsets_json(void) {
	char *s = r_file_slurp("r2flutter/offsets.json", NULL);
	if (!s) s = r_file_slurp("offsets.json", NULL);
	if (!s) return NULL;
	RJson *j = r_json_parse(s);
	//free(s);
	return j;
}

static bool read_uleb128_at(RCore *core, ut64 addr, ut64 *out_val, ut64 *out_next) {
	// Read unsigned LEB128 value from memory at addr.
	// Returns true on success, false on failure.
	ut64 v = 0;
	int shift = 0;
	for (int i = 0; i < 10; i++) {
		ut8 b = 0;
		if (!read_mem(core, addr + i, &b, 1)) {
			return false;
		}
		v |= ((ut64)(b & 0x7f)) << shift;
		if ((b & 0x80) == 0) {
			if (out_val) *out_val = v;
			if (out_next) *out_next = addr + i + 1;
			return true;
		}
		shift += 7;
	}
	return false;
}

static const DartVerLayout* load_layout_from_json(const char *hash, DartVerLayout *out) {
	RJson *j = load_offsets_json ();
	if (!j) {
		return NULL;
	}
	const RJson *hashes = r_json_get (j, "hashes");
	const RJson *item = r_json_get(hashes, hash);
	if (!item) { r_json_free(j); return NULL; }
	memset(out, 0, sizeof(*out));
	const char *h = r_json_get_str(item, "hash");
	if (h && *h) strncpy(out->hash, h, 32);
	else strncpy(out->hash, hash, 32);
	out->hash[32] = '\0';
	out->compressed_word_size = (int)r_json_get_num(item, "compressed_word_size");
	out->heap_object_tag = (int)r_json_get_num(item, "heap_object_tag");
	int mal = (int)r_json_get_num(item, "max_alignment");
	out->max_alignment = mal > 0 ? mal : 16;
	ut64 cap = (ut64)r_json_get_num(item, "it_cap");
	out->it_cap = cap > 0 ? cap : 20000;
	r_json_free(j);
	return out;
}

static void extract_snapshot_hash_flags(RCore *core, ut64 vm_data, char out_hash[33]) {
	if (out_hash) out_hash[0] = '\0';
	if (!core || !vm_data) return;
	ut8 buf[20 + 32 + 256] = {0};
	if (!read_mem(core, vm_data, buf, sizeof(buf))) return;
	if (out_hash) {
		memcpy(out_hash, buf + 20, 32);
		out_hash[32] = '\0';
	}
	const char *flags = (const char *)(buf + 20 + 32);
	if (G_VERBOSE > 0) {
		fprintf(stderr, "[r2flutter] snapshot_hash=%.*s flags=%.128s\n", 32, (const char*)(buf + 20), flags);
	}
}

static void derive_layout_from_flags(DartCtx *ctx) {
	// Read flags again to infer compressed pointer mode when no per-hash layout is available.
	if (!ctx || !ctx->vm_data) return;
	ut8 buf[20 + 32 + 256] = {0};
	if (!read_mem(ctx->core, ctx->vm_data, buf, sizeof(buf))) return;
	const char *flags = (const char *)(buf + 20 + 32);
	// Heuristic: many 64-bit AOT builds use 4-byte compressed pointers; check flag substring
	if (strstr(flags, "compressed") || strstr(flags, "compress")) {
		ctx->compressed_word_size = 4;
	} else {
		ctx->compressed_word_size = 8;
	}
	if (ctx->layout) {
		// layout wins if provided
		ctx->compressed_word_size = ctx->layout->compressed_word_size;
	}
}

// Placeholder: future decoding of ObjectPool and emission of functions
static int decode_pool_and_emit(DartCtx *ctx,
		void (*on_fn)(const char* name, unsigned long long addr, unsigned long long size, void* user),
		void* user) {
	(void)on_fn; (void)user;
	if (!ctx || !ctx->iso_data) return -1;
	if (!ctx->layout) {
		fprintf(stderr, "[r2flutter] No layout for snapshot hash %s. Populate known_layouts.\n", ctx->snapshot_hash);
		return -1;
	}
	// Minimal clustered snapshot header reader (pre-work for full pool decode)
	// Layout reference: third_party/dartvm/snapshot.h + app_snapshot.cc (SnapshotHeaderReader + Deserializer)
	// We only parse the header and clustered-section counters to validate access.
	const ut64 base = ctx->iso_data;
	// Snapshot header: magic (u32), length (i64, not incl. magic), kind (i64)
	ut8 hdr[4 + 8 + 8];
	if (!read_mem(ctx->core, base, hdr, sizeof(hdr))) {
		eprintf ("Cannot read head\n");
		return -1;
	}
	uint32_t magic = *(uint32_t*)(hdr + 0);
	if (magic != 0xdcdcf5f5) {
		fprintf(stderr, "[r2flutter] Unexpected snapshot magic at 0x%"PFMT64x"\n", (ut64)base);
		return -1;
	}
	// length (excluding magic) + magic size yields total
	uint64_t length_ex_magic = *(uint64_t*)(hdr + 4);
	uint64_t total_len = length_ex_magic + 4;
	uint64_t kind = *(uint64_t*)(hdr + 12);
	// Skip version+features header.
	// In AOT, the version string is NOT guaranteed to be NUL-terminated,
	// while the features string IS NUL-terminated and follows immediately.
	// So from the position after header, we advance to the first NUL byte,
	// which marks the end of the features string.
	ut64 cursor = base + 4 + 8 + 8; // after header
					// Scan up to a reasonable cap to find the 0 terminator of features
	const int max_scan = 1024;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem(ctx->core, cursor + scanned, &b, 1)) {
			break;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	if (b != '\0') {
		// couldn't find terminator; continue, but LEB128 parsing may fail
		if (G_VERBOSE > 0) {
			eprintf("[r2flutter] warning: could not find features terminator within %d bytes\n", max_scan);
		}
	} else if (G_VERBOSE > 1) {
		// For debugging, try to print a tail of what we scanned (it's the end of features)
		int toshow = scanned > 128 ? 128 : scanned;
		char feat[129];
		memset(feat, 0, sizeof(feat));
		// read up to toshow bytes ending at scanned position
		int start = scanned - toshow;
		for (int i = 0; i < toshow; i++) {
			ut8 ch = 0;
			if (!read_mem(ctx->core, cursor + start + i, &ch, 1)) break;
			feat[i] = (ch >= 32 && ch < 127) ? (char)ch : '.';
		}
		eprintf("[r2flutter] features tail: %s\n", feat);
	}
	cursor += (ut64)(scanned + 1);
	// Now clustered header (Deserializer::Deserialize):
	// num_base_objects, num_objects, num_clusters, instructions_table_len, instruction_table_data_offset
	// These are encoded as unsigned LEB128 in Dart snapshot streams.
	// Implement a small LEB128 reader over memory.
	ut64 nb=0,no=0,nc=0,itlen=0,itdata=0;
	ut64 next = cursor;
	if (!read_uleb128_at(ctx->core, next, &nb, &next)) return -1;
	if (!read_uleb128_at(ctx->core, next, &no, &next)) return -1;
	if (!read_uleb128_at(ctx->core, next, &nc, &next)) return -1;
	if (!read_uleb128_at(ctx->core, next, &itlen, &next)) return -1;
	if (!read_uleb128_at(ctx->core, next, &itdata, &next)) return -1;
	if (G_VERBOSE > 0) {
		fprintf(stderr, "[r2flutter] snapshot clustered header: base_objs=%"PRIu64" objs=%"PRIu64" clusters=%"PRIu64" it_len=%"PRIu64" it_data_off=%"PRIu64" total_len=%"PRIu64"\n",
				(uint64_t)nb,(uint64_t)no,(uint64_t)nc,(uint64_t)itlen,(uint64_t)itdata,(uint64_t)total_len);
	}

	if (G_DUMP_SNAPSHOT_JSON) {
		// Emit a compact single-line JSON with basic snapshot info
		printf("{\"kind\":%llu,\"hash\":\"%s\",\"vm_data\":%llu,\"vm_instr\":%llu,\"iso_data\":%llu,\"iso_instr\":%llu,\"cluster\":{\"base\":%llu,\"objs\":%llu,\"clusters\":%llu,\"it_len\":%llu,\"it_off\":%llu,\"total\":%llu},\"cws\":%d}\n",
				(unsigned long long)kind,
				ctx->snapshot_hash,
				(unsigned long long)ctx->vm_data,
				(unsigned long long)ctx->vm_instr,
				(unsigned long long)ctx->iso_data,
				(unsigned long long)ctx->iso_instr,
				(unsigned long long)nb,
				(unsigned long long)no,
				(unsigned long long)nc,
				(unsigned long long)itlen,
				(unsigned long long)itdata,
				(unsigned long long)total_len,
				ctx->compressed_word_size);
	}
	// Build symbol cache for name lookup using r_bin APIs (faster than core JSON)
	HtUP *sym_by_addr = ht_up_new0 ();
	if (ctx->core && ctx->core->bin && sym_by_addr) {
		RVecRBinSymbol *v = r_bin_get_symbols_vec (ctx->core->bin);
		if (v) {
			RBinSymbol *sym;
			R_VEC_FOREACH (v, sym) {
				if (!sym) continue;
				if (sym->type && strcmp (sym->type, R_BIN_TYPE_FUNC_STR)) {
					continue;
				}
				if (sym->vaddr) {
					ht_up_insert (sym_by_addr, sym->vaddr, sym);
				}
			}
		}
	}
	// Attempt to enumerate code entrypoints using InstructionsTable rodata.
	if (!ctx->iso_instr) {
		// Without instructions image base, we cannot map pc_offsets to addresses.
		return 0;
	}
	// Compute data image base = iso_data + RoundUp(total_len, kMaxObjectAlignment)
	// Use 16-byte alignment as a reasonable default on 64-bit.
	ut64 kAlign = ctx->layout && ctx->layout->max_alignment ? (ut64)ctx->layout->max_alignment : 16;
	ut64 data_image_base = base + ((total_len + (kAlign - 1)) & ~(kAlign - 1));
	// instruction_table_data_offset is optional; if 0, we can't read rodata entries easily.
	if (itlen == 0) {
		// nothing to emit
		if (sym_by_addr) ht_up_free (sym_by_addr);
		return 0;
	}
	if (itdata == 0) {
		// No rodata pointer: emit a conservative number of sequential entries.
		ut64 cap2 = ctx->layout && ctx->layout->it_cap ? ctx->layout->it_cap : 20000;
		if (cap2 > 256) cap2 = 256; // keep outputs small/deterministic
		ut64 limit2 = itlen > cap2 ? cap2 : itlen;
		for (ut64 i = 0; i < limit2; i++) {
			ut64 ep = ctx->iso_instr + (i * 4);
			const char *resolved = NULL;
			if (sym_by_addr) {
				RBinSymbol *bs = (RBinSymbol *)ht_up_find (sym_by_addr, ep, NULL);
				if (bs && bs->name) {
					resolved = r_bin_name_tostring (bs->name);
				}
			}
			char name[128];
			if (resolved && *resolved) snprintf (name, sizeof (name), "%s", resolved);
			else snprintf (name, sizeof (name), "method.fn_%"PRIu64, (uint64_t)i);
			if (on_fn) on_fn (name, (unsigned long long)ep, 0, user);
			if (G_DUMP_IT) {
				fprintf (stderr, "[it] %"PRIu64" 0x%"PFMT64x"\n", (uint64_t)i, (ut64)(ctx->iso_instr + (i * 4)));
			}
		}
		if (sym_by_addr) ht_up_free (sym_by_addr);
		return 0;
	}
	// Try to locate InstructionsTable::Data bytes. It's stored in a String object.
	// We heuristically scan around data_image_base + itdata to find a header where
	//   header.length is reasonable and header.first_entry_with_code < header.length.
	ut64 cand = data_image_base + itdata;
	uint32_t header_len = 0;
	uint32_t first_with_code = 0;
	bool found = false;
	ut8 hdr2[8];
	for (int delta = -64; delta <= 64; delta += 4) {
		ut64 addr = cand + delta;
		if (!read_mem(ctx->core, addr, hdr2, sizeof(hdr2))) continue;
		header_len = *(uint32_t*)(hdr2 + 0);
		first_with_code = *(uint32_t*)(hdr2 + 4);
		if (header_len > 0 && header_len < (1u<<24) && first_with_code < header_len) {
			found = true;
			cand = addr;
			break;
		}
	}
	if (!found) {
		fprintf(stderr, "[r2flutter] Could not locate InstructionsTable::Data at 0x%"PFMT64x"\n", (ut64)(data_image_base + itdata));
		return 0;
	}
	// Read DataEntry array (header_len entries), each entry is {uint32 pc_offset; uint32 sm_offset}
	// Binary search table is exactly header_len entries and comes right after 8-byte header.
	ut64 entries_addr = cand + 8;
	// Sanity cap
	if (header_len > 200000) header_len = 200000;
	// We need pc offsets for indices first_with_code .. first_with_code + itlen - 1
	// We'll read those selectively instead of allocating the whole array.
	ut64 cap = ctx->layout && ctx->layout->it_cap ? ctx->layout->it_cap : 20000;
	ut64 limit = itlen > cap ? cap : itlen;
	for (ut64 i = 0; i < limit; i++) {
		ut64 idx = (ut64)first_with_code + i;
		if (idx >= header_len) break;
		ut64 entry_addr = entries_addr + idx * 8;
		ut8 ebuf[8];
		if (!read_mem(ctx->core, entry_addr, ebuf, sizeof(ebuf))) {
			break;
		}
		uint32_t pc_offset = *(uint32_t*)(ebuf + 0);
		// uint32_t sm_off = *(uint32_t*)(ebuf + 4);
		ut64 ep = ctx->iso_instr + (ut64)pc_offset;
		const char *resolved = NULL;
		if (sym_by_addr) {
			RBinSymbol *bs = (RBinSymbol *)ht_up_find (sym_by_addr, ep, NULL);
			if (bs && bs->name) {
				resolved = r_bin_name_tostring (bs->name);
			}
		}
		char name[128];
		if (resolved && *resolved) snprintf(name, sizeof(name), "%s", resolved);
		else snprintf(name, sizeof(name), "method.fn_%"PRIu64, (uint64_t)i);
		if (on_fn) on_fn(name, (unsigned long long)ep, 0, user);
		if (G_DUMP_IT) {
			fprintf(stderr, "[it] %"PRIu64" 0x%"PFMT64x"\n", (uint64_t)i, (ut64)ep);
		}
	}
	if (sym_by_addr) ht_up_free (sym_by_addr);
	return 0;
}
// Standalone AOT snapshot/ObjectPool parser (no Dart VM deps)
// Snapshot discovery is implemented in find_snapshots_with_r2; pool decoding is handled in decode_pool_and_emit.
// For now it’s a stub that returns not implemented.

static int find_snapshots_with_r2(RCore *core, ut64 *vm_data, ut64 *vm_instr, ut64 *iso_data, ut64 *iso_instr) {
	if (!core) return -1;
	if (vm_data) *vm_data = 0;
	if (vm_instr) *vm_instr = 0;
	if (iso_data) *iso_data = 0;
	if (iso_instr) *iso_instr = 0;

	// 1) Prefer symbol names via r_bin APIs
	const char *names[8] = {
		"_kDartVmSnapshotData", "DartVmSnapshotData",
		"_kDartVmSnapshotInstructions", "DartVmSnapshotInstructions",
		"_kDartIsolateSnapshotData", "DartIsolateSnapshotData",
		"_kDartIsolateSnapshotInstructions", "DartIsolateSnapshotInstructions",
	};
	ut64 *outs[4] = { vm_data, vm_instr, iso_data, iso_instr };
	if (core->bin) {
		RVecRBinSymbol *v = r_bin_get_symbols_vec (core->bin);
		if (v) {
			RBinSymbol *sym;
			R_VEC_FOREACH (v, sym) {
				if (!sym || !sym->name) continue;
				const char *nm = r_bin_name_tostring2 (sym->name, 'o');
				if (!nm || !*nm) continue;
				for (int k = 0; k < 8; k++) {
					if (!strcmp (nm, names[k])) {
						int idx = k / 2;
						if (outs[idx]) {
							*outs[idx] = sym->vaddr ? sym->vaddr : 0;
						}
					}
				}
			}
		}
	}
	if (vm_data && *vm_data && vm_instr && *vm_instr && iso_data && *iso_data && iso_instr && *iso_instr) {
		return 0;
	}

	// 2) Fallback: scan sections for magic using r_bin sections
	RList *sections = r_bin_get_sections (core->bin);
	const uint32_t kMagic = 0xdcdcf5f5; // Snapshot::kMagicValue
	ut64 found_addrs[8]; int found_cnt = 0;
	if (sections) {
		RListIter *it; RBinSection *sec;
		r_list_foreach (sections, it, sec) {
			if (!sec || !sec->vaddr || !sec->vsize) continue;
			ut64 vaddr = sec->vaddr;
			ut64 size = sec->vsize;
			const int chunk = 4096;
			ut8 buf[chunk];
			for (ut64 off = 0; off + 4 <= size; off += (chunk - 16)) {
				ut64 addr = vaddr + off;
				int toread = (int)((off + chunk <= size) ? chunk : (size - off));
				if (toread <= 0) break;
				if (r_io_read_at (core->io, addr, buf, toread) != toread) break;
				for (int j2 = 0; j2 + 4 <= toread; j2 += 4) {
					uint32_t val = *(uint32_t*)(buf + j2);
					if (val == kMagic) {
						if (found_cnt < (int)(sizeof(found_addrs)/sizeof(found_addrs[0]))) {
							found_addrs[found_cnt++] = addr + j2;
						}
					}
				}
				if (found_cnt >= 8) break;
			}
			if (found_cnt >= 8) break;
		}
	}
	if (found_cnt >= 1) {
		ut64 vm_addr = 0, iso_addr = 0;
		ut64 vm_len = (ut64)-1, iso_len = 0;
		for (int i = 0; i < found_cnt; i++) {
			ut8 hdr[16];
			if (r_io_read_at(core->io, found_addrs[i] + 4, hdr, sizeof(hdr)) < 1) {
				continue;
			}
			uint64_t len = *(uint64_t*)(hdr + 0) + 4; // large_length() adds magic size
			if (len < vm_len) { vm_len = len; vm_addr = found_addrs[i]; }
			if (len > iso_len) { iso_len = len; iso_addr = found_addrs[i]; }
		}
		if (vm_addr && iso_addr) {
			if (vm_data) *vm_data = vm_addr;
			if (iso_data) *iso_data = iso_addr;
			return 0; // partial success (data blobs found)
		}
	}
	return -1;
}

static void read_snapshot_hash_flags(RCore *core, ut64 vm_data, char out_hash[33]) {
	extract_snapshot_hash_flags(core, vm_data, out_hash);
}

static void emit_stub_symbols(RCore *core,
		void (*on_fn)(const char* name, unsigned long long addr, unsigned long long size, void* user),
		void* user) {
	if (!core || !core->bin || !on_fn) return;
	RVecRBinSymbol *v = r_bin_get_symbols_vec (core->bin);
	if (!v) return;
	RBinSymbol *sym;
	R_VEC_FOREACH (v, sym) {
		if (!sym) continue;
		if (sym->type && strcmp (sym->type, R_BIN_TYPE_FUNC_STR)) continue;
		ut64 addr = sym->vaddr;
		if (!addr) continue;
		ut64 size = sym->size;
		const char *nm = sym->name ? r_bin_name_tostring2 (sym->name, 'o') : NULL;
		if (!nm) nm = "sym.func";
		char tmp[512];
		snprintf (tmp, sizeof (tmp), "%s", nm);
		for (char *p = tmp; *p; p++) if (*p == ' ') *p = '.';
		on_fn (tmp, (unsigned long long)addr, (unsigned long long)size, user);
	}
}

static ut64 find_pp_base_via_r2(RCore *core, ut64 iso_instr) {
	(void)core; (void)iso_instr;
	// Disabled heuristic to avoid slow JSON disassembly; use 0 until we add a fast r_asm pattern.
	return 0;
}

int dart_pool_enumerate(RCore *core, const char* libapp_path,
		void (*on_fn)(const char* name, unsigned long long addr, unsigned long long size, void* user),
		void* user,
		unsigned long long* out_base,
		unsigned long long* out_heap_base) {
	(void)on_fn; (void)user; (void)libapp_path;
	if (!core) return -1;
	ut64 vm_data = 0, vm_instr = 0, iso_data = 0, iso_instr = 0;
	int ok = find_snapshots_with_r2(core, &vm_data, &vm_instr, &iso_data, &iso_instr);
	if (ok == 0) {
		if (out_base) *out_base = (unsigned long long)r_bin_get_baddr(core->bin);
		if (out_heap_base) *out_heap_base = 0;
		eprintf ("[r2flutter] Found Dart snapshots: vm_data=0x%llx vm_instr=0x%llx iso_data=0x%llx iso_instr=0x%llx\n",
				(unsigned long long)vm_data, (unsigned long long)vm_instr,
				(unsigned long long)iso_data, (unsigned long long)iso_instr);
		DartCtx ctx = {0};
		ctx.core = core;
		ctx.vm_data = vm_data; ctx.vm_instr = vm_instr;
		ctx.iso_data = iso_data; ctx.iso_instr = iso_instr;
		read_snapshot_hash_flags(core, vm_data, ctx.snapshot_hash);
		DartVerLayout layout_tmp;
		ctx.layout = load_layout_from_json(ctx.snapshot_hash, &layout_tmp);
		if (!ctx.layout) {
			ctx.layout = pick_layout_by_hash(ctx.snapshot_hash);
		}
		derive_layout_from_flags(&ctx);
		// Debug: dump first 32 bytes of isolate snapshot data
		if (G_VERBOSE > 1) {
			ut8 peek[32] = {0};
			if (read_mem(core, iso_data, peek, sizeof(peek))) {
				fprintf(stderr, "[r2flutter] iso_data[0..32]: ");
				for (int i = 0; i < 32; i++) {
					fprintf(stderr, "%02x", (unsigned int)peek[i]);
				}
				fprintf(stderr, "\n");
			}
		}
		// Emit FUNC symbols available in the binary (e.g., VM stubs)
		if (!G_NO_STUBS) {
			emit_stub_symbols (core, on_fn, user);
		}
		// Decode and emit functions from ObjectPool if layout is known (WIP)
		(void)decode_pool_and_emit (&ctx, on_fn, user);
		// Try to guess PP base (global ObjectPool) using adrp/add prologue pattern
		ut64 pp_base = find_pp_base_via_r2(core, iso_instr);
		if (!pp_base && vm_instr) {
			pp_base = find_pp_base_via_r2(core, vm_instr);
		}
		if (pp_base && out_heap_base) {
			*out_heap_base = (unsigned long long)pp_base;
			if (G_VERBOSE > 0) {
				fprintf(stderr, "[r2flutter] PP(base)=0x%"PFMT64x"\n", (uint64_t)pp_base);
			}
		}
		return 0; // return 0 to let caller proceed even if pool decoding isn't finished
	}
	if (out_base) {
		*out_base = 0;
	}
	if (out_heap_base) {
		*out_heap_base = 0;
	}
	eprintf ("[r2flutter] Dart snapshots not found in symbols (file=%s).\n", libapp_path ? libapp_path : "(null)");
	return -1;
}
