#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <r_core.h>
#include <r_io.h>
#include <r_util/r_json.h>
#include <r_util/r_file.h>

// Minimal, standalone AOT snapshot/ObjectPool decoder scaffolding.
// This file will progressively implement decoding without Dart VM deps.

typedef struct {
	char hash[33]; // snapshot hash as ASCII (32 chars)
	int compressed_word_size; // 4 or 8
	int heap_object_tag;      // usually 1
				  // Future: offsets for Code.entry_point, Code.size, Function.name, etc.
} DartVerLayout;

#if 0
static const DartVerLayout known_layouts[] = {
	// TODO: populate with known snapshot hashes from your target SDKs.
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
	(void)hash;
	return NULL;
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

static bool read_mem(RCore *core, ut64 addr, void *buf, int len) {
	if (!core || !buf || len <= 0) return false;
	int r = r_io_read_at(core->io, addr, (ut8*)buf, len);
	return r == len;
}

static RJson* load_offsets_json(void) {
	char *s = r_file_slurp("r2flutter/offsets.json", NULL);
	if (!s) s = r_file_slurp("offsets.json", NULL);
	if (!s) return NULL;
	RJson *j = r_json_parse(s);
	free(s);
	return j;
}

static const DartVerLayout* load_layout_from_json(const char *hash, DartVerLayout *out) {
	RJson *j = load_offsets_json();
	if (!j) return NULL;
	const RJson *hashes = r_json_get(j, "hashes");
	const RJson *item = r_json_get(hashes, hash);
	if (!item) { r_json_free(j); return NULL; }
	memset(out, 0, sizeof(*out));
	const char *h = r_json_get_str(item, "hash");
	if (h && *h) strncpy(out->hash, h, 32);
	else strncpy(out->hash, hash, 32);
	out->hash[32] = '\0';
	out->compressed_word_size = (int)r_json_get_num(item, "compressed_word_size");
	out->heap_object_tag = (int)r_json_get_num(item, "heap_object_tag");
	r_json_free(j);
	return out;
}

static bool read_string_at(RCore *core, ut64 addr, char *out, int maxlen) {
	if (!out || maxlen <= 1) return false;
	int i;
	for (i = 0; i < maxlen - 1; i++) {
		ut8 ch = 0;
		if (!read_mem(core, addr + i, &ch, 1)) break;
		out[i] = (char)ch;
		if (ch == '\0') break;
	}
	out[i < maxlen ? i : maxlen - 1] = '\0';
	return true;
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
	fprintf(stderr, "[r2flutter] snapshot_hash=%.*s flags=%.128s\n", 32, (const char*)(buf + 20), flags);
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
	// TODO:
	// - Read isolate snapshot header and find the heap object area
	// - Locate the global ObjectPool and iterate entries
	// - For kTaggedObject entries: when Function/Code/String are found, resolve names and entrypoints
	// - For kImmediate entries adjacent to UnlinkedCall, recover call targets
	// - Emit on_fn(name, ep, size, user)
	(void)read_string_at;
	return -1;
}
// Standalone AOT snapshot/ObjectPool parser (no Dart VM deps)
// TODO: Implement ELF/Mach-O scan to locate snapshot blobs and decode ObjectPool
// For now it’s a stub that returns not implemented.

static int find_snapshots_with_r2(RCore *core, ut64 *vm_data, ut64 *vm_instr, ut64 *iso_data, ut64 *iso_instr) {
	if (!core) return -1;
	r_core_cmd(core, "e bin.cache=true", false);
	char *s = r_core_cmd_str(core, "isj");
	if (!s) return -1;
	RJson *j = r_json_parse(s);
	free(s);
	if (!j) return -1;
	// Accept both underscore and non-underscore symbol prefixes
	const char *names[8] = {
		"_kDartVmSnapshotData", "DartVmSnapshotData",
		"_kDartVmSnapshotInstructions", "DartVmSnapshotInstructions",
		"_kDartIsolateSnapshotData", "DartIsolateSnapshotData",
		"_kDartIsolateSnapshotInstructions", "DartIsolateSnapshotInstructions",
	};
	ut64 *outs[4] = { vm_data, vm_instr, iso_data, iso_instr };
	// ut64 sizes[4] = {0};
	size_t i;
	for (i = 0;; i++) {
		const RJson *item = r_json_item(j, i);
		if (!item) break;
		const char *nm = r_json_get_str(item, "name");
		if (!nm || !*nm) continue;
		ut64 vaddr = (ut64)r_json_get_num(item, "vaddr");
		if (!vaddr) vaddr = (ut64)r_json_get_num(item, "plt");
		// ut64 sz = (ut64)r_json_get_num(item, "size");
		for (int k = 0; k < 8; k++) {
			if (strcmp(nm, names[k]) == 0) {
				int idx = k / 2;
				if (outs[idx]) {
					*outs[idx] = vaddr;
		//			sizes[idx] = sz;
				}
			}
		}
	}
	r_json_free(j);
	// sizes[] are available if needed later; currently unused
	if (*vm_data && *vm_instr && *iso_data && *iso_instr) {
		return 0;
	}

	// Fallback for Mach-O/iOS: scan sections for snapshot magic and infer vm/isolate data
	char *sec = r_core_cmd_str(core, "iSj");
	if (!sec) return -1;
	RJson *js = r_json_parse(sec);
	free(sec);
	if (!js) return -1;
	const uint32_t kMagic = 0xdcdcf5f5; // Snapshot::kMagicValue
	ut64 found_addrs[8]; int found_cnt = 0;
	for (size_t i = 0;; i++) {
		const RJson *item = r_json_item(js, i);
		if (!item) break;
		ut64 vaddr = (ut64)r_json_get_num(item, "vaddr");
		ut64 size = (ut64)r_json_get_num(item, "vsize");
		if (!vaddr || !size) continue;
		// Scan each section for magic value at 4-byte aligned offsets
		const int chunk = 4096;
		ut8 buf[chunk];
		for (ut64 off = 0; off + 4 <= size; off += chunk - 16) {
			ut64 addr = vaddr + off;
			int toread = (int)((off + chunk <= size) ? chunk : (size - off));
			if (toread <= 0) break;
			if (r_io_read_at(core->io, addr, buf, toread) != toread) break;
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
	r_json_free(js);
	if (found_cnt >= 1) {
		// Heuristic: smaller snapshot is VM, larger is Isolate.
		// Read length (int64 at +4) and compute size = length + magic_size.
		ut64 vm_addr = 0, iso_addr = 0;
		ut64 vm_len = (ut64)-1, iso_len = 0;
		for (int i = 0; i < found_cnt; i++) {
			ut8 hdr[16];
			// if (r_io_read_at(core->io, found_addrs[i] + 4, hdr, sizeof(hdr)) != sizeof(hdr)) continue;
			if (r_io_read_at(core->io, found_addrs[i] + 4, hdr, sizeof(hdr)) < 1) {
				continue;
			}
			uint64_t len = *(uint64_t*)(hdr + 0) + 4; // large_length() adds magic size
			if (len < vm_len) { vm_len = len; vm_addr = found_addrs[i]; }
			if (len > iso_len) { iso_len = len; iso_addr = found_addrs[i]; }
		}
		if (vm_addr && iso_addr) {
			*vm_data = vm_addr;
			*iso_data = iso_addr;
			// instructions images are not discoverable by magic; keep 0 here.
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
	if (!core || !on_fn) return;
	char *s = r_core_cmd_str(core, "isj");
	if (!s) return;
	RJson *j = r_json_parse(s);
	free(s);
	if (!j) return;
	for (size_t i = 0;; i++) {
		const RJson *item = r_json_item(j, i);
		if (!item) break;
		const char *nm = r_json_get_str(item, "name");
		const char *type = r_json_get_str(item, "type");
		if (!nm || !type) continue;
		if (strcmp(type, "FUNC")) continue;
		ut64 addr = (ut64)r_json_get_num(item, "vaddr");
		if (!addr) addr = (ut64)r_json_get_num(item, "plt");
		ut64 size = (ut64)r_json_get_num(item, "size");
		if (!addr) continue;
		// Normalize radare's synthetic names: replace spaces with dots
		char tmp[512];
		snprintf(tmp, sizeof(tmp), "%s", nm);
		for (char *p = tmp; *p; p++) if (*p == ' ') *p = '.';
		on_fn(tmp, (unsigned long long)addr, (unsigned long long)size, user);
	}
	r_json_free(j);
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
		ut8 peek[32] = {0};
		if (read_mem(core, iso_data, peek, sizeof(peek))) {
			fprintf(stderr, "[r2flutter] iso_data[0..32]: ");
			for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", (unsigned int)peek[i]);
			fprintf(stderr, "\n");
		}
		// Emit FUNC symbols available in the binary (e.g., VM stubs)
		emit_stub_symbols(core, on_fn, user);
		// Decode and emit functions from ObjectPool if layout is known (WIP)
		(void)decode_pool_and_emit(&ctx, on_fn, user);
		return 0; // return 0 to let caller proceed even if pool decoding isn't finished
	}
	if (out_base) *out_base = 0;
	if (out_heap_base) *out_heap_base = 0;
	fprintf(stderr, "[r2flutter] Dart snapshots not found in symbols (file=%s).\n", libapp_path ? libapp_path : "(null)");
	return -1;
}
