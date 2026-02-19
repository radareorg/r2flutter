/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <r_core.h>
#include <r_io.h>
#include <r_list.h>
#include "../../include/r2flutter/dart_r2.h"

static bool read_mem(RCore *core, ut64 addr, void *buf, int len) {
	if (!core || !buf || len <= 0) {
		return false;
	}
	int r = r_io_read_at (core->io, addr, (ut8 *)buf, len);
	return r > 0;
}

static bool read_uleb128_at(RCore *core, ut64 addr, ut64 *out_val, ut64 *out_next) {
	ut64 v = 0;
	int shift = 0;
	for (int i = 0; i < 10; i++) {
		ut8 b = 0;
		if (!read_mem (core, addr + i, &b, 1)) {
			return false;
		}
		v |= ((ut64) (b & 0x7f)) << shift;
		if ((b & 0x80) == 0) {
			if (out_val) {
				*out_val = v;
			}
			if (out_next) {
				*out_next = addr + i + 1;
			}
			return true;
		}
		shift += 7;
	}
	return false;
}

static bool looks_like_data_snapshot(RCore *core, ut64 base, ut64 *out_total_len) {
	if (!core || !base) {
		return false;
	}
	ut8 hdr[4 + 8 + 8];
	if (!read_mem (core, base, hdr, sizeof (hdr))) {
		return false;
	}
	uint32_t magic = *(uint32_t *) (hdr + 0);
	if (magic != 0xdcdcf5f5) {
		return false;
	}
	uint64_t length_ex_magic = *(uint64_t *) (hdr + 4);
	uint64_t total_len = length_ex_magic + 4;
	ut64 cursor = base + 4 + 8 + 8;
	const int max_scan = 2048;
	ut8 b = 0;
	int scanned = 0;
	while (scanned < max_scan) {
		if (!read_mem (core, cursor + scanned, &b, 1)) {
			return false;
		}
		if (b == '\0') {
			break;
		}
		scanned++;
	}
	if (b != '\0') {
		return false;
	}
	ut64 nb = 0, no = 0, nc = 0, itlen = 0, itdata = 0, tmp = cursor + scanned + 1;
	if (!read_uleb128_at (core, tmp, &nb, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &no, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &nc, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &itlen, &tmp)) {
		return false;
	}
	if (!read_uleb128_at (core, tmp, &itdata, &tmp)) {
		return false;
	}
	if (nb == 0 || no == 0 || nc == 0) {
		return false;
	}
	if (itlen > (1ULL << 32)) {
		return false;
	}
	if (itdata > (1ULL << 40)) {
		return false;
	}
	if (out_total_len) {
		*out_total_len = total_len;
	}
	return true;
}

int dart_r2_find_snapshots(RCore *core, ut64 *vm_data, ut64 *vm_instr, ut64 *iso_data, ut64 *iso_instr) {
	if (!core) {
		return -1;
	}
	if (vm_data) {
		*vm_data = 0;
	}
	if (vm_instr) {
		*vm_instr = 0;
	}
	if (iso_data) {
		*iso_data = 0;
	}
	if (iso_instr) {
		*iso_instr = 0;
	}

	const char *names[8] = {
		"_kDartVmSnapshotData",
		"DartVmSnapshotData",
		"_kDartVmSnapshotInstructions",
		"DartVmSnapshotInstructions",
		"_kDartIsolateSnapshotData",
		"DartIsolateSnapshotData",
		"_kDartIsolateSnapshotInstructions",
		"DartIsolateSnapshotInstructions",
	};
	ut64 *outs[4] = { vm_data, vm_instr, iso_data, iso_instr };
	if (core->bin) {
		RVecRBinSymbol *v = r_bin_get_symbols_vec (core->bin);
		if (v) {
			RBinSymbol *sym;
			R_VEC_FOREACH (v, sym) {
				if (!sym || !sym->name) {
					continue;
				}
				const char *nm = r_bin_name_tostring2 (sym->name, 'o');
				if (!nm || !*nm) {
					continue;
				}
				for (int k = 0; k < 8; k++) {
					if (!strcmp (nm, names[k])) {
						int idx = k / 2;
						if (outs[idx]) {
							*outs[idx] = sym->vaddr? sym->vaddr: 0;
						}
					}
				}
			}
		}
	}
	if (vm_data && *vm_data && vm_instr && *vm_instr && iso_data && *iso_data && iso_instr && *iso_instr) {
		return 0;
	}

	RList *sections = r_bin_get_sections (core->bin);
	const uint32_t kMagic = 0xdcdcf5f5;
	ut64 found_addrs[32];
	int found_cnt = 0;
	if (sections) {
		RListIter *it;
		RBinSection *sec;
		r_list_foreach (sections, it, sec) {
			if (!sec || !sec->vaddr || !sec->vsize) {
				continue;
			}
			ut64 vaddr = sec->vaddr;
			ut64 size = sec->vsize;
			ut8 buf[4096];
			for (ut64 off = 0; off + 4 <= size; off += (sizeof (buf) - 16)) {
				ut64 addr = vaddr + off;
				int toread = (int) ((off + sizeof (buf) <= size)? sizeof (buf): (size - off));
				if (toread <= 0) {
					break;
				}
				if (r_io_read_at (core->io, addr, buf, toread) != toread) {
					break;
				}
				for (int j2 = 0; j2 + 4 <= toread; j2 += 4) {
					uint32_t val = *(uint32_t *) (buf + j2);
					if (val == kMagic) {
						if (found_cnt < (int) (sizeof (found_addrs) / sizeof (found_addrs[0]))) {
							found_addrs[found_cnt++] = addr + j2;
						}
					}
				}
				if (found_cnt >= 8) {
					break;
				}
			}
			if (found_cnt >= 8) {
				break;
			}
		}
	}
	if (found_cnt >= 1) {
		ut64 data_addrs[4], data_lens[4];
		int data_cnt = 0;
		ut64 instr_addrs[4], instr_lens[4];
		int instr_cnt = 0;
		for (int i = 0; i < found_cnt; i++) {
			ut8 hdr2[16];
			if (r_io_read_at (core->io, found_addrs[i] + 4, hdr2, sizeof (hdr2)) < 1) {
				continue;
			}
			ut64 total_len = *(uint64_t *) (hdr2 + 0) + 4;
			ut64 classified_len = 0;
			bool is_data = looks_like_data_snapshot (core, found_addrs[i], &classified_len);
			if (is_data) {
				if (data_cnt < 4) {
					data_addrs[data_cnt] = found_addrs[i];
					data_lens[data_cnt] = total_len;
					data_cnt++;
				}
			} else {
				if (instr_cnt < 4) {
					instr_addrs[instr_cnt] = found_addrs[i];
					instr_lens[instr_cnt] = total_len;
					instr_cnt++;
				}
			}
		}
		if (data_cnt >= 1) {
			ut64 vm_addr = 0, iso_addr = 0;
			ut64 vm_len = (ut64)-1, iso_len = 0;
			for (int i = 0; i < data_cnt; i++) {
				if (data_lens[i] < vm_len) {
					vm_len = data_lens[i];
					vm_addr = data_addrs[i];
				}
				if (data_lens[i] > iso_len) {
					iso_len = data_lens[i];
					iso_addr = data_addrs[i];
				}
			}
			if (vm_addr && vm_data) {
				*vm_data = vm_addr;
			}
			if (iso_addr && iso_data) {
				*iso_data = iso_addr;
			}
		}
		if (instr_cnt >= 1) {
			ut64 vm_addr = 0, iso_addr = 0;
			ut64 vm_len = (ut64)-1, iso_len = 0;
			for (int i = 0; i < instr_cnt; i++) {
				if (instr_lens[i] < vm_len) {
					vm_len = instr_lens[i];
					vm_addr = instr_addrs[i];
				}
				if (instr_lens[i] > iso_len) {
					iso_len = instr_lens[i];
					iso_addr = instr_addrs[i];
				}
			}
			if (vm_addr && vm_instr) {
				*vm_instr = vm_addr;
			}
			if (iso_addr && iso_instr) {
				*iso_instr = iso_addr;
			}
		}
		if ((vm_data && *vm_data) || (iso_data && *iso_data) || (vm_instr && *vm_instr) || (iso_instr && *iso_instr)) {
			return 0;
		}
	}
	return -1;
}

void dart_r2_emit_stub_symbols(DartCtx *ctx, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user) {
	if (!ctx || !ctx->core || !ctx->core->bin || !on_fn) {
		return;
	}
	RCore *core = ctx->core;
	RVecRBinSymbol *v = r_bin_get_symbols_vec (core->bin);
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
		on_fn (tmp, (unsigned long long)addr, (unsigned long long)size, user);
	}
}

ut64 dart_r2_find_pp_base(DartCtx *ctx) {
	(void)ctx;
	return 0;
}

static bool ctx_read_mem(DartCtx *ctx, ut64 addr, void *buf, int len) {
	if (!ctx || !ctx->core || !buf || len <= 0) {
		return false;
	}
	int r = r_io_read_at (ctx->core->io, addr, (ut8 *)buf, len);
	return r > 0;
}

HtUP *dart_r2_scan_code_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	HtUP *name_by_ep = ht_up_new0 ();
	if (!name_by_ep) {
		return NULL;
	}
	ut64 max_hits = 200;
	if (data_image_end <= data_image_base) {
		return name_by_ep;
	}
	ut64 iso_instr = ctx->iso_instr;
	for (ut64 a = data_image_base; a + 0x30 < data_image_end; a += 16) {
		ut64 ep = 0;
		if (!ctx_read_mem (ctx, a + 0x10, &ep, sizeof (ep))) {
			continue;
		}
		if (ep < iso_instr || ep - iso_instr > (1ULL << 24)) {
			continue;
		}
		ut64 owner = 0;
		if (!ctx_read_mem (ctx, a + 0x10, &owner, sizeof (owner))) {
			continue;
		}
		if (owner < data_image_base || owner >= data_image_end) {
			continue;
		}
		ut64 namep = 0;
		if (!ctx_read_mem (ctx, owner + 0x10, &namep, sizeof (namep))) {
			continue;
		}
		if (namep < data_image_base || namep >= data_image_end) {
			continue;
		}
		ut8 sbuf[128];
		if (!ctx_read_mem (ctx, namep + 24, sbuf, sizeof (sbuf))) {
			continue;
		}
		char sname[128];
		int k = 0;
		for (int j = 0; j < 100 && k < 127; j++) {
			if (sbuf[j] >= 32 && sbuf[j] < 127) {
				sname[k++] = sbuf[j];
			} else if (sbuf[j] == 0) {
				break;
			}
		}
		sname[k] = '\0';
		if (k > 5 && (strstr (sname, "package:") || strstr (sname, "dart:") || strchr (sname, '.') || strchr (sname, '/'))) {
			char *dup = strdup (sname);
			if (dup) {
				ht_up_update (name_by_ep, ep, dup);
				if (--max_hits == 0) {
					break;
				}
			}
		}
	}
	return name_by_ep;
}

#define CHUNK_SIZE 4096

RList *dart_r2_collect_data_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return NULL;
	}
	const char *needle1 = "package:";
	const char *needle2 = "dart:";
	ut8 buf[CHUNK_SIZE];
	RList *out = r_list_newf (free);
	if (!out) {
		return NULL;
	}
	ut64 limit = data_image_end - data_image_base;
	if (limit > (1ULL << 22)) {
		limit = (1ULL << 22);
	}
	ut64 cap = 512;
	for (ut64 off = 0; off < limit; off += (sizeof (buf) - 8)) {
		ut64 addr = data_image_base + off;
		int toread = (int) ((off + sizeof (buf) <= limit)? sizeof (buf): (limit - off));
		if (toread <= 0) {
			break;
		}
		if (r_io_read_at (ctx->core->io, addr, buf, toread) != toread) {
			break;
		}
		for (int i = 0; i + 8 < toread; i++) {
			if (buf[i] == 'p' && i + 8 < toread && !memcmp (buf + i, needle1, 8)) {
				char s[128];
				int k = 0;
				for (int j = i; j < toread && k < 127; j++) {
					ut8 ch = buf[j];
					if (ch == '\0') {
						break;
					}
					if ((ch >= 32 && ch < 127) || ch == '\t') {
						s[k++] = (char)ch;
					} else {
						break;
					}
				}
				s[k] = '\0';
				if (k > 8) {
					char *dup = strdup (s);
					if (dup) {
						r_list_append (out, dup);
						if (--cap == 0) {
							return out;
						}
					}
				}
			} else if (buf[i] == 'd' && i + 5 < toread && !memcmp (buf + i, needle2, 5)) {
				char s[128];
				int k = 0;
				for (int j = i; j < toread && k < 127; j++) {
					ut8 ch = buf[j];
					if (ch == '\0') {
						break;
					}
					if ((ch >= 32 && ch < 127) || ch == '\t') {
						s[k++] = (char)ch;
					} else {
						break;
					}
				}
				s[k] = '\0';
				if (k > 5) {
					char *dup = strdup (s);
					if (dup) {
						r_list_append (out, dup);
						if (--cap == 0) {
							return out;
						}
					}
				}
			}
		}
	}
	return out;
}

void dart_r2_collect_data_names_with_cmd(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end) {
	if (!ctx || !ctx->core) {
		return;
	}
	if (!ctx->name_pool) {
		ctx->name_pool = r_list_newf (free);
	}
	if (!ctx->name_pool) {
		return;
	}
	ut64 limit = data_image_end - data_image_base;
	if (limit > (1ULL << 22)) {
		limit = (1ULL << 22);
	}
	const char *needles[] = { "package:", "dart:" };
	char *out = NULL;
	for (int k = 0; k < 2; k++) {
		out = r_core_cmd_strf (ctx->core, "e search.in=range; e search.from=0x%" PFMT64x "; e search.to=0x%" PFMT64x "; /c %s\n", data_image_base, data_image_base + limit, needles[k]);
		if (!out) {
			continue;
		}
		char *line, *saveptr = NULL;
		for (line = strtok_r (out, "\n", &saveptr); line; line = strtok_r (NULL, "\n", &saveptr)) {
			if (!r_str_startswith (line, "0x")) {
				continue;
			}
			ut64 addr = (ut64)strtoull (line, NULL, 16);
			ut8 buf[128];
			int n = r_io_read_at (ctx->core->io, addr, buf, sizeof (buf));
			if (n > 0) {
				char s2[128];
				int z = 0;
				for (int i = 0; i < n && z < 127; i++) {
					ut8 ch = buf[i];
					if (ch == '\0') {
						break;
					}
					if ((ch >= 32 && ch < 127) || ch == '\t') {
						s2[z++] = (char)ch;
					} else {
						break;
					}
				}
				s2[z] = '\0';
				if (z > 5) {
					char *dup2 = strdup (s2);
					if (dup2) {
						r_list_append (ctx->name_pool, dup2);
					}
				}
			}
			if (r_list_length (ctx->name_pool) >= 512) {
				break;
			}
		}
		free (out);
		if (r_list_length (ctx->name_pool) >= 512) {
			break;
		}
	}
}
