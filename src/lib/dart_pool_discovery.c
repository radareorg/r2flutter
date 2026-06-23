/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

static bool looks_like_data_snapshot(DartCtx *ctx, ut64 base, ut64 *out_total_len) {
	DartSnapshotHeader hdr;
	if (!dart_snapshot_header_read (ctx, base, &hdr)) {
		return false;
	}
	if (hdr.nb == 0 || hdr.no == 0 || hdr.nc == 0) {
		return false;
	}
	if (hdr.itlen > (1ULL << 32)) {
		return false;
	}
	if (hdr.itdata > (1ULL << 40)) {
		return false;
	}
	if (out_total_len) {
		*out_total_len = hdr.total_len;
	}
	return true;
}

static void pick_vm_iso_by_size(const ut64 *addrs, const ut64 *lens, int count, ut64 *vm_out, ut64 *iso_out) {
	if (count < 1) {
		return;
	}
	ut64 vm_addr = 0;
	ut64 iso_addr = 0;
	ut64 vm_len = UT64_MAX;
	ut64 iso_len = 0;
	for (int i = 0; i < count; i++) {
		if (lens[i] < vm_len) {
			vm_len = lens[i];
			vm_addr = addrs[i];
		}
		if (lens[i] > iso_len) {
			iso_len = lens[i];
			iso_addr = addrs[i];
		}
	}
	if (vm_addr) {
		*vm_out = vm_addr;
	}
	if (iso_addr) {
		*iso_out = iso_addr;
	}
}

static int collect_snapshot_magics_in_range(DartCtx *ctx, ut64 start, ut64 size, ut64 *found_addrs, int found_cap, int found_cnt) {
	if (!ctx || !found_addrs || found_cap <= 0 || found_cnt >= found_cap || size < 4) {
		return found_cnt;
	}
	ut8 buf[4096];
	for (ut64 off = 0; off + 4 <= size; off += (sizeof (buf) - 16)) {
		ut64 addr = start + off;
		int toread = (int) ((off + sizeof (buf) <= size)? sizeof (buf): (size - off));
		if (!read_mem (ctx, addr, buf, toread)) {
			break;
		}
		for (int j = 0; j <= toread - 4; j += 4) {
			uint32_t val = r_read_le32 (buf + j);
			if (val == DART_SNAPSHOT_MAGIC) {
				found_addrs[found_cnt++] = addr + j;
				if (found_cnt >= found_cap) {
					return found_cnt;
				}
			}
		}
	}
	return found_cnt;
}

int find_snapshots(DartCtx *ctx) {
	if (!ctx || !ctx->core) {
		return -1;
	}
	RCore *core = ctx->core;
	ctx->vm_data = 0;
	ctx->vm_instr = 0;
	ctx->iso_data = 0;
	ctx->iso_instr = 0;

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
	ut64 *outs[4] = { &ctx->vm_data, &ctx->vm_instr, &ctx->iso_data, &ctx->iso_instr };
	if (core->bin) {
		RVecRBinSymbol *v = r_bin_get_symbols_vec (core->bin);
		if (v) {
			RBinSymbol *sym;
			R_VEC_FOREACH (v, sym) {
				if (!sym || !sym->name) {
					continue;
				}
				const char *nm = r_bin_name_tostring2 (sym->name, 'o');
				if (R_STR_ISEMPTY (nm)) {
					continue;
				}
				for (int k = 0; k < 8; k++) {
					if (!strcmp (nm, names[k])) {
						int idx = k / 2;
						*outs[idx] = sym->vaddr? sym->vaddr: 0;
					}
				}
			}
		}
	}
	if (ctx->vm_data && ctx->vm_instr && ctx->iso_data && ctx->iso_instr) {
		return 0;
	}

	RVecRBinSection *sections = r_bin_get_sections_vec (core->bin);
	ut64 found_addrs[32];
	int found_cnt = 0;
	if (sections) {
		RBinSection *sec;
		R_VEC_FOREACH (sections, sec) {
			if (!sec || !sec->vaddr || !sec->vsize) {
				continue;
			}
			ut64 vaddr = sec->vaddr;
			ut64 size = sec->vsize;
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] scanning section '%s' vaddr=0x%" PFMT64x " size=0x%" PFMT64x "\n", sec->name? sec->name: "(null)", (ut64)vaddr, (ut64)size);
			}
			found_cnt = collect_snapshot_magics_in_range (ctx, vaddr, size, found_addrs, (int) (sizeof (found_addrs) / sizeof (found_addrs[0])), found_cnt);
			if (found_cnt >= 8) {
				break;
			}
		}
	}
	if (found_cnt == 0) {
		ut64 size = r_io_size (core->io);
		if (size > 0 && size < (1ULL << 32)) {
			if (ctx->verbose > 0) {
				fprintf (stderr, "[r2flutter] scanning raw file size=0x%" PFMT64x "\n", (ut64)size);
			}
			found_cnt = collect_snapshot_magics_in_range (ctx, 0, size, found_addrs, (int) (sizeof (found_addrs) / sizeof (found_addrs[0])), found_cnt);
		}
	}
	if (found_cnt >= 1) {
		ut64 data_addrs[4];
		ut64 data_lens[4];
		int data_cnt = 0;
		ut64 instr_addrs[4];
		ut64 instr_lens[4];
		int instr_cnt = 0;
		for (int i = 0; i < found_cnt; i++) {
			ut8 hdr2[16];
			if (!read_mem (ctx, found_addrs[i] + 4, hdr2, sizeof (hdr2))) {
				continue;
			}
			ut64 total_len = r_read_le64 (hdr2) + 4;
			ut64 classified_len = 0;
			bool is_data = looks_like_data_snapshot (ctx, found_addrs[i], &classified_len);
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
			pick_vm_iso_by_size (data_addrs, data_lens, data_cnt, &ctx->vm_data, &ctx->iso_data);
		}
		if (instr_cnt >= 1) {
			pick_vm_iso_by_size (instr_addrs, instr_lens, instr_cnt, &ctx->vm_instr, &ctx->iso_instr);
		}
		if (ctx->vm_data || ctx->iso_data || ctx->vm_instr || ctx->iso_instr) {
			return 0;
		}
	}
	return -1;
}
