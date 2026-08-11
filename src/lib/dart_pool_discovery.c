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

static ut64 rebase_bin_addr(DartCtx *ctx, ut64 addr) {
	if (!ctx || !ctx->core || !ctx->core->bin || !ctx->core->io || !addr) {
		return addr;
	}
	ut64 baddr = r_bin_get_baddr (ctx->core->bin);
	if (!baddr || addr >= baddr || baddr > UT64_MAX - addr) {
		return addr;
	}
	ut64 rebased = baddr + addr;
	return r_io_v2p (ctx->core->io, rebased) != UT64_MAX? rebased: addr;
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
			if (val != DART_SNAPSHOT_MAGIC) {
				continue;
			}
			const ut64 hit = addr + j;
			// The read window overlaps the previous chunk by 16 bytes so a magic
			// straddling a boundary is not missed; dedup so those overlap bytes
			// (and Mach-O segment/section double-coverage) don't count twice.
			bool dup = false;
			for (int d = 0; d < found_cnt; d++) {
				if (found_addrs[d] == hit) {
					dup = true;
					break;
				}
			}
			if (!dup) {
				found_addrs[found_cnt++] = hit;
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
					// Only assign when this symbol carries an address: Mach-O
					// often lists a name twice and a later vaddr==0 duplicate
					// must not erase the good value we already resolved.
					if (!strcmp (nm, names[k]) && sym->vaddr) {
						int idx = k / 2;
						*outs[idx] = rebase_bin_addr (ctx, sym->vaddr);
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
			// r_bin_get_sections_vec returns both segments and their child
			// sections on Mach-O; scanning both covers the same bytes twice.
			if (sec->is_segment) {
				continue;
			}
			ut64 vaddr = rebase_bin_addr (ctx, sec->vaddr);
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
		// Only data snapshots carry the snapshot magic; instruction images do
		// not. The old code classified every non-data magic hit as an
		// "instructions" snapshot and fed its bogus total_len into the vm/iso
		// picker, so a stray f5f5dcdc byte run could poison vm_instr/iso_instr.
		// Derive only the data snapshots here; instruction images come from
		// symbols (and, once implemented, structural section location).
		ut64 data_addrs[4];
		ut64 data_lens[4];
		int data_cnt = 0;
		for (int i = 0; i < found_cnt && data_cnt < 4; i++) {
			ut64 total_len = 0;
			if (looks_like_data_snapshot (ctx, found_addrs[i], &total_len)) {
				data_addrs[data_cnt] = found_addrs[i];
				data_lens[data_cnt] = total_len;
				data_cnt++;
			}
		}
		if (data_cnt >= 1) {
			// Preserve any addresses already resolved from symbols; only fill
			// the ones still unset so scan guesses cannot overwrite good values.
			ut64 scan_vm_data = 0;
			ut64 scan_iso_data = 0;
			pick_vm_iso_by_size (data_addrs, data_lens, data_cnt, &scan_vm_data, &scan_iso_data);
			if (!ctx->vm_data) {
				ctx->vm_data = scan_vm_data;
			}
			if (!ctx->iso_data) {
				ctx->iso_data = scan_iso_data;
			}
		}
		if (ctx->vm_data || ctx->iso_data || ctx->vm_instr || ctx->iso_instr) {
			return 0;
		}
	}
	return -1;
}
