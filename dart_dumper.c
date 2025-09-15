#include <r_core.h>
#include <r_flag.h>
#include <r_util/r_name.h>
#include <r_util/r_json.h>
#include <r_util/r_str.h>
#include <r_list.h>
#include "dart_dumper.h"


static bool list_contains_offset(RList *list, ut64 off) {
	RListIter *it;
	ut64 *p;
	r_list_foreach(list, it, p) {
		if (*p == off) {
			return true;
		}
	}
	return false;
}

static void collect_pool_offsets_from_fn(RCore *core, ut64 addr, RList *offsets) {
	if (!core || !offsets) return;
	char cmd[128];
	snprintf(cmd, sizeof(cmd), "pdfj @ 0x%"PFMT64x, addr);
	char *s = r_core_cmd_str(core, cmd);
	if (!s) return;
	RJson *j = r_json_parse(s);
	if (!j) { free(s); return; }
	const RJson *ops = r_json_get(j, "ops");
	const RJson *arr = ops ? ops : j;
	size_t i;
	for (i = 0;; i++) {
		const RJson *item = r_json_item(arr, i);
		if (!item) break;
		const char *opstr = r_json_get_str(item, "opstr");
		if (!opstr || !*opstr) opstr = r_json_get_str(item, "opcode");
		if (!opstr || !*opstr) continue;
		// search for pattern like: ldr x0, [x27, 0x123]; also match wX, qX
		const char *b = strstr(opstr, "[x27");
		if (!b) continue;
		const char *comma = strchr(b, ',');
		if (!comma) continue;
		// skip spaces
		const char *p = comma + 1;
		while (*p == ' ' || *p == '#') p++;
		// read number until non-hex/non-digit
		bool is_hex = false;
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { is_hex = true; p += 2; }
		ut64 val = 0;
		const char *q = p;
		while ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) q++;
		if (q == p) continue;
		char numbuf[32];
		size_t len = q - p;
		if (len >= sizeof(numbuf)) len = sizeof(numbuf) - 1;
		memcpy(numbuf, p, len);
		numbuf[len] = '\0';
		if (is_hex) {
			val = strtoull(numbuf, NULL, 16);
		} else {
			val = strtoull(numbuf, NULL, 10);
		}
		if (!list_contains_offset(offsets, val)) {
			ut64 *pv = (ut64*)calloc(1, sizeof(ut64));
			if (!pv) continue;
			*pv = val;
			r_list_append(offsets, pv);
		}
	}
	r_json_free(j);
	free(s);
}

static void dump_pool_offsets_flags(DartApp *app, FILE *of) {
	if (!app || !app->core || !app->functions) return;
	RList *offsets = r_list_newf(free);
	if (!offsets) return;
	// collect from all known functions
	RListIter *it;
	DartFunction *fn;
	r_list_foreach(app->functions, it, fn) {
		if (fn->name && !strncmp(fn->name, "sym.imp.", 8)) continue;
		collect_pool_offsets_from_fn(app->core, fn->addr, offsets);
	}
	// emit flags and comments
	RListIter *it2;
	ut64 *offp;
	r_list_foreach(offsets, it2, offp) {
		fprintf(of, "f pp.off_%llx=PP+%#llx\n", (unsigned long long)*offp, (unsigned long long)*offp);
		fprintf(of, "'@PP+%#llx'CC pool_entry_%llx\n", (unsigned long long)*offp, (unsigned long long)*offp);
	}
	r_list_free(offsets);
}

void dart_dumper_dump4radare2(DartApp* app, const char* out_dir) {
	if (!app || !out_dir) return;
	if (!r_sys_mkdirp (out_dir)) {
		R_LOG_ERROR ("cannot mkdirp");
		return;
	}

	char path[4096];
	snprintf(path, sizeof(path), "%s/addNames.r2", out_dir);
	FILE *of = fopen(path, "w");
	if (!of) return;

	fprintf(of, "# create flags for libraries, classes and methods\n");
	fprintf(of, "e emu.str=true\n");
	fprintf(of, "f app.base = %#llx\n", (unsigned long long)app->base_addr);
	fprintf(of, "f app.heap_base = %#llx\n", (unsigned long long)app->heap_base);

	if (app->functions) {
		RListIter *it;
		DartFunction *fn;
		r_list_foreach(app->functions, it, fn) {
			if (!fn || !fn->name) continue;
			char safe[1024];
			snprintf(safe, sizeof(safe), "%s", fn->name);
			r_name_filter(safe, 0);
			fprintf(of, "f method.%s = %#llx\n", safe, (unsigned long long)fn->addr);
			fprintf(of, "'@%#llx'CC %s\n", (unsigned long long)fn->addr, fn->name);
		}
	}

	fprintf(of, "dr x27=`e anal.gp`\n");
	fprintf(of, "'f PP=x27\n");

	// Scan code to gather Object Pool offsets used via PP (x27)
	dump_pool_offsets_flags(app, of);

	fclose(of);

	if (app->core && app->core->flags) {
		r_flag_set(app->core->flags, "app.base", app->base_addr, 0);
		if (app->heap_base) r_flag_set(app->core->flags, "app.heap_base", app->heap_base, 0);
		if (app->functions) {
			RListIter *it;
			DartFunction *fn;
			r_list_foreach(app->functions, it, fn) {
				if (!fn || !fn->name) continue;
				char flagname[1100];
				snprintf(flagname, sizeof(flagname), "method.%s", fn->name);
				r_name_filter(flagname, 0);
				r_flag_set(app->core->flags, flagname, fn->addr, 0);
			}
		}
	}
}
