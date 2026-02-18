#include <r_core.h>
#include <r_flag.h>
#include <r_util/r_name.h>
#include <r_util/r_json.h>
#include <r_util/r_str.h>
#include <r_list.h>
#include "../../include/r2flutter/dart_dumper.h"

static bool list_contains_offset(RList *list, ut64 off) {
	RListIter *it;
	ut64 *p;
	r_list_foreach (list, it, p) {
		if (*p == off) {
			return true;
		}
	}
	return false;
}

static void collect_pool_offsets_from_fn(RCore *core, ut64 addr, RList *offsets) {
	if (!core || !offsets) {
		return;
	}
	// r_core_cmdf (core, "af@0x%08"PFMT64x, addr);
	r_strf_var (cmd, 128, "pdfj @ 0x%" PFMT64x, addr);
	char *s = r_core_cmd_str (core, cmd);
	if (!s) {
		return;
	}
	RJson *j = r_json_parse (s);
	if (!j) {
		free (s);
		return;
	}
	const RJson *ops = r_json_get (j, "ops");
	const RJson *arr = ops? ops: j;
	size_t i;
	for (i = 0;; i++) {
		const RJson *item = r_json_item (arr, i);
		if (!item) {
			break;
		}
		const char *opstr = r_json_get_str (item, "opstr");
		if (!opstr || !*opstr) {
			opstr = r_json_get_str (item, "opcode");
		}
		if (!opstr || !*opstr) {
			continue;
		}
		// search for pattern like: ldr x0, [x27, 0x123]; also match wX, qX
		const char *b = strstr (opstr, "[x27");
		if (!b) {
			continue;
		}
		const char *comma = strchr (b, ',');
		if (!comma) {
			continue;
		}
		// skip spaces
		const char *p = comma + 1;
		while (*p == ' ' || *p == '#') {
			p++;
		}
		// read number until non-hex/non-digit
		const char *q = p;
		while ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) {
			q++;
		}
		if (q == p) {
			continue;
		}
		char numbuf[32];
		size_t len = q - p;
		if (len >= sizeof (numbuf)) {
			len = sizeof (numbuf) - 1;
		}
		memcpy (numbuf, p, len);
		numbuf[len] = '\0';
		ut64 val = r_num_get (NULL, numbuf);
		if (!list_contains_offset (offsets, val)) {
			ut64 *pv = (ut64 *)calloc (1, sizeof (ut64));
			if (!pv) {
				continue;
			}
			*pv = val;
			r_list_append (offsets, pv);
		}
	}
	r_json_free (j);
	free (s);
}

static void dump_pool_offsets_flags(DartApp *app, RStrBuf *sb) {
	if (!app || !app->core || !app->functions) {
		return;
	}
	RList *offsets = r_list_newf (free);
	// collect from all known functions
	RListIter *it;
	DartFunction *fn;
	r_list_foreach (app->functions, it, fn) {
		if (fn->name && r_str_startswith (fn->name, "sym.imp.")) {
			continue;
		}
		collect_pool_offsets_from_fn (app->core, fn->addr, offsets);
	}
	// emit flags and comments
	RListIter *it2;
	ut64 *offp;
	r_list_foreach (offsets, it2, offp) {
		r_strbuf_appendf (sb, "f pp.off_0x%" PFMT64x "=PP+0x%" PFMT64x "\n", (uint64_t)*offp, (uint64_t)*offp);
		r_strbuf_appendf (sb, "'@PP+0x%" PFMT64x "'CC pool_entry_%" PFMT64x "\n", (uint64_t)*offp, (uint64_t)*offp);
	}
	r_list_free (offsets);
}

char *dart_dumper_dump4radare2(DartApp *app) {
	RStrBuf *sb = r_strbuf_new ("");

	r_strbuf_append (sb, "# create flags for libraries, classes and methods\n");
	r_strbuf_append (sb, "e emu.str=true\n");
	r_strbuf_appendf (sb, "f app.base = 0x%" PFMT64x "\n", (uint64_t)app->base_addr);
	r_strbuf_appendf (sb, "f app.heap_base = 0x%" PFMT64x "\n", (uint64_t)app->heap_base);

	if (app->functions) {
		RListIter *it;
		DartFunction *fn;
		r_list_foreach (app->functions, it, fn) {
			if (!fn || !fn->name) {
				continue;
			}
			r_strf_var (safe, 1024, "%s", fn->name);
			r_name_filter (safe, 0);
			// Avoid double 'method.' prefix if the name already includes it
			if (r_str_startswith (safe, "method.")) {
				r_strbuf_appendf (sb, "f %s = 0x%" PFMT64x "\n", safe, (uint64_t)fn->addr);
			} else {
				r_strbuf_appendf (sb, "f method.%s = 0x%" PFMT64x "\n", safe, (uint64_t)fn->addr);
			}
			r_strbuf_appendf (sb, "'@0x%" PFMT64x "'CC %s\n", (uint64_t)fn->addr, fn->name);
		}
	}

	r_strbuf_append (sb, "dr x27=`e anal.gp`\n");
	r_strbuf_append (sb, "'f PP=x27\n");

	// Scan code to gather Object Pool offsets used via PP (x27)
	dump_pool_offsets_flags (app, sb);

	return r_strbuf_drain (sb);
}

void dart_dumper_apply_to_core(DartApp *app) {
	if (!app || !app->core) {
		return;
	}
	RCore *core = app->core;

	r_flag_set (core->flags, "app.base", app->base_addr, 0);
	if (app->heap_base) {
		r_flag_set (core->flags, "app.heap_base", app->heap_base, 0);
	}

	if (app->functions) {
		RListIter *it;
		DartFunction *fn;
		r_list_foreach (app->functions, it, fn) {
			if (!fn || !fn->name) {
				continue;
			}
			char *safe = strdup (fn->name);
			r_name_filter (safe, 0);
			char *flagname;
			if (r_str_startswith (safe, "method.")) {
				flagname = r_str_newf ("%s", safe);
			} else {
				flagname = r_str_newf ("method.%s", safe);
			}
			r_flag_set (core->flags, flagname, fn->addr, fn->size);
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, fn->addr, fn->name);
			free (flagname);
			free (safe);
		}
	}

	r_core_cmd0 (core, "e emu.str=true");
}
