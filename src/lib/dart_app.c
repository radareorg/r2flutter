/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <r_core.h>
#include <r_flag.h>
#include <r_list.h>
#include <r_util/r_name.h>
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_obf.h"
#include "../../include/r2flutter/dart_pool_parse.h"

extern int dart_pool_enumerate(DartCtx *ctx, const char *libapp_path, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user, unsigned long long *out_base, unsigned long long *out_heap_base);

typedef unsigned long long ull;

static void free_dart_function(void *p) {
	DartFunction *fn = (DartFunction *)p;
	if (!fn) {
		return;
	}
	free (fn->name);
	free (fn);
}

DartApp *dart_app_new(const char *path) {
	DartApp *app = (DartApp *)calloc (1, sizeof (DartApp));
	if (!app) {
		return NULL;
	}
	if (path) {
		app->file_path = strdup (path);
	} else {
		app->file_path = NULL;
	}
	app->functions = r_list_newf (free_dart_function);
	return app;
}

void dart_app_free(DartApp *app) {
	if (!app) {
		return;
	}
	dart_obf_fini (&app->dctx);
	r_list_free (app->functions);
	if (app->file_path) {
		free (app->file_path);
	}
	free (app);
}

static void add_fn_cb(const char *name, unsigned long long addr, unsigned long long size, void *user) {
	DartApp *app = (DartApp *)user;
	if (!app || !app->functions) {
		return;
	}
	// avoid duplicate addresses
	RListIter *itx;
	DartFunction *fx;
	r_list_foreach (app->functions, itx, fx) {
		if (fx && fx->addr == (ut64)addr) {
			return; // already added
		}
	}
	DartFunction *fn = (DartFunction *)calloc (1, sizeof (DartFunction));
	if (!fn) {
		return;
	}
	fn->addr = (ut64)addr;
	fn->size = (ut64)size;
	if (name && *name) {
		char *tmp = dart_obf_resolve (&app->dctx, name);
		r_name_filter (tmp, 0);
		fn->name = tmp;
	} else {
		char buf[64];
		snprintf (buf, sizeof (buf), "func_%llx", (unsigned long long)fn->addr);
		fn->name = strdup (buf);
	}
	r_list_append (app->functions, fn);
}

void dart_app_load_info(DartApp *app) {
	if (!app || !app->file_path) {
		return;
	}
	app->dctx.core = app->core;
	unsigned long long base = 0, heap_base = 0;
	int rc = dart_pool_enumerate (&app->dctx, app->file_path, add_fn_cb, app, &base, &heap_base);
	if (rc == 0) {
		app->base_addr = (ut64)base;
		app->heap_base = (ut64)heap_base;
	}
	if (app->dctx.verbose) {
		fprintf (stderr, "Found %d functions (from Dart ObjectPool)\n", app->functions? r_list_length (app->functions): 0);
	}
}

static int ensure_dir(const char *path) {
	if (!path) {
		return -1;
	}
	struct stat st;
	if (stat (path, &st) == 0) {
		if (S_ISDIR (st.st_mode)) {
			return 0;
		}
		return -1;
	}
	// try to create
	char cmd[1024];
	snprintf (cmd, sizeof (cmd), "mkdir -p '%s'", path);
	return system (cmd);
}

static void write_struct_header(const char *outpath, ut64 base) {
	FILE *of = fopen (outpath, "w");
	if (!of) {
		return;
	}
	fprintf (of, "typedef struct DartThread {\n");
	fprintf (of, "\tunsigned long long pad0;\n");
	fprintf (of, "} DartThread;\n\n");
	fprintf (of, "typedef struct DartObjectPool {\n");
	fprintf (of, "\tunsigned long long pool_base; /* base: %#llx */\n", (unsigned long long)base);
	fprintf (of, "} DartObjectPool;\n");
	fclose (of);
}

void dart_app_dump4radare2(DartApp *app, const char *out_dir) {
	if (!app || !out_dir) {
		return;
	}
	ensure_dir (out_dir);

	char path[4096];
	snprintf (path, sizeof (path), "%s/addNames.r2", out_dir);
	FILE *of = fopen (path, "w");
	if (!of) {
		return;
	}

	fprintf (of, "# create flags for libraries, classes and methods\n");
	fprintf (of, "e emu.str=true\n");
	fprintf (of, "f app.base = %#llx\n", (unsigned long long)app->base_addr);
	fprintf (of, "f app.heap_base = %#llx\n", (unsigned long long)app->heap_base);

	if (app->functions) {
		RListIter *it;
		DartFunction *fn;
		r_list_foreach (app->functions, it, fn) {
			if (!fn || !fn->name) {
				continue;
			}
			char flagname[1024];
			snprintf (flagname, sizeof (flagname), "method.%s", fn->name);
			r_name_filter (flagname, 0);
			fprintf (of, "f %s = %#llx\n", flagname, (unsigned long long)fn->addr);
			fprintf (of, "'@%#llx'CC %s\n", (unsigned long long)fn->addr, fn->name);
		}
	}

	// add gp/pp helper and object pool struct
	fprintf (of, "dr x27=`e anal.gp`\n");
	fprintf (of, "'f PP=x27\n");

	// write a simple struct header
	snprintf (path, sizeof (path), "%s/r2_dart_struct.h", out_dir);
	write_struct_header (path, app->base_addr);

	fclose (of);

	// Also set flags in the loaded r2 core so they appear in session
	if (app->core && app->core->flags) {
		r_flag_set (app->core->flags, "app.base", app->base_addr, 0);
		if (app->heap_base) {
			r_flag_set (app->core->flags, "app.heap_base", app->heap_base, 0);
		}
		if (app->functions) {
			RListIter *it;
			DartFunction *fn;
			r_list_foreach (app->functions, it, fn) {
				if (!fn) {
					continue;
				}
				char flagname[1024];
				snprintf (flagname, sizeof (flagname), "method.%s", fn->name);
				r_name_filter (flagname, 0);
				r_flag_set (app->core->flags, flagname, fn->addr, 0);
			}
		}
	}
}
