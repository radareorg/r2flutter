/* r2flutter - LGPL3 - Copyright 2026 - pancake, Ahmeth4n */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_core.h>
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
	app->file_path = path? strdup (path): NULL;
	app->functions = r_list_newf (free_dart_function);
	return app;
}

DartApp *dart_app_new_from_core(RCore *core, DartCtx *dctx) {
	const char *filepath = R_UNWRAP4 (core, bin, cur, file);
	if (!filepath) {
		return NULL;
	}
	DartApp *app = dart_app_new (filepath);
	if (!app) {
		return NULL;
	}
	app->core = core;
	app->base_addr = r_bin_get_baddr (core->bin);
	if (app->base_addr == UT64_MAX) {
		app->base_addr = 0;
	}
	app->heap_base = 0;
	memcpy (&app->dctx, dctx, sizeof (DartCtx));
	app->dctx.core = core;
	return app;
}

void dart_app_free(DartApp *app) {
	if (!app) {
		return;
	}
	dart_obf_fini (&app->dctx);
	r_list_free (app->functions);
	free (app->file_path);
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
