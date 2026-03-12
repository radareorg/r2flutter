#ifndef R2C_DART_APP_H
#define R2C_DART_APP_H

#include <r_core.h>
#include <r_list.h>

#include <stddef.h>
#include "dart_r2.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DartFunction {
	char *name;
	ut64 addr;
	ut64 size;
	int quality;
} DartFunction;

typedef struct DartApp {
	RCore *core;
	ut64 base_addr;
	ut64 heap_base;
	char *file_path;
	RList *functions;
	DartCtx dctx;
} DartApp;

DartApp *dart_app_new(const char *path);
DartApp *dart_app_new_from_core(RCore *core, DartCtx *dctx);
void dart_app_free(DartApp *app);
void dart_app_load_info(DartApp *app);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_APP_H
