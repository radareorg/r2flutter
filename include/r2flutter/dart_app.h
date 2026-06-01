#ifndef R2C_DART_APP_H
#define R2C_DART_APP_H

#include <stdbool.h>
#include <r_core.h>
#include <r_list.h>
#include <r_vec.h>

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

void dart_function_fini(DartFunction *fn);
R_VEC_TYPE_WITH_FINI(RVecDartFunction, DartFunction, dart_function_fini);

typedef struct DartApp {
	RCore *core;
	ut64 base_addr;
	ut64 heap_base;
	char *file_path;
	RVecDartFunction *functions;
	DartCtx dctx;
} DartApp;

typedef struct DartAppEmbeddedPayload {
	char owner[17];
	ut64 payload_offset;
	ut64 payload_size;
	ut64 macho_offset;
} DartAppEmbeddedPayload;

DartApp *dart_app_new(const char *path);
DartApp *dart_app_new_from_core(RCore *core, DartCtx *dctx);
void dart_app_free(DartApp *app);
void dart_app_load_info(DartApp *app);
bool dart_app_find_macho_embedded_dart(const char *path, DartAppEmbeddedPayload *out);
char *dart_app_extract_embedded_payload(const char *path, const DartAppEmbeddedPayload *payload);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_APP_H
