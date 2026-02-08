#ifndef R2C_DART_APP_H
#define R2C_DART_APP_H

#include <r_core.h>
#include <r_flag.h>
#include <r_list.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DartFunction {
    char *name;
    ut64 addr;
    ut64 size;
} DartFunction;

typedef struct DartApp {
    RCore *core;
    ut64 base_addr;
    ut64 heap_base;
    char *file_path;
    RList *functions; // list of DartFunction*
} DartApp;

DartApp* dart_app_new(const char* path);
void dart_app_free(DartApp* app);
void dart_app_load_info(DartApp* app);
void dart_app_load_functions_from_r2(DartApp* app);
void dart_app_dump4radare2(DartApp* app, const char* out_dir);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_APP_H
