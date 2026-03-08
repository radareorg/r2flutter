#ifndef R2C_DART_DUMPER_H
#define R2C_DART_DUMPER_H

#include "dart_app.h"

#ifdef __cplusplus
extern "C" {
#endif

char *dart_dumper_dump4radare2(DartApp *app);
char *dart_dumper_dump_funcs(DartApp *app, int fmt);
void dart_dumper_apply_to_core(DartApp *app);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_DUMPER_H
