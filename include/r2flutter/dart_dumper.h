#ifndef R2C_DART_DUMPER_H
#define R2C_DART_DUMPER_H

#include "dart_app.h"

#ifdef __cplusplus
extern "C" {
#endif

char *dart_dumper_dump_r2(DartApp *app);
char *dart_dumper_dump_funcs(DartApp *app, int fmt);
void dart_dumper_apply_to_core(DartApp *app, bool apply_signatures);
void dart_dumper_apply_signatures(DartApp *app);
// Disable anal.trycatch while r2flutter runs many `af` commands, when no try.*
// flag exists for it to find. Returns the previous value to pass to the restore.
bool dart_core_trycatch_suspend(RCore *core);
void dart_core_trycatch_restore(RCore *core, bool prev);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_DUMPER_H
