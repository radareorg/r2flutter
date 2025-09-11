#ifndef R2C_DART_DUMPER_H
#define R2C_DART_DUMPER_H

#include "dart_app.h"

#ifdef __cplusplus
extern "C" {
#endif

void dart_dumper_dump4radare2(DartApp* app, const char* out_dir);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_DUMPER_H
