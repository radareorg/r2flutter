#ifndef R2C_DART_OBF_H
#define R2C_DART_OBF_H

#include <stddef.h>
#include "dart_r2.h"

#ifdef __cplusplus
extern "C" {
#endif

bool dart_obf_load(DartCtx *ctx);
void dart_obf_fini(DartCtx *ctx);
char *dart_obf_resolve(DartCtx *ctx, const char *name);
void dart_obf_apply(DartCtx *ctx, char **name);
void dart_obf_apply_buf(DartCtx *ctx, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif
