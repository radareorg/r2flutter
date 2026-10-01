#ifndef R2FLUTTER_R2_ANALYSIS_H
#define R2FLUTTER_R2_ANALYSIS_H

#include <r_core.h>
#include "../../include/r2flutter/dart_r2.h"

bool r2flutter_analysis_run(RCore *core, DartCtx *dctx, bool quiet);
void r2flutter_setup_pp_gp(RCore *core, DartCtx *dctx);

#endif
