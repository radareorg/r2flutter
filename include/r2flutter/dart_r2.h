#ifndef R2C_DART_R2_H
#define R2C_DART_R2_H

#include <stdint.h>
#include <stdbool.h>
#include "dart_version.h"

typedef struct r_core_t RCore;
typedef struct r_list_t RList;
typedef struct ht_up_t HtUP;
typedef uint64_t ut64;

typedef struct {
	ut64 ref_id;
	char *value;
	int length;
	bool is_two_byte;
} DartString;

typedef struct {
	RCore *core;
	ut64 vm_data;
	ut64 vm_instr;
	ut64 iso_data;
	ut64 iso_instr;
	char snapshot_hash[33];
	const DartVerLayout *layout;
	int compressed_word_size;
	HtUP *name_by_ep;
	RList *name_pool;
	int name_pool_idx;
	RList *strings;
	RList *classes;
	RList *functions;
	void **refs;
	ut64 refs_count;
	ut64 num_base_objects;
	ut64 num_objects;
	ut64 num_clusters;
	int verbose;
	bool no_stubs;
	int dump_snapshot_json;
	bool dump_it;
	int quiet;
	int dump_fns;
	int dump_fns_limit;
	bool use_name_pool;
	int dump_classes;
	int dump_fields;
	int dump_strings;
	int dump_header;
	int dump_header_json;
} DartCtx;

int dart_r2_find_snapshots(RCore *core, ut64 *vm_data, ut64 *vm_instr, ut64 *iso_data, ut64 *iso_instr);
void dart_r2_emit_stub_symbols(DartCtx *ctx, void(*on_fn)(const char *name, unsigned long long addr, unsigned long long size, void *user), void *user);
ut64 dart_r2_find_pp_base(DartCtx *ctx);
HtUP *dart_r2_scan_code_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end);
RList *dart_r2_collect_data_names(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end);
void dart_r2_collect_data_names_with_cmd(DartCtx *ctx, ut64 data_image_base, ut64 data_image_end);

#endif
