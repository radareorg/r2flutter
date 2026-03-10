#ifndef R2C_DART_R2_H
#define R2C_DART_R2_H

#include <stdint.h>
#include <stdbool.h>
#include "dart_version.h"

typedef struct r_core_t RCore;
typedef struct r_list_t RList;
typedef struct ht_pp_t HtPP;
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
	ut64 it_length;
	ut64 it_first_with_code;
	ut64 it_canonical_stack_map_offset;
	int verbose;
	bool no_stubs;
	int dump_snapshot_json;
	bool dump_it;
	int quiet;
	int dump_fns_limit;
	bool use_name_pool;
	int dump_classes;
	int dump_fields;
	int dump_strings;
	const char *obf_map_path;
	HtPP *obf_by_obfuscated;
	bool obf_map_tried;
} DartCtx;

#endif
