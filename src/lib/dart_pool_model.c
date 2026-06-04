/* r2flutter - MIT - Copyright 2026 - pancake */

#include "dart_pool_parse_priv.h"

static ut64 model_normalize_code_addr(ut64 addr) {
	return (addr & 1ULL)? addr - 1: addr;
}

static bool string_ref_exists(RList *refs, const char *kind, ut64 object_ref) {
	if (!refs || R_STR_ISEMPTY (kind)) {
		return false;
	}
	RListIter *it;
	DartStringRef *sr;
	r_list_foreach (refs, it, sr) {
		if (sr && sr->object_ref == object_ref && R_STR_ISNOTEMPTY (sr->kind) && !strcmp (sr->kind, kind)) {
			return true;
		}
	}
	return false;
}

static void add_string_ref_by_value(DartRecoveryModel *model, const char *value, const char *kind, ut32 object_type, ut64 object_ref, const char *object_name, ut64 source_addr) {
	if (!model || R_STR_ISEMPTY (value) || R_STR_ISEMPTY (kind)) {
		return;
	}
	DartStringInfo *si = dart_recovery_model_string_by_value (model, value);
	if (!si || !si->references || string_ref_exists (si->references, kind, object_ref)) {
		return;
	}
	DartStringRef *sr = R_NEW0 (DartStringRef);
	sr->object_ref = object_ref;
	sr->source_addr = source_addr;
	sr->object_type = object_type;
	sr->kind = strdup (kind);
	sr->object_name = R_STR_ISNOTEMPTY (object_name)? strdup (object_name): NULL;
	r_list_append (si->references, sr);
}

static void index_strings(DartRecoveryModel *model) {
	model->string_by_value = ht_pp_new0 ();
	model->string_by_addr = ht_up_new0 ();
	if (!model->strings) {
		return;
	}
	RListIter *it;
	DartStringInfo *si;
	r_list_foreach (model->strings, it, si) {
		if (!si || R_STR_ISEMPTY (si->value)) {
			continue;
		}
		if (!ht_pp_find (model->string_by_value, si->value, NULL)) {
			ht_pp_insert (model->string_by_value, si->value, si);
		}
		if (si->address && !ht_up_find (model->string_by_addr, si->address, NULL)) {
			ht_up_insert (model->string_by_addr, si->address, si);
		}
	}
}

static void index_classes(DartRecoveryModel *model, bool index_methods) {
	model->class_by_name = ht_pp_new0 ();
	if (index_methods) {
		model->method_by_addr = ht_up_new0 ();
	}
	if (!model->classes) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (model->classes, it, ci) {
		if (!ci || R_STR_ISEMPTY (ci->name)) {
			continue;
		}
		if (!ht_pp_find (model->class_by_name, ci->name, NULL)) {
			ht_pp_insert (model->class_by_name, ci->name, ci);
		}
		if (!index_methods || !ci->methods) {
			continue;
		}
		RListIter *mit;
		DartMethodInfo *mi;
		r_list_foreach (ci->methods, mit, mi) {
			if (!mi || !mi->entry_point) {
				continue;
			}
			ut64 addr = model_normalize_code_addr (mi->entry_point);
			if (!ht_up_find (model->method_by_addr, addr, NULL)) {
				ht_up_insert (model->method_by_addr, addr, mi);
			}
		}
	}
}

static void populate_string_metadata_references(DartRecoveryModel *model) {
	if (!model || !model->strings || !model->classes || r_list_length (model->strings) == 0) {
		return;
	}
	RListIter *it;
	DartClassInfo *ci;
	r_list_foreach (model->classes, it, ci) {
		if (!ci || (ci->ref_id == 0 && ci->name_ref == 0)) {
			continue;
		}
		add_string_ref_by_value (model, ci->name, "class.name", DART_REF_CLASS, ci->ref_id, ci->name, 0);
		add_string_ref_by_value (model, ci->library_name, "library.name", DART_REF_LIBRARY, ci->library_ref, ci->library_name, 0);
		add_string_ref_by_value (model, ci->super_class_name, "class.super", DART_REF_CLASS, ci->super_class_ref, ci->name, 0);
		if (ci->interfaces) {
			RListIter *iit;
			DartInterfaceInfo *ii;
			r_list_foreach (ci->interfaces, iit, ii) {
				if (ii) {
					add_string_ref_by_value (model, ii->name, "class.interface", DART_REF_CLASS, ci->ref_id, ci->name, 0);
				}
			}
		}
		if (ci->fields) {
			RListIter *fit;
			DartFieldInfo *fi;
			r_list_foreach (ci->fields, fit, fi) {
				if (!fi || (fi->ref_id == 0 && fi->name_ref == 0)) {
					continue;
				}
				char *field_name = R_STR_ISNOTEMPTY (ci->name)? r_str_newf ("%s.%s", ci->name, r_str_get (fi->name)): strdup (r_str_get (fi->name));
				add_string_ref_by_value (model, fi->name, "field.name", DART_REF_FIELD, fi->ref_id, field_name, 0);
				add_string_ref_by_value (model, fi->type_name, "field.type", DART_REF_FIELD, fi->ref_id, field_name, 0);
				free (field_name);
			}
		}
		if (ci->methods) {
			RListIter *mit;
			DartMethodInfo *mi;
			r_list_foreach (ci->methods, mit, mi) {
				if (!mi || (mi->ref_id == 0 && mi->name_ref == 0 && mi->signature_ref == 0)) {
					continue;
				}
				char *method_name = R_STR_ISNOTEMPTY (ci->name)? r_str_newf ("%s.%s", ci->name, r_str_get (mi->name)): strdup (r_str_get (mi->name));
				const ut64 entry_point = model_normalize_code_addr (mi->entry_point);
				add_string_ref_by_value (model, mi->name, "method.name", DART_REF_FUNCTION, mi->ref_id, method_name, entry_point);
				add_string_ref_by_value (model, mi->signature, "method.signature", DART_REF_FUNCTION, mi->ref_id, method_name, entry_point);
				free (method_name);
			}
		}
	}
}

bool dart_recovery_model_load(DartCtx *ctx, DartRecoveryModel *model, int flags) {
	if (!ctx || !model) {
		return false;
	}
	memset (model, 0, sizeof (*model));
	model->ctx = ctx;
	if (flags & DART_RECOVERY_STRING_REFS) {
		flags |= DART_RECOVERY_STRINGS | DART_RECOVERY_CLASSES;
	}
	if (flags & DART_RECOVERY_METHOD_INDEX) {
		flags |= DART_RECOVERY_CLASSES;
	}
	DartCtx work = *ctx;
	if (flags & DART_RECOVERY_CLASS_FIELDS) {
		work.dump_fields = 1;
	}
	if (flags & DART_RECOVERY_STRINGS) {
		model->strings = dart_pool_extract_strings (&work);
		index_strings (model);
	}
	if (flags & DART_RECOVERY_CLASSES) {
		model->classes = dart_pool_extract_classes (&work);
		index_classes (model, (flags & DART_RECOVERY_METHOD_INDEX) != 0);
	}
	if (flags & DART_RECOVERY_IT) {
		model->it_entries = dart_pool_extract_instruction_table (&work);
	}
	if (flags & DART_RECOVERY_STRING_REFS) {
		populate_string_metadata_references (model);
	}
	return true;
}

void dart_recovery_model_fini(DartRecoveryModel *model) {
	if (!model) {
		return;
	}
	dart_string_list_free (model->strings);
	dart_class_list_free (model->classes);
	dart_instruction_table_list_free (model->it_entries);
	ht_pp_free (model->string_by_value);
	ht_up_free (model->string_by_addr);
	ht_pp_free (model->class_by_name);
	ht_up_free (model->method_by_addr);
	memset (model, 0, sizeof (*model));
}

DartStringInfo *dart_recovery_model_string_by_value(DartRecoveryModel *model, const char *value) {
	return model && model->string_by_value && value? ht_pp_find (model->string_by_value, value, NULL): NULL;
}

DartStringInfo *dart_recovery_model_string_by_addr(DartRecoveryModel *model, ut64 addr) {
	return model && model->string_by_addr && addr? ht_up_find (model->string_by_addr, addr, NULL): NULL;
}

DartClassInfo *dart_recovery_model_class_by_name(DartRecoveryModel *model, const char *name) {
	return model && model->class_by_name && name? ht_pp_find (model->class_by_name, name, NULL): NULL;
}

DartMethodInfo *dart_recovery_model_method_by_addr(DartRecoveryModel *model, ut64 addr) {
	return model && model->method_by_addr? ht_up_find (model->method_by_addr, model_normalize_code_addr (addr), NULL): NULL;
}
