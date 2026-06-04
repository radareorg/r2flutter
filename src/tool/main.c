/* r2flutter - MIT - Copyright 2026 - pancake, Ahmeth4n */

#include <r_core.h>
#include <r_getopt.h>
#include "../../include/r2flutter/dart_app.h"
#include "../../include/r2flutter/dart_dumper.h"
#include "../../include/r2flutter/dart_obf.h"
#include "../../include/r2flutter/dart_pool_parse.h"
#include "../../include/r2flutter/version.h"
#include "../r2/flutter_analysis.h"

static const char usage_text[] =
	"Usage: %s [options] <libapp_path_or_dir>\n"
	"Modifiers:\n"
	"  -h                    Show help\n"
	"  -j                    Output in JSON format\n"
	"  -q                    Compact output; suppress non-essential detail\n"
	"  -r                    Output r2 commands for the selected action\n"
	"  -n                    Heuristic fallback for unknown functions; may assign wrong names\n"
	"  -v                    Verbose (stderr debug info)\n"
	"  -vv                   More verbose (dump headers)\n"
	"  -V                    Show version\n"
	"Actions:\n"
	"  -A                    Analyze Dart snapshot and apply flags/comments\n"
	"  -AA                   Analyze with field extraction enabled\n"
	"  -AAA                  Run Dart-aware code analysis and recover code refs\n"
	"  -c                    Print extracted class information\n"
	"  -f                    Print all extracted functions (addr name)\n"
	"  -H                    Print Dart AOT snapshot header info\n"
	"  -HH                   Print extended snapshot header and cluster layout\n"
	"  -i                    Print instruction table entries to stdout\n"
	"  -R                    Print radare2 script for snapshot analysis\n"
	"  -T                    Print string-based type names\n"
	"  -x                    Print metadata/data-image xrefs\n"
	"  -z                    Print all extracted strings\n"
	"Options:\n"
	"  -l <N>                Limit output to N items\n"
	"  -m <file>             Load Flutter obfuscation map JSON\n";

static void print_usage(const char *argv0) {
	printf (usage_text, argv0);
}

static void free_resolved_path(char *path, bool extracted_inner) {
	if (extracted_inner) {
		r_file_rm (path);
	}
	free (path);
}

static void set_embedded_payload_ctx(DartCtx *dctx, const DartAppEmbeddedPayload *payload) {
	r_str_ncpy (dctx->container_kind, "macho-lc-note", sizeof (dctx->container_kind));
	r_str_ncpy (dctx->container_note_owner, payload->owner, sizeof (dctx->container_note_owner));
	dctx->container_payload_offset = payload->payload_offset;
	dctx->container_payload_size = payload->payload_size;
	dctx->container_macho_offset = payload->macho_offset;
}

static char *resolve_directory_input_path(const char *path) {
	char *candidate = r_file_new (path, "libapp.so", NULL); // Android
	if (r_file_exists (candidate)) {
		return candidate;
	}
	free (candidate);
	candidate = r_file_new (path, "Frameworks", "App.framework", "App", NULL); // iOS
	if (r_file_exists (candidate)) {
		return candidate;
	}
	free (candidate);
	return NULL;
}

static char *resolve_input_path(const char *s, DartCtx *dctx, bool *extracted_inner) {
	*extracted_inner = false;
	if (r_file_is_directory (s)) {
		return resolve_directory_input_path (s);
	}
	if (!r_file_exists (s)) {
		return NULL;
	}
	DartAppEmbeddedPayload payload;
	if (dart_app_find_macho_embedded_dart (s, &payload)) {
		char *inner = dart_app_extract_embedded_payload (s, &payload);
		if (!inner) {
			R_LOG_ERROR ("Failed to extract embedded Dart Mach-O from: %s", s);
			return NULL;
		}
		set_embedded_payload_ctx (dctx, &payload);
		*extracted_inner = true;
		if (dctx->verbose) {
			fprintf (stderr, "[r2flutter] extracted %s payload 0x%" PFMT64x "..0x%" PFMT64x " to %s\n", payload.owner, payload.payload_offset, payload.payload_offset + payload.payload_size, inner);
		}
		return inner;
	}
	return strdup (s);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		print_usage (argv[0]);
		return 0;
	}

	const char *libapp_path_in = NULL;
	int fmt = 0;
	char action = 0;
	int analysis_depth = 0;
	int header_depth = 0;
	DartCtx dctx = {
		.no_stubs = true
	};
	RGetopt opt;
	r_getopt_init (&opt, argc, (const char **)argv, "AcfhHijnm:qrRzTvVxl:");
	int c;
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'A':
			action = c;
			analysis_depth++;
			break;
		case 'c':
			action = c;
			break;
		case 'f':
			action = c;
			break;
		case 'H':
			action = c;
			header_depth++;
			break;
		case 'h':
			print_usage (argv[0]);
			return 0;
		case 'i':
			action = c;
			dctx.dump_it = true;
			break;
		case 'j':
			fmt = c;
			break;
		case 'l':
			dctx.dump_fns_limit = atoi (opt.arg);
			break;
		case 'n':
			dctx.use_name_pool = true;
			break;
		case 'm':
			dctx.obf_map_path = opt.arg;
			break;
		case 'q':
			dctx.quiet = 1;
			break;
		case 'r':
			fmt = c;
			break;
		case 'R':
			action = c;
			break;
		case 'z':
			action = c;
			break;
		case 'T':
			action = c;
			break;
		case 'v':
			dctx.verbose++;
			break;
		case 'V':
			printf ("r2flutter %s\n", R2FLUTTER_VERSION);
			return 0;
		case 'x':
			action = c;
			break;
		case 0:
			R_LOG_ERROR ("Long options are not supported");
			print_usage (argv[0]);
			return 1;
		default:
			return 1;
		}
	}
	if (opt.ind < argc) {
		libapp_path_in = argv[opt.ind++];
	}
	if (opt.ind < argc) {
		R_LOG_ERROR ("Unexpected argument: %s", argv[opt.ind]);
		return 1;
	}
	if (!libapp_path_in) {
		print_usage (argv[0]);
		return action? 1: 0;
	}
	if (!action) {
		print_usage (argv[0]);
		return 0;
	}
	bool extracted_inner = false;
	char *libapp_path = resolve_input_path (libapp_path_in, &dctx, &extracted_inner);
	if (!libapp_path) {
		R_LOG_ERROR ("File or directory does not exist: %s", libapp_path_in);
		return 1;
	}
	RCore *core = r_core_new ();
	if (!core) {
		R_LOG_ERROR ("Failed to create radare2 core");
		free_resolved_path (libapp_path, extracted_inner);
		return 1;
	}

	if (!r_core_file_open (core, libapp_path, R_PERM_R, 0)) {
		R_LOG_ERROR ("Failed to open file: %s", libapp_path);
		r_core_free (core);
		free_resolved_path (libapp_path, extracted_inner);
		return 1;
	}
	r_core_bin_load (core, NULL, 0);

	dctx.core = core;
	int ret = 0;
	if (action == 'A' && analysis_depth >= 2) {
		dctx.dump_fields = 1;
	}

	if (action == 'A' && analysis_depth >= 3) {
		if (!r2flutter_analysis_run (core, &dctx, dctx.quiet)) {
			ret = 1;
		}
		dart_obf_fini (&dctx);
		r_core_free (core);
		free_resolved_path (libapp_path, extracted_inner);
		return ret;
	}

	DartApp *app = dart_app_new_from_core (core, &dctx);
	if (!app) {
		R_LOG_ERROR ("Failed to create DartApp");
		r_core_free (core);
		free_resolved_path (libapp_path, extracted_inner);
		return 1;
	}
	if (dctx.obf_map_path && !dart_obf_load (&dctx)) {
		dart_app_free (app);
		r_core_free (core);
		free_resolved_path (libapp_path, extracted_inner);
		return 1;
	}

	if (dctx.verbose) {
		fprintf (stderr, "libapp is loaded at 0x%" PFMT64x "\n", app->base_addr);
		fprintf (stderr, "Dart heap at 0x%" PFMT64x "\n", app->heap_base);
		fprintf (stderr, "app->file_path = %s\n", app->file_path? app->file_path: "(null)");
	}

	char *output = NULL;

	switch (action) {
	case 'A':
		dart_app_load_info (app);
		if (!dctx.quiet && app->functions) {
			size_t count = RVecDartFunction_length (app->functions);
			if (count > 0) {
				R_LOG_INFO ("Loaded %zu functions from Dart snapshot", count);
			}
		}
		dart_dumper_apply_to_core (app);
		break;
	case 'z':
		output = dart_pool_dump_strings (&dctx, fmt);
		break;
	case 'c':
		dctx.dump_classes = 1;
		dctx.dump_fields = 1;
		output = dart_pool_dump_classes (&dctx, fmt);
		break;
	case 'T':
		dctx.dump_classes = 3;
		output = dart_pool_dump_classes (&dctx, fmt);
		break;
	case 'H':
		output = header_depth >= 2? dart_pool_dump_header_ext (&app->dctx, fmt): dart_pool_dump_header (&app->dctx, fmt);
		break;
	case 'f':
		dart_app_load_info (app);
		output = dart_dumper_dump_funcs (app, fmt);
		break;
	case 'i':
		output = dart_pool_dump_it (&app->dctx, fmt);
		break;
	case 'x':
		output = dart_pool_dump_xrefs (&dctx, fmt);
		break;
	case 'R':
		dart_app_load_info (app);
		if (dctx.verbose) {
			R_LOG_ERROR ("Dumping radare2 script");
		}
		char *s = dart_dumper_dump4radare2 (app);
		printf ("%s\n", s);
		free (s);
		break;
	case 0:
	default:
		print_usage (argv[0]);
		break;
	}

	if (output) {
		printf ("%s\n", output);
		free (output);
	}

	dart_app_free (app);
	dart_obf_fini (&dctx);
	r_core_free (core);
	free_resolved_path (libapp_path, extracted_inner);

	return ret;
}
