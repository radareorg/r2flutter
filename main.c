#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <r_core.h>
#include <r_flag.h>
#include "dart_app.h"
#include "dart_dumper.h"

static bool is_library(const char *name) {
	return r_str_endswith (name, ".so")
		|| r_str_endswith (name, ".dylib")
		|| r_str_endswith (name, ".aot")
		|| r_str_endswith (name, ".bin")
		|| r_str_startswith (name, "lib");
}

static char *find_lib_in_dir(const char *dir) {
	if (!dir) {
		return NULL;
	}
	DIR *d = opendir (dir);
	if (!d) {
		return NULL;
	}
	struct dirent *ent;
	// Prefer libapp.so explicitly if present
	char *preferred = NULL;
	while ((ent = readdir(d)) != NULL) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		char *full = r_str_newf ("%s/%s", dir, ent->d_name);
		struct stat st;
		if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
			if (!strcmp (ent->d_name, "libapp.so")) {
				closedir (d);
				return full;
			}
			if (!preferred && is_library (ent->d_name)) {
				preferred = full;
				full = NULL;
			}
		}
		free (full);
	}
	closedir (d);
	return preferred;
}

int main(int argc, char** argv) {
	if (argc < 2) {
		eprintf ("Usage: %s <libapp_path>\n", argv[0]);
		return 1;
	}

	const char* libapp_path_in = argv[1];

	char *libapp_path = NULL;
	struct stat st;
	if (stat(libapp_path_in, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			// Prefer libapp.so explicitly if present in dir
			char *candidate = r_str_newf ("%s/%s", libapp_path_in, "libapp.so");
			struct stat st2;
			if (candidate && stat (candidate, &st2) == 0 && S_ISREG (st2.st_mode)) {
				libapp_path = candidate;
			} else {
				free (candidate);
				libapp_path = find_lib_in_dir (libapp_path_in);
			}
			if (!libapp_path) {
				eprintf ("No suitable library file found in directory: %s\n", libapp_path_in);
				return 1;
			}
		} else if (S_ISREG(st.st_mode)) {
			libapp_path = strdup (libapp_path_in);
		} else {
			eprintf ("Not a regular file or directory: %s\n", libapp_path_in);
			return 1;
		}
	} else {
		eprintf ("File or directory does not exist: %s\n", libapp_path_in);
		return 1;
	}

	RCore *core = r_core_new ();
	if (!core) {
		eprintf ("Failed to create radare2 core\n");
		free (libapp_path);
		return 1;
	}

	if (!r_core_file_open(core, libapp_path, 0, 0)) {
		fprintf(stderr, "Failed to open file: %s\n", libapp_path);
		r_core_free(core);
		free(libapp_path);
		return 1;
	}
	// Ensure binary info/symbols are loaded for queries like `isj`
	r_core_bin_load (core, NULL, 0);

	DartApp* app = dart_app_new (libapp_path);
	if (!app) {
		eprintf ("Failed to create DartApp\n");
		r_core_free (core);
		free (libapp_path);
		return 1;
	}

	app->core = core;
	app->base_addr = r_bin_get_baddr(core->bin);
	if (app->base_addr == (ut64)-1) {
		app->base_addr = 0;
	}
	app->heap_base = 0;

	printf("libapp is loaded at 0x%" PFMT64x "\n", app->base_addr);
	printf("Dart heap at 0x%" PFMT64x "\n", app->heap_base);

	printf("app->file_path = %s\n", app->file_path ? app->file_path : "(null)");

	dart_app_load_info (app);

	printf ("Dumping for radare2\n");
	char *s = dart_dumper_dump4radare2 (app);
	printf ("%s\n", s);
	free (s);

	dart_app_free (app);
	r_core_free (core);
	free (libapp_path);

	return 0;
}
