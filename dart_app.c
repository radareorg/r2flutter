#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <r_core.h>
#include <r_flag.h>
#include <r_util/r_json.h>
#include <r_list.h>
#include <r_util/r_name.h>
#include "dart_app.h"

typedef unsigned long long ull;

static void free_dart_function(void *p) {
    DartFunction *fn = (DartFunction *)p;
    if (!fn) return;
    free(fn->name);
    free(fn);
}

DartApp* dart_app_new(const char* path) {
    DartApp* app = (DartApp*)calloc(1, sizeof(DartApp));
    if (!app) return NULL;
    if (path) app->file_path = strdup(path);
    else app->file_path = NULL;
    app->functions = r_list_newf(free_dart_function);
    return app;
}

void dart_app_free(DartApp* app) {
    if (!app) return;
    if (app->functions) r_list_free(app->functions);
    if (app->file_path) free(app->file_path);
    free(app);
}

void dart_app_load_info(DartApp* app) {
    if (!app || !app->core) return;
    printf("Analyzing binary (aaa)...\n");
    r_core_cmd(app->core, "e anal.hasnext=true", false);
    r_core_cmd(app->core, "aaa", false);

    char *out = r_core_cmd_str(app->core, "aflj");
    if (!out) {
        out = r_core_cmd_str(app->core, "afl");
        if (!out) return;
    }

    // write debug dump of analysis output
    {
        FILE *dbg = fopen("/tmp/blutter_afl_dump.txt", "w");
        if (dbg) {
            fwrite(out, 1, strlen(out), dbg);
            fclose(dbg);
        }
    }

    // If JSON (aflj) was returned we parse JSON-like array, otherwise fallback to parsing plain afl lines
    // Try robust JSON parsing with libr_util r_json
    if (out[0] == '[') {
        RJson *j = r_json_parse(out);
        if (j) {
            size_t i;
            for (i = 0;; i++) {
                const RJson *item = r_json_item(j, i);
                if (!item) break;
                st64 off = r_json_get_num(item, "offset");
                if (off <= 0) off = r_json_get_num(item, "addr");
                st64 size = r_json_get_num(item, "size");
                const char *nm = r_json_get_str(item, "name");
                if (off > 0) {
                    DartFunction *fn = (DartFunction*)calloc(1, sizeof(DartFunction));
                    if (!fn) break;
                    fn->addr = (ut64)off;
                    fn->size = (ut64)(size > 0 ? size : 0);
                    if (nm && *nm) {
                        char *tmp = strdup(nm);
                        r_name_filter(tmp, 0);
                        fn->name = tmp;
                    } else {
                        char buf[64];
                        snprintf(buf, sizeof(buf), "func_%llx", (unsigned long long)fn->addr);
                        fn->name = strdup(buf);
                    }
                    r_list_append(app->functions, fn);
                }
            }
            r_json_free(j);
        }
    }

    // Fallback to parse plain afl lines
    char *saveptr = NULL;
    char *line = strtok_r(out, "\n", &saveptr);
    while (line) {
        // trim leading spaces
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) { line = strtok_r(NULL, "\n", &saveptr); continue; }

        // parse address
        char addrbuf[64] = {0};
        char sizebuf[64] = {0};
        char namebuf[1024] = {0};

        // try sscanf - common format: 0xADDR SIZE NAME
        int matched = sscanf(p, "%63s %63s %1023s", addrbuf, sizebuf, namebuf);
        if (matched >= 1) {
            ut64 addr = 0;
            ut64 size = 0;
            if (addrbuf[0] == '0' && (addrbuf[1] == 'x' || addrbuf[1] == 'X')) {
                addr = strtoull(addrbuf, NULL, 16);
            } else {
                addr = strtoull(addrbuf, NULL, 10);
            }
            if (matched >= 2) size = (ut64)strtoull(sizebuf, NULL, 10);

            const char *nameptr = namebuf;
            if (matched < 3) {
                // fallback: last token after address and size
                char *lastspace = strrchr(p, ' ');
                if (lastspace) nameptr = lastspace + 1;
                else nameptr = p;
            }

            if (addr != 0) {
                DartFunction *fn = (DartFunction*)calloc(1, sizeof(DartFunction));
                if (!fn) break;
                fn->addr = addr;
                fn->size = size;
                char *tmp = strdup(nameptr);
                r_name_filter(tmp, 0);
                fn->name = tmp;
                r_list_append(app->functions, fn);
            }
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(out);

    // If no functions found, fallback to invoking r2 externally and parsing aflj
    if ((!app->functions || r_list_empty(app->functions)) && app->file_path) {
        printf("Fallback: invoking external r2 for %s\n", app->file_path);
        char cmd[4096];
        snprintf(cmd, sizeof(cmd), "r2 -q -c 'aa;aflj' '%s' 2>/dev/null", app->file_path);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            size_t cap = 8192;
            size_t len = 0;
            char *buf = malloc(cap);
            if (buf) {
                while (!feof(fp)) {
                    size_t n = fread(buf + len, 1, cap - len - 1, fp);
                    if (n > 0) len += n;
                    if (len + 1 >= cap) {
                        cap *= 2;
                        char *tmp = realloc(buf, cap);
                        if (!tmp) break;
                        buf = tmp;
                    }
                }
                buf[len] = '\0';
                pclose(fp);

                if (buf[0] == '[') {
                    RJson *j = r_json_parse(buf);
                    if (j) {
                        size_t i;
                        for (i = 0;; i++) {
                            const RJson *item = r_json_item(j, i);
                            if (!item) break;
                            st64 off = r_json_get_num(item, "offset");
                            if (off <= 0) off = r_json_get_num(item, "addr");
                            st64 sizev = r_json_get_num(item, "size");
                            const char *nm = r_json_get_str(item, "name");
                            if (off > 0) {
                                DartFunction *fn = (DartFunction*)calloc(1, sizeof(DartFunction));
                                if (!fn) break;
                                fn->addr = (ut64)off;
                                fn->size = (ut64)(sizev > 0 ? sizev : 0);
                                if (nm && *nm) {
                                    char *tmp = strdup(nm);
                                    r_name_filter(tmp, 0);
                                    fn->name = tmp;
                                } else {
                                    char t[64];
                                    snprintf(t, sizeof(t), "func_%llx", (unsigned long long)fn->addr);
                                    fn->name = strdup(t);
                                }
                                r_list_append(app->functions, fn);
                            }
                        }
                        r_json_free(j);
                    }
                }
                // write fallback debug
                {
                    FILE *dbg2 = fopen("/tmp/blutter_afl_fallback.txt", "w");
                    if (dbg2) {
                        fwrite(buf, 1, len, dbg2);
                        fclose(dbg2);
                    }
                }
                free(buf);
            } else {
                pclose(fp);
            }
        }
    }

    printf("Found %d functions\n", app->functions ? r_list_length(app->functions) : 0);
}

static int ensure_dir(const char *path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    // try to create
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", path);
    return system(cmd);
}

static void write_struct_header(const char *outpath, ut64 base) {
    FILE *of = fopen(outpath, "w");
    if (!of) return;
    fprintf(of, "typedef struct DartThread {\n");
    fprintf(of, "\tunsigned long long pad0;\n");
    fprintf(of, "} DartThread;\n\n");
    fprintf(of, "typedef struct DartObjectPool {\n");
    fprintf(of, "\tunsigned long long pool_base; /* base: %#llx */\n", (unsigned long long)base);
    fprintf(of, "} DartObjectPool;\n");
    fclose(of);
}

void dart_app_dump4radare2(DartApp* app, const char* out_dir) {
    if (!app || !out_dir) return;
    ensure_dir(out_dir);

    char path[4096];
    snprintf(path, sizeof(path), "%s/addNames.r2", out_dir);
    FILE *of = fopen(path, "w");
    if (!of) return;

    fprintf(of, "# create flags for libraries, classes and methods\n");
    fprintf(of, "e emu.str=true\n");
    fprintf(of, "f app.base = %#llx\n", (unsigned long long)app->base_addr);
    fprintf(of, "f app.heap_base = %#llx\n", (unsigned long long)app->heap_base);

    if (app->functions) {
        RListIter *it;
        DartFunction *fn;
        r_list_foreach(app->functions, it, fn) {
            if (!fn || !fn->name) continue;
            char flagname[1024];
            snprintf(flagname, sizeof(flagname), "method.%s", fn->name);
            r_name_filter(flagname, 0);
            fprintf(of, "f %s = %#llx\n", flagname, (unsigned long long)fn->addr);
            fprintf(of, "'@%#llx'CC %s\n", (unsigned long long)fn->addr, fn->name);
        }
    }

    // add gp/pp helper and object pool struct
    fprintf(of, "dr x27=`e anal.gp`\n");
    fprintf(of, "'f PP=x27\n");

    // write a simple struct header
    snprintf(path, sizeof(path), "%s/r2_dart_struct.h", out_dir);
    write_struct_header(path, app->base_addr);

    fclose(of);

    // Also set flags in the loaded r2 core so they appear in session
    if (app->core && app->core->flags) {
        r_flag_set(app->core->flags, "app.base", app->base_addr, 0);
        if (app->heap_base) r_flag_set(app->core->flags, "app.heap_base", app->heap_base, 0);
        if (app->functions) {
            RListIter *it;
            DartFunction *fn;
            r_list_foreach(app->functions, it, fn) {
                if (!fn) continue;
                char flagname[1024];
                snprintf(flagname, sizeof(flagname), "method.%s", fn->name);
                r_name_filter(flagname, 0);
                r_flag_set(app->core->flags, flagname, fn->addr, 0);
            }
        }
    }
}
