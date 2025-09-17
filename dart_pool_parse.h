// Simple debug controls for the Dart pool/snapshot parser
#ifndef R2C_DART_POOL_PARSE_H
#define R2C_DART_POOL_PARSE_H

#ifdef __cplusplus
extern "C" {
#endif

// Controls verbosity of stderr diagnostics (0=quiet, 1=info, 2=debug)
void dart_pool_set_verbose(int level);

// If true, skip emitting ELF/R2 stub FUNC symbols
void dart_pool_set_no_stubs(int on);

// If true, dump snapshot header + clustered header as a single JSON line to stdout
void dart_pool_set_dump_snapshot_json(int on);

// If true, print resolved InstructionTable entries (index + address) to stderr
void dart_pool_set_dump_it(int on);

// Global quiet flag used by helpers to suppress noisy prints
void dart_pool_set_quiet(int on);
int dart_pool_is_quiet(void);

// Optional: print first N functions (addr+name) after loading
void dart_pool_set_dump_fns(int n);
int dart_pool_get_dump_fns(void);

#ifdef __cplusplus
}
#endif

#endif // R2C_DART_POOL_PARSE_H
