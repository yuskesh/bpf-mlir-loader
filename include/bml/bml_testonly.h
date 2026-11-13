#ifndef BML_BML_TESTONLY_H
#define BML_BML_TESTONLY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif



int64_t bml_testonly_load_unchecked_targets(const uint8_t *elf, int64_t n, const char *sha, int64_t sha_len, const char *maps, int64_t maps_len,
					    const char *config, int64_t config_len, const char *targets, int64_t targets_len);

int64_t bml_testonly_global_set_raw(int64_t obj, const char *name, int64_t len, int64_t bits);

int64_t bml_testonly_freeze_map(int64_t obj, const char *name, int64_t len);

int64_t bml_testonly_ringbuf_fault(int64_t obj, const char *name, int64_t len);

int64_t bml_testonly_uprobe_symbol(const char *prog, int64_t prog_len, const char *sym, int64_t sym_len);

int64_t bml_testonly_uprobe_offset_mode(const char *mode, int64_t mode_len);

int64_t bml_testonly_tpbtf_declared(const char *tp, int64_t len);



int64_t bml_testonly_usdt_mode(const char *mode, int64_t len);

#ifdef __cplusplus
}
#endif

#endif
