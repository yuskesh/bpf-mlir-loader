/* CONTRACT: spinelbpf.h — C ABI of the spinel-bpf-mlir loader (`spinelbpf_*`, the same names and
 * signatures as the Go loader's exports, including the per-CPU calls), implemented as a shim over bml_*. It is in libbml_spinel.a and links with libbml.a (it is not part of libbml.a).
 *
 * Contract differences from the Go loader (aligned to bml): a second ringbuf_close, close or detach is OK (idempotent),
 * test_run_xdp with count 0 is VALUE_RANGE (Go: OK with 0 runs), and the Go runtime's signal coexistence stage (RUNTIME_CONFLICT) does not exist.
 * Text for the checks the shim performs itself (int64 byte range 0..255, sizes, u32 key, packet length, ring buffer range, hash_keys cap) is
 * byte-identical to spinel. bml_* text (checks, kernel errno) keeps the `bml:` prefix. */
#ifndef BML_SHIM_SPINELBPF_H
#define BML_SHIM_SPINELBPF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int64_t spinelbpf_load_checked(uint8_t *elf, int64_t n, char *sha, char *maps, int64_t capsKind);
int64_t spinelbpf_attach_xdp(int64_t obj, char *prog, char *ifname);
int64_t spinelbpf_detach(int64_t l);
int64_t spinelbpf_map_get(int64_t obj, char *decl, int64_t key);
int64_t spinelbpf_map_put(int64_t obj, char *decl, int64_t key, int64_t value);
int64_t spinelbpf_map_get_bytes(int64_t obj, char *decl, int64_t key, int64_t *buf, int64_t n);
int64_t spinelbpf_map_put_bytes(int64_t obj, char *decl, int64_t key, int64_t *buf, int64_t n);
int64_t spinelbpf_hash_get(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *val, int64_t vlen);
int64_t spinelbpf_hash_put(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *val, int64_t vlen);
int64_t spinelbpf_hash_delete(int64_t obj, char *decl, int64_t *key, int64_t klen);
int64_t spinelbpf_hash_keys(int64_t obj, char *decl, int64_t klen, int64_t *out, int64_t capacity);
int64_t spinelbpf_ringbuf_open(int64_t obj, char *name);
int64_t spinelbpf_ringbuf_read(int64_t rb, int64_t timeoutMs, int64_t *buf, int64_t n);
int64_t spinelbpf_ringbuf_close(int64_t rb);
int64_t spinelbpf_test_run_xdp(int64_t obj, char *prog, int64_t repeat);
int64_t spinelbpf_test_run_xdp_packet(int64_t obj, char *prog, int64_t *bytes, int64_t n);
int64_t spinelbpf_object_unmet(int64_t obj);
int64_t spinelbpf_close(int64_t obj);
int64_t spinelbpf_result_kind(int64_t r);
int64_t spinelbpf_result_value(int64_t r);
char *spinelbpf_result_message(int64_t r);
int64_t spinelbpf_result_unmet_count(int64_t r);
char *spinelbpf_result_unmet(int64_t r, int64_t i);
void spinelbpf_result_free(int64_t r);
int64_t spinelbpf_policy_version(void);

int64_t spinelbpf_possible_cpus(void);
int64_t spinelbpf_percpu_get(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *out, int64_t n);
int64_t spinelbpf_percpu_put(int64_t obj, char *decl, int64_t *key, int64_t klen, int64_t *vals, int64_t n);

#ifdef __cplusplus
}
#endif

#endif
