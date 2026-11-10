
#ifndef BML_ABI_INTERNAL_H
#define BML_ABI_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "bml/bml.h"
#include "caps/live_caps.h"
#include "load/load.h"
#include "maps/mapdecl.h"
#include "req/check.h"
#include "req/req.h"


struct abi_unmet {
	char *f[4];
	size_t len[4];
};

struct abi_result {
	int64_t kind, value;
	char *msg;
	size_t msg_len;
	struct abi_unmet *u;
	size_t n_u;
};

/* CONTRACT: places the result in the registry and returns a handle (ownership of r's contents moves). Out of memory is -1 (callers read a negative handle as STATE) */
int64_t abi_put(struct abi_result *r);

int64_t abi_fail(int64_t kind, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int64_t abi_ok(int64_t value);

int abi_set_unmets(struct abi_result *r, const struct bml_unmet *u, size_t n);


enum { H_OBJECT = 1, H_LINK, H_READER, H_ITER };

struct abi_object {
	struct bml_obj *lo;
	struct bml_requirements *req;
	uint8_t *elf;
	size_t elf_len;
	struct bml_unmets rest;
	struct bml_live_caps caps;
	struct bml_loader_decl arena_decl;
	int closed;
	int inflight; /* CONTRACT: number of running calls (under the registry lock). close only at 0 */

	struct bml_global_decl *globals;
	size_t n_globals;
};



int64_t abi_config(const char *cfg, int64_t cfg_len, const struct bml_map_decls *d, const uint8_t *elf, size_t elf_len,
		   struct bml_rodata_value **vals, size_t *n_vals);

int abi_globals_keep(struct abi_object *o, const struct bml_map_decls *d);
void abi_globals_free(struct abi_object *o);


void abi_lock(void);
void abi_unlock(void);
/* CONTRACT: new handle (type, contents, and the owning object's handle, or 0 if none). Returns -1 when out of memory. Call with the lock held */
int64_t abi_handle_new(int type, void *p, int64_t owner);
/* CONTRACT: contents of a handle (NULL for a wrong type or absent). Call with the lock held */
void *abi_handle_get(int64_t h, int type);
/* CONTRACT: removes a handle from the table (returns its contents, or NULL). Call with the lock held */
void *abi_handle_take(int64_t h, int type);

size_t abi_handle_list_owned(int type, int64_t owner, void ***out);

/* CONTRACT: the open object (one per process; 0 for none). Read with the lock held */
extern int64_t abi_loaded;


void abi_close_owned(int64_t obj);

/* CONTRACT: errno text (Go's spelling; per-thread buffer, valid until the next call) */
const char *abi_errno(int e);


struct abi_object *abi_object_get(int64_t h, int64_t *err);
/* CONTRACT: the same, counted as a running call (the closed check and the increment are under one lock, closing the check-then-close window).
 * The caller must release the count with abi_object_release */
struct abi_object *abi_object_acquire(int64_t h, int64_t *err);
void abi_object_release(struct abi_object *o);


struct bpf_program;
struct bpf_link;

int64_t abi_program(struct abi_object *o, const char *prog, int64_t len, struct bpf_program **p);

int64_t abi_link_put(struct bpf_link *l);


int64_t abi_uprobe_targets(struct abi_object *o, const char *doc, int64_t len);

struct abi_link {
	struct bpf_link *l;
	int64_t uprobe_owner;
	char *uprobe_file;
	int *extra_fds;
	size_t n_extra;
	struct bpf_link **more;
	size_t n_more;
};
/* CONTRACT: the same, for per-point USDT links (ownership of the n entries in more moves, the array is copied; failure destroys them all) */
int64_t abi_link_put_more(struct bpf_link *l, struct bpf_link **more, size_t n);


int abi_uprobe_target_fd(const struct abi_object *o, const char *prog);
uint8_t *abi_read_fd(int fd, size_t *len);
int abi_uprobe_info(int fd, uint32_t want, uint32_t *off, uint64_t *cookie, char *file, uint32_t cap);

int abi_kprobe_link_name(int fd, uint32_t want, char *buf, uint32_t cap);

const struct bml_attach *abi_usdt_row(const struct abi_object *o, const char *name);
/* CONTRACT: the same, for a uprobe link (ownership of owner and file moves) */
int64_t abi_link_put_uprobe(struct bpf_link *l, int64_t owner, char *file);
/* CONTRACT: the same, for a tracepoint link (ownership of the other CPUs' perf fds moves; failure destroys l and closes every fd) */
int64_t abi_link_put_extra(struct bpf_link *l, int *fds, size_t n);
/* CONTRACT: dups the link's kernel fd and returns it (to read its info outside detach races; the caller closes it).
 * For a missing link or one already detached, stores the STATE result handle in *err and returns -1 */
int abi_link_dup_fd(int64_t link, int64_t *err);

const char *abi_kind_name(const struct abi_object *o, struct bpf_program *p);

#endif
