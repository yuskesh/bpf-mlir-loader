/* abi/internal.h — the internals of the C ABI (bml_*): the registry of results and handles
 * (guarded by a mutex), and the loaded object. */
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

/* ---- results ---- */
struct abi_unmet {
	char *f[4]; /* kind, program, name, detail */
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
/* A result made of a kind and a message (printf style). */
int64_t abi_fail(int64_t kind, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int64_t abi_ok(int64_t value);
/* Copies a list of Unmet into a result (kind, program, name, detail; the detail is Unmet.Detail). */
int abi_set_unmets(struct abi_result *r, const struct bml_unmet *u, size_t n);

/* ---- handle ---- */
enum { H_OBJECT = 1, H_LINK, H_READER, H_ITER };

struct abi_object {
	struct bml_obj *lo;            /* The libbpf object loaded behind the guard. */
	struct bml_requirements *req;  /* The requirements, read once (used to check the declarations of map operations). */
	uint8_t *elf;                  /* A copy of the ELF (the records check reads its BTF). */
	size_t elf_len;
	struct bml_unmets rest;        /* The Unmet entries that did not stop the load. */
	struct bml_live_caps caps;     /* The caps used for the check (same lifetime as the object). */
	struct bml_loader_decl arena_decl; /* arena-only copy; strings remain borrowed from the static preset */
	int closed;
	int inflight; /* CONTRACT: number of running calls (under the registry lock). close only at 0 */
	/* The declarations of the globals given at load time (the globals of maps.json); bml_global_get checks against them. */
	struct bml_global_decl *globals;
	size_t n_globals;
};

/* (globals.c) Reads the config document, checks it against the declared globals and stores the values to
 * write into .rodata in *vals (malloc). Success is 0; failure is a result handle
 * (PRECHECK_FAILED, MAP_MISMATCH, VALUE_RANGE or CONFIG_NOT_SET). */
int64_t abi_config(const char *cfg, int64_t cfg_len, const struct bml_map_decls *d, const uint8_t *elf, size_t elf_len,
		   struct bml_rodata_value **vals, size_t *n_vals);
/* Copies the declared globals into the object (-1 on failure) and releases them. */
int abi_globals_keep(struct abi_object *o, const struct bml_map_decls *d);
void abi_globals_free(struct abi_object *o);

/* The registry lock (every handle operation looks up the table under this lock). */
void abi_lock(void);
void abi_unlock(void);
/* CONTRACT: new handle (type, contents, and the owning object's handle, or 0 if none). Returns -1 when out of memory. Call with the lock held */
int64_t abi_handle_new(int type, void *p, int64_t owner);
/* CONTRACT: contents of a handle (NULL for a wrong type or absent). Call with the lock held */
void *abi_handle_get(int64_t h, int type);
/* CONTRACT: removes a handle from the table (returns its contents, or NULL). Call with the lock held */
void *abi_handle_take(int64_t h, int type);
/* The contents of the handles of a type that belong to owner (an object handle). They stay in the table,
 * because a closed reader or iterator must still answer STATE. */
size_t abi_handle_list_owned(int type, int64_t owner, void ***out);

/* CONTRACT: the open object (one per process; 0 for none). Read with the lock held */
extern int64_t abi_loaded;

/* Closes the object's readers and iterators (owned.c; done before the close). */
void abi_close_owned(int64_t obj);

/* CONTRACT: errno text (Go's spelling; per-thread buffer, valid until the next call) */
const char *abi_errno(int e);

/* Looks up an object (a missing or closed one stores a STATE result in *err). */
struct abi_object *abi_object_get(int64_t h, int64_t *err);
/* CONTRACT: the same, counted as a running call (the closed check and the increment are under one lock, closing the check-then-close window).
 * The caller must release the count with abi_object_release */
struct abi_object *abi_object_acquire(int64_t h, int64_t *err);
void abi_object_release(struct abi_object *o);

/* ---- programs and links (run.c; shared with trace.c) ---- */
struct bpf_program;
struct bpf_link;
/* The program with the name (ptr, len): a STATE result handle if there is none, otherwise 0 and *p. */
int64_t abi_program(struct abi_object *o, const char *prog, int64_t len, struct bpf_program **p);
/* Puts a link into the handle table (an OK result whose value is the link handle; on failure l is destroyed and OTHER returned). */
int64_t abi_link_put(struct bpf_link *l);
/* (uprobe.c) Reads the document of uprobe targets, matches it with the uprobe programs of the ELF, opens
 * each path and stores it in o->caps.bins, so that the uprobe_binary check and the attach use the same fd.
 * Success is 0 (a len of 0 means there is no target); failure is a result handle (an unreadable document
 * is PRECHECK_FAILED; a path that cannot be opened, or a program that is not a uprobe, is OTHER). */
int64_t abi_uprobe_targets(struct abi_object *o, const char *doc, int64_t len);
/* The contents of an H_LINK handle. */
struct abi_link {
	struct bpf_link *l; /* NULL means already detached. */
	int64_t uprobe_owner; /* The object of a uprobe link (checked by bml_uprobe_link_file); 0 for other links. */
	char *uprobe_file;    /* The file in the perf link info at attach time (same lifetime as the table entry). */
	int *extra_fds;       /* A tracepoint link: the perf events of the other CPUs, which have no program of their own (closed together with l on detach). */
	size_t n_extra;
	struct bpf_link **more; /* USDT: the second and later uprobe links, one per probe point (destroyed together with l on detach). */
	size_t n_more;
};
/* CONTRACT: the same, for per-point USDT links (ownership of the n entries in more moves, the array is copied; failure destroys them all) */
int64_t abi_link_put_more(struct bpf_link *l, struct bpf_link **more, size_t n);
/* (Defined in uprobe.c and shared with usdt.c.) The target fd recorded when the program was loaded (-1 if
 * none); the whole contents of an fd's file (malloc; NULL and errno on failure); and the uprobe offset and
 * cookie from the perf link info (1 if the link is not of the wanted type, -errno if it cannot be read). */
int abi_uprobe_target_fd(const struct abi_object *o, const char *prog);
uint8_t *abi_read_fd(int fd, size_t *len);
int abi_uprobe_info(int fd, uint32_t want, uint32_t *off, uint64_t *cookie, char *file, uint32_t cap);
/* (Defined in trace.c and shared with ksyscall.c.) Stores the name of the kprobe function from the perf link
 * info in buf ("" if the link is not of the wanted type). Success is 0; failure is -errno. */
int abi_kprobe_link_name(int fd, uint32_t want, char *buf, uint32_t cap);
/* (usdt.c) The usdt attach row of a program (NULL if none). */
const struct bml_attach *abi_usdt_row(const struct abi_object *o, const char *name);
/* CONTRACT: the same, for a uprobe link (ownership of owner and file moves) */
int64_t abi_link_put_uprobe(struct bpf_link *l, int64_t owner, char *file);
/* CONTRACT: the same, for a tracepoint link (ownership of the other CPUs' perf fds moves; failure destroys l and closes every fd) */
int64_t abi_link_put_extra(struct bpf_link *l, int *fds, size_t n);
/* CONTRACT: dups the link's kernel fd and returns it (to read its info outside detach races; the caller closes it).
 * For a missing link or one already detached, stores the STATE result handle in *err and returns -1 */
int abi_link_dup_fd(int64_t link, int64_t *err);
/* The name of a program kind, used in the messages for a mix-up: xdp, fentry, fexit, kprobe, uprobe, tc ingress,
 * tc egress, and for any other kind the name of the libbpf type (trace.c). */
const char *abi_kind_name(const struct abi_object *o, struct bpf_program *p);

#endif
