#ifndef BML_CAPS_LIVE_INTERNAL_H
#define BML_CAPS_LIVE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "caps/live.h"


int lv_bpf(int cmd, void *attr, unsigned size);
void lv_close(int fd);
int lv_close_checked(int fd);

enum { LV_LOG_DISABLED, LV_LOG_0, LV_LOG_1 };
enum { LV_NO_KIND = 0 };


struct lv_prog {
	uint32_t type, attach_type, flags;
	const uint8_t *insns;
	size_t n_insns;
	const char *license, *name;
	int log_mode;
	const uint8_t *btf;
	size_t btf_len;
	const uint8_t *func_info;
	uint32_t func_info_cnt;
	const char *attach_to;
	uint32_t attach_kind;
	uint32_t attach_btf_id, attach_prog_fd;
	int bpf2bpf;
};


struct lv_res {
	int fd;
	int err;
	int verifier;
	int notsup;
	char **lines;
	size_t n_lines;
	

	const char *suffix;
	int cause;
	char *text;
};

char *lv_res_text(const struct lv_res *r);
void lv_res_free(struct lv_res *r);
int lv_prog_load(struct bml_live *l, const struct lv_prog *p, struct lv_res *r);


int lv_btf_handle(struct bml_live *l, const uint8_t *btf, size_t len, struct lv_res *r);
int lv_btf_handle_reason(struct bml_live *l, const uint8_t *btf, size_t len, struct lv_res *r);


int lv_feat(struct bml_live *l, int which);

struct lv_kmo {
	int strip_func_linkage, replace_decl_tags, replace_type_tags, replace_enum64;
};
void lv_kmo(struct bml_live *l, struct lv_kmo *o);

uint8_t *lv_strip_func_linkage(const uint8_t *btf, size_t len);

int lv_kernel_version(struct bml_live *l, uint32_t *v);

void lv_obj_name(struct bml_live *l, const char *name, char dst[16]);


int lv_vmlinux(struct bml_live *l, const struct bml_kbtf **kb);


void lv_log_lines(const char *buf, size_t size, char ***lines, size_t *n);


struct lv_memo *lv_memo_get(struct bml_live *l, const char *key);
int lv_memo_put(struct bml_live *l, const char *key, int rc, int value);
int lv_unknownf(char **msg,const char *fmt,...);
void lv_btf_reason(struct lv_res *r,int load_error,const char *log,size_t size);
int lv_memo_answer(const struct lv_memo *m,int *out,char **msg);
int lv_memo_reason(struct bml_live *l,const char *key,int rc,int value,char *why,int *out,char **msg);
void lv_caps_kernel_values(struct bml_caps *out);



struct bml_buf;
const struct bml_kbtf *lv_kb(struct bml_live *l, const char **err);
int lv_msg(char **msg, int rc, const char *prefix, const char *err);
int lv_push(struct bml_strs *out, struct bml_buf *b);
int lv_oom(struct bml_strs *out, char **msg);
void lv_int_spell(const struct bml_kbtf *kb, const struct kbtf_type *t, char *dst, size_t n);

const char *bml_arg_name(const char *n);


int lv_compare_proto(const struct bml_kbtf *kb, const struct kbtf_type *fp, const char *what, int64_t nargs, const char *ret,
		     const struct bml_str *args, size_t n_args, struct bml_strs *out);

int lv_tracefs_event_id(const char *event, int *out, char **msg);


int lv_sockmap_link_probe(struct bml_live *l, const char *pt_name, uint32_t pt, const char *at_name, uint32_t at, int *val, char **why);

int lv_multi_link_probe(struct bml_live *l, const char *pt_name, const char *at_name, uint32_t at, int *val, char **why);

int lv_read_file(const char *path, char **data, size_t *len, int *e);
int lv_lookup(const struct bml_kbtf *kb, const char *name, uint32_t kind, uint32_t *id, char **err);


struct kbtf_member;
int lv_find_member_path(const struct bml_kbtf *kb, uint32_t struct_id, const char *path, struct kbtf_member *out, int *twice);
int lv_kfield_embedded(const struct bml_kbtf *kb, const struct kbtf_member *mb, const char *name, struct bml_buf *b);


int lv_tp_field_name(const char *d, size_t n, size_t *s, size_t *e);
int lv_tp_char_depth(const char *decl, size_t n, int *depth);

int lv_tp_array_shape(const char *decl, size_t n, int64_t *count, char *sign);
int lv_sys_char_depth(const struct bml_kbtf *kb, const char *typ, int *depth);
int lv_sys_btf_char_depth(const struct bml_kbtf *kb, uint32_t id, int *depth);
int lv_str_depth_ok(int depth, const char *typ);
int lv_is_str(const char *typ);

char *lv_str_arg(int depth, const char *typ);
/* CONTRACT: tracefsRoots (shared by tracepoint id, format and syscall format). The product does not change it; only the classification differential tool replaces it
 * with a constructed tracefs directory (the Go oracle points its copy at the same directory) */
extern const char *lv_tracefs_roots[2];

int lv_tp_field_text(const char *text, size_t len, const char *event, const char *field, int64_t off, int64_t bytes, const char *sign,
		     struct bml_strs *out, char **msg);

#endif
