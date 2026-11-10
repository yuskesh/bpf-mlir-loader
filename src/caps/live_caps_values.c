
#include "caps/live_caps.h"

static int enum_value(void *ctx, const char *en, const char *name, uint64_t *out, char **msg)
{ return bml_live_enum_value(&((struct bml_live_caps *)ctx)->live, en, name, out, msg); }
static int struct_size(void *ctx, const char *name, uint32_t *out, char **msg)
{ return bml_live_struct_size(&((struct bml_live_caps *)ctx)->live, name, out, msg); }
static int ksym_var(void *ctx, const char *name, char **out, char **msg)
{ return bml_live_ksym_var(&((struct bml_live_caps *)ctx)->live, name, out, msg); }
static int kconfig(void *ctx, const char *name, char **out, char **msg)
{ return bml_live_kconfig(&((struct bml_live_caps *)ctx)->live, name, out, msg); }
static int btf_presence(void *ctx, const char *kind, const char *target, int *out, char **msg)
{ return bml_live_btf_presence(&((struct bml_live_caps *)ctx)->live, kind, target, out, msg); }
static int func_ret(void *ctx, const char *name, const char *type, struct bml_strs *out, char **msg)
{ return bml_live_func_ret(&((struct bml_live_caps *)ctx)->live, name, type, out, msg); }
static int fib_flags(void *ctx, const char *prog, int64_t id, uint32_t mask, int *out, char **msg)
{ return bml_live_fib_flags(&((struct bml_live_caps *)ctx)->live, prog, id, mask, out, msg); }

static int netkit(void *ctx, const char *d, int *out, char **msg)
{ return bml_live_netkit(&((struct bml_live_caps *)ctx)->live, d, out, msg); }
static int sleepable(void *ctx, const char *pt, const char *at, int *out, char **msg)
{ return bml_live_sleepable(&((struct bml_live_caps *)ctx)->live, pt, at, out, msg); }
static int helper_target(void *ctx, const char *pt, int64_t id, const struct bml_helper_target *h, struct bml_strs *out, char **msg)
{ return bml_live_helper_target(&((struct bml_live_caps *)ctx)->live, pt, id, h, out, msg); }

void lv_caps_kernel_values(struct bml_caps *out)
{
	out->netkit = netkit; out->sleepable = sleepable; out->helper_target = helper_target;
	out->enum_value = enum_value; out->struct_size = struct_size;
	out->ksym_var = ksym_var; out->kconfig = kconfig; out->btf_presence = btf_presence;
	out->func_ret = func_ret; out->fib_flags = fib_flags;
}
