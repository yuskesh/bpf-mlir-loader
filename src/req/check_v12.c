#include "req/check_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caps/caps.h"
#include "req/uprobe.h"
#include "req/usdt.h"
#include "util/gostr.h"
#include "util/mutation.h"


static int mtarget_args_of(const struct bml_attach *a, size_t i, struct bml_intarg **args, size_t *n)
{
	*args = NULL, *n = 0;
	for (size_t k = 0; k < a->n_mtarget_args; k++)
		if (a->mtarget_args[k].i == (int64_t)i) {
			struct bml_intarg *na = realloc(*args, (*n + 1) * sizeof **args);
			if (!na) {
				free(*args);
				*args = NULL;
				return -1;
			}
			*args = na;
			(*args)[(*n)++] = (struct bml_intarg){a->mtarget_args[k].n, a->mtarget_args[k].type};
		}
	return 0;
}

int ck_check_multi(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *AT = a->attach_type.p;
	if ((int64_t)a->n_mtargets != a->multi_n)
		return ck_fail(c, ck_fmtd("program %s: %s attach row with %zu mtarget rows, want %lld", P, AT, a->n_mtargets, (long long)a->multi_n));
	int kp = !strcmp(AT, "kprobe_multi") || !strcmp(AT, "kretprobe_multi");
	if (ck_check_attach_type(c, P, kp ? "trace_kprobe_multi" : "trace_uprobe_multi"))
		return -1;
	char *ta;
	if (ck_check_arch_ctx(c, a, &ta)) {
		free(ta);
		return -1;
	}
	size_t nt = BML_MUT("check.multi_target_first_only") && a->n_mtargets > 0 ? 1 : a->n_mtargets;
	if (kp) {
		for (size_t i = 0; i < nt; i++) {
			struct bml_attach b = *a;
			b.target = a->mtargets[i];
			struct bml_intarg *ma = NULL;
			size_t nm = 0;
			if (a->n_mtarget_args > 0) {
				if (mtarget_args_of(a, i, &ma, &nm)) {
					free(ta);
					return ck_fail(c, ck_dupn("out of memory"));
				}
				b.kprobe_args = ma;
				b.n_kprobe_args = nm;
			}
			int rc = ck_check_kprobe_target(c, &b, ta, 0);
			free(ma);
			if (rc) {
				free(ta);
				return -1;
			}
		}
		free(ta);
		return 0;
	}
	free(ta);
	struct bml_buf jb = {0};
	for (size_t i = 0; i < a->n_mtargets; i++) {
		if (i)
			bml_buf_adds(&jb, ",");
		bml_buf_add(&jb, a->mtargets[i].p, a->mtargets[i].len);
	}
	char *joined = bml_buf_take(&jb);
	if (!joined)
		return ck_fail(c, ck_dupn("out of memory"));
	uint8_t *bin;
	struct bml_elf elf;
	int o = ck_uprobe_open(c, a, joined, &bin, &elf);
	free(joined);
	if (o <= 0)
		return o;
	struct ck_dsrc src;
	ck_dsrc_init(&src, &elf, a->program.p);
	for (size_t i = 0; i < nt; i++) {
		struct bml_attach ca = *a;
		struct bml_intarg *ma = NULL;
		size_t nm = 0;
		if (a->n_mtarget_args > 0) {
			if (mtarget_args_of(a, i, &ma, &nm)) {
				c->oom = 1;
				break;
			}
			ca.uprobe_args = ma;
			ca.n_uprobe_args = nm;
		}
		ck_uprobe_target(c, &ca, &elf, a->mtargets[i].p, !strcmp(AT, "uretprobe_multi"), &src);
		free(ma);
	}
	ck_dsrc_free(&src);
	bml_elf_close(&elf);
	free(bin);
	return 0;
}


static void spelling(char out[8], int size, int is_signed)
{
	snprintf(out, 8, "%c%d", is_signed ? 'i' : 'u', size * 8);
}


static void usdt_point(struct ck *c, const struct bml_attach *a, const struct bml_usdt_point *p, int64_t max_n)
{
	const char *P = a->program.p, *T = a->target.p;
	char *at = ck_fmtd("%s at pc 0x%llx", T, (unsigned long long)p->pc);
	if (!at) {
		c->oom = 1;
		return;
	}
	int has = p->semaphore != 0;
	if (has != !strcmp(a->usdt_sem.p, "required")) {
		if (has)
			ck_add(c, "usdt_probe", P, at,
			       0, ck_fmtd("the point has a semaphore (0x%llx), but the object declares none (usdtsem none) — a loader that passes no ref_ctr_offset leaves the point silent",
					  (unsigned long long)p->semaphore));
		else
			ck_add(c, "usdt_probe", P, at, 0, ck_dupn("the point has no semaphore, but the object declares the point semaphore-guarded (usdtsem required)"));
	}
	size_t *st, *ln, na;
	if (bml_go_fields(p->args, strlen(p->args), &st, &ln, &na)) {
		c->oom = 1;
		free(at);
		return;
	}
	if (max_n > (int64_t)na) {
		struct bml_buf b = {0};
		bml_buf_addf(&b, "the point has %zu arguments (", na);
		bml_buf_add_goquote(&b, p->args, strlen(p->args));
		bml_buf_addf(&b, "), but the object reads argument %lld", (long long)max_n);
		ck_add(c, "usdtarg", P, at, 0, bml_buf_take(&b));
		goto out;
	}
	for (size_t i = 0; i < a->n_usdt_args; i++) {
		const struct bml_intarg *k = &a->usdt_args[i];
		if (BML_MUT("check.usdt_arg_skip"))
			break;
		char *an = ck_fmtd("%lld of %s at pc 0x%llx (%s)", (long long)k->n, T, (unsigned long long)p->pc, k->type.p);
		const char *as = p->args + st[k->n - 1];
		size_t al = ln[k->n - 1];
		struct bml_usdt_arg spec;
		int size_ok;
		char *err = NULL;
		if (!an || bml_usdt_parse_arg(as, al, &spec, &size_ok, &err)) {
			free(an);
			c->oom = 1;
			goto out;
		}
		int size = atoi(k->type.p + 1) / 8, is_signed = k->type.p[0] == 'i';
		if (!size_ok) {
			ck_add(c, "usdtarg_unknown", P, an, 0, err);
		} else if (size != spec.size || is_signed != spec.is_signed) {
			char sp[8];
			spelling(sp, spec.size, spec.is_signed);
			struct bml_buf b = {0};
			bml_buf_addf(&b, "argument %lld of the point is ", (long long)k->n);
			bml_buf_add_goquote(&b, as, al);
			bml_buf_addf(&b, " (%s), but the object reads it as %s", sp, k->type.p);
			ck_add(c, "usdtarg", P, an, 0, bml_buf_take(&b));
			free(err);
		} else if (err) {
			ck_add(c, "usdtarg_unknown", P, an, 0, err);
		}
		free(an);
	}
out:
	free(st);
	free(ln);
	free(at);
}

int ck_check_usdt(struct ck *c, const struct bml_attach *a)
{
	const char *P = a->program.p, *T = a->target.p;
	if (a->usdt_sem.len == 0)
		return ck_fail(c, ck_fmtd("program %s: usdt attach row without a usdtsem row", P));
	char *ta;
	if (ck_check_arch_ctx(c, a, &ta)) {
		free(ta);
		return -1;
	}
	free(ta);

	const struct bml_loader_decl *d = ck_loader_of(c);
	const char *ua = d->usdt_attach ? d->usdt_attach : "";
	struct bml_buf qn = {0};
	bml_buf_add_goquote(&qn, d->name, strlen(d->name));
	char *q = bml_buf_take(&qn);
	if (!q)
		return ck_fail(c, ck_dupn("out of memory"));
	if (!strcmp(ua, "none"))
		ck_add(c, "usdt_loader", P, T, 0, ck_fmtd("the loader %s does not attach USDT points (usdt_attach none)", q));
	else if (!strcmp(ua, "plain")) {
		if (!strcmp(a->usdt_sem.p, "required"))
			ck_add(c, "usdt_loader", P, T, 0,
			       ck_fmtd("the points are guarded by a semaphore, but the loader %s cannot pass the uprobe ref_ctr_offset (usdt_attach plain) — the points would not fire and the program would see no events silently",
				       q));
	} else if (strcmp(ua, "ref_ctr") != 0)
		ck_add(c, "usdt_loader_unknown", P, T, 0, ck_fmtd("the loader %s does not declare usdt_attach", q));
	free(q);
	uint8_t *bin;
	struct bml_elf elf;
	int o = ck_uprobe_open(c, a, T, &bin, &elf);
	if (o <= 0)
		return o;
	struct bml_usdt_points pts;
	char *rerr = NULL;
	if (bml_usdt_read_points(&elf, &pts, &rerr)) {
		if (rerr)
			ck_add(c, "usdtarg_unknown", P, T, 0, ck_fmtd("the binary's stapsdt notes cannot be read: %s", rerr));
		else
			c->oom = 1;
		free(rerr);
		goto done;
	}
	const char *colon = strchr(T, ':');
	size_t pl = colon ? (size_t)(colon - T) : strlen(T);
	const char *name = colon ? colon + 1 : "";
	size_t n_mine = 0;
	for (size_t i = 0; i < pts.n; i++)
		if (strlen(pts.p[i].provider) == pl && !memcmp(pts.p[i].provider, T, pl) && !strcmp(pts.p[i].name, name))
			n_mine++;
	if (n_mine == 0) {
		ck_add(c, "usdt_probe", P, T, 0, ck_fmtd("the binary has no stapsdt note for %s (%zu points of other probes)", T, pts.n));
		goto done;
	}

	for (size_t i = 0; i < c->req->n_maps; i++) {
		const struct bml_map *m = &c->req->maps[i];
		size_t pre = strlen(BML_USDT_SPEC_MAP_PREFIX);
		if (m->symbol.len == pre + a->program.len && !memcmp(m->symbol.p, BML_USDT_SPEC_MAP_PREFIX, pre) &&
		    !memcmp(m->symbol.p + pre, P, a->program.len) && (uint64_t)n_mine > m->max_entries)
			ck_add(c, "usdt_probe", P, T, 0,
			       ck_fmtd("the binary has %zu points of %s, but the object's USDT spec map %s holds %llu (max_points) — the points past it would read no spec",
				       n_mine, T, m->symbol.p, (unsigned long long)m->max_entries));
	}
	int64_t max_n = a->n_usdt_args ? a->usdt_args[a->n_usdt_args - 1].n : 0;
	for (size_t i = 0; i < pts.n; i++)
		if (strlen(pts.p[i].provider) == pl && !memcmp(pts.p[i].provider, T, pl) && !strcmp(pts.p[i].name, name))
			usdt_point(c, a, &pts.p[i], max_n);
done:
	bml_usdt_points_free(&pts);
	bml_elf_close(&elf);
	free(bin);
	return 0;
}


int ck_check_innermaps(struct ck *c)
{
	for (size_t i = 0; i < c->req->n_innermaps; i++) {
		const struct bml_innermap *im = &c->req->innermaps[i];
		int ok = 0;
		char *msg = NULL;
		if (c->caps->map_type(c->caps->ctx, im->map_type.p, im->id, &ok, &msg) != BML_Q_OK)
			return ck_fail(c, msg);
		if (!ok)
			ck_add(c, "map_type", im->outer.p, im->map_type.p, im->id, ck_dupn("inner"));
	}
	return 0;
}
