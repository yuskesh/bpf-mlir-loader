/* abi/struct_ops.c — the struct_ops attach: bml_attach_struct_ops (register one .struct_ops.link table of a loaded object; bml_detach
 * unregisters it) and the bookkeeping that bml_close uses to refuse while a table is registered (the close rule).
 *
 * Every read and write of a table's state is under the registry lock. A table is "live" for close and attach while it
 * is registered (link > 0) or reserved (busy): an attach reserves it (ATTACHING) before it calls the kernel and keeps the
 * reservation through any cleanup of a failed attach; a detach reserves it (DETACHING) before it destroys the link and
 * releases it only after the destroy has returned (destroy before release). So close is STATE, and a second attach or detach of
 * the same table is STATE, during either window. */
#define _GNU_SOURCE
#include "abi/internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "util/errtext.h"
#include "util/mutation.h"

int abi_sops_fill(struct abi_object *o)
{
	struct bpf_map *m;
	size_t n = 0;
	bpf_object__for_each_map(m, bml_obj_bpf(o->lo)) n++;
	o->sops = calloc(n ? n : 1, sizeof *o->sops);
	if (!o->sops)
		return -1;
	bpf_object__for_each_map(m, bml_obj_bpf(o->lo))
	{
		struct abi_sop *s = &o->sops[o->n_sops];
		if (!(s->name = strdup(bpf_map__name(m))))
			return -1;
		s->kind = bpf_map__type(m) != BPF_MAP_TYPE_STRUCT_OPS ? ABI_SOP_OTHER
			  : (bpf_map__map_flags(m) & BPF_F_LINK)    ? ABI_SOP_LINK
								    : ABI_SOP_PLAIN;
		o->n_sops++;
	}
	return 0;
}

void abi_sops_free(struct abi_object *o)
{
	for (size_t i = 0; i < o->n_sops; i++)
		free(o->sops[i].name);
	free(o->sops);
	o->sops = NULL, o->n_sops = 0;
}

const struct abi_sop *abi_sops_live(const struct abi_object *o)
{
	for (size_t i = 0; i < o->n_sops; i++)
		if (o->sops[i].link > 0 || o->sops[i].busy)
			return &o->sops[i];
	return NULL;
}

static struct abi_sop *sop_of_link(int64_t owner, int64_t link)
{
	struct abi_object *o = abi_handle_get(owner, H_OBJECT);
	for (size_t i = 0; o && i < o->n_sops; i++)
		if (o->sops[i].link == link)
			return &o->sops[i];
	return NULL;
}

int abi_sops_detach_begin(struct abi_link *al, int64_t link)
{
	if (al->detaching)
		return -1;
	if (!al->l && !al->fake)
		return 0;
	struct abi_sop *s = sop_of_link(al->sop_owner, link);
	al->detaching = 1;
	if (s && !BML_MUT("abi.struct_ops_early_clear")) /* mutant: the earlier behavior, the table freed before the destroy */
		s->busy = ABI_SOP_DETACHING;
	else if (s)
		s->link = 0;
	return 1;
}

void abi_sops_detach_done(struct abi_link *al, int64_t link)
{
	struct abi_sop *s = sop_of_link(al->sop_owner, link);
	if (s)
		s->link = 0, s->busy = ABI_SOP_IDLE;
	al->detaching = 0;
}

int64_t bml_attach_struct_ops(int64_t obj, const char *map, int64_t map_len)
{
	if (map_len < 0 || (!map && map_len))
		return abi_fail(BML_OTHER, "bml: a negative length or a NULL string with a length");
	char *name = strndup(map ? map : "", (size_t)map_len);
	if (!name)
		return abi_fail(BML_OTHER, "bml: out of memory");
	int64_t err;
	struct abi_object *o = abi_object_acquire(obj, &err);
	if (!o) {
		free(name);
		return err;
	}
	abi_lock();
	struct abi_sop *s = NULL;
	for (size_t i = 0; i < o->n_sops && !s; i++)
		if (!strcmp(o->sops[i].name, name))
			s = &o->sops[i];
	int busy = s ? s->busy : 0, registered = s && s->link > 0;
	if (s && s->kind == ABI_SOP_LINK && !busy && !registered)
		s->busy = ABI_SOP_ATTACHING;
	abi_unlock();
	int64_t res;
	if (!s)
		res = abi_fail(BML_TARGET_REJECTED, "bml: no such struct_ops map %s", name);
	else if (s->kind != ABI_SOP_LINK)
		res = abi_fail(BML_TARGET_REJECTED, "bml: %s is not a link table (.struct_ops.link)", name);
	else if (busy) /* before "registered": a table being unregistered still has its link until the destroy returns */
		res = abi_fail(BML_STATE, "bml: struct_ops map %s is being %s on another thread", name,
			       busy == ABI_SOP_ATTACHING ? "registered" : "unregistered");
	else if (registered)
		res = abi_fail(BML_STATE, "bml: struct_ops map %s is already registered by this object (detach its link first)", name);
	else {
		struct bpf_link *l = NULL;
		int e = 0;
		if (!o->fake) {
			l = bpf_map__attach_struct_ops(bpf_object__find_map_by_name(bml_obj_bpf(o->lo), name));
			e = l ? 0 : errno;
		}
		struct abi_link *al = (l || o->fake) ? calloc(1, sizeof *al) : NULL;
		int64_t id = -1;
		abi_lock();
		if (al && !abi_test_take_handle_failure()) {
			al->l = l, al->fake = o->fake, al->sop_owner = obj;
			id = abi_handle_new(H_LINK, al, 0); /* like every link: not closed by closing the object */
		}
		if (id > 0)
			s->link = id, s->busy = ABI_SOP_IDLE;
		else if (!l && !o->fake)
			s->busy = ABI_SOP_IDLE; /* the kernel refused: nothing to clean up */
		abi_unlock();
		if (id > 0)
			res = abi_ok(id);
		else if (!l && !o->fake) {
			char *t = bml_errno_named(e); /* the errno tables: "EBUSY (device or resource busy)", "ENOTSUPP (kernel-internal errno 524)" */
			res = abi_fail(BML_RUNTIME_CONFLICT, "bml: the kernel refused to register struct_ops map %s: %s", name,
				       t ? t : abi_errno(e));
			free(t);
		} else { /* a registered but untracked link: destroy it while the table stays reserved */
			free(al);
			abi_test_pause("attach-cleanup");
			bpf_link__destroy(l);
			abi_lock();
			s->busy = ABI_SOP_IDLE;
			abi_unlock();
			res = abi_fail(BML_OTHER, "bml: out of memory (the struct_ops link of map %s was destroyed)", name);
		}
	}
	abi_object_release(o);
	free(name);
	return res;
}
