#include "maps/arena.h"
#include "maps/internal.h"
#include "btf/kernel.h"
#include "elf/elf.h"
#include "util/mutation.h"

#include <stdlib.h>
#include <string.h>

int bml_arena_shape(uint64_t pages, uint64_t flags, uint64_t address,
	struct bml_arena_spec *out, char **err)
{
	memset(out, 0, sizeof(*out)); *err = NULL;
#if !defined(__x86_64__)
	*err = md_xstrdup("arena requires x86_64 with 4096-byte pages"); return -1;
#endif
	const char *why = NULL;
	if (!pages || pages > (UINT64_C(1) << 20)) why = "arena max_entries must be 1..1048576 pages";
	else if (flags != 1024 && flags != 132096 && !BML_MUT("arena.any_flags"))
		why = "arena flags must be exactly BPF_F_MMAPABLE (1024) or BPF_F_MMAPABLE|BPF_F_SEGV_ON_FAULT (132096)";
	else if ((address & 4095) || (uint32_t)address < 4096) why = "arena map_extra must be page aligned with low32 >= 4096";
	else {
		uint64_t length = pages * 4096;
		if (address > UINT64_MAX - length) why = "arena address plus length overflows u64";
		else if ((address >> 32) != ((address + length - 1) >> 32)) why = "arena range crosses a 4GiB boundary";
		else { *out = (struct bml_arena_spec){address, length, (uint32_t)pages, (uint32_t)flags}; return 0; }
	}
	*err = md_xstrdup(why); return -1;
}

static int constant(const struct bml_kbtf *b, uint32_t id, int wide, uint64_t *value)
{
	int cycle; struct kbtf_type t;
	bml_kbtf_type(b, bml_kbtf_underlying(b, id, &cycle), &t);
	if (cycle) return -1;
	if (t.kind == KBTF_PTR) {
		bml_kbtf_type(b, bml_kbtf_underlying(b, t.size_type, &cycle), &t);
		if (cycle || t.kind != KBTF_ARRAY) return -1;
		*value = bml_kbtf_u32(b, t.aux + 8); return 0;
	}
	if (!wide || t.vlen != 1) return -1;
	if (t.kind == KBTF_ENUM) {
		*value = (uint64_t)(int64_t)(int32_t)bml_kbtf_u32(b, t.aux + 4); return 0;
	}
	if (t.kind == KBTF_ENUM64) {
		*value = bml_kbtf_u32(b, t.aux + 4) | (uint64_t)bml_kbtf_u32(b, t.aux + 8) << 32; return 0;
	}
	return -1;
}

static int fields(const struct bml_kbtf *b, uint32_t var, struct bml_arena_spec *out, char **err)
{
	struct kbtf_type t, v; int cycle;
	bml_kbtf_type(b, var, &v);
	bml_kbtf_type(b, bml_kbtf_underlying(b, v.size_type, &cycle), &t);
	if (cycle || t.kind != KBTF_STRUCT) { *err = md_xstrdup("arena map BTF VAR is not a struct"); return -1; }
	uint64_t values[4] = {0}; unsigned seen = 0;
	static const char *const names[] = {"type", "max_entries", "map_flags", "map_extra"};
	for (uint32_t i = 0; i < t.vlen; i++) {
		struct kbtf_member m; bml_kbtf_member(b, &t, i, &m);
		if (!strcmp(m.name, "key") || !strcmp(m.name, "value")) { *err = md_xstrdup("arena must have no key/value BTF types"); return -1; }
		for (unsigned k = 0; k < 4; k++) if (!strcmp(m.name, names[k])) {
			if ((seen & (1u << k)) || m.bitfield_size || constant(b, m.type, k == 3, &values[k])) {
				*err = md_fmts("arena BTF attribute %s is duplicated or not a constant", names[k]); return -1;
			}
			seen |= 1u << k;
		}
	}
	if (seen != 15 || values[0] != 33) { *err = md_xstrdup("arena BTF requires type33, max_entries, map_flags and map_extra"); return -1; }
	return bml_arena_shape(values[1], values[2], values[3], out, err);
}

int bml_arena_elf(const void *data, size_t len, const char *name, struct bml_arena_spec *out, char **err)
{
	memset(out, 0, sizeof(*out)); *err = NULL;
	struct bml_elf e;
	if (bml_elf_open(data, len, &e, err)) return -1;
	int rc = -1;
	if (!e.is64 || e.big_endian || e.machine != 247) { *err = md_xstrdup("arena requires little-endian ELF64 BPF for x86_64"); goto done; }
	if (bml_elf_section(&e, ".addr_space.1")) { *err = md_xstrdup("arena_data/.addr_space.1 globals are outside the arena copy contract"); goto done; }
	const struct bml_elf_shdr *sec = bml_elf_section(&e, ".BTF");
	const uint8_t *raw; size_t size;
	if (!sec) { *err = md_xstrdup("arena ELF has no .BTF"); goto done; }
	if (bml_elf_section_data(&e, sec, &raw, &size, err)) goto done;
	uint8_t *copy = malloc(size ? size : 1);
	if (!copy) { *err = md_xstrdup("out of memory"); goto done; }
	memcpy(copy, raw, size); struct bml_kbtf b;
	if (bml_kbtf_from_raw(copy, size, &b, err)) goto done;
	uint32_t found = 0;
	for (uint32_t id = 1; id < b.n; id++) {
		struct kbtf_type ds; bml_kbtf_type(&b, id, &ds);
		if (ds.kind != KBTF_DATASEC || strcmp(ds.name, ".maps")) continue;
		for (uint32_t i = 0; i < ds.vlen; i++) {
			uint32_t vid = bml_kbtf_u32(&b, ds.aux + i * 12u); struct kbtf_type v; bml_kbtf_type(&b, vid, &v);
			if (v.kind != KBTF_VAR || strcmp(v.name, name)) continue;
			if (found) { *err = md_xstrdup("arena ELF has duplicate .maps VARs of the name"); goto free_btf; }
			found = vid;
		}
	}
	if (!found) *err = md_fmts("arena ELF has no .maps VAR %s", name);
	else rc = fields(&b, found, out, err);
free_btf:
	bml_kbtf_free(&b);
done:
	bml_elf_close(&e); return rc;
}

int md_check_arena_decl(const struct bml_requirements *req, const struct bml_map_decl *m,
	const void *elf, size_t len, struct bml_map_problems *out)
{
	size_t count = 0; for (size_t i = 0; i < req->n_maps; i++) if (!strcmp(req->maps[i].map_type.p, "arena")) count++;
	char *err = NULL; struct bml_arena_spec d, e;
	if (count != 1) err = md_xstrdup("the arena copy contract requires exactly one arena");
	else if (!m->has_map_extra) err = md_xstrdup("arena map_extra must be declared (zero is distinct from missing)");
	else if (bml_arena_shape(m->max_entries, m->flags, m->map_extra, &d, &err)) {                            }
	else if (!elf) err = md_xstrdup("arena map_extra check requires the ELF, not only requirements");
	else if (bml_arena_elf(elf, len, m->name, &e, &err)) {                                   }
	else if (d.address != e.address || d.length != e.length || d.pages != e.pages || d.flags != e.flags)
		err = md_xstrdup("arena declaration map_extra/address/length differs from ELF/BTF");
	else return 0;
	if (!err) return -1; /* CONTRACT: allocation failure must never turn a refusal into success */
	return md_add(out, md_xstrdup(m->name), "decl", err, NULL);
}

int bml_check_arena_decls(const struct bml_requirements *req,const void *elf,size_t len,
	const struct bml_map_decls *decls,int require_all,struct bml_map_problems *out)
{
	memset(out,0,sizeof *out);

	for(size_t i=0;i<req->n_maps;i++) {
		const struct bml_map *row=&req->maps[i];
		if(strcmp(row->map_type.p,"arena"))continue;
		const struct bml_map_decl *decl=NULL;
		for(size_t k=0;k<decls->n_maps;k++)
			if(!strcmp(row->symbol.p,decls->maps[k].name))decl=&decls->maps[k];
		if(!decl) {
			if(require_all && md_add(out,md_xstrdup(row->symbol.p),"decl",md_xstrdup("arena declaration is required before load"),NULL))return -1;
			continue;
		}
		if(md_check_arena_decl(req,decl,elf,len,out))return -1;
	}
	return out->n?1:0;
}
