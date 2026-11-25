/* maps/decode_globals.c — the "globals" part of maps.json ([]GlobalDecl), split out of decode.c (at its size
 * limit). bpf-mlir's record globals add the record key and Go's presence read: after the strict decode has accepted the document,
 * ParseMapDecls reads each element again and marks type and record as present when the key exists, whatever its value
 * ("" and null included). */
#include "maps/internal.h"

#include <stdlib.h>

#include "json/json.h"

/* A missing key or null is nil (not checked); `[]` is an empty list with has_globals set. Failure is -1; if *err is
 * NULL the cause is out of memory. */
int md_decode_globals(const struct bml_json *gs, struct bml_map_decls *d, char **err)
{
	if (!gs || gs->type == BML_JSON_NULL)
		return 0;
	if (gs->type != BML_JSON_ARRAY) {
		*err = md_xstrdup("json: cannot unmarshal into field globals of type []GlobalDecl");
		return -1;
	}
	d->has_globals = 1;
	d->globals = calloc(gs->n + 1, sizeof(*d->globals));
	if (!d->globals)
		return -1;
	for (size_t i = 0; i < gs->n; i++) {
		const struct bml_json *g = gs->items[i];
		struct bml_global_decl *x = &d->globals[d->n_globals++];
		if (g->type == BML_JSON_NULL) { /* Go's zero GlobalDecl, with no key present */
			if (!(x->name = md_xstrdup("")) || !(x->section = md_xstrdup("")) || !(x->type = md_xstrdup("")) ||
			    !(x->record = md_xstrdup("")))
				return -1;
			continue;
		}
		if (g->type != BML_JSON_OBJECT) {
			*err = md_xstrdup("json: cannot unmarshal into a global declaration");
			return -1;
		}
		static const char *const gk[] = {"name", "section", "type", "record"};
		if (md_keys_ok(g, gk, 4, err) || md_jstr(g, "name", &x->name, err) || md_jstr(g, "section", &x->section, err) ||
		    md_jstr(g, "type", &x->type, err) || md_jstr(g, "record", &x->record, err))
			return -1;
		x->type_key = bml_json_get(g, "type") != NULL;
		x->record_key = bml_json_get(g, "record") != NULL;
	}
	return 0;
}
