#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json.h"
#include "maps/mapdecl.h"
#include "req/from_elf.h"
#include "util/gostr.h"

static char *read_all(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return NULL;
	struct bml_buf b = {0};
	char tmp[65536];
	size_t n;
	while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
		bml_buf_add(&b, tmp, n);
	fclose(f);
	*len = b.len;
	if (!b.p)
		bml_buf_add(&b, "", 0);
	return bml_buf_take(&b);
}

static void js(struct bml_buf *b, const char *s)
{
	bml_json_write_string(b, s, strlen(s));
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: maps_case <case dir>\n");
		return 2;
	}
	char path[4096];
	size_t len, elf_len = 0;
	struct bml_requirements *req = NULL;
	snprintf(path, sizeof(path), "%s/object.bpf.o", argv[1]);
	char *elf = read_all(path, &elf_len);
	if (elf) {
		struct bml_req_elf_error e;
		if (bml_req_from_elf(elf, elf_len, &req, &e)) {
			fprintf(stderr, "maps_case: %s: the ELF cannot be read\n", argv[1]);
			bml_req_elf_error_free(&e);
			return 2;
		}
	} else {
		snprintf(path, sizeof(path), "%s/requirements.txt", argv[1]);
		char *text = read_all(path, &len);
		struct bml_parse_error pe;
		if (!text || bml_req_parse(text, len, &req, &pe)) {
			fprintf(stderr, "maps_case: %s: neither a readable object.bpf.o nor requirements.txt\n", argv[1]);
			return 2;
		}
		free(text);
	}
	snprintf(path, sizeof(path), "%s/maps.json", argv[1]);
	char *mj = read_all(path, &len);
	struct bml_map_decls d;
	char *err = NULL;
	if (!mj || bml_map_decls_parse(mj, len, &d, &err)) {
		fprintf(stderr, "maps_case: %s: maps.json: %s\n", argv[1], err ? err : "unreadable");
		return 2;
	}
	free(mj);
	struct bml_map_problems p;
	int rc = bml_check_map_decls(req, elf, elf_len, &d, &p);
	if (rc < 0) {
		fprintf(stderr, "maps_case: out of memory\n");
		return 2;
	}
	struct bml_buf b = {0};
	bml_buf_addf(&b, "{\"result\":\"%s\",\"problems\":[", rc ? "map_mismatch" : "ok");
	for (size_t i = 0; i < p.n; i++) {
		bml_buf_adds(&b, i ? ",{\"map\":" : "{\"map\":");
		js(&b, p.p[i].map);
		bml_buf_adds(&b, ",\"field\":");
		js(&b, p.p[i].field);
		bml_buf_adds(&b, ",\"declared\":");
		js(&b, p.p[i].declared);
		bml_buf_adds(&b, ",\"elf\":");
		js(&b, p.p[i].elf);
		bml_buf_adds(&b, "}");
		if (getenv("MAPS_CASE_MSG")) {
			char *s = bml_map_problem_string(&p.p[i]);
			fprintf(stderr, "  %s\n", s);
			free(s);
		}
	}
	bml_buf_adds(&b, "]}");
	printf("%s\n", b.p);
	bml_buf_free(&b);
	bml_map_problems_free(&p);
	bml_map_decls_free(&d);
	bml_requirements_free(req);
	free(elf);
	return 0;
}
