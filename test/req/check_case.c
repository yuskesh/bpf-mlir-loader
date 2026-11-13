#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "req/check.h"
#include "util/gostr.h"
#include "json/json.h"
#include "caps/recorded.h"
#include "caps/recorder.h"
#include "req/from_elf.h"

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

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: check_case <case dir>\n");
		return 2;
	}
	const char *dir = argv[1];
	char path[4096];
	snprintf(path, sizeof(path), "%s/caps.json", dir);
	char *err = NULL;
	struct bml_recorded *rc = bml_recorded_read(path, &err);
	if (!rc) {
		fprintf(stderr, "check_case: %s\n", err);
		free(err);
		return 2;
	}
	struct bml_caps caps;
	bml_recorded_caps(rc, &caps);

	struct bml_recorded *rp = NULL;
	struct bml_caps rpc;
	snprintf(path, sizeof(path), "%s/load_as.json", dir);
	size_t llen;
	char *la = read_all(path, &llen);
	if (la) {
		struct bml_json *j = NULL;
		char *je = NULL;
		const struct bml_json *u = NULL, *c = NULL;
		int64_t uid = 0;
		if (bml_json_parse(la, llen, &j, &je) || j->type != BML_JSON_OBJECT || !(u = bml_json_get(j, "uid")) || !(c = bml_json_get(j, "cap_eff")) ||
		    bml_json_int64(u, &uid) || c->type != BML_JSON_STRING) {
			fprintf(stderr, "check_case: %s: load_as.json: %s\n", dir, je ? je : "want {\"uid\": <int>, \"cap_eff\": <string>}");
			return 2;
		}
		snprintf(path, sizeof(path), "%s/reprobe.json", dir);
		FILE *rf = fopen(path, "r");
		if (rf) {
			fclose(rf);
			if (!(rp = bml_recorded_read(path, &err))) {
				fprintf(stderr, "check_case: %s\n", err);
				return 2;
			}
			bml_recorded_caps(rp, &rpc);
		}
		if (bml_recorded_for_load(rc, (long long)uid, c->str, rp ? &rpc : NULL))
			return 2;
		bml_json_free(j);
		free(je);
		free(la);
	}
	struct bml_requirements *req = NULL;
	int precheck_failed = 0;
	size_t len;
	snprintf(path, sizeof(path), "%s/object.bpf.o", dir);
	char *data = read_all(path, &len);
	if (data) {
		struct bml_req_elf_error e;
		if (bml_req_from_elf(data, len, &req, &e)) {
			precheck_failed = 1;
			bml_req_elf_error_free(&e);
		}
		free(data);
	} else {
		snprintf(path, sizeof(path), "%s/requirements.txt", dir);
		data = read_all(path, &len);
		if (!data) {
			fprintf(stderr, "check_case: %s: neither object.bpf.o nor requirements.txt\n", dir);
			bml_recorded_free(rc);
			return 2;
		}
		struct bml_parse_error pe;
		if (bml_req_parse(data, len, &req, &pe)) {
			fprintf(stderr, "check_case: %s: requirements.txt: %s\n", dir, pe.msg);
			bml_parse_error_free(&pe);
			bml_requirements_free(req);
			free(data);
			bml_recorded_free(rc);
			return 2;
		}
		free(data);
	}
	struct bml_unmets u = {0};
	struct bml_caps original = caps;
	struct bml_recorder *recorder = NULL;
	const char *record_path = getenv("CHECK_CASE_RECORD");
	if (record_path) {
		recorder = bml_recorder_new(&original);
		if (!recorder) return 2;
		bml_recorder_caps(recorder, &caps);
	}
	if (!precheck_failed) {
		char *cerr = NULL;
		if (bml_check(req, &caps, &u, &cerr)) {
			precheck_failed = 1;
			if (getenv("CHECK_CASE_MSG"))
				fprintf(stderr, "check_case: %s: %s\n", dir, cerr);
			free(cerr);
		}
	}
	struct bml_buf b = {0};
	if (precheck_failed) {
		bml_buf_adds(&b, "{\"result\":\"precheck_failed\",\"unmet\":[]}");
	} else {
		int blocks = 0;
		for (size_t i = 0; i < u.n; i++)
			blocks |= bml_unmet_blocks_load(&u.u[i]);
		bml_buf_addf(&b, "{\"result\":\"%s\",\"unmet\":[", blocks ? "target_rejected" : "ok");
		for (size_t i = 0; i < u.n; i++) {
			const struct bml_unmet *x = &u.u[i];
			bml_buf_adds(&b, i ? ",{\"kind\":" : "{\"kind\":");
			bml_json_write_string(&b, x->kind, strlen(x->kind));
			bml_buf_adds(&b, ",\"program\":");
			bml_json_write_string(&b, x->program, strlen(x->program));
			bml_buf_adds(&b, ",\"name\":");
			bml_json_write_string(&b, x->name, strlen(x->name));
			bml_buf_addf(&b, ",\"id\":%lld,\"blocks_load\":%s}", (long long)x->id, bml_unmet_blocks_load(x) ? "true" : "false");
			if (getenv("CHECK_CASE_MSG")) {
				char *s = bml_unmet_string(x);
				fprintf(stderr, "  %s\n", s);
				free(s);
			}
		}
		bml_buf_adds(&b, "]}");
	}
	printf("%s\n", b.p);
	bml_buf_free(&b);
	int save_failed = 0;
	if (recorder) {
		size_t len;
		const struct bml_loader_decl *decl = original.loader ? original.loader(original.ctx) : &bml_loader_cilium022;
		char *record = bml_recorder_json(recorder, 0, "0", decl, &len);
		FILE *f = record ? fopen(record_path, "wb") : NULL;
		if (!f) save_failed = 1;
		else { if (fwrite(record, 1, len, f) != len) save_failed = 1; if (fclose(f)) save_failed = 1; }
		free(record); bml_recorder_free(recorder);
	}
	bml_unmets_free(&u);
	bml_requirements_free(req);
	bml_recorded_free(rc);
	bml_recorded_free(rp);
	return save_failed ? 2 : 0;
}
