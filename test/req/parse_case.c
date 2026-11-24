// test/corpus/parse_case.c — reads a parse case of the conformance corpus (requirements.txt) with bml_req_parse and prints one
// line of JSON in the same form as want.json (the Go reference's wantParse in go/bindrt/conformance_test.go, with omitempty).
//
//   parse_case <requirements.txt>
//
// rc: 0 means a verdict was printed (whether accepted or rejected); 2 means an untyped error (a failure in the Go harness too)
// or an I/O error.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "req/req.h"

static char *read_all(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return NULL;
	size_t cap = 4096, n = 0;
	char *buf = malloc(cap);
	while (buf) {
		size_t r = fread(buf + n, 1, cap - n, f);
		n += r;
		if (n < cap)
			break;
		char *nb = realloc(buf, cap * 2);
		if (!nb) {
			free(buf);
			buf = NULL;
			break;
		}
		buf = nb;
		cap *= 2;
	}
	fclose(f);
	*len = n;
	return buf;
}

static void hex(const char *s)
{
	for (const unsigned char *p = (const unsigned char *)s; *p; p++)
		printf("%02x", *p);
}

/* -m: several files, in the same form as test/oracle's parse-oracle ("<path>\t<json>", including the hex of the rejection text) */
static int multi(int argc, char **argv)
{
	for (int i = 2; i < argc; i++) {
		size_t len;
		char *data = read_all(argv[i], &len);
		if (!data) {
			fprintf(stderr, "parse_case: %s: %s\n", argv[i], strerror(errno));
			return 2;
		}
		struct bml_requirements *r = NULL;
		struct bml_parse_error e;
		int rc = bml_req_parse(data, len, &r, &e);
		free(data);
		if (rc == 0) {
			printf("%s\t{\"accept\":true,\"version\":%d}\n", argv[i], r->version);
		} else if (e.rule[0] == 0) {
			printf("%s\t{\"untyped\":true,\"msg_hex\":\"", argv[i]);
			hex(e.msg ? e.msg : "");
			printf("\"}\n");
		} else {
			printf("%s\t{\"accept\":false,\"line\":%d,\"row\":\"%s\",\"rule\":\"%s\",\"msg_hex\":\"", argv[i], e.line,
			       e.row, e.rule);
			hex(e.msg ? e.msg : "");
			printf("\"}\n");
		}
		bml_requirements_free(r);
		if (rc)
			bml_parse_error_free(&e);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "-m") == 0)
		return multi(argc, argv);
	if (argc != 2) {
		fprintf(stderr, "usage: parse_case <requirements.txt> | parse_case -m <file>...\n");
		return 2;
	}
	size_t len;
	char *data = read_all(argv[1], &len);
	if (!data) {
		fprintf(stderr, "parse_case: %s: %s\n", argv[1], strerror(errno));
		return 2;
	}
	struct bml_requirements *r = NULL;
	struct bml_parse_error e;
	int rc = bml_req_parse(data, len, &r, &e);
	free(data);
	if (rc == 0) {
		printf("{\"accept\":true,\"version\":%d}\n", r->version);
		bml_requirements_free(r);
		return 0;
	}
	bml_requirements_free(r);
	if (e.rule[0] == 0) {
		fprintf(stderr, "parse_case: untyped error: %s\n", e.msg ? e.msg : "(no message)");
		bml_parse_error_free(&e);
		return 2;
	}
	printf("{\"accept\":false");
	if (e.line != 0)
		printf(",\"line\":%d", e.line);
	if (e.row[0])
		printf(",\"row\":\"%s\"", e.row);
	printf(",\"rule\":\"%s\"}\n", e.rule);
	if (getenv("PARSE_CASE_MSG"))
		fprintf(stderr, "%s\n", e.msg);
	bml_parse_error_free(&e);
	return 0;
}
