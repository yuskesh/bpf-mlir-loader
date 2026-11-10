


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/gostr.h"
#include "json/json.h"
#include "maps/mapdecl.h"
#include "caps/recorded.h"

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: json_case caps|maps|loader <file>...\n");
		return 2;
	}
	const char *kind = argv[1];
	for (int i = 2; i < argc; i++) {
		FILE *f = fopen(argv[i], "rb");
		if (!f) {
			fprintf(stderr, "json_case: %s: %s\n", argv[i], strerror(errno));
			return 2;
		}
		struct bml_buf b = {0};
		char tmp[65536];
		size_t r;
		while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0)
			bml_buf_add(&b, tmp, r);
		fclose(f);
		const char *data = b.p ? b.p : "";
		char *err = NULL;
		enum bml_json_rule rule = BML_JR_NONE;
		int bad;
		if (!strcmp(kind, "caps")) {
			struct bml_recorded *rc = bml_recorded_parse_rule(data, b.len, ".", &err, &rule);
			bad = rc == NULL;
			bml_recorded_free(rc);
		} else if (!strcmp(kind, "maps")) {
			struct bml_map_decls d;
			bad = bml_map_decls_parse_rule(data, b.len, &d, &err, &rule) != 0;
			if (!bad)
				bml_map_decls_free(&d);
		} else {
			struct bml_loader_decl d;
			bad = bml_loader_decl_parse(data, b.len, &d, &err, &rule) != 0;
			if (!bad)
				bml_loader_decl_free(&d);
		}
		if (!bad)
			printf("%s\tok\n", argv[i]);
		else
			printf("%s\tinvalid\t%s\n", argv[i], rule == BML_JR_NONE ? "other" : bml_json_rule_name(rule));
		if (getenv("JSON_CASE_MSG") && err)
			fprintf(stderr, "%s: %s\n", argv[i], err);
		free(err);
		bml_buf_free(&b);
	}
	return 0;
}
