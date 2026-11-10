

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json.h"

static int fails;

static void expect(const char *in, size_t n, const char *want_err)
{
	struct bml_json *j;
	char *err;
	int rc = bml_json_parse(in, n, &j, &err);
	if (!want_err && rc) {
		printf("FAIL: %s — want ok, got %s\n", in, err);
		fails++;
	} else if (want_err && !rc) {
		printf("FAIL: %s — want error (%s), got ok\n", in, want_err);
		fails++;
	} else if (want_err && !strstr(err, want_err)) {
		printf("FAIL: %s — want error containing %s, got %s\n", in, want_err, err);
		fails++;
	}
	if (rc)
		free(err);
	else
		bml_json_free(j);
}

#define OK(s) expect(s, sizeof(s) - 1, NULL)
#define ERR(s, e) expect(s, sizeof(s) - 1, e)

static void num(const char *s, int want_ok, uint64_t want)
{
	struct bml_json *j;
	char *err;
	if (bml_json_parse(s, strlen(s), &j, &err)) {
		printf("FAIL: number %s did not parse: %s\n", s, err);
		free(err);
		fails++;
		return;
	}
	uint64_t v = 0;
	int ok = bml_json_uint64(j, &v) == 0;
	if (ok != want_ok || (ok && v != want)) {
		printf("FAIL: uint64 %s — want %d/%llu got %d/%llu\n", s, want_ok, (unsigned long long)want, ok,
		       (unsigned long long)v);
		fails++;
	}
	bml_json_free(j);
}

int main(void)
{

	ERR("{\"a\":1,\"a\":2}", "duplicate key");
	ERR("{\"a\":\"\xff\"}", "invalid UTF-8");
	ERR("\"\\ud800\"", "unpaired surrogate");
	ERR("\"\\udc00\"", "unpaired surrogate");
	ERR("{} x", "trailing data");
	ERR("{}{}", "trailing data");

	{
		char in[600], *p = in;
		for (int i = 0; i < 129; i++)
			*p++ = '[';
		for (int i = 0; i < 129; i++)
			*p++ = ']';
		expect(in, 258, "nesting too deep");
		expect(in + 1, 256, NULL);
	}

	ERR("", "unexpected end");
	ERR("{\"a\":}", "");
	ERR("[1,]", "");
	ERR("\"a\nb\"", "control character");
	ERR("01", "trailing data");
	ERR("1.", "bad number");
	ERR("tru", "unexpected token");

	ERR("{\"k\":[{\"x\":)]}", "");
	ERR("[[[\"a\",{\"b\":[1,2,}]]]", "");
	ERR("{\"a\":[\"x\",\"\xff\"]}", "invalid UTF-8");

	OK("{\"a\":[1,-2,3.5e+2,true,false,null,\"\\u00e9\\ud83d\\ude00\\n\"]}");
	OK("  \n{}\n");
	OK("{\"A\":1,\"a\":2}");

	num("0", 1, 0);
	num("18446744073709551615", 1, UINT64_MAX);
	num("18446744073709551616", 0, 0);
	num("-1", 0, 0);
	num("-0", 0, 0);
	num("1e3", 0, 0);
	num("1.0", 0, 0);

	{
		struct bml_buf b = {0};
		bml_json_write_string(&b, "a\"\\\n\r\t\x01<>&\xe2\x80\xa8\xff", 14);
		const char *want = "\"a\\\"\\\\\\n\\r\\t\\u0001<>&\\u2028\\ufffd\"";
		if (strcmp(b.p, want) != 0) {
			printf("FAIL: write_string got %s want %s\n", b.p, want);
			fails++;
		}
		bml_buf_free(&b);
	}
	printf("json_test: %s (%d fail)\n", fails ? "FAIL" : "ok", fails);
	return fails != 0;
}
