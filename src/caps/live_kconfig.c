
#define _GNU_SOURCE
#include "caps/value_sources.h"
#include "caps/live_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

static char *quoted_line(size_t n, const char *p, size_t len, const char *reason)
{
	struct bml_buf b = {0};
	bml_buf_addf(&b, "line %zu ", n); bml_buf_add_goquote(&b, p, len); bml_buf_addf(&b, ": %s", reason);
	return bml_buf_take(&b);
}

static int parse_config(struct bml_kernel_sources *s, const char *data, size_t size, char **err)
{
	size_t n = 0;
	for (size_t pos = 0; pos < size;) {
		const char *p = data + pos, *nl = memchr(p, '\n', size - pos);
		size_t len = nl ? (size_t)(nl - p) : size - pos;
		pos += len + !!nl; n++;
		if (len >= 1u << 20) return (*err = strdup("bufio.Scanner: token too long"), -1);
		if (len && p[len - 1] == '\r') len--;
		if (len < 7 || memcmp(p, "CONFIG_", 7)) continue;
		const char *eq = memchr(p, '=', len);
		if (!eq) return (*err = quoted_line(n, p, len, "no '=' separator"), -1);
		size_t keylen = (size_t)(eq - p), vn = len - keylen - 1;
		if (!vn) return (*err = quoted_line(n, p, len, "no value"), -1);
		if (memchr(p, 0, len)) return (*err = strdup("kernel config contains a NUL byte (not supported)"), -1);
		int found = 0;
		for (size_t i = 0; i < s->config_count; i++)
			if (strlen(s->config[i].key) == keylen && !memcmp(s->config[i].key, p, keylen)) found = 1;
		if (found) continue;
		struct bml_kv *a = realloc(s->config, (s->config_count + 1) * sizeof(*a));
		if (!a) return (*err = strdup("out of memory"), -1);
		s->config = a;
		struct bml_kv *v = &s->config[s->config_count++];
		v->key = strndup(p, keylen); v->value = strndup(eq + 1, vn);
		if (!v->key || !v->value) return (*err = strdup("out of memory"), -1);
	}
	return 0;
}

static void load_config(struct bml_kernel_sources *s)
{
	s->config_done = 1;
	uint8_t *release = NULL; size_t rn; char *err = NULL;
	char *boot = NULL;
	if (!lv_value_read("/proc/sys/kernel/osrelease", &release, &rn, &err)) {
		while (rn && (release[rn - 1] == '\n' || release[rn - 1] == '\r' || release[rn - 1] == ' ' || release[rn - 1] == '\t')) rn--;
		size_t start = 0; while (start < rn && (release[start] == ' ' || release[start] == '\t' || release[start] == '\n' || release[start] == '\r')) start++;
		if (asprintf(&boot, "/boot/config-%.*s", (int)(rn - start), release + start) < 0) {
			free(release); free(err); s->config_failed = 1; s->config_error = strdup("out of memory"); return;
		}
	}
	free(release); free(err);
	const char *paths[] = {boot, "/proc/config.gz"};
	struct bml_buf tried = {0};
	for (size_t i = boot ? 0 : 1; i < 2; i++) {
		int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			char *why = bml_go_errno_str(errno);
			if (tried.len) bml_buf_adds(&tried, "; ");
			bml_buf_addf(&tried, "open %s: %s", paths[i], why ? why : "out of memory"); free(why); continue;
		}
		struct bml_buf raw = {0};
		char *why = NULL;
		if (i == 1) {
			gzFile gz = gzdopen(fd, "rb");
			if (!gz) { close(fd); why = strdup("invalid gzip reader"); }
			else {
				char buf[8192]; int got;
				got = 0;
				if (gzdirect(gz)) why = strdup("gzip: invalid header");
				while (!why && (got = gzread(gz, buf, sizeof(buf))) > 0) bml_buf_add(&raw, buf, (size_t)got);
				if (got < 0) { int code; const char *text = gzerror(gz, &code); why = strdup(text ? text : "gzip read failed"); }
				if (gzclose(gz) != Z_OK && !why) why = strdup("gzip close failed");
			}
		} else {
			char buf[8192]; ssize_t got;
			while ((got = read(fd, buf, sizeof(buf))) != 0) {
				if (got < 0) { if (errno == EINTR) continue; why = bml_go_errno_str(errno); break; }
				bml_buf_add(&raw, buf, (size_t)got);
			}
			if (close(fd) && !why) why = bml_go_errno_str(errno);
		}
		if (raw.oom && !why) why = strdup("out of memory");
		if (!why && !raw.oom) parse_config(s, raw.p, raw.len, &why);
		if (why || raw.oom) {
			s->config_failed = 1;
			if (asprintf(&s->config_error, "kernel config %s: %s: cannot be determined on this target", paths[i], why ? why : "out of memory") < 0) s->config_error = NULL;
		}
		free(why); bml_buf_free(&raw); bml_buf_free(&tried); free(boot); return;
	}
	s->config_failed = 1;
	if (asprintf(&s->config_error, "no kernel config file (%s): cannot be determined on this target", tried.p ? tried.p : "out of memory") < 0) s->config_error = NULL;
	bml_buf_free(&tried); free(boot);
}

int bml_live_kconfig(struct bml_live *l, const char *name, char **out, char **msg)
{
	*out = NULL;
	struct bml_kernel_sources *s = lv_value_sources(l);
	if (!s) return (*msg = strdup("out of memory"), BML_Q_ERROR);
	if (!s->config_done) load_config(s);
	if (s->config_failed) return (*msg = strdup(s->config_error ? s->config_error : "out of memory"), BML_Q_UNKNOWN);
	for (size_t i = 0; i < s->config_count; i++)
		if (!strcmp(s->config[i].key, name)) {
			*out = strdup(s->config[i].value); return *out ? BML_Q_OK : (*msg = strdup("out of memory"), BML_Q_ERROR);
		}
	struct bml_buf b = {0}; bml_buf_addf(&b, "the kernel config has no %s= line: kconfig option not set", name);
	*msg = bml_buf_take(&b); return *msg ? BML_Q_ABSENT : BML_Q_ERROR;
}
