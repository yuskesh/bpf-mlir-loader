#define _GNU_SOURCE
#include "abi/tp_cpus.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util/gostr.h"

#define MAX_CPU 65535

static char *quoted(const char *pre, const char *s, size_t n, const char *post)
{
	struct bml_buf b = {0};
	bml_buf_adds(&b, pre);
	bml_buf_add_goquote(&b, s, n);
	bml_buf_adds(&b, post);
	return bml_buf_take(&b);
}

static int is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

int bml_tp_parse_cpus(const char *s0, int **out, size_t *n, char **err)
{
	*out = NULL, *n = 0, *err = NULL;
	size_t len = strlen(s0);
	const char *s = s0;
	while (len && is_space(*s))
		s++, len--;
	while (len && is_space(s[len - 1]))
		len--;
	if (len == 0) {
		*err = strdup("empty cpu list");
		return -1;
	}
	size_t cap = 0;
	int64_t last = -1;
	const char *p = s, *end = s + len;
	for (;;) {
		const char *comma = memchr(p, ',', (size_t)(end - p));
		const char *pe = comma ? comma : end;
		const char *dash = memchr(p, '-', (size_t)(pe - p));
		int64_t a, b;
		if (bml_go_atoi(p, (size_t)((dash ? dash : pe) - p), &a) || a < 0)
			goto bad;
		b = a;
		if (dash && (bml_go_atoi(dash + 1, (size_t)(pe - dash - 1), &b) || b < a))
			goto bad;
		if (a <= last) {
			*err = quoted("cpu list ", s, len, " is not ascending");
			goto fail;
		}
		if (b > MAX_CPU)
			goto bad;
		for (int64_t c = a; c <= b; c++) {
			if (*n == cap) {
				cap = cap ? cap * 2 : 16;
				int *np = realloc(*out, cap * sizeof *np);
				if (!np)
					goto fail;
				*out = np;
			}
			(*out)[(*n)++] = (int)c;
		}
		last = b;
		if (!comma)
			return 0;
		p = comma + 1;
	}
bad:
	*err = quoted("bad cpu list ", s, len, "");
fail:
	free(*out);
	*out = NULL, *n = 0;
	return -1;
}

int bml_tp_select_cpus(const int *possible, size_t np, const int *online, size_t no, int online_only, int **out, size_t *n, char **err)
{
	*out = NULL, *n = 0, *err = NULL;
	struct bml_buf off = {0};
	int any = 0;
	for (size_t i = 0; i < np; i++) {
		int on = 0;
		for (size_t j = 0; j < no && !on; j++)
			on = online[j] == possible[i];
		if (!on) {
			bml_buf_addf(&off, any ? ",%d" : "%d", possible[i]);
			any = 1;
		}
	}
	char *offs = bml_buf_take(&off);
	if (any && !online_only) {
		if (offs && asprintf(err, "possible CPUs %s are offline: an event opened now would miss them if they come online (set BML_TRACEPOINT_ONLINE_ONLY to open on the online CPUs only)", offs) < 0)
			*err = NULL;
		free(offs);
		return -1;
	}
	free(offs);
	if (no == 0) {
		*err = strdup("no online CPU");
		return -1;
	}
	*out = malloc(no * sizeof **out);
	if (!*out)
		return -1;
	memcpy(*out, online, no * sizeof **out);
	*n = no;
	return 0;
}

static int read_cpus(const char *path, int **out, size_t *n, char **err)
{
	char buf[4096];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t k = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
	int e = errno;
	if (fd >= 0)
		close(fd);
	if (k < 0) {
		if (asprintf(err, "open %s: %s", path, strerror(e)) < 0)
			*err = NULL;
		return -1;
	}
	buf[k] = 0;
	char *perr = NULL;
	if (bml_tp_parse_cpus(buf, out, n, &perr) != 0) {
		if (!perr || asprintf(err, "%s: %s", path, perr) < 0)
			*err = NULL;
		free(perr);
		return -1;
	}
	return 0;
}

int bml_tp_cpus(int online_only, int **out, size_t *n, char **err)
{
	int *pos = NULL, *on = NULL;
	size_t np = 0, no = 0;
	*out = NULL, *n = 0, *err = NULL;
	int rc = -1;
	if (read_cpus("/sys/devices/system/cpu/possible", &pos, &np, err) == 0 && read_cpus("/sys/devices/system/cpu/online", &on, &no, err) == 0)
		rc = bml_tp_select_cpus(pos, np, on, no, online_only, out, n, err);
	free(pos);
	free(on);
	return rc;
}
