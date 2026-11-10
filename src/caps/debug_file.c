


#include "caps/caps.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dwarf/dwarf.h"
#include "util/gopath.h"

char *bml_caps_uprobe_debug_key(const char *program, const uint8_t *id, size_t n)
{
	size_t pl = strlen(program);
	char *k = malloc(pl + 1 + 2 * n + 1);
	if (!k)
		return NULL;
	memcpy(k, program, pl);
	k[pl] = '/';
	for (size_t i = 0; i < n; i++)
		snprintf(k + pl + 1 + 2 * i, 3, "%02x", id[i]);
	k[pl + 1 + 2 * n] = 0;
	return k;
}

static int unknown(char **msg, const char *s)
{
	*msg = strdup(s);
	return *msg ? BML_Q_UNKNOWN : BML_Q_ERROR;
}

int bml_caps_debug_build_id_path(const char *root, const uint8_t *id, size_t n, char **path, char **msg)
{
	*path = NULL;
	if (n < 1 || n > 64)
		return (*msg = strdup("GNU build ID must contain 1..64 bytes"), BML_Q_ERROR);
	if (!root[0])
		return unknown(msg, "separate DWARF lookup is disabled");
	char h[129], rest[136];
	for (size_t i = 0; i < n; i++)
		snprintf(h + 2 * i, 3, "%02x", id[i]);
	snprintf(rest, sizeof rest, "%s.debug", h + 2);
	h[2] = 0;
	const char *e[4] = {root, ".build-id", h, rest};
	*path = bml_go_path_join(e, 4);
	return *path ? BML_Q_OK : (*msg = strdup("out of memory"), BML_Q_ERROR);
}

int bml_caps_debug_read_file(const char *path, uint8_t **data, size_t *len, char **abs, char **msg)
{
	*data = NULL, *len = 0, *abs = bml_go_path_abs(path);
	if (!*abs)
		return unknown(msg, "separate DWARF file is unavailable");
	int fd = open(*abs, O_RDONLY | O_CLOEXEC);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) != 0) {
		if (fd >= 0)
			close(fd);
		return unknown(msg, "separate DWARF file is unavailable");
	}
	if (st.st_size > BML_DEBUG_RAW_LIMIT) {
		close(fd);
		return unknown(msg, "separate DWARF file exceeds 268435456 bytes");
	}
	size_t cap = st.st_size > 0 ? (size_t)st.st_size + 1 : 4096, n = 0;
	uint8_t *b = malloc(cap);
	for (;;) {
		if (!b) {
			close(fd);
			return (*msg = strdup("out of memory"), BML_Q_ERROR);
		}
		if (n == cap) {
			size_t nc = cap * 2 > (size_t)BML_DEBUG_RAW_LIMIT + 1 ? (size_t)BML_DEBUG_RAW_LIMIT + 1 : cap * 2;
			if (nc == cap)
				break;
			uint8_t *nb = realloc(b, nc);
			if (!nb)
				free(b);
			b = nb, cap = nc;
			continue;
		}
		ssize_t r = read(fd, b + n, cap - n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			free(b);
			close(fd);
			return unknown(msg, "separate DWARF file is unavailable");
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	close(fd);
	if (n > BML_DEBUG_RAW_LIMIT) {
		free(b);
		return unknown(msg, "separate DWARF file exceeds 268435456 bytes");
	}
	if ((int64_t)n != (int64_t)st.st_size) {
		free(b);
		return unknown(msg, "separate DWARF file changed while reading");
	}
	*data = b, *len = n;
	return BML_Q_OK;
}
