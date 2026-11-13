#include "caps/live.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "util/gostr.h"

int bml_live_arch(char **out, char **msg)
{
	struct utsname u;
	*out = NULL;
	if (uname(&u) != 0) {
		*msg = strdup("uname failed");
		return BML_Q_UNKNOWN;
	}
	*out = strdup(u.machine);
	if (!*out) {
		*msg = strdup("out of memory");
		return BML_Q_ERROR;
	}
	return BML_Q_OK;
}


static int is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

int bml_live_kernel_symbol(const char *name, int *out, char **msg)
{
	*out = 0;
	int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		*msg = strdup("kallsyms: open failed");
		return BML_Q_UNKNOWN;
	}
	struct bml_buf b = {0};
	char chunk[65536];
	for (;;) {
		ssize_t r = read(fd, chunk, sizeof chunk);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			close(fd);
			bml_buf_free(&b);
			*msg = strdup("kallsyms: read failed");
			return BML_Q_UNKNOWN;
		}
		if (r == 0)
			break;
		bml_buf_add(&b, chunk, (size_t)r);
	}
	close(fd);
	if (b.oom) {
		bml_buf_free(&b);
		*msg = strdup("out of memory");
		return BML_Q_ERROR;
	}
	size_t nl = strlen(name);
	for (size_t i = 0; i < b.len;) {
		size_t e = i;
		while (e < b.len && b.p[e] != '\n')
			e++;

		size_t k = i, field = 0;
		while (k < e) {
			while (k < e && is_space(b.p[k]))
				k++;
			if (k >= e)
				break;
			size_t s = k;
			while (k < e && !is_space(b.p[k]))
				k++;
			if (field++ == 2) {
				if (k - s == nl && memcmp(b.p + s, name, nl) == 0) {
					*out = 1;
					bml_buf_free(&b);
					return BML_Q_OK;
				}
				break;
			}
		}
		i = e + 1;
	}
	bml_buf_free(&b);
	return BML_Q_OK;
}
