#include "util/gopath.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

char *bml_go_path_clean(const char *path)
{
	size_t n = strlen(path);
	if (n == 0)
		return strdup(".");
	char *out = malloc(n + 2);
	if (!out)
		return NULL;
	int rooted = path[0] == '/';
	size_t w = 0, r = 0, dotdot = 0;
	if (rooted) {
		out[w++] = '/';
		r = 1;
		dotdot = 1;
	}
	while (r < n) {
		if (path[r] == '/') {
			r++;
		} else if (path[r] == '.' && (r + 1 == n || path[r + 1] == '/')) {
			r++;
		} else if (path[r] == '.' && path[r + 1] == '.' && (r + 2 == n || path[r + 2] == '/')) {
			r += 2;
			if (w > dotdot) {
				w--;
				while (w > dotdot && out[w] != '/')
					w--;
			} else if (!rooted) {
				if (w > 0)
					out[w++] = '/';
				out[w++] = '.';
				out[w++] = '.';
				dotdot = w;
			}
		} else {
			if ((rooted && w != 1) || (!rooted && w != 0))
				out[w++] = '/';
			for (; r < n && path[r] != '/'; r++)
				out[w++] = path[r];
		}
	}
	if (w == 0)
		out[w++] = '.';
	out[w] = 0;
	return out;
}

char *bml_go_path_join(const char *const *elem, size_t n)
{
	size_t len = 0;
	for (size_t i = 0; i < n; i++)
		len += strlen(elem[i]) + 1;
	char *s = malloc(len + 1), *p = s;
	if (!s)
		return NULL;
	*p = 0;
	for (size_t i = 0; i < n; i++) {
		if (!elem[i][0])
			continue;
		if (p != s)
			*p++ = '/';
		size_t k = strlen(elem[i]);
		memcpy(p, elem[i], k);
		p += k;
		*p = 0;
	}
	if (p == s) {
		free(s);
		return strdup("");
	}
	char *c = bml_go_path_clean(s);
	free(s);
	return c;
}


static char *go_getwd(void)
{
	const char *pwd = getenv("PWD");
	struct stat a, b;
	if (pwd && pwd[0] == '/' && stat(pwd, &a) == 0 && stat(".", &b) == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino)
		return strdup(pwd);
	return getcwd(NULL, 0);
}

char *bml_go_path_abs(const char *path)
{
	if (path[0] == '/')
		return bml_go_path_clean(path);
	char *cwd = go_getwd();
	if (!cwd)
		return NULL;
	const char *e[2] = {cwd, path};
	char *r = bml_go_path_join(e, 2);
	free(cwd);
	return r;
}
