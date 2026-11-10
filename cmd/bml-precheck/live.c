

#define _GNU_SOURCE
#include "bml-precheck/precheck.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util/gopath.h"

static char *errno_msg(const char *op, const char *path, int err)
{
	struct bml_buf b = {0};
	char *es = bml_go_errno_str(err);
	bml_buf_addf(&b, "%s %s: %s", op, path, es ? es : "");
	free(es);
	return bml_buf_take(&b);
}

char *pc_open_live(const struct flags *f, const struct bml_loader_decl *decl, struct bml_live_caps *lc, struct bml_caps *caps)
{
	lc->decl = decl;

	if (f->n_ext_target) {
		lc->exts = calloc((size_t)f->n_ext_target, sizeof *lc->exts);
		if (!lc->exts)
			return strdup("out of memory");
	}
	for (int i = 0; i < f->n_ext_target; i++) {
		const char *e = f->ext_target[i], *eq = strchr(e, '=');
		if (!eq || eq == e || !eq[1]) {
			struct bml_buf m = {0};
			bml_buf_adds(&m, "--ext-target ");
			bml_buf_add_goquote(&m, e, strlen(e));
			bml_buf_adds(&m, ": want <program>=<path | prog-id:<id>>");
			return bml_buf_take(&m);
		}
		struct bml_live_ext *x = &lc->exts[lc->n_exts++];
		x->program = strndup(e, (size_t)(eq - e));
		if (!x->program)
			return strdup("out of memory");
		x->ok = bml_ext_target_load(eq + 1, &x->kb, &x->err) == 0;
	}
	if (f->n_binary) {
		lc->bins = calloc((size_t)f->n_binary, sizeof *lc->bins);
		if (!lc->bins)
			return strdup("out of memory");
	}
	for (int i = 0; i < f->n_binary; i++) {
		const char *b = f->binary[i], *eq = strchr(b, '=');
		if (!eq || eq == b || !eq[1]) {
			struct bml_buf m = {0};
			bml_buf_adds(&m, "--binary ");
			bml_buf_add_goquote(&m, b, strlen(b));
			bml_buf_adds(&m, ": want <program>=<path>");
			return bml_buf_take(&m);
		}
		struct bml_live_bin *x = &lc->bins[lc->n_bins];
		x->fd = open(eq + 1, O_RDONLY | O_CLOEXEC);
		if (x->fd < 0)
			return errno_msg("open", eq + 1, errno);
		x->program = strndup(b, (size_t)(eq - b));
		x->path = strdup(eq + 1);
		lc->n_bins++;
		if (!x->program || !x->path)
			return strdup("out of memory");
	}

	lc->debug_root = strdup(f->debug_root_set ? f->debug_root : "/usr/lib/debug");
	lc->debugs = f->n_debug ? calloc((size_t)f->n_debug, sizeof *lc->debugs) : NULL;
	if (!lc->debug_root || (f->n_debug && !lc->debugs))
		return strdup("out of memory");
	for (int i = 0; i < f->n_debug; i++) {
		const char *d = f->debug[i], *eq = strchr(d, '=');
		struct bml_buf m = {0};
		if (!eq || eq == d || !eq[1]) {
			bml_buf_adds(&m, "--debug ");
			bml_buf_add_goquote(&m, d, strlen(d));
			bml_buf_adds(&m, ": want <program>=<path>");
			return bml_buf_take(&m);
		}
		char *prog = strndup(d, (size_t)(eq - d)), *abs = bml_go_path_abs(eq + 1);
		for (size_t k = 0; prog && k < lc->n_debugs; k++)
			if (!strcmp(lc->debugs[k].program, prog)) {
				bml_buf_adds(&m, "--debug: duplicate program ");
				bml_buf_add_goquote(&m, prog, strlen(prog));
				free(prog), free(abs);
				return bml_buf_take(&m);
			}
		if (!prog || !abs) {
			free(prog), free(abs);
			return strdup("out of memory");
		}
		lc->debugs[lc->n_debugs++] = (struct bml_live_debug){prog, abs};
	}
	bml_live_caps(lc, caps);
	return NULL;
}

char *pc_write_record(struct bml_recorder *r, const char *path, long long uid, const char *cap, const struct bml_loader_decl *decl)
{
	size_t len;
	char *data = bml_recorder_json(r, uid, cap, decl, &len);
	if (!data)
		return strdup("record: out of memory");
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		int e = errno;
		free(data);
		char *m = errno_msg("open", path, e), *s = NULL;
		if (m && asprintf(&s, "record: %s", m) < 0)
			s = NULL;
		free(m);
		return s ? s : strdup("record: open failed");
	}
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0) {
			int e = w < 0 ? errno : EIO;
			close(fd);
			free(data);
			char *m = errno_msg("write", path, e), *s = NULL;
			if (m && asprintf(&s, "record: %s", m) < 0)
				s = NULL;
			free(m);
			return s ? s : strdup("record: write failed");
		}
		off += (size_t)w;
	}
	free(data);
	if (close(fd) != 0)
		return strdup("record: close failed");
	return NULL;
}
