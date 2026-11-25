/* test/caps/sentinel_unit.c — the no-errno sentinel: lv_feat's no-errno sentinel (LV_NO_ERRNO) and EPERM, with no kernel and no root.
 * This executable defines syscall(), so every bpf(2) call from libbml.a gets the answer of the case's script. The fake is
 * strict (addendum 1): a syscall other than bpf, a command other than the next scripted one, or a call after the script
 * stops the run at once, and a script left over fails the case.
 *   sentinel_unit GO_TEXT_FOR_ERRNO_0 GO_TEXT_FOR_ERRNO_1
 * One line per case: "<case>\tok" or "<case>\tFAIL\t<what>". The exit status is 0 (the lines are the result). */
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "caps/live.h"
#include "caps/live_internal.h"

struct step {
	int cmd, err; /* err 0 answers with an fd */
};
static const char *case_name = "(none)";
static const struct step *script;
static size_t n_script, used;

long syscall(long n, ...)
{
	if (n != __NR_bpf) {
		fprintf(stderr, "sentinel_unit: %s: unexpected syscall %ld at call %zu\n", case_name, n, used);
		exit(2);
	}
	va_list ap;
	va_start(ap, n);
	int cmd = va_arg(ap, int);
	va_end(ap);
	if (used >= n_script) {
		fprintf(stderr, "sentinel_unit: %s: bpf cmd %d after the script (%zu steps)\n", case_name, cmd, n_script);
		exit(2);
	}
	const struct step *s = &script[used++];
	if (cmd != s->cmd) {
		fprintf(stderr, "sentinel_unit: %s: bpf cmd %d at call %zu, scripted %d\n", case_name, cmd, used - 1, s->cmd);
		exit(2);
	}
	if (s->err) {
		errno = s->err;
		return -1;
	}
	return open("/dev/null", O_RDONLY | O_CLOEXEC);
}

static struct bml_live *start(const char *name, const struct step *s, size_t n)
{
	case_name = name;
	script = s;
	n_script = n;
	used = 0;
	struct bml_live *l = calloc(1, sizeof *l);
	if (!l) {
		fprintf(stderr, "sentinel_unit: out of memory\n");
		exit(2);
	}
	return l;
}

/* the case's line: the check's verdict, and a script left over is a failure too */
static void finish(struct bml_live *l, int ok, const char *what)
{
	if (used != n_script)
		printf("%s\tFAIL\tscript left over: %zu of %zu steps used\n", case_name, used, n_script);
	else if (ok)
		printf("%s\tok\n", case_name);
	else
		printf("%s\tFAIL\t%s\n", case_name, what);
	bml_live_free(l);
	free(l);
}

#define LOAD(e) {BPF_BTF_LOAD, e}
static const struct step eperm1[] = {LOAD(EPERM)};
static const struct step ok_eperm[] = {LOAD(0), LOAD(EPERM)};
static const struct step handle[] = {LOAD(EINVAL), LOAD(EINVAL)};                     /* btf_handle: no log, then with a log */
static const struct step mapfield[] = {LOAD(EINVAL), LOAD(EINVAL), LOAD(EINVAL), LOAD(EINVAL), /* lv_kmo: PROG_BTF, DECL_TAGS, */
				       LOAD(EINVAL), LOAD(EINVAL)};                     /* TYPE_TAGS, ENUM64; then btf_handle */
#define N(a) (sizeof a / sizeof a[0])

static const uint8_t blob[24] = {0x9f, 0xeb, 1, 0, 24};

static void site1(const char *name, int preset, int want_err, const char *want_text)
{
	struct bml_live *l = start(name, handle, N(handle));
	l->feat[LVF_BTF] = preset;
	struct lv_res r;
	int fd = lv_btf_handle_reason(l, blob, sizeof blob, &r);
	char what[512];
	snprintf(what, sizeof what, "fd %d err %d text %s", fd, r.err, r.text ? r.text : "(null)");
	finish(l, fd < 0 && r.err == want_err && r.text && !strcmp(r.text, want_text), what);
	lv_res_free(&r);
}

static void site2(const char *name, int preset, const char *go)
{
	struct bml_live *l = start(name, mapfield, N(mapfield));
	l->feat[LVF_BTF] = LV_OK;
	l->feat[LVF_MAP_BTF] = preset;
	int out = -9;
	char *msg = NULL, want[512], what[640];
	int rc = bml_live_map_field(l, "xdp", BPF_PROG_TYPE_XDP, "bpf_spin_lock", &out, &msg);
	snprintf(want, sizeof want,
		 "creating the map without bpf_spin_lock failed (creating map: load BTF: detect support for Map BTF (Var/Datasec): "
		 "%s): cannot be determined on this target",
		 go);
	snprintf(what, sizeof what, "rc %d msg %s", rc, msg ? msg : "(null)");
	finish(l, rc == BML_Q_UNKNOWN && msg && !strcmp(msg, want), what);
	free(msg);
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: sentinel_unit GO_TEXT_FOR_ERRNO_0 GO_TEXT_FOR_ERRNO_1\n");
		return 2;
	}
	const char *go0 = argv[1], *go1 = argv[2];
	char t0[256], t1[256], what[128];
	snprintf(t0, sizeof t0, "detect support for BTF: %s", go0);
	snprintf(t1, sizeof t1, "detect support for BTF: %s", go1);

	/* H1: EPERM is LV_NOTSUP for both features (and LVF_BTF's answer is remembered: a second call asks nothing) */
	struct bml_live *l = start("H1-btf-eperm", eperm1, N(eperm1));
	int a = lv_feat(l, LVF_BTF), b = a == LV_NOTSUP ? lv_feat(l, LVF_BTF) : a; /* unremembered, a second call would probe */
	snprintf(what, sizeof what, "first %d second %d", a, b);
	finish(l, a == LV_NOTSUP && b == LV_NOTSUP && l->feat[LVF_BTF] == LV_NOTSUP, what);
	l = start("H1-mapbtf-eperm", ok_eperm, N(ok_eperm));
	a = lv_feat(l, LVF_MAP_BTF);
	snprintf(what, sizeof what, "map_btf %d btf %d", a, l->feat[LVF_BTF]);
	finish(l, a == LV_NOTSUP && l->feat[LVF_BTF] == LV_OK && l->feat[LVF_MAP_BTF] == LV_NOTSUP, what);
	l = start("H1-mapbtf-via-btf", eperm1, N(eperm1));
	a = lv_feat(l, LVF_MAP_BTF);
	snprintf(what, sizeof what, "map_btf %d btf %d", a, l->feat[LVF_BTF]);
	finish(l, a == LV_NOTSUP && l->feat[LVF_BTF] == LV_NOTSUP, what);

	/* H2: the sentinel at both sites is Go's errno 0 */
	site1("H2-site1-sentinel", LV_NO_ERRNO, 0, t0);
	site2("H2-site2-sentinel", LV_NO_ERRNO, go0);
	/* H3: a preset -EPERM at both sites is EPERM */
	site1("H3-site1-eperm", -EPERM, EPERM, t1);
	site2("H3-site2-eperm", -EPERM, go1);

	/* H4: no other value moves */
	case_name = "H4-range-2-4095";
	int bad = 0;
	for (int e = 2; e <= 4095; e++)
		if (lv_feat_errno(-e) != e && !bad++)
			printf("%s\tFAIL\t-%d gives %d\n", case_name, e, lv_feat_errno(-e));
	if (!bad)
		printf("%s\tok\n", case_name);
	int m1 = lv_feat_errno(-1), s = lv_feat_errno(LV_NO_ERRNO);
	if (m1 == 1)
		printf("H4-minus-1\tok\n");
	else
		printf("H4-minus-1\tFAIL\t-1 gives %d\n", m1);
	if (s == 0)
		printf("H4-sentinel\tok\n");
	else
		printf("H4-sentinel\tFAIL\tgives %d\n", s);
	return 0;
}
