#include "run_own.h"

#include <stdlib.h>

static struct {
	int next_rc, open_rc, info_rc, close_rc, n, pos, present_polls;
	uint32_t ids[4];
	struct bpf_link_info infos[4];
	int64_t t;
} s;

static int f_next(uint32_t id, uint32_t *next)
{
	if (s.next_rc)
		return s.next_rc;
	for (int i = 0; i < s.n; i++)
		if (s.ids[i] > id) {
			*next = s.ids[i];
			return 0;
		}
	return -ENOENT;
}
static int f_open(uint32_t id)
{
	if (s.open_rc)
		return s.open_rc;
	for (int i = 0; i < s.n; i++)
		if (s.ids[i] == id) {
			s.pos = i;
			return 100 + i;
		}
	return -ENOENT;
}
static int f_info(int fd, struct bpf_link_info *o) { *o = s.infos[fd - 100]; return s.info_rc; }
static int f_close(int fd) { (void)fd; return s.close_rc; }
static int64_t f_now(void) { return s.t; }
static void f_sleep(int ms) { s.t += ms; if (s.present_polls > 0 && --s.present_polls == 0) s.n = 0; }
static const struct own_sys fk = {f_next, f_open, f_info, f_open, f_close, f_now, f_sleep};

static int fails;
static void verdict(const char *id, int ok, const char *extra)
{
	printf("%s: %s\n", id, ok ? "PASS" : "FAIL");
	if (!ok)
		fails++, printf("  %s\n", extra);
}

static void one(uint32_t id, uint32_t prog, uint32_t ifindex)
{
	int i = s.n++;
	s.ids[i] = id;
	s.infos[i].type = BPF_LINK_TYPE_NETKIT;
	s.infos[i].id = id;
	s.infos[i].prog_id = prog;
	s.infos[i].netkit.ifindex = ifindex;
}

static int collect(uint32_t *ids, int *n, char *err, size_t en)
{
	struct bpf_link_info inf[4];
	return own_collect_links(&fk, 7, 5, 6, ids, inf, 4, n, err, en);
}


static struct { int mode, reads; } w;
static ssize_t r_read(void *c, uint8_t *b, size_t n, int *o)
{
	(void)c, (void)n, (void)o;
	w.reads++;
	s.t += 1;
	b[0] = 0;
	if (w.mode == 1 && w.reads == 3)
		return -EIO;
	if (w.mode == 2)
		return -EAGAIN;
	return 1;
}
static int r_match(const uint8_t *b, ssize_t n, void *a) { (void)b, (void)n, (void)a; return 0; }
static const struct window_ops wo = {r_read, f_now, NULL};


static struct { char log[32]; int len, fail_at, out_after; } a;
static int a_rec(char c, int rc)
{
	a.log[a.len++] = c;
	return a.fail_at == a.len ? 1 : rc;
}
static int a_own(void *c) { (void)c; return a_rec('O', 0); }
static int a_phase(void *c, enum arm_phase p) { (void)c; return a_rec("narf"[p], 0); }
static int a_attach(void *c) { (void)c; return a_rec('A', 0); }
static int a_info(void *c) { (void)c; return a_rec('I', 0); }
static int a_detach(void *c) { (void)c; return a_rec('D', 0); }
static int a_closeo(void *c) { (void)c; return a_rec('C', 0); }
static int a_out(void *c) { (void)c; return a.out_after && a.len >= a.out_after; }
static const struct arm_steps as = {NULL, a_own, a_phase, a_attach, a_info, a_detach, a_closeo, a_out};
static void wiring(const char *id, int fail_at, int out_after, int want_fault, const char *want)
{
	memset(&a, 0, sizeof a);
	a.fail_at = fail_at, a.out_after = out_after;
	int f = arm_sequence(&as);
	char got[64];
	snprintf(got, sizeof got, "got %s fault %d", a.log, f);
	verdict(id, !!f == want_fault && !strcmp(a.log, want), got);
}

int main(void)
{
	wiring("wire-normal", 0, 0, 0, "OnAIarDfC");
	wiring("wire-own-id-failure", 1, 0, 1, "OC");
	wiring("wire-first-phase-eio", 2, 0, 1, "OnC");
	wiring("wire-attach-failure", 3, 0, 1, "OnAC");
	wiring("wire-info-error", 4, 0, 1, "OnAIDC");
	wiring("wire-attached-phase-eio", 5, 0, 1, "OnAIaDC");
	wiring("wire-detach-unobserved", 7, 0, 1, "OnAIarDC");
	wiring("wire-save-error-before-attach", 0, 2, 1, "OnC");
	wiring("wire-save-error-after-attach", 0, 3, 1, "OnADC");
	wiring("wire-close-error", 9, 0, 1, "OnAIarDfC");

	verdict("send-pass-full", send_outcome_ok(64, 0, 64, 0), "");
	verdict("send-pass-enobufs-fails", !send_outcome_ok(-1, ENOBUFS, 64, 0), "");
	verdict("send-pass-short-fails", !send_outcome_ok(10, 0, 64, 0), "");
	verdict("send-drop-enobufs", send_outcome_ok(-1, ENOBUFS, 64, 1), "");
	verdict("send-drop-success-fails", !send_outcome_ok(64, 0, 64, 1), "");
	verdict("send-drop-eio-fails", !send_outcome_ok(-1, EIO, 64, 1), "");

	char err[128] = "";
	uint32_t ids[4];
	int n = 0;

	memset(&s, 0, sizeof s), one(3, 7, 5);
	verdict("collect-own", collect(ids, &n, err, sizeof err) == 0 && n == 1 && ids[0] == 3, err);
	memset(&s, 0, sizeof s), one(3, 9, 5);
	verdict("collect-foreign-program-excluded", collect(ids, &n, err, sizeof err) == 0 && n == 0, err);
	memset(&s, 0, sizeof s), one(3, 7, 8);
	verdict("collect-foreign-pair-unobserved", collect(ids, &n, err, sizeof err) == -1 && strstr(err, "foreign ifindex"), err);
	memset(&s, 0, sizeof s), s.next_rc = -EPERM;
	verdict("collect-next-eperm-unobserved", collect(ids, &n, err, sizeof err) == -1 && strstr(err, "errno 1"), err);
	memset(&s, 0, sizeof s), one(3, 7, 5), s.open_rc = -EPERM;
	verdict("collect-open-eperm-unobserved", collect(ids, &n, err, sizeof err) == -1, err);
	memset(&s, 0, sizeof s), one(3, 7, 5), s.info_rc = -EBADF;
	verdict("collect-info-error-unobserved", collect(ids, &n, err, sizeof err) == -1 && strstr(err, "link_info"), err);
	memset(&s, 0, sizeof s), one(3, 7, 5), s.close_rc = -EIO;
	verdict("collect-close-error-unobserved", collect(ids, &n, err, sizeof err) == -1 && strstr(err, "close"), err);

	memset(&s, 0, sizeof s), one(3, 7, 5), s.present_polls = 3;
	verdict("poll-gone-enoent", own_poll(&fk, f_open, 3, 15000, err, sizeof err) == OWN_GONE, err);
	memset(&s, 0, sizeof s), one(3, 7, 5);
	verdict("poll-present-deadline", own_poll(&fk, f_open, 3, 200, err, sizeof err) == OWN_PRESENT && s.t >= 200, err);
	memset(&s, 0, sizeof s), one(3, 7, 5), s.open_rc = -EPERM;
	verdict("poll-eperm-unobserved", own_poll(&fk, f_open, 3, 200, err, sizeof err) == OWN_UNOBSERVED, err);
	memset(&s, 0, sizeof s), one(3, 7, 5), s.close_rc = -EIO;
	verdict("poll-close-error-unobserved", own_poll(&fk, f_open, 3, 200, err, sizeof err) == OWN_UNOBSERVED, err);
	memset(&s, 0, sizeof s), one(3, 7, 5);
	verdict("poll-foreign-id-gone", own_poll(&fk, f_open, 4, 200, err, sizeof err) == OWN_GONE, err);

	int e = 0;
	memset(&s, 0, sizeof s), w.mode = 0, w.reads = 0;
	int got = window_count(&wo, 1000, r_match, NULL, &e);
	verdict("window-noise-runs-to-deadline", got == 0 && s.t >= 1000 && w.reads >= 1000, "");
	memset(&s, 0, sizeof s), w.mode = 1, w.reads = 0;
	got = window_count(&wo, 1000, r_match, NULL, &e);
	verdict("window-eio-fails", got == -1 && e == EIO, "");
	memset(&s, 0, sizeof s), w.mode = 2, w.reads = 0;
	got = window_count(&wo, 1000, r_match, NULL, &e);
	verdict("window-timeout-is-absence", got == 0 && s.t >= 1000, "");

	verdict("stop-expected", stop_is_expected(3, 1, "attach", "filter", "primary", "primary"), "");
	verdict("stop-other-direction", !stop_is_expected(3, 1, "attach", "filter", "peer", "primary"), "");
	verdict("stop-unreadable-input", !stop_is_expected(-1, 0, NULL, NULL, NULL, "primary"), "");
	verdict("stop-other-kind", !stop_is_expected(5, 1, "attach", "filter", "primary", "primary"), "");
	verdict("stop-other-unmet", !stop_is_expected(3, 1, "helper", "filter", "primary", "primary"), "");
	verdict("stop-two-unmets", !stop_is_expected(3, 2, "attach", "filter", "primary", "primary"), "");
	return fails != 0;
}
