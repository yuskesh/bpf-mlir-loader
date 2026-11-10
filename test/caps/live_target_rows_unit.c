
#include "caps/live.h"

#include <errno.h>
#include <stdio.h>

static int fails;

static void expect(const char *name, int got, int want)
{
	printf("%s: %s\n", name, got == want ? "PASS" : "FAIL");
	fails += got != want;
}

int main(void)
{
	const char *sl[] = {"0: R1=ctx", "Program of this type cannot be sleepable"};
	const char *ht[] = {"7: (85) call bpf_d_path#147", "helper call is not allowed in probe"};
	const char *other[] = {"R1 type=scalar expected=ctx"};

	expect("netkit-link-created", bml_live_netkit_answer(3), BML_LV_UNEXPECTED);
	expect("netkit-enodev", bml_live_netkit_answer(-ENODEV), BML_LV_TRUE);
	expect("netkit-einval", bml_live_netkit_answer(-EINVAL), BML_LV_FALSE);
	expect("netkit-eperm", bml_live_netkit_answer(-EPERM), BML_LV_UNKNOWN);
	expect("netkit-eopnotsupp", bml_live_netkit_answer(-EOPNOTSUPP), BML_LV_UNKNOWN);

	expect("sleepable-type-refused", bml_live_sleepable_refused_by_type(1, sl, 2), 1);
	expect("sleepable-other-log", bml_live_sleepable_refused_by_type(1, other, 1), 0);
	expect("sleepable-not-verifier", bml_live_sleepable_refused_by_type(0, sl, 2), 0);

	expect("ht-denied", bml_live_helper_target_denied(EINVAL, 1, ht, 2), 1);
	expect("ht-einval-other-log", bml_live_helper_target_denied(EINVAL, 1, other, 1), 0);
	expect("ht-einval-not-verifier", bml_live_helper_target_denied(EINVAL, 0, ht, 2), 0);
	expect("ht-eperm-same-log", bml_live_helper_target_denied(EPERM, 1, ht, 2), 0);
	return fails != 0;
}
