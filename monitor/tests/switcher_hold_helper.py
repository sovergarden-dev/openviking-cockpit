"""Switcher hold semantics — run under the OpenViking venv Python.

Exercises the patched OrderedCredentialSwitcher / PrimaryBackupSwitcher with a
fake monotonic clock. Prints CHECK_OK lines; exits non-zero on first failure.
"""
import sys
import time

from openviking.utils.model_retry import OrderedCredentialSwitcher, PrimaryBackupSwitcher

FAKE = [1000.0]
_real_monotonic = time.monotonic
time.monotonic = lambda: FAKE[0]


def check(label, cond):
    print(("CHECK_OK " if cond else "CHECK_FAIL ") + label)
    if not cond:
        sys.exit(1)


try:
    s = OrderedCredentialSwitcher(n=4)
    check("initial idx 0, no hold", s.get_active_index() == 0 and s.manual_hold is False)

    s.set_active_index(2, hold=True)
    check("manual set idx 2 hold", s.get_active_index() == 2 and s.manual_hold is True)

    FAKE[0] += 999999.0
    check("hold blocks failback", s.maybe_failback() == 2)

    s.commit_success(3)
    check("fast failover works under hold", s.get_active_index() == 3 and s.maybe_failback() == 3)

    s.release_hold()
    check("release clears hold", s.manual_hold is False and s.get_active_index() == 3)

    FAKE[0] += 999999.0
    check("failback step 3->2", s.maybe_failback() == 2)
    FAKE[0] += 999999.0
    check("failback step 2->1", s.maybe_failback() == 1)
    FAKE[0] += 999999.0
    check("failback step 1->0", s.maybe_failback() == 0)
    FAKE[0] += 999999.0
    check("stays at 0", s.maybe_failback() == 0)

    s.set_active_index(0, hold=False)
    check("set idx0 no hold", s.get_active_index() == 0 and s.manual_hold is False)

    try:
        s.set_active_index(4)
        check("bounds raise", False)
    except IndexError:
        check("bounds raise", True)

    p = PrimaryBackupSwitcher()
    check("pb initial primary", p.is_using_backup is False and p.manual_hold is False)

    p.set_manual_backup()
    check("pb pin backup + hold", p.is_using_backup is True and p.manual_hold is True)

    FAKE[0] += 999999.0
    check("pb hold blocks failback", p.should_try_primary() is False)

    p.set_manual_primary()
    check("pb back to primary", p.is_using_backup is False and p.manual_hold is False)
    check("pb tries primary now", p.should_try_primary() is True)

    print("SWITCHER_HOLD_ALL_OK")
finally:
    time.monotonic = _real_monotonic
