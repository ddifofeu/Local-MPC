# PMR-001 Audit verifier does not detect records removed from the end of the log
kind: bug
status: fixed
reported: 2026-11-06, claude
blocker: -
test: tests/test_audit.py::test_verifier_detects_records_removed_from_the_end; tests/test_audit.py::test_restart_on_a_shortened_log_leaves_a_permanent_record; tests/test_audit.py::test_verifier_requires_the_anchor
fixed-in: pending

## History
- 2026-11-06 open: found by Claude in a README accuracy review
- 2026-11-06 fixed: the .anchor file records size and last hash after each append; the verifier and server startup both compare it; rewriting log and anchor together stays undetected, as documented. Tests fail without the fix; no real deployment has run it yet
