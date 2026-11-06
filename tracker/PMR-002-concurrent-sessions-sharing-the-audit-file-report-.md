# PMR-002 Concurrent sessions sharing the audit file report a false broken chain
kind: bug
status: fixed
reported: 2026-11-06, claude
blocker: -
test: tests/test_audit.py::test_two_open_writers_keep_one_chain; tests/test_audit.py::test_concurrent_processes_keep_one_chain
fixed-in: pending

## History
- 2026-11-06 open: found by Claude in a README accuracy review
- 2026-11-06 fixed: each append takes an exclusive lock and chains from the file, not from memory. Tests fail without the fix; no real deployment has run it yet
