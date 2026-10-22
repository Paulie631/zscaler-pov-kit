# Recorded API fixtures

Each `.jsonl` file here comes from a lab tenant run with recording on (`pov-kit record on`, then discover, plan,
apply, status, teardown, then `pov-kit record export NAME`). The export keeps field names, types and Zscaler's own
values and replaces every other string, so no customer data is in this folder.

`tests/test_replay.py` checks the kit against every file here: the fake tenant may only answer with fields the real
API sends, and discovery and planning must run on the recorded responses.
