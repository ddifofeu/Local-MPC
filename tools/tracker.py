#!/usr/bin/env python3
"""A bug and change tracker in the repository: one Markdown file per entry in tracker/.

    tracker.py list [STATUS...]   entries by status (default: all but verified/wontfix)
    tracker.py new bug|change "Title" [reported-by]
    tracker.py check              fails on a bad entry (run it before every commit)

It works on the git repository of the current directory. IDs are PREFIX-NNN; the prefix comes
from TRACKER_PREFIX, else from the existing entries, else "T".

An entry starts with a header block:

    # T-012 Title
    kind: bug | change
    status: open | in-progress | blocked | fixed | verified | wontfix
    reported: 2026-11-03, owner
    blocker: what is blocking it, and who must act (required when blocked)
    test: path/to/test_file::text the test contains (required when fixed or verified; several: ; )
    fixed-in: commit (required when fixed or verified)

then "## History", one dated line per change of status. A fixed entry that breaks again is
reopened (status back to open, a "reopened" history line), never filed anew.
"""
import datetime
import re
import sys
from pathlib import Path

import os
import subprocess

ROOT = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip() or ".")
DIR = ROOT / "tracker"
STATUSES = ["open", "in-progress", "blocked", "fixed", "verified", "wontfix"]
CLOSED = {"verified", "wontfix"}
HEADER = re.compile(r"^# ([A-Z][A-Z0-9]*-\d{3,}) (.+)$")
FIELD = re.compile(r"^([a-z-]+): ?(.*)$")


def load(path: Path) -> dict:
    lines = path.read_text().splitlines()
    head = HEADER.match(lines[0]) if lines else None
    entry = {"path": path, "id": head.group(1) if head else None, "title": head.group(2) if head else ""}
    for line in lines[1:]:
        if not line.strip() or line.startswith("#"):
            break
        m = FIELD.match(line)
        if m:
            entry[m.group(1)] = m.group(2).strip()
    entry["reopened"] = sum("reopened" in line.lower() for line in lines if line.startswith("- "))
    return entry


def entries() -> list[dict]:
    return [load(p) for p in sorted(DIR.glob("*-[0-9][0-9][0-9]*.md"))]


def problems(e: dict) -> list[str]:
    out = []
    if not e["id"] or not e["path"].name.startswith(e["id"]):
        out.append("first line must be '# PREFIX-NNN Title', matching the file name")
    if e.get("kind") not in ("bug", "change"):
        out.append("kind: bug or change")
    status = e.get("status")
    if status not in STATUSES:
        out.append(f"status: one of {', '.join(STATUSES)}")
    if not e.get("reported"):
        out.append("reported: date and who")
    if status == "blocked" and e.get("blocker", "-") in ("", "-"):
        out.append("blocked: say what blocks it and who must act (blocker:)")
    if status in ("fixed", "verified"):
        if not e.get("fixed-in") or e["fixed-in"] == "-":
            out.append("fixed/verified: name the commit (fixed-in:)")
        tests = [t.strip() for t in e.get("test", "").split(";") if t.strip() and t.strip() != "-"]
        if not tests:
            out.append("fixed/verified: name the regression test (test:)")
        for t in tests:
            file, _, text = t.partition("::")
            path = ROOT / file.strip()
            if not path.is_file():
                out.append(f"test file missing: {file.strip()}")
            elif text and text.strip() not in path.read_text():
                out.append(f"test not found in {file.strip()}: {text.strip()}")
    return out


def check() -> int:
    bad = 0
    ids = {}
    for e in entries():
        if e["id"] in ids:
            print(f"{e['path'].name}: duplicate id {e['id']}")
            bad += 1
        ids[e["id"]] = e
        for p in problems(e):
            print(f"{e['path'].name}: {p}")
            bad += 1
    print(f"tracker: {len(ids)} entries, {bad} problem(s)")
    return 1 if bad else 0


def show(statuses: list[str]) -> None:
    rows = [e for e in entries() if (e.get("status") in statuses if statuses else e.get("status") not in CLOSED)]
    # Regressions first, then by status in workflow order.
    rows.sort(key=lambda e: (-e["reopened"], STATUSES.index(e["status"]) if e.get("status") in STATUSES else 9, e["id"]))
    for e in rows:
        flag = f" REOPENED x{e['reopened']}" if e["reopened"] else ""
        extra = f"  [blocked: {e.get('blocker')}]" if e.get("status") == "blocked" else ""
        print(f"{e['id']}  {e.get('status', '?'):<11} {e.get('kind', '?'):<6} {e['title']}{flag}{extra}")


def new(kind: str, title: str, who: str) -> None:
    known = [e["id"] for e in entries() if e["id"]]
    prefix = os.environ.get("TRACKER_PREFIX") or (known[0].rsplit("-", 1)[0] if known else "T")
    n = max([int(i.rsplit("-", 1)[1]) for i in known] or [0]) + 1
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:50]
    DIR.mkdir(exist_ok=True)
    path = DIR / f"{prefix}-{n:03d}-{slug}.md"
    today = datetime.date.today().isoformat()
    path.write_text(f"# {prefix}-{n:03d} {title}\nkind: {kind}\nstatus: open\nreported: {today}, {who}\n"
                    f"blocker: -\ntest: -\nfixed-in: -\n\n## History\n- {today} open: reported by {who}\n")
    print(path.relative_to(ROOT))


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["check"]:
        sys.exit(check())
    elif args[:1] == ["new"] and len(args) >= 3:
        new(args[1], args[2], args[3] if len(args) > 3 else "owner")
    elif args[:1] == ["list"]:
        show(args[1:])
    else:
        print(__doc__)
        sys.exit(2)
