#!/usr/bin/env python3
"""Render the shifted baselines integrationTest wrote as a GitHub Actions job summary.

CI runs integrationTest with -PignoreBaselines=true, so a counter that leaves its committed
baseline does not stop the tests; it writes a shifted copy under build/test-output/shifted-baselines/,
and the job's last step fails on it instead. This compares each shifted copy with the committed file
it shifted from and prints, as Markdown, one table per fixture or scorecard case: counter, committed
value, new value, delta. With no shifted baselines it prints a one-line all-clear.

Two layouts:
  * stabs import baselines: <root>/build/test-output/shifted-baselines/<fixture>-baseline.json against
    <root>/src/test/resources/baselines/, counters as {"counters": {name: {"min", "max", "degrades"}}}.
  * ghicpp scorecards: <root>/ghicpp/build/test-output/shifted-baselines/scorecard-<case>.json against
    <root>/ghicpp/src/test/resources/ghicpp/scorecard/baselines/<case>.json, a flat {name: count} map.

Usage: baseline_summary.py [repo-root] [--artifact NAME] [--summary FILE] [--output FILE]
  --summary  append the Markdown there (CI passes $GITHUB_STEP_SUMMARY) instead of printing it
  --output   append `moved=<count>` there (CI passes $GITHUB_OUTPUT), so a later step can fail the job
With --summary, it also prints one `::warning` workflow command per moved baseline, which GitHub shows
as an annotation on the run and the PR.
"""
import argparse
import json
import sys
from pathlib import Path

SHIFTED = Path("build/test-output/shifted-baselines")
STABS_BASELINES = Path("src/test/resources/baselines")
SCORECARD_BASELINES = Path("ghicpp/src/test/resources/ghicpp/scorecard/baselines")
# How many degraded targets to name per counter before eliding the rest.
MAX_TARGETS = 6


def load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def stabs_counters(doc):
    """{name: (min, max, degrades)} from a stabs baseline document."""
    out = {}
    for name, r in (doc or {}).get("counters", {}).items():
        out[name] = (int(r.get("min", 0)), int(r.get("max", 0)), tuple(r.get("degrades", ())))
    return out


def scorecard_counters(doc):
    return {name: (int(v), int(v), ()) for name, v in (doc or {}).items() if isinstance(v, (int, float))}


def fmt_range(r):
    if r is None:
        return "—"
    lo, hi, _ = r
    return f"{lo}" if lo == hi else f"{lo}..{hi}"


def fmt_delta(old, new):
    if old is None or new is None:
        return "new" if old is None else "removed"

    def signed(n):
        return f"+{n}" if n > 0 else f"{n}" if n < 0 else "0"

    (olo, ohi, _), (nlo, nhi, _) = old, new
    if olo == ohi and nlo == nhi:
        return signed(nlo - olo)
    if nlo - olo == nhi - ohi:
        return signed(nlo - olo)
    return f"{signed(nlo - olo)} / {signed(nhi - ohi)}"


def fmt_targets(old, new):
    was = set(old[2]) if old else set()
    now = set(new[2]) if new else set()
    moved = sorted([f"+{t}" for t in now - was] + [f"-{t}" for t in was - now])
    if not moved:
        return ""
    shown = ", ".join(f"`{t}`" for t in moved[:MAX_TARGETS])
    return shown + (f" … (+{len(moved) - MAX_TARGETS} more)" if len(moved) > MAX_TARGETS else "")


def moves(committed, shifted):
    """Rows (name, old, new) for every counter whose range differs, sorted by name."""
    rows = []
    for name in sorted(set(committed) | set(shifted)):
        old, new = committed.get(name), shifted.get(name)
        if old is None and new is not None and new[0] == new[1] == 0:
            continue  # a counter that appears at 0 everywhere has not moved anything
        # Only a range change is a move, as the drift check sees it; a changed target list alone is not.
        if old is None or new is None or old[:2] != new[:2]:
            rows.append((name, old, new))
    return rows


def collect(root):
    """[(kind, label, rows)] for every shifted baseline under root."""
    found = []
    stabs_dir = root / SHIFTED
    for f in sorted(stabs_dir.glob("*.json")) if stabs_dir.is_dir() else []:
        label = f.name.removesuffix("-baseline.json").removesuffix(".json")
        committed = stabs_counters(load(root / STABS_BASELINES / f.name))
        found.append(("Import baseline", label, moves(committed, stabs_counters(load(f)))))
    score_dir = root / "ghicpp" / SHIFTED
    for f in sorted(score_dir.glob("scorecard-*.json")) if score_dir.is_dir() else []:
        case = f.name.removeprefix("scorecard-").removesuffix(".json")
        committed = scorecard_counters(load(root / SCORECARD_BASELINES / f"{case}.json"))
        found.append(("Scorecard", case, moves(committed, scorecard_counters(load(f)))))
    return found


def render(found, artifact=None):
    lines = ["## Baseline counters"]
    moved = [(k, label, rows) for k, label, rows in found if rows]
    if not moved:
        lines += ["", "No baseline counter moved." if not found else
                  "Shifted baselines were written, but no counter differs from the committed ones."]
        return "\n".join(lines) + "\n"
    total = sum(len(rows) for _, _, rows in moved)
    lines += ["", f"**{total}** counter{'s' if total != 1 else ''} moved in **{len(moved)}** "
              f"baseline{'s' if len(moved) != 1 else ''}. The job fails on them once the rest of it has run."]
    if artifact:
        lines.append(f"The new baselines are in the `{artifact}` artifact.")
    for kind, label, rows in moved:
        any_targets = any(fmt_targets(o, n) for _, o, n in rows)
        lines += ["", f"### {kind}: `{label}`", ""]
        header = "| Counter | Committed | New | Δ |" + (" What moved |" if any_targets else "")
        lines += [header, "|---|---:|---:|---:|" + ("---|" if any_targets else "")]
        for name, old, new in rows:
            row = f"| `{name}` | {fmt_range(old)} | {fmt_range(new)} | {fmt_delta(old, new)} |"
            lines.append(row + (f" {fmt_targets(old, new)} |" if any_targets else ""))
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("root", nargs="?", default=".", type=Path)
    p.add_argument("--artifact", help="name of the uploaded shifted-baselines artifact, to point readers at")
    p.add_argument("--summary", type=Path, help="file to append the Markdown to, instead of stdout")
    p.add_argument("--output", type=Path, help="file to append `moved=<count>` to")
    args = p.parse_args(argv)
    found = collect(args.root)
    text = render(found, args.artifact)
    if args.summary is None:
        sys.stdout.write(text)
    else:
        with args.summary.open("a") as f:
            f.write(text)
        for kind, label, rows in found:
            if rows:
                names = ", ".join(name for name, _, _ in rows[:8]) + (" …" if len(rows) > 8 else "")
                print(f"::warning title={kind} moved: {label}::{len(rows)} counter(s) moved: {names}")
    if args.output is not None:
        with args.output.open("a") as f:
            f.write(f"moved={sum(len(rows) for _, _, rows in found)}\n")


if __name__ == "__main__":
    main()
