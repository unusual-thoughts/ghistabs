#!/usr/bin/env python3
"""Render the shifted baselines integrationTest wrote as a GitHub Actions job summary.

CI runs integrationTest with -PignoreBaselines=true, so a counter that leaves its committed
baseline does not stop the tests; it writes a shifted copy under build/test-output/shifted-baselines/,
and the job's last step fails on it instead. This compares each shifted copy with the committed file
it shifted from and prints, as Markdown, one table per fixture or scorecard case: counter, committed
value, new value, delta, the delta led by 🟢 or 🔴 where the counter has a better direction (a
scorecard's -tp up, its -fp or -fn down, an import counter that names what it degrades down), and for
a scorecard, as extra columns on each attribute's first row, its precision and recall old → new.
With no shifted baselines it prints a one-line all-clear.

Two layouts:
  * stabs import baselines: <root>/build/test-output/shifted-baselines/<fixture>-baseline.json against
    <root>/src/test/resources/baselines/, counters as {"counters": {name: {"min", "max", "degrades"}}}.
  * ghicpp scorecards: <root>/ghicpp/build/test-output/shifted-baselines/scorecard-<case>.json against
    <root>/ghicpp/src/test/resources/ghicpp/scorecard/baselines/<case>.json, a flat {name: count} map.

Usage: baseline_summary.py [repo-root] [--artifact NAME] [--summary FILE] [--output FILE]
                           [--patch DIR [--patch-artifact NAME]]
  --summary  append the Markdown there (CI passes $GITHUB_STEP_SUMMARY) instead of printing it
  --output   append `moved=<count>` there (CI passes $GITHUB_OUTPUT), so a later step can fail the job
  --patch    when a counter moved, write shifted-baselines.diff in DIR: every moved baseline's committed
             file turned into its shifted copy, ready for `git apply` at the repository root
With --summary, it also prints one `::warning` workflow command per moved baseline, which GitHub shows
as an annotation on the run and the PR.
"""
import argparse
import difflib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

SHIFTED = Path("build/test-output/shifted-baselines")
STABS_BASELINES = Path("src/test/resources/baselines")
SCORECARD_BASELINES = Path("ghicpp/src/test/resources/ghicpp/scorecard/baselines")
# The patch's file name inside its artifact.
PATCH_NAME = "shifted-baselines.diff"
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


GOOD, BAD = "🟢", "🔴"


def direction(name, old, new):
    """+1 when a counter's rise is an improvement, -1 when it is a regression, 0 when it says neither.

    A scorecard's `-tp` is a match, its `-fp` and `-fn` are misses; an import counter that names what it
    degrades counts a fallback, so more of it is worse. Any other counter only tallies.
    """
    if name.endswith("-tp"):
        return 1
    if name.endswith(("-fp", "-fn")):
        return -1
    if (old and old[2]) or (new and new[2]):
        return -1
    return 0


def marker(sign):
    return GOOD if sign > 0 else BAD if sign < 0 else ""


def fmt_coloured_delta(name, old, new):
    """The delta, led by 🟢 or 🔴 when the counter has a better direction and moved one way."""
    text = fmt_delta(old, new)
    if old is None or new is None:
        return text
    moved = (new[0] - old[0]) + (new[1] - old[1])
    sign = direction(name, old, new) * ((moved > 0) - (moved < 0))
    return f"{marker(sign)} {text}".strip()


def ratio(num, den):
    return num / den if den else None


def fmt_pct(x):
    return "—" if x is None else f"{100 * x:.1f}%"


def fmt_pts(old, new):
    """The change in percentage points, coloured: precision and recall are better higher."""
    if old is None or new is None:
        return ""
    if abs(new - old) < 5e-4:
        return "0"
    d = 100 * (new - old)
    return f"{marker(d)} {'+' if d > 0 else ''}{d:.1f} pts"


def fmt_ratio_move(old, new):
    pts = fmt_pts(old, new)
    return f"{fmt_pct(old)} → {fmt_pct(new)}" + (f" ({pts})" if pts else "")


def precision_recall(committed, shifted, rows):
    """Rows (attribute, P old, P new, R old, R new) for each scorecard attribute with a moved counter."""
    moved = sorted({name.rsplit("-", 1)[0] for name, _, _ in rows if name.endswith(("-tp", "-fp", "-fn"))})
    out = []
    for attr in moved:
        def get(side, kind):
            r = side.get(f"{attr}-{kind}")
            return r[0] if r else 0
        pr = []
        for side in (committed, shifted):
            tp, fp, fn = get(side, "tp"), get(side, "fp"), get(side, "fn")
            pr.append((ratio(tp, tp + fp), ratio(tp, tp + fn)))
        out.append((attr, pr[0][0], pr[1][0], pr[0][1], pr[1][1]))
    return out


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


@dataclass
class Found:
    """A shifted baseline: its moved rows, both sides' counters, and where each file is."""
    kind: str
    label: str
    rows: list
    committed: dict
    shifted: dict
    path: Path  # the committed file, relative to the repository root
    source: Path  # the shifted file


def collect(root):
    """[Found] for every shifted baseline under root."""
    found = []
    stabs_dir = root / SHIFTED
    for f in sorted(stabs_dir.glob("*.json")) if stabs_dir.is_dir() else []:
        label = f.name.removesuffix("-baseline.json").removesuffix(".json")
        base = STABS_BASELINES / f.name
        committed, shifted = stabs_counters(load(root / base)), stabs_counters(load(f))
        found.append(Found("Import baseline", label, moves(committed, shifted), committed, shifted, base, f))
    score_dir = root / "ghicpp" / SHIFTED
    for f in sorted(score_dir.glob("scorecard-*.json")) if score_dir.is_dir() else []:
        case = f.name.removeprefix("scorecard-").removesuffix(".json")
        base = SCORECARD_BASELINES / f"{case}.json"
        committed, shifted = scorecard_counters(load(root / base)), scorecard_counters(load(f))
        found.append(Found("Scorecard", case, moves(committed, shifted), committed, shifted, base, f))
    return found


def patch_text(root, found):
    """A unified diff, from each committed baseline to its shifted copy, that `git apply` takes."""
    out = []
    for f in found:
        if not f.rows:
            continue
        a = (root / f.path).read_text().splitlines(keepends=True)
        b = f.source.read_text().splitlines(keepends=True)
        for line in difflib.unified_diff(a, b, f"a/{f.path.as_posix()}", f"b/{f.path.as_posix()}"):
            # A last line with no newline needs git's marker, or the hunk after it is unreadable.
            out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)


def render(found, artifact=None, patch=None):
    lines = ["## Baseline counters"]
    moved = [f for f in found if f.rows]
    if not moved:
        lines += ["", "No baseline counter moved." if not found else
                  "Shifted baselines were written, but no counter differs from the committed ones."]
        return "\n".join(lines) + "\n"
    total = sum(len(f.rows) for f in moved)
    lines += ["", f"**{total}** counter{'s' if total != 1 else ''} moved in **{len(moved)}** "
              f"baseline{'s' if len(moved) != 1 else ''}. The job fails on them once the rest of it has run."]
    if artifact:
        lines.append(f"The new baselines are in the `{artifact}` artifact.")
    if patch:
        lines.append(f"To commit them, download the `{patch}` artifact and run `git apply {PATCH_NAME}` "
                     "at the repository root.")
    lines.append(f"{GOOD} marks a move for the better, {BAD} one for the worse.")
    for f in moved:
        any_targets = any(fmt_targets(o, n) for _, o, n in f.rows)
        pr = {attr: rest for attr, *rest in precision_recall(f.committed, f.shifted, f.rows)}
        lines += ["", f"### {f.kind}: `{f.label}`", ""]
        header = "| Counter | Committed | New | Δ |" + (" Precision | Recall |" if pr else "") \
            + (" What moved |" if any_targets else "")
        lines += [header, "|---|---:|---:|---:|" + ("---:|---:|" if pr else "") + ("---|" if any_targets else "")]
        shown = set()
        for name, old, new in f.rows:
            row = f"| `{name}` | {fmt_range(old)} | {fmt_range(new)} | {fmt_coloured_delta(name, old, new)} |"
            if pr:
                # An attribute's precision and recall go on the first of its rows only.
                attr = name.rsplit("-", 1)[0]
                if attr in pr and attr not in shown:
                    shown.add(attr)
                    p0, p1, r0, r1 = pr[attr]
                    row += f" {fmt_ratio_move(p0, p1)} | {fmt_ratio_move(r0, r1)} |"
                else:
                    row += " | |"
            lines.append(row + (f" {fmt_targets(old, new)} |" if any_targets else ""))
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("root", nargs="?", default=".", type=Path)
    p.add_argument("--artifact", help="name of the uploaded shifted-baselines artifact, to point readers at")
    p.add_argument("--summary", type=Path, help="file to append the Markdown to, instead of stdout")
    p.add_argument("--output", type=Path, help="file to append `moved=<count>` to")
    p.add_argument("--patch", type=Path, metavar="DIR",
                   help=f"write {PATCH_NAME} there when a counter moved: the committed baselines' diff to the shifted ones")
    p.add_argument("--patch-artifact", help="name of the artifact the patch is uploaded as, to point readers at")
    args = p.parse_args(argv)
    found = collect(args.root)
    moved = sum(len(f.rows) for f in found)
    if args.patch is not None and moved:
        args.patch.mkdir(parents=True, exist_ok=True)
        (args.patch / PATCH_NAME).write_text(patch_text(args.root, found))
    text = render(found, args.artifact, args.patch_artifact if moved else None)
    if args.summary is None:
        sys.stdout.write(text)
    else:
        with args.summary.open("a") as out:
            out.write(text)
        for f in found:
            if f.rows:
                names = ", ".join(name for name, _, _ in f.rows[:8]) + (" …" if len(f.rows) > 8 else "")
                print(f"::warning title={f.kind} moved: {f.label}::{len(f.rows)} counter(s) moved: {names}")
    if args.output is not None:
        with args.output.open("a") as out:
            out.write(f"moved={moved}\n")


if __name__ == "__main__":
    main()
