#!/usr/bin/env python3
"""Decide which integration suites a CI run needs, from the files it changed.

Two suites: `ghistabs` (the root project's integrationTest) and `ghicpp` (:ghicpp:integrationTest).
Each changed path maps to the suites it can affect:
  * ghicpp/**                        -> ghicpp (its hello fixtures, which ghistabs reads too, -> both)
  * src/**, root build/extension files -> ghistabs (its binary corpus, which ghicpp reads too, -> both)
  * ghidrakt/**, build-logic/**, gradle/**, settings, CI workflow and actions -> both
  * docs, lint configs and the CI's own report scripts -> neither
  * anything else                    -> both, so an unlisted file never skips a suite it affects

The CI passes the run's changed files on stdin, one per line, and gets back one `<suite>=true|false`
line per suite, `suites=<JSON list of those that run>` and `reason=...`, for $GITHUB_OUTPUT. --force runs both whatever changed (the manual
gate: a workflow_dispatch, a push to main, or the PR label).

Usage: git diff --name-only A B | changed_suites.py [--force REASON] [--output FILE] [--summary FILE]
       changed_suites.py --self-test
"""
import argparse
import fnmatch
import json
import sys

SUITES = ("ghistabs", "ghicpp")
BOTH = set(SUITES)

# First match wins, so the narrower patterns go first.
RULES = [
    # Fixtures read by both projects' tests (TestBinaries' binariesDir and hellosDir).
    ("src/test/resources/binaries/*", BOTH),
    ("ghicpp/src/test/resources/binaries/*", BOTH),
    # The shared kernel and the build both projects are built with.
    ("ghidrakt/*", BOTH),
    ("build-logic/*", BOTH),
    ("gradle/*", BOTH),
    ("settings.gradle.kts", BOTH),
    ("gradle.properties", BOTH),
    ("gradlew", BOTH),
    ("gradlew.bat", BOTH),
    (".github/workflows/commit.yml", BOTH),
    (".github/actions/*", BOTH),
    # Run on every CI job whatever the suites; no test reads them.
    (".github/scripts/*", set()),
    (".github/dependabot.yml", set()),
    (".github/workflows/release.yml", set()),
    ("*.md", set()),
    ("LICENSE", set()),
    (".detekt.yml", set()),
    (".detekt-baseline.xml", set()),
    (".editorconfig", set()),
    (".gitignore", set()),
    # Each project's own code, tests, baselines and build file.
    ("ghicpp/*", {"ghicpp"}),
    ("src/*", {"ghistabs"}),
    ("build.gradle.kts", {"ghistabs"}),
    ("Module.manifest", {"ghistabs"}),
    ("extension.properties", {"ghistabs"}),
    ("data/*", {"ghistabs"}),
]


def suites_for(path):
    for pattern, suites in RULES:
        if fnmatch.fnmatchcase(path, pattern):
            return suites
    return BOTH


def classify(paths):
    """{suite: [paths that select it]} for the given changed paths."""
    hits = {s: [] for s in SUITES}
    for p in paths:
        for s in suites_for(p):
            hits[s].append(p)
    return hits


def self_test():
    cases = {
        "src/main/kotlin/ghistabs/Foo.kt": {"ghistabs"},
        "src/test/resources/baselines/x-baseline.json": {"ghistabs"},
        "src/test/resources/binaries/foo.exe": BOTH,
        "ghicpp/src/main/kotlin/ghicpp/Foo.kt": {"ghicpp"},
        "ghicpp/build.gradle.kts": {"ghicpp"},
        "ghicpp/src/test/resources/binaries/features/hello.exe": BOTH,
        "ghicpp/README.md": set(),
        "ghidrakt/src/main/kotlin/ghidrakt/Foo.kt": BOTH,
        "build-logic/src/main/kotlin/integration-tests.gradle.kts": BOTH,
        "gradle/libs.versions.toml": BOTH,
        ".github/workflows/commit.yml": BOTH,
        ".github/actions/setup-ghidra/action.yml": BOTH,
        ".github/scripts/baseline_summary.py": set(),
        "TESTING.md": set(),
        "build.gradle.kts": {"ghistabs"},
        "something/new.txt": BOTH,
    }
    bad = [(p, suites_for(p), want) for p, want in cases.items() if suites_for(p) != want]
    for p, got, want in bad:
        print(f"FAIL {p}: got {sorted(got)}, want {sorted(want)}")
    print(f"{len(cases) - len(bad)}/{len(cases)} passed")
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", metavar="REASON", help="run both suites; REASON names the gate")
    ap.add_argument("--output", help="append the outputs here ($GITHUB_OUTPUT) instead of printing them")
    ap.add_argument("--summary", help="append a Markdown note here ($GITHUB_STEP_SUMMARY)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    if args.force:
        run = {s: True for s in SUITES}
        why = {s: args.force for s in SUITES}
    else:
        paths = [line.strip() for line in sys.stdin if line.strip()]
        hits = classify(paths)
        run = {s: bool(hits[s]) for s in SUITES}
        why = {
            s: (f"{len(hits[s])} changed file(s), e.g. `{hits[s][0]}`" if hits[s] else "no relevant changes")
            for s in SUITES
        }

    lines = [f"{s}={'true' if run[s] else 'false'}" for s in SUITES]
    # For the integration job's matrix; `[]` when nothing runs.
    lines.append("suites=" + json.dumps([s for s in SUITES if run[s]], separators=(",", ":")))
    lines.append("reason=" + "; ".join(f"{s}: {why[s]}" for s in SUITES))
    if args.output:
        with open(args.output, "a") as f:
            f.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))

    if args.summary:
        rows = [f"| {s} | {'runs' if run[s] else 'skipped'} | {why[s]} |" for s in SUITES]
        note = (
            "### Integration suites\n\n| Suite | | Why |\n|---|---|---|\n" + "\n".join(rows) + "\n\n"
            "A skipped suite writes no shifted baselines, so it cannot move a counter. To run both anyway, "
            "add the `run-all-integration` label to the PR, or start the workflow by hand.\n"
        )
        with open(args.summary, "a") as f:
            f.write(note)
    for s in SUITES:
        print(f"{s}: {'runs' if run[s] else 'skipped'} ({why[s]})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
