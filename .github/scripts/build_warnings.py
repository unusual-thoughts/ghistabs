#!/usr/bin/env python3
"""Render the compiler warnings in a Gradle log as a GitHub Actions job summary.

Reads the console output of a build (the CI tees its compile step into a file) and collects:
  * Kotlin compiler warnings:  `w: file:///abs/path/Foo.kt:12:5 message`
  * javac warnings:            `/abs/path/Foo.java:12: warning: [deprecation] message`
  * Kotlin warnings about the whole build: `w: API version 1.9 is deprecated…`
  * Gradle's own deprecations: `... has been deprecated. ...` lines, with --warning-mode all

It prints, as Markdown, a count per kind and a table per kind (deprecations first, since they are the
ones that break on the next upgrade), with paths relative to the repo root. With --annotate it also
prints one `::warning file=…,line=…` workflow command per compiler warning, which GitHub shows on the
PR's diff. It never fails the job.

Usage: build_warnings.py LOG [--root DIR] [--summary FILE] [--annotate]
       build_warnings.py --self-test
"""
import argparse
import os
import re
import sys

KOTLIN = re.compile(r"^w: (?:file://)?(?P<path>/[^:]+\.kts?):(?P<line>\d+):(?P<col>\d+) (?P<msg>.+)$")
# A warning about the build as a whole, with no source position: `w: API version 1.9 is deprecated…`.
KOTLIN_GLOBAL = re.compile(r"^w: (?!file://|/)(?P<msg>.+)$")
JAVAC = re.compile(r"^(?P<path>/[^:]+\.java):(?P<line>\d+): warning: (?P<msg>.+)$")
GRADLE = re.compile(r"(?P<msg>.*\bhas been deprecated\b.*)$")
# Tables longer than this collapse behind a <details>.
OPEN_ROWS = 20


def is_deprecation(msg):
    m = msg.lower()
    return "deprecat" in m or "[removal]" in m


def parse(lines, root):
    """[(kind, path, line, col, message)], deduplicated in first-seen order."""
    seen, out = set(), []
    root = os.path.abspath(root) + os.sep
    for raw in lines:
        line = raw.rstrip("\n")
        # Gradle prefixes nothing on the plain console, but strip a GitHub log timestamp if present.
        line = re.sub(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ", "", line)
        m = KOTLIN.match(line) or JAVAC.match(line)
        if m:
            path = m["path"]
            path = path[len(root):] if path.startswith(root) else path
            msg = m["msg"].strip()
            kind = "deprecation" if is_deprecation(msg) else "other"
            entry = (kind, path, int(m["line"]), int(m.groupdict().get("col") or 0), msg)
        elif m := KOTLIN_GLOBAL.match(line):
            msg = m["msg"].strip()
            entry = ("deprecation" if is_deprecation(msg) else "other", "", 0, 0, msg)
        elif GRADLE.match(line) and not line.startswith(("w: ", "e: ")):
            entry = ("gradle", "", 0, 0, line.strip())
        else:
            continue
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def esc(s):
    return s.replace("|", "\\|").replace("\n", " ")


def render(warnings):
    by = {k: [w for w in warnings if w[0] == k] for k in ("deprecation", "other", "gradle")}
    if not warnings:
        return "### Build warnings\n\nNo compiler warnings.\n"
    parts = [
        "### Build warnings\n",
        f"{len(by['deprecation'])} deprecation(s), {len(by['other'])} other compiler warning(s), "
        f"{len(by['gradle'])} Gradle deprecation(s).\n",
    ]
    titles = {"deprecation": "Deprecated API use", "other": "Other compiler warnings", "gradle": "Gradle deprecations"}
    for kind, rows in by.items():
        if not rows:
            continue
        if kind == "gradle":
            body = "\n".join(f"- {esc(w[4])}" for w in rows)
        else:
            body = "| Where | Warning |\n|---|---|\n" + "\n".join(f"| {f'`{esc(w[1])}:{w[2]}`' if w[1] else 'whole build'} | {esc(w[4])} |" for w in rows)
        if len(rows) > OPEN_ROWS:
            parts.append(f"<details><summary><b>{titles[kind]}</b> ({len(rows)})</summary>\n\n{body}\n\n</details>\n")
        else:
            parts.append(f"#### {titles[kind]} ({len(rows)})\n\n{body}\n")
    return "\n".join(parts)


def annotations(warnings):
    for kind, path, line, col, msg in warnings:
        if kind == "gradle":
            continue
        title = "Deprecated API" if kind == "deprecation" else "Compiler warning"
        if not path:
            yield f"::warning title={title}::{msg}"
            continue
        loc = f"file={path},line={line}" + (f",col={col}" if col else "")
        yield f"::warning {loc},title={title}::{msg}"


def self_test():
    root = "/repo"
    log = [
        "> Task :ghicpp:compileKotlin\n",
        "w: file:///repo/ghicpp/src/main/kotlin/ghicpp/A.kt:12:5 'getFoo(): Int' is deprecated. Use bar.\n",
        "w: file:///repo/ghicpp/src/main/kotlin/ghicpp/A.kt:12:5 'getFoo(): Int' is deprecated. Use bar.\n",
        "w: file:///repo/src/main/kotlin/ghistabs/B.kt:3:1 Variable 'x' is never used.\n",
        "/repo/src/main/java/ghidra/C.java:7: warning: [removal] finalize() in Object has been deprecated and marked for removal\n",
        "The Project.exec(Action) method has been deprecated. This is scheduled to be removed in Gradle 10.\n",
        "w: API version 1.9 is deprecated and its support will be removed in a future version of Kotlin.\n",
        "BUILD SUCCESSFUL in 1m\n",
    ]
    got = parse(log, root)
    want = [
        ("deprecation", "ghicpp/src/main/kotlin/ghicpp/A.kt", 12, 5, "'getFoo(): Int' is deprecated. Use bar."),
        ("other", "src/main/kotlin/ghistabs/B.kt", 3, 1, "Variable 'x' is never used."),
        ("deprecation", "src/main/java/ghidra/C.java", 7, 0,
         "[removal] finalize() in Object has been deprecated and marked for removal"),
        ("gradle", "", 0, 0, "The Project.exec(Action) method has been deprecated. This is scheduled to be removed in Gradle 10."),
        ("deprecation", "", 0, 0, "API version 1.9 is deprecated and its support will be removed in a future version of Kotlin."),
    ]
    ok = got == want
    if not ok:
        print("FAIL parse:", *got, sep="\n  ")
    md = render(got)
    for needle in ("3 deprecation(s), 1 other", "| whole build | API version 1.9", "`ghicpp/src/main/kotlin/ghicpp/A.kt:12`", "Gradle deprecations (1)"):
        if needle not in md:
            ok = False
            print("FAIL render: missing", needle)
    ann = list(annotations(got))
    if len(ann) != 4 or not ann[0].startswith("::warning file=ghicpp/src/main/kotlin/ghicpp/A.kt,line=12,col=5"):
        ok = False
        print("FAIL annotations:", *ann, sep="\n  ")
    if render([]) != "### Build warnings\n\nNo compiler warnings.\n":
        ok = False
        print("FAIL render empty")
    print("ok" if ok else "failed")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="?")
    ap.add_argument("--root", default=".", help="repo root, to make paths relative (default: .)")
    ap.add_argument("--summary", help="append the Markdown here ($GITHUB_STEP_SUMMARY) instead of printing it")
    ap.add_argument("--annotate", action="store_true", help="print a ::warning command per compiler warning")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.log:
        ap.error("LOG is required")
    try:
        with open(args.log, errors="replace") as f:
            warnings = parse(f, args.root)
    except OSError as e:
        print(f"build_warnings: cannot read {args.log}: {e}", file=sys.stderr)
        return 0
    md = render(warnings)
    if args.summary:
        with open(args.summary, "a") as f:
            f.write(md + "\n")
    else:
        print(md)
    if args.annotate:
        for a in annotations(warnings):
            print(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
