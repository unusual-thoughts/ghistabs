#!/usr/bin/env python3
"""Annotate the compile errors and warnings in a Gradle log on the GitHub Actions run.

Reads the console output of a build (the CI tees its compile step into a file) and collects:
  * Kotlin compiler errors and warnings: `e: file:///abs/path/Foo.kt:12:5 message` (`w:` for a warning)
  * javac errors and warnings: `/abs/path/Foo.java:12: warning: [deprecation] message` (`error:`)
  * Kotlin warnings about the whole build: `w: API version 1.9 is deprecated…`
  * Gradle's own deprecations: `... has been deprecated. ...` lines, with --warning-mode all

and prints one `::error` or `::warning` workflow command per distinct one. One with a file and line (a compiler
warning, or a Gradle deprecation that names its build file) shows on the PR's diff at that line; one
without shows on the run and the PR's checks. GitHub keeps only 10 warning annotations, and 10 errors, per
step, so `--kind error`, `--kind compiler` and `--kind gradle` let the CI give each its own step. It never fails the job.

Usage: build_warnings.py LOG [--root DIR] [--kind compiler|error|gradle|all]
       build_warnings.py --self-test
"""
import argparse
import os
import re
import sys

KOTLIN = re.compile(r"^(?P<level>[we]): (?:file://)?(?P<path>/[^:]+\.kts?):(?P<line>\d+):(?P<col>\d+) (?P<msg>.+)$")
# A warning about the build as a whole, with no source position: `w: API version 1.9 is deprecated…`.
KOTLIN_GLOBAL = re.compile(r"^(?P<level>[we]): (?!file://|/)(?P<msg>.+)$")
JAVAC = re.compile(r"^(?P<path>/[^:]+\.java):(?P<line>\d+): (?P<level>warning|error): (?P<msg>.+)$")
GRADLE = re.compile(r"(?P<msg>.*\bhas been deprecated\b.*)$")
# Where Gradle says a deprecation comes from, when it does: `Build file '/abs/build.gradle.kts': line 12`.
GRADLE_WHERE = re.compile(r"(?:Build|Settings|Init) (?:file|script) '(?P<path>[^']+)': line (?P<line>\d+)")


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
            kind = "error" if m["level"] in ("e", "error") else "deprecation" if is_deprecation(msg) else "other"
            entry = (kind, path, int(m["line"]), int(m.groupdict().get("col") or 0), msg)
        elif m := KOTLIN_GLOBAL.match(line):
            msg = m["msg"].strip()
            kind = "error" if m["level"] == "e" else "deprecation" if is_deprecation(msg) else "other"
            entry = (kind, "", 0, 0, msg)
        elif GRADLE.match(line) and not line.startswith(("w: ", "e: ")):
            where = GRADLE_WHERE.search(line)
            path, at = (where["path"], int(where["line"])) if where else ("", 0)
            path = path[len(root):] if path.startswith(root) else path
            entry = ("gradle", path, at, 0, line.strip())
        else:
            continue
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def annotations(problems, which="compiler"):
    """`which` is compiler (warnings), error, gradle or all."""
    for kind, path, line, col, msg in problems:
        group = kind if kind in ("error", "gradle") else "compiler"
        if which not in ("all", group):
            continue
        level = "error" if kind == "error" else "warning"
        if not path:
            # About the build itself (the Kotlin API version, say), not a use of an API.
            title = {"gradle": "Gradle deprecation", "error": "Kotlin compiler error"}.get(kind, "Kotlin compiler")
            yield f"::{level} title={title}::{msg}"
            continue
        title = {"deprecation": "Deprecated API", "gradle": "Gradle deprecation", "error": "Compile error"}.get(
            kind, "Compiler warning")
        loc = f"file={path}" + (f",line={line}" if line else "") + (f",col={col}" if col else "")
        yield f"::{level} {loc},title={title}::{msg}"


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
        "e: file:///repo/ghicpp/src/main/kotlin/ghicpp/eh/S.kt:214:30 The spread operator (*foo) can only be applied in a vararg position.\n",
        "/repo/src/main/java/ghidra/C.java:9: error: cannot find symbol\n",
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
        ("error", "ghicpp/src/main/kotlin/ghicpp/eh/S.kt", 214, 30,
         "The spread operator (*foo) can only be applied in a vararg position."),
        ("error", "src/main/java/ghidra/C.java", 9, 0, "cannot find symbol"),
    ]
    ok = got == want
    if not ok:
        print("FAIL parse:", *got, sep="\n  ")
    ann = list(annotations(got))
    if len(ann) != 4 or not ann[0].startswith("::warning file=ghicpp/src/main/kotlin/ghicpp/A.kt,line=12,col=5"):
        ok = False
        print("FAIL annotations:", *ann, sep="\n  ")
    gradle_ann = list(annotations(got, "gradle"))
    if gradle_ann != ["::warning title=Gradle deprecation::" + want[3][4]] or len(list(annotations(got, "all"))) != 7:
        ok = False
        print("FAIL gradle annotations:", *gradle_ann, sep="\n  ")
    where = parse(["Build file '/repo/ghicpp/build.gradle.kts': line 9\n",
                   "The X method has been deprecated. Build file '/repo/ghicpp/build.gradle.kts': line 9\n"], root)
    if where != [("gradle", "ghicpp/build.gradle.kts", 9, 0,
                  "The X method has been deprecated. Build file '/repo/ghicpp/build.gradle.kts': line 9")]:
        ok = False
        print("FAIL gradle location:", where)
    errors = list(annotations(got, "error"))
    if errors != ["::error file=ghicpp/src/main/kotlin/ghicpp/eh/S.kt,line=214,col=30,title=Compile error::" + want[5][4],
                  "::error file=src/main/java/ghidra/C.java,line=9,title=Compile error::cannot find symbol"]:
        ok = False
        print("FAIL error annotations:", *errors, sep="\n  ")
    print("ok" if ok else "failed")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="?")
    ap.add_argument("--root", default=".", help="repo root, to make paths relative (default: .)")
    ap.add_argument("--kind", default="all", choices=("compiler", "error", "gradle", "all"),
                    help="what to annotate: compiler warnings, compile errors, Gradle deprecations (default: all)")
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
    for a in annotations(warnings, args.kind):
        print(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
