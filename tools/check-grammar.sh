#!/usr/bin/env bash
# Check that a render directory is structurally valid C++ — braces nest, comments and strings
# terminate, statements end. Not that it *compiles*: the render emits no definitions for the types it
# names, so "undeclared identifier" and friends are expected and ignored. Only diagnostics that mean
# the text cannot be parsed as C++ at all are counted.
#
#   tools/check-grammar.sh <render-dir> [-v]
#
# Exits non-zero if any file has a structural error. -v lists them.
set -uo pipefail

dir=${1:?usage: check-grammar.sh <render-dir> [-v]}
verbose=${2:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Diagnostics that indicate broken structure rather than a missing declaration. `expected ';' after`
# catches an unterminated statement; the brace and comment ones are self-explanatory.
structural="extraneous closing brace|expected '\}'|expected '\)'|unterminated|expected ';' after (top level declarator|struct|class|union|enum)"

total=0
bad=0
badfiles=0
for f in "$dir"/*; do
    [ -f "$f" ] || continue
    total=$((total + 1))
    # The include graph is not under test and its targets are the render's own mangled filenames;
    # strip them so a missing header does not abort the parse at line 1.
    sed 's/^#include.*//' "$f" > "$work/u.cpp"
    n=$(clang -fsyntax-only -x c++ -std=c++03 -w -ferror-limit=0 -nostdinc "$work/u.cpp" 2>&1 |
        grep -cE "error: ($structural)")
    if [ "$n" -gt 0 ]; then
        bad=$((bad + n))
        badfiles=$((badfiles + 1))
        [ -n "$verbose" ] && clang -fsyntax-only -x c++ -std=c++03 -w -ferror-limit=0 -nostdinc \
            "$work/u.cpp" 2>&1 | grep -E "error: ($structural)" | sed "s|$work/u.cpp|$(basename "$f")|"
    fi
done

echo "$dir: $badfiles/$total files with structural errors ($bad total)"
[ "$badfiles" -eq 0 ]
