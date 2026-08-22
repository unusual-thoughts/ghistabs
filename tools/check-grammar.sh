#!/usr/bin/env bash
# Check that a render is valid C++, by parsing it with clang.
#
#   tools/check-grammar.sh <render-dir> [-v]
#
# Everything clang reports counts, except one named family: errors that follow from the render not
# emitting a definition for something it names. Those are inherent — a per-file view of one
# translation unit cannot declare every type it mentions — and there is no clang flag that turns them
# off, so they are subtracted by name rather than by a whitelist of the errors we happen to expect.
# Anything clang says that is *not* in that family is a render defect, including ones we have not
# seen yet: an earlier whitelist of brace/paren messages scored 39 errors on one fixture and hid ~1500
# others, among them `constructor cannot have a return type`, `invalid parameter name: 'this' is a
# keyword`, and `invalid digit 8 in octal constant`.
#
# Ghidra's pseudo-types are declared in a prelude instead of being ignored: they are a fixed, known
# vocabulary, so declaring them is cheaper and truer than filtering their diagnostics.
set -uo pipefail

dir=${1:?usage: check-grammar.sh <render-dir> [-v]}
verbose=${2:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/prelude.h" <<'EOF'
typedef unsigned char undefined, undefined1, byte;
typedef unsigned short undefined2, ushort, word;
typedef unsigned int undefined4, uint, dword;
typedef unsigned long long undefined6, undefined8, ulonglong, qword;
typedef signed char sbyte;
typedef unsigned long ulong;
typedef void code;
EOF

# Errors that mean "you never declared this", which a per-file render cannot avoid. Kept deliberately
# narrow: each entry names a missing declaration, not a malformed one.
undeclared='use of undeclared identifier|unknown type name|undeclared template|no template named'
undeclared+='|unknown template name|variable has incomplete type|does not refer to a value'
undeclared+='|is a private member of|no member named|undeclared label|expected class name'
undeclared+='|call to non-static member function without an object argument'
undeclared+='|explicit specialization of non-template'

scan() {
    # The include graph is not under test — its targets are the render's own mangled filenames — so
    # strip it and supply the prelude instead.
    sed 's/^#include.*//' "$1" > "$work/u.cpp"
    clang -fsyntax-only -x c++ -std=c++03 -w -ferror-limit=0 -nostdinc \
        -include "$work/prelude.h" "$work/u.cpp" 2>&1 |
        grep -E "error: " | grep -Ev "($undeclared)"
}

total=0
bad=0
badfiles=0
# Recursive: the render mirrors the source tree (`E/work/.../appimage.h`), so a flat glob saw 9 of
# one fixture's 66 files and reported a total that meant nothing.
while IFS= read -r f; do
    total=$((total + 1))
    out=$(scan "$f")
    n=$(printf '%s' "$out" | grep -c "error: ")
    if [ "$n" -gt 0 ]; then
        bad=$((bad + n))
        badfiles=$((badfiles + 1))
        [ -n "$verbose" ] && printf '%s\n' "$out" | sed "s|$work/u.cpp|${f#"$dir"/}|"
    fi
done < <(find "$dir" -type f | sort)

echo "$dir: $badfiles/$total files with errors ($bad total)"
[ "$badfiles" -eq 0 ]
