#!/usr/bin/env bash
# Builds stl_probe.cpp for the libstdc++ archives: one binary holding three units, the default
# (std::__cxx11) ABI, the old copy-on-write ABI and _GLIBCXX_DEBUG, with the full DWARF of every class.
#   gcc_probe.sh <out> [g++ flags...]      e.g. gcc_probe.sh probe32 -m32
# CXX picks the compiler (default g++), for an older gcc or a MinGW cross g++.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=$1
shift
cxx=${CXX:-g++}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Without -femit-class-debug-always gcc only declares the classes whose vtable the library emits.
flags=(-std=c++17 -g -O0 -femit-class-debug-always "$@")
printf '#include "%s/stl_probe.cpp"\n' "$here" > "$work/abi.cpp"
printf '#define _GLIBCXX_USE_CXX11_ABI 0\n#define probe probe_cow\n#define main probe_cow_main\n#include "%s/stl_probe.cpp"\n' \
    "$here" > "$work/cow.cpp"
printf '#define _GLIBCXX_DEBUG 1\n#define probe probe_debug\n#define main probe_debug_main\n#include "%s/stl_probe.cpp"\n' \
    "$here" > "$work/debug.cpp"
for unit in abi cow debug; do
    "$cxx" "${flags[@]}" -c "$work/$unit.cpp" -o "$work/$unit.o"
done
"$cxx" "$@" -pthread "$work/abi.o" "$work/cow.o" "$work/debug.o" -o "$out"
