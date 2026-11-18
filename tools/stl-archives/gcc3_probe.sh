#!/usr/bin/env bash
# Builds stl_probe98.cpp with gcc 3.3 for the libstdc++.so.5 archives, in a Debian etch chroot, which
# ships g++-3.3 and the library's own debug build. Needs root and debootstrap.
#   gcc3_probe.sh <out> <i386|amd64> [chroot dir]
# gcc 3.3 has no -femit-class-debug-always and only declares the classes whose vtable the library
# emits (exception, logic_error, basic_filebuf...), so the probe links statically against the debug
# libstdc++.a, whose units define them.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=$(realpath -m "$1")
arch=$2
root=${3:-$(mktemp -d)}

if [ ! -x "$root/usr/bin/g++-3.3" ]; then
    debootstrap --arch="$arch" --variant=minbase --no-check-gpg \
        --include=g++-3.3,libstdc++5-3.3-dev,libstdc++5-3.3-dbg \
        etch "$root" http://archive.debian.org/debian
fi
mkdir -p "$root/probe"
cp "$here/stl_probe98.cpp" "$root/probe/"
chroot "$root" /bin/sh -c 'cd /probe && g++-3.3 --version | head -1 &&
    g++-3.3 -g -O0 -Wno-deprecated -c stl_probe98.cpp -o probe.o &&
    g++-3.3 -g -static -o probe probe.o -L/usr/lib/debug'
cp "$root/probe/probe" "$out"
