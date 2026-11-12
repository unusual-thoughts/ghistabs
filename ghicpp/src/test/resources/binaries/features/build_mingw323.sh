#!/bin/sh
# The MinGW-3.1.0-1 toolchain, rebuilt
# from its own sources as a Linux cross so that every target library carries
# stabs: mingw-runtime (crt2.o, libmingw32, libmingwex, libmoldname),
# libgcc (incl. the SJLJ unwinder in unwind-sjlj.c), libsupc++ and libstdc++.
#
# MinGW-3.1.0-1 = gcc-3.2.3-20030504-1, binutils-2.13.90-20030111-1,
# mingw-runtime-3.1, w32api-2.4. Sources, from
# https://sourceforge.net/projects/mingw/files/OldFiles/ , in /build/src2:
#   gcc-3.2.3-20030504-1-src.tar.gz            (MinGW-patched gcc 3.2.3)
#   binutils-2.13.90-20030111-1-src.tar.gz     (in "Previous Release_ binutils-2.13.90/")
#   mingw-runtime-3.1-src.tar.gz
#   w32api-2.4-src.tar.gz
#   gcc-3.2.3-20030504-1.tar.gz                (the binary release: for its c++config.h)
#
# Three things the bundle's binaries show that its build scripts don't:
# - mingw-runtime 3.1 was compiled -O2 -mcpu=i686 (its isascii schedules
#   push/mov/xor/test, which only gcc 3.2.3 -mcpu=i686 produces).
# - gcc's source tree was called gcc: anonymous-namespace symbols embed the
#   path (_GLOBAL__N_.._.._.._.._gcc_libstdc___v3_libsupc___vec.cc...).
# - libstdc++ was configured natively. A cross configure misses HAVE_MODFF,
#   HAVE_EXPF, HAVE___BUILTIN_* and so on and links libmath stubs the bundle
#   doesn't have, so its config.h is rebuilt from the binary release's installed
#   bits/c++config.h: the c++config template stripped and the
#   HAVE_/PACKAGE/VERSION/WORDS_ renaming undone.
#
# Configuration follows MinGW's own gcc-3.2.3-build.sh and binutils-2.13-build.sh
# (target mingw32, prefix /mingw, --enable-threads --enable-sjlj-exceptions
# --disable-shared --disable-win32-registry, CFLAGS=-O2). The only change is
# -gstabs+ on the target libraries; optimisation stays -O2, so their code is the
# code MinGW shipped (checked function by function against the bundle).
#
# Runs inside a Debian sarge i386 chroot:
#   debootstrap --arch=i386 --no-check-gpg --variant=buildd \
#     --include=flex-old,bison,make,patch,bzip2 \
#     sarge <root> http://archive.debian.org/debian
set -ex
T=mingw32
P=/mingw
DBG="-gstabs+"
export PATH=$P/bin:$PATH
cd /build
S=/build/src2

rm -rf gcc gcc-3.2.3-20030504-1 binutils-2.13.90-20030111-1-src mingw-runtime-3.1 w32api-2.4 w32api
for f in gcc-3.2.3-20030504-1-src binutils-2.13.90-20030111-1-src mingw-runtime-3.1-src w32api-2.4-src; do
  tar xzf $S/$f.tar.gz
done
mv gcc-3.2.3-20030504-1 gcc
# runtime's configure finds w32api as a sibling named w32api
ln -sfn w32api-2.4 w32api

# binutils
rm -rf b-binutils && mkdir b-binutils && cd b-binutils
../binutils-2.13.90-20030111-1-src/configure --prefix=$P --target=$T \
  --disable-nls --disable-shared
make CFLAGS="-O2 -g0"
make install
cd ..

# headers first; --with-headers keeps libgcc from being built -Dinhibit_libc
# (MinGW built it natively, with headers)
mkdir -p $P/$T/include
cp -r w32api-2.4/include/* $P/$T/include/
cp -r mingw-runtime-3.1/include/* $P/$T/include/

# stage 1: the compiler and libgcc
rm -rf b-gcc && mkdir b-gcc && cd b-gcc
../gcc/configure --prefix=$P --target=$T \
  --with-gnu-ld --with-gnu-as \
  --enable-threads --disable-nls --enable-languages=c++ \
  --disable-win32-registry --disable-shared --enable-sjlj-exceptions \
  --with-headers=$P/$T/include
make all-gcc CFLAGS=-O2 LIBGCC2_DEBUG_CFLAGS="$DBG"
make install-gcc LIBGCC2_DEBUG_CFLAGS="$DBG"
cd ..

# w32api import libs and mingw-runtime, with stabs
for d in w32api-2.4 mingw-runtime-3.1; do
  rm -rf b-$d && mkdir b-$d && cd b-$d
  CC=$T-gcc AR=$T-ar RANLIB=$T-ranlib AS=$T-as DLLTOOL=$T-dlltool \
  CFLAGS="$DBG -O2 -mcpu=i686" \
  ../$d/configure --prefix=$P/$T --host=$T --build=i386-linux
  # mingwthrd.dll links -lmingwex from the build tree, which a native build
  # found already installed; build the subdirs (profile, mingwex) first
  if [ $d = mingw-runtime-3.1 ]; then make subdirs DO=all W32API_INCLUDE=-I/build/w32api-2.4/include; fi
  make W32API_INCLUDE=-I/build/w32api-2.4/include
  make install prefix=$P/$T
  cd ..
done

# stage 2: libsupc++ / libstdc++, with stabs, configured as the bundle's
cd b-gcc
make configure-target-libstdc++-v3 CFLAGS=-O2 CFLAGS_FOR_TARGET="$DBG -O2" CXXFLAGS_FOR_TARGET="$DBG -O2"
C=include/c++/3.2.3/mingw32/bits/c++config.h
rm -rf /build/bin-323 && mkdir /build/bin-323
tar xzf $S/gcc-3.2.3-20030504-1.tar.gz -C /build/bin-323 $C
n=$(wc -l < ../gcc/libstdc++-v3/include/bits/c++config)
tail -n +$((n+1)) /build/bin-323/$C | sed '$d' | sed -e 's/_GLIBCPP_HAVE_/HAVE_/g' \
  -e 's/_GLIBCPP_PACKAGE/PACKAGE/g' -e 's/_GLIBCPP_VERSION/VERSION/g' -e 's/_GLIBCPP_WORDS_/WORDS_/g' \
  > $T/libstdc++-v3/config.h
make all CFLAGS=-O2 CFLAGS_FOR_TARGET="$DBG -O2" CXXFLAGS_FOR_TARGET="$DBG -O2" \
  LIBGCC2_DEBUG_CFLAGS="$DBG"
make install
cd ..

# the fixture, from hello.cc in /out
cd /out && $T-g++ -gstabs+ -O0 -static hello.cc -o hello_gcc323_fullstabs.exe
