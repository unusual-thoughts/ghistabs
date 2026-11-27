# STL type archives

Ghidra data type archives of the MSVC standard library (below) and of libstdc++ ([further down](#libstdc)).

## MSVC

Ghidra data type archives (`.gdt`) of the MSVC standard library layouts, one per runtime, architecture
and CRT: `msvcp140_x86.gdt`, `msvcp140d_x64.gdt`, `msvcp90_x86.gdt` and so on. Types are named and
filed where Ghidra's Microsoft demangler puts a class (`/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>`),
so the `this` of a demangled `std::` method matches the archive type by path: the demangler's
placeholder is that path under `/Demangler`.

The [`STL archives`](../../.github/workflows/stl-archives.yml) workflow builds them and uploads
them as one artifact per archive, each downloading as its `.gdt` file. The published archives are
rebuilt on Ghidra 10.4 from the layouts text (see below), so 10.4 and every newer release opens them; the
`compat` job checks that 11.4, 12.0, 12.1 and 12.3 read them back unchanged.


| Archive | Source | Check |
| --- | --- | --- |
| `msvcp140_{x86,x64}` | [`stl_probe.cpp`](stl_probe.cpp) built with `/MD` on the runner's Visual Studio | same sizes and field offsets as Microsoft's public `msvcp140` PDB, for every type both define |
| `msvcp140d_{x86,x64}` | the probe built with `/MDd` (`_ITERATOR_DEBUG_LEVEL=2`) | |
| `msvcp90_{x86,x64}` | Microsoft's public PDB of msvcp90 9.0.30729.9619, the last security rebuild | |
| `msvcp120_{x86,x64}` | Microsoft's public PDB of msvcp120 as the Visual Studio 2013 redistributable installs it | |
| `msvcp80_x86` | Microsoft's public PDB of msvcp80 8.0.50727.6195, the last security rebuild; the x64 one stops Ghidra 12.3's PDB applicator on a virtual base table entry with no offset | |
| `msvcp70_x86` | Microsoft's public PDB of msvcp70 (Visual Studio .NET 2002), with the DLL the symbol server also keeps as the program; serves msvcp70d too, whose layouts differ only in `basic_filebuf::_Mystr` pointing at a `_DebugHeapString` | |
| `msvcp50_x86` | `MSVCP50D.PDB` from Visual Studio 97 Professional's third disc, its module records rewritten in the 6.0 layout by [`modi50to60.py`](modi50to60.py) (Ghidra reads only that one), with its `MSVCP50D.DLL` as the program | |
| `msvcp60_x86` | `MSVCP60D.PDB` from the Visual C++ 6.0 Professional disc (archive.org's X04-58170), with its `MSVCP60D.DLL` as the program | |

msvcp60 serves both VC6 runtimes: its headers test `_DEBUG` only to pick the library to link, so the
debug DLL lays everything out as the release one does. The release `MSVCP60.PDB` on the disc stalls Ghidra
12.3's PDB applicator, and the debug one loses `strstream`, which nests deeper than the applicator follows.

msvcp90 covers what the DLL itself instantiates (strings, iostreams, locale and facets, exceptions),
not header-only containers, and has no debug variant: neither needs more than a VS2008 toolchain
running the same probe.

### Building one yourself

[`build/MsvcStlArchiveScript.java`](build/MsvcStlArchiveScript.java) builds one. It uses ghicpp's classes and Ghidra 12.3+ APIs, so it needs the
ghicpp extension installed. It sits in its own folder, beside `scripts/` rather than above it, because Ghidra compiles a script folder and its subfolders as one bundle, and the scripts in `scripts/` also run on 10.4, where this one cannot compile. Add that folder to the Script Manager's paths and run it on any program of the
right architecture, pointing it at a PDB with type information, or headless. A PDB whose classes have
virtual bases needs the DLL it describes as the program, since the applicator reads their tables there:

```
tools/stl-archives/run.sh archive out.gdt <program> <pdb>
tools/stl-archives/run.sh compare <program> out.gdt reference.gdt
```

Which runtime builds have typed public PDBs is not obvious: for msvcp80 and msvcp90 only the 2016 to
2019 security rebuilds do, for msvcp100 build 40219.325 on x64 only, msvcp110 none, msvcp120 both.
[`pdb_url.py`](pdb_url.py) prints the symbol server URL of a DLL's PDB.

### In ghicpp

ghicpp ships the six 10.4 archives in `ghicpp/data/typeinfo/msvc/`, where Ghidra lists them with its own
archives. The ghistabs extension reads them from the ghicpp jar it bundles instead: Ghidra refuses
two archives of one name, so a copy in its own `data/` collides with ghicpp's when both are installed. Its `MSVC standard library layouts` analyzer reads the
`MSVCP<nn>[D].DLL` a PE program imports and its pointer size, opens the matching archive, and replaces each
empty `std` struct the Microsoft demangler made (`/Demangler/std/...`) with the archive's type at the same
path. Only those types are resolved, with what they depend on, and they stay linked to the archive. To
refresh the copies, download this workflow's `.gdt` artifacts into that folder; the workflow warns when a
fresh build no longer matches them.

Beside each archive is a `.classes.xml.gz` file (the `classes` artifact) with each class's direct bases off the
PDB: their access, virtuality and offset, which a struct cannot say, and the empty bases it has no bytes
for. The analyzer records them for each std class the program has a class namespace for, so the Class
Hierarchy window shows the library's classes and how the program's own derive from them. ghicpp's class
passes take an archive type at a class's namespace path as that class's struct, as it is: they lay it as
the base of the classes deriving from it, and neither size nor fill it. The file is ghicpp's own model of
the classes (`ghicpp.stl.StdClasses`), encoded by the same `GPropertiesFormat` as its class hierarchy
record and saved as gzipped GProperties XML, so [`MsvcStlArchiveScript`](build/MsvcStlArchiveScript.java)
needs the ghicpp extension installed; the workflow builds and installs it first.

The file also lists the virtual functions each class introduces, by vftable offset, and the archive gives
each class that holds its own `{vfptr}` a `<Class>_vftable` struct of typed, named slot pointers, filed in
the class's category, with the `{vfptr}` pointing at it. A call through a `std::streambuf *` or a
`_Ref_count_base *` then reads as `overflow` or `_Destroy`, not as an offset. The model and the vftable
builder (`StdClasses`, `StlVftables`, `StlApplier`, `StlArchives`) say nothing of MSVC; only
`MsvcPdbClasses` and `MsvcRuntime` do, so a libstdc++ archive off DWARF can reuse them.

A member function's access, and whether it is virtual or static, need no PDB: an MSVC name spells them,
and the Class Hierarchy window reads them off the imported or mangled name.

The archives travel between Ghidra versions as text: [`ExportStlLayouts.java`](scripts/ExportStlLayouts.java)
writes it (`run.sh layouts <program> <archive> <out.txt>`) and describes the format, and
[`LayoutsToGdt.java`](scripts/LayoutsToGdt.java) turns it back into a `.gdt` on whichever Ghidra runs it
(`run.sh gdt <program> <layouts.txt> <out.gdt>`). The round trip is needed: Ghidra 10.4 and 11.4 refuse a
`.gdt` that 12.3 wrote ("data created with newer version and can not be read").

## libstdc++

`libstdcxx_x86.gdt` and `libstdcxx_x64.gdt` hold libstdc++'s layouts, and `libstdcxx_mingw_x86.gdt`
and `libstdcxx_mingw_x64.gdt` MinGW-w64's, whose `wchar_t` is 2 bytes, `long` 4 on x64, and x86 alignment of
8-byte types 8. They are filed where Ghidra's GNU demangler
puts a class. One archive per target holds both string ABIs: the C++11 ABI's classes under
`std::__cxx11` (`/std/__cxx11/basic_string<…>`), the copy-on-write ABI's under `std`, and
`std::ios_base::failure[abi:cxx11]` beside the old `failure`, as the demangler names them. The `_GLIBCXX_DEBUG`
containers are under `std::__debug`.

[`gcc_probe.sh`](gcc_probe.sh) builds [`stl_probe.cpp`](stl_probe.cpp) as one binary of three units, the
default ABI, the copy-on-write ABI and `_GLIBCXX_DEBUG`, with `g++ -g -femit-class-debug-always`, without
which gcc only declares the classes whose vtables the library emits. [`build/GccStlArchiveScript.java`](build/GccStlArchiveScript.java)
reads its DWARF on Ghidra 12.3, then:

- files the `std` and `__gnu_cxx` types at their demangled paths and keeps a typedef for each name the
  demangler puts for a library template since 11.4 (`std::string`, `std::__cxx11::wistringstream`);
- lays a base that has virtual bases as its non-virtual part, which the DWARF importer cannot, as
  ghicpp's class passes do;
- names the vptrs `vfptr` and gives each class its `<Class>_vftable` from the slots' `DW_AT_vtable_elem_location`.
  A destructor has none, so its complete and deleting entries go where the Itanium ABI puts them;
- folds the copies the three units leave where they lay out alike. Where they don't (the copy-on-write
  `_List_node_header`, the debug `match_results`), it names the second copy `X#1`.

12.3 cannot give a new `.gdt` an architecture from a headless script, so the script lays the types out in
the probe's own data type manager and writes them as layouts text, with the classes file beside it:

```
tools/stl-archives/gcc_probe.sh probe -m64     # CXX=x86_64-w64-mingw32-g++-posix for MinGW
tools/stl-archives/run.sh gcc out/libstdcxx_x64.gdt probe        # writes out/libstdcxx_x64.txt
tools/stl-archives/run.sh gdt <program> out/libstdcxx_x64.txt out/libstdcxx_x64.gdt   # on 10.4
```

The workflow's `gcc-versions` job builds the probe with gcc 9, 11, 12 and 14 and fails if any of them lays
out a class it shares with the runner's gcc differently ([`compare_layouts.py`](compare_layouts.py)).

### gcc 3.3

`libstdcxx5_x86.gdt` and `libstdcxx5_x64.gdt` hold gcc 3.3's libstdc++ (`libstdc++.so.5`), from before
gcc 3.4 changed the C++ ABI and the containers' allocators: its `map` is 12 bytes on x86, not 24, and its
containers take `std::__default_alloc_template` nodes. [`gcc3_probe.sh`](gcc3_probe.sh) builds
[`stl_probe98.cpp`](stl_probe98.cpp), a C++98 probe that adds the `__gnu_cxx` extensions (`hash_map`, `slist`,
`rope`) and `strstream`, with Debian etch's `g++-3.3` in a debootstrapped chroot (root and `debootstrap`
needed). gcc 3.3 writes DWARF 2, which Ghidra reads, but without `-femit-class-debug-always` or namespaces:

- the probe links statically against etch's debug `libstdc++.a` (`libstdc++5-3.3-dbg`), whose units define
  the classes the headers only declare (`exception`, `logic_error`, `basic_filebuf`, the stream classes);
- the script takes each class's namespace from the program's mangled names, since the DWARF files
  `std::basic_string<…>` at the root, and widens the one-byte placeholder a unit left for a base it only
  declared.

```
sudo tools/stl-archives/gcc3_probe.sh probe i386     # or amd64
tools/stl-archives/run.sh gcc out/libstdcxx5_x86.gdt probe
```

gcc 3.0 to 3.2 (`libstdc++.so.3` and `.so.4`) and gcc 2.95 have no archive.

### In ghicpp

ghicpp's `libstdc++ layouts` analyzer applies the archive to an ELF that imports `libstdc++.so.6`, or a PE
that imports `libstdc++-6.dll` (MinGW's), or either one linking it statically (which shows in its `std::` functions' Itanium mangled names, outside libc++'s `std::__1`).
An ELF importing `libstdc++.so.5`, or linking gcc 3's library statically (which names
`std::__default_alloc_template`), gets the gcc 3.3 archive. A program with debug info of its own (DWARF or
stabs) is left alone, as its own types already lay the classes out.
It works as the MSVC one does. The demangler and the DWARF spell some names differently
(`pair<int_const,int>` against `pair<int_const,_int>`, `vector<std::string>` against the written-out
`basic_string`, `0ul` against `0`), so a class not found at its exact path is looked up by a key that leaves
those differences out (`ghicpp.stl.StlIndex`).
