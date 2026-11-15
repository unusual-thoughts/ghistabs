# MSVC STL type archives

Ghidra data type archives (`.gdt`) of the MSVC standard library layouts, one per runtime, architecture
and CRT: `msvcp140_x86.gdt`, `msvcp140d_x64.gdt`, `msvcp90_x86.gdt` and so on. Types are named and
filed where Ghidra's Microsoft demangler puts a class (`/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>`),
so the `this` of a demangled `std::` method matches the archive type by path: the demangler's
placeholder is that path under `/Demangler`.

The [`MSVC STL archives`](../../.github/workflows/stl-archives.yml) workflow builds them and uploads
them as one artifact per archive, each downloading as its `.gdt` file. The published archives are
rebuilt on Ghidra 10.4 from the layouts text (see below), so 10.4 and every newer release opens them; the
`compat` job checks that 11.4, 12.0, 12.1 and 12.3 read them back unchanged.


| Archive | Source | Check |
| --- | --- | --- |
| `msvcp140_{x86,x64}` | [`stl_probe.cpp`](stl_probe.cpp) built with `/MD` on the runner's Visual Studio | same sizes and field offsets as Microsoft's public `msvcp140` PDB, for every type both define |
| `msvcp140d_{x86,x64}` | the probe built with `/MDd` (`_ITERATOR_DEBUG_LEVEL=2`) | |
| `msvcp90_{x86,x64}` | Microsoft's public PDB of msvcp90 9.0.30729.9619, the last security rebuild | |
| `msvcp60_x86` | `MSVCP60D.PDB` from the Visual C++ 6.0 Professional disc (archive.org's X04-58170), with its `MSVCP60D.DLL` as the program | |

msvcp60 serves both VC6 runtimes: its headers test `_DEBUG` only to pick the library to link, so the
debug DLL lays everything out as the release one does. The release `MSVCP60.PDB` on the disc stalls Ghidra
12.3's PDB applicator, and the debug one loses `strstream`, which nests deeper than the applicator follows.

msvcp90 covers what the DLL itself instantiates (strings, iostreams, locale and facets, exceptions),
not header-only containers, and has no debug variant: neither needs more than a VS2008 toolchain
running the same probe.

## Building one yourself

[`build/MsvcStlArchiveScript.java`](build/MsvcStlArchiveScript.java) builds one. It uses ghicpp's classes and Ghidra 12.2+ APIs, so it needs the
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

## In ghicpp

ghicpp ships the six 10.4 archives in `ghicpp/data/typeinfo/msvc/`, where Ghidra lists them with its own
archives (the ghistabs extension carries them too). Its `MSVC standard library layouts` analyzer reads the
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
