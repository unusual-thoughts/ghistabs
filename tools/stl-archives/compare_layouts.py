"""Compares two layouts texts (ExportStlLayouts) of one architecture, from probes built by different gccs.

    compare_layouts.py <reference.txt> <other.txt>

Fails when a struct or union both define differs in its size or in a field's offset, size or name: the
one archive ghicpp ships for an architecture would then misplace that class's fields for one of the two
compilers' programs. The types only one of them has, and the names the fields' types go by (a copy's
`#<n>` follows its compiler's units), are reported but do not fail.
"""
import sys


def read(path):
    """The composites of a layouts text: path to (kind, size, [(offset, size, name)])."""
    composites = {}
    current = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.startswith("\t"):
                fields = line.split("\t")
                current = None
                if fields[0] in ("S", "U") and int(fields[2]) > 0:
                    current = composites[fields[1]] = (fields[0], int(fields[2]), [])
            elif current is not None:
                member = line.lstrip("\t").split("\t")
                # A union's members have no offset.
                if current[0] == "U":
                    member.insert(0, "0")
                current[2].append((int(member[0]), int(member[1]), member[2]))
    return composites


def main(reference, other):
    ours, theirs = read(reference), read(other)
    common = sorted(set(ours) & set(theirs))
    differ = [p for p in common if ours[p] != theirs[p]]
    for path in differ:
        print(f"{path}:\n  {reference}: {ours[path][1]} {ours[path][2]}\n  {other}: {theirs[path][1]} {theirs[path][2]}")
    print(f"{len(common)} composites compared, {len(differ)} differ; "
          f"{len(set(ours) - set(theirs))} only in {reference}, {len(set(theirs) - set(ours))} only in {other}")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
