"""Compares two layouts texts (ExportStlLayouts) of one architecture, from probes built by different gccs.

    compare_layouts.py <reference.txt> <other.txt>

Fails when a library class (under std or __gnu_cxx) both define differs in its size or in where its bytes
lie: the one archive ghicpp ships for an architecture would then misplace that class's fields for one of
the two compilers' programs. A class is compared flattened, each base or member of a class type replaced
by its own fields and empty classes left out, so that a member moved into a new base between releases
(gcc 10's `_Deque_impl_data`) or an empty base laid as a member compares equal. Field names, the types
only one of them has, and glibc's own types (`_IO_FILE`, `__pthread_cond_s`, which follow the C library
the probe was built against) are reported but do not fail.
"""
ROOTS = ("/std/", "/__gnu_cxx/")
import sys


def read(path):
    """The composites of a layouts text: path to (kind, size, [(offset, size, name, type)]), each member's
    type followed through the typedefs the text lists (gcc 14 types a list's header by `_Node_traits`'
    typedef of it)."""
    composites, typedefs = {}, {}
    current = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.startswith("\t"):
                fields = line.split("\t")
                current = None
                if fields[0] == "T" and len(fields) > 2:
                    typedefs[fields[1]] = fields[2]
                if fields[0] in ("S", "U") and int(fields[2]) > 0:
                    current = composites[fields[1]] = (fields[0], int(fields[2]), [])
            elif current is not None:
                member = line.lstrip("\t").split("\t")
                # A union's members have no offset.
                if current[0] == "U":
                    member.insert(0, "0")
                current[2].append((int(member[0]), int(member[1]), member[2], member[3] if len(member) > 3 else ""))
    def target(spec, seen=()):
        return target(typedefs[spec], seen + (spec,)) if spec in typedefs and spec not in seen else spec

    return {p: (k, n, [(o, z, m, target(t)) for o, z, m, t in members])
            for p, (k, n, members) in composites.items()}


def flat(composites, path, at=0, seen=()):
    """The (offset, size) of each field of the composite at [path], its library-class-typed fields' own in
    their place."""
    out = []
    for offset, size, _name, spec in composites[path][2]:
        # glibc's types (`pthread_cond_t`) stay whole: they follow the C library, not the compiler.
        if spec in composites and spec.startswith(ROOTS) and spec not in seen:
            out += flat(composites, spec, at + offset, seen + (path,))
        else:
            out.append((at + offset, size))
    return out


def users(composites, path, seen=None):
    """The composites that hold the one at [path] as a base or member, or hold one that does."""
    seen = set() if seen is None else seen
    for p, (_, _, members) in composites.items():
        if p not in seen and any(m[3] == path for m in members):
            seen.add(p)
            users(composites, p, seen)
    return seen


def named(composites, path):
    return [(m[0], m[1], m[2]) for m in composites[path][2]]


def main(reference, other):
    ours, theirs = read(reference), read(other)
    common = sorted(p for p in set(ours) & set(theirs) if p.startswith(ROOTS))
    differ = [p for p in common
              if ours[p][1] != theirs[p][1] or flat(ours, p) != flat(theirs, p)]
    # A base whose fields moved into the classes deriving from it, as gcc 11 moved `_Hash_node_value_base`'s
    # next pointer into `_Hash_node`: every class that holds it still lays out alike.
    def holders(p):
        return sorted((users(ours, p) | users(theirs, p)) & set(common))

    moved = [p for p in differ if holders(p) and
             all(ours[u][1] == theirs[u][1] and flat(ours, u) == flat(theirs, u) for u in holders(p))]
    differ = [p for p in differ if p not in moved]
    renamed = [p for p in common if p not in differ and named(ours, p) != named(theirs, p)]
    for path in moved:
        print(f"{path} differs, but every class holding it lays out alike")
    for path in differ:
        print(f"{path}:\n  {reference}: {ours[path][1]} {named(ours, path)}\n  {other}: {theirs[path][1]} {named(theirs, path)}")
    print(f"{len(common)} library composites compared, {len(differ)} differ, {len(renamed)} differ only in "
          f"their fields' names or nesting; {len(set(ours) - set(theirs))} only in {reference}, "
          f"{len(set(theirs) - set(ours))} only in {other}")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
