#!/usr/bin/env python3
"""Package import graph for src/main: one cluster per layer, layering violations in red.

Layers, bottom up:

  1 kernel   ghidrakt, ghidrakt.diagnose
  2 C++      stages: ghicpp (model) → ghicpp.dissect, ghicpp.eh, ghicpp.fixup → ghicpp.abi →
             ghicpp.structs → ghicpp.recover → ghicpp.hierarchy → ghicpp.analyzers → ghicpp.gui
  3 stabs    stages: parse → harvest → index → materialize → scan → importer → render → entrypoints

An edge is a violation when it points up this stack: a layer importing a higher one (so ghicpp
importing anything of stabs), or an earlier stage of a layer importing a later one. An edge that closes
a cycle between packages of one stage is one too; a cycle across stages already has an edge up a stage.
A package in no layer, or a C++ or stabs package in no stage, is flagged too, so a new one has to be
placed here. Counts are import lines, not distinct edges, so weight tracks how entangled a pair is.

A package is folded to two levels (`ghicpp.abi.itanium` into `ghicpp.abi`) and self-loops dropped. An
import is attributed to the deepest declared package it names, so `import ghicpp.isTemplated` counts as
`ghicpp` and `import ghidrakt.at` as the kernel. Packages outside ghidrakt/ghistabs/ghicpp (the
`ghidra.*` compat shims) are left out, and so is build-logic, which is the build, not the code.

Usage:
  import_graph.py [out.pdf]        the graph through graphviz; no argument opens it in okular
  import_graph.py --dot            the graphviz source on stdout
  import_graph.py --text           the edges as text, violations first; exits 1 on any
  import_graph.py --markdown FILE  appends a job-summary section to FILE (CI passes
                                   $GITHUB_STEP_SUMMARY): the violations as a table, then the graph as
                                   mermaid; prints a `::warning` annotation per violation; exits 0
"""
import argparse
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOTS = ("ghidrakt", "ghistabs", "ghicpp")
KERNEL = {"ghidrakt", "ghidrakt.diagnose"}
LAYER_TITLES = {0: "in no layer", 1: "kernel", 2: "C++", 3: "stabs"}

# Packages of one stage may import each other, short of a cycle.
CPP_STAGES = [
    ["ghicpp"],
    ["ghicpp.dissect", "ghicpp.eh", "ghicpp.fixup"],
    ["ghicpp.abi"],
    ["ghicpp.structs"],
    ["ghicpp.recover"],
    ["ghicpp.hierarchy"],
    ["ghicpp.analyzers"],
    ["ghicpp.gui"],
]
STABS_STAGES = ["parse", "harvest", "index", "materialize", "scan", "importer", "render", "entrypoints"]
STAGE = {p: i for i, stage in enumerate(CPP_STAGES, 1) for p in stage} | {
    f"ghistabs.{s}": i for i, s in enumerate(STABS_STAGES, 1)
}

LINE = re.compile(r"^(package|import) ([\w.]+)")
OURS = re.compile(rf"^({'|'.join(ROOTS)})(\.|$)")

RED, BLUE, GREY = "#d1242f", "#000080", "#808080"


@dataclass
class Edge:
    count: int
    src: str
    dst: str
    why: str  # empty when allowed

    @property
    def bad(self):
        return bool(self.why)


def fold(p):
    return ".".join(p.split(".")[:2])


def layer_of(p):
    if p in KERNEL:
        return 1
    if p == "ghicpp" or p.startswith("ghicpp."):
        return 2
    if p.startswith("ghistabs."):
        return 3
    return 0


def sources(root):
    """Every Kotlin and Java source under a src/main, build-logic aside."""
    for main in [root / "src/main", *root.glob("*/src/main")]:
        if main.parts[len(root.parts)] == "build-logic":
            continue
        yield from (f for f in main.rglob("*") if f.suffix in (".kt", ".java"))


def edges(root):
    files = []
    for f in sources(root):
        pkg, imports = None, []
        for line in f.read_text(errors="replace").splitlines():
            m = LINE.match(line)
            if not m:
                continue
            kind, name = m.groups()
            if kind == "package":
                pkg = name
            elif OURS.match(name):
                imports.append(name)
        files.append((pkg, imports))
    declared = {pkg for pkg, _ in files if pkg and OURS.match(pkg)}

    def owner(name):
        """The deepest declared package that prefixes the imported name, folded."""
        parts = name.split(".")
        for n in range(len(parts), 0, -1):
            if ".".join(parts[:n]) in declared:
                return fold(".".join(parts[:n]))
        return None

    counts = Counter()
    for pkg, imports in files:
        if not (pkg and OURS.match(pkg)):
            continue
        src = fold(pkg)
        for name in imports:
            dst = owner(name)
            if dst and dst != src:
                counts[src, dst] += 1

    # Closure over the edges within a stage: an edge u → v of one stage closes a cycle when v reaches
    # u without leaving it.
    def same_stage(a, b):
        return layer_of(a) == layer_of(b) and STAGE.get(a) == STAGE.get(b)

    reach = {(a, b) for a, b in counts if same_stage(a, b)}
    nodes = {p for pair in counts for p in pair}
    for k in nodes:
        for i in nodes:
            if (i, k) in reach:
                reach |= {(i, j) for j in nodes if (k, j) in reach}

    def why(a, b):
        la, lb = layer_of(a), layer_of(b)
        if la == 0 or lb == 0:
            return "package in no layer"
        if la < lb:
            return "imports a higher layer"
        if la == lb > 1:
            sa, sb = STAGE.get(a), STAGE.get(b)
            if sa is None or sb is None:
                return "package in no stage"
            if sa < sb:
                return "imports a later stage"
        if (a, b) in reach and (b, a) in reach:
            return "closes a cycle"
        return ""

    out = [Edge(n, a, b, why(a, b)) for (a, b), n in counts.items()]
    return sorted(out, key=lambda e: (not e.bad, -e.count, e.src, e.dst))


def by_layer(es):
    """Each layer's packages, in first-seen order."""
    seen = {}
    for e in es:
        for p in (e.src, e.dst):
            seen.setdefault(p, layer_of(p))
    return {layer: [p for p, lp in seen.items() if lp == layer] for layer in sorted(set(seen.values()))}


def kernel_imports(es):
    """Imports of the kernel per layer above it: every layer may, so they are drawn one edge per layer."""
    totals = Counter()
    for e in es:
        if not e.bad and layer_of(e.dst) == 1 and layer_of(e.src) > 1:
            totals[layer_of(e.src)] += e.count
    return totals


def detailed(es):
    return [e for e in es if e.bad or not (layer_of(e.dst) == 1 and layer_of(e.src) > 1)]


def colour(e):
    if e.bad:
        return RED
    return BLUE if layer_of(e.src) != layer_of(e.dst) else None


def summary_line(es):
    v = sum(e.count for e in es if e.bad)
    return v, sum(e.count for e in es)


def dot(es):
    q = '"{}"'.format
    out = [
        "digraph {",
        # Counts go in xlabel: graphviz 2.42 fails in init_rank on labelled edges between clusters,
        # and newrank (the other way round it) lets the clusters drift apart.
        "  rankdir=LR; compound=true; node [shape=box style=rounded]; edge [fontsize=10];",
    ]
    layers = by_layer(es)
    totals = kernel_imports(es)
    for layer, pkgs in layers.items():
        # An invisible point per cluster anchors the layer-to-kernel edges. Outside the kernel it
        # ranks after every package of its layer, so the kernel lands at the far end.
        out.append(f"  subgraph cluster_{layer} {{")
        out.append(f'    label="{layer} {LAYER_TITLES[layer]}"; style="rounded,dashed"; color=gray50;')
        out.append(f"    anchor_{layer} [shape=point style=invis width=0];")
        out += [f"    {q(p)};" for p in pkgs]
        out.append("  }")
    for e in detailed(es):
        attrs = f"xlabel={e.count} penwidth={0.5 + e.count / 8:.1f}"
        if c := colour(e):
            attrs += f' color="{c}" fontcolor="{c}"'
        if e.bad:
            # A violation does not rank, so the layout keeps the layer order and the edge points back.
            attrs += " constraint=false"
        out.append(f"  {q(e.src)} -> {q(e.dst)} [{attrs}];")
    for layer, n in sorted(totals.items()):
        out += [f"  {q(p)} -> anchor_{layer} [style=invis];" for p in layers[layer]]
        out.append(
            f"  anchor_{layer} -> anchor_1 [ltail=cluster_{layer} lhead=cluster_1 xlabel={n} "
            f'penwidth={0.5 + n / 40:.1f} color="{GREY}" fontcolor="{GREY}"];'
        )
    v, total = summary_line(es)
    out += [f'  labelloc=b; label="{v} violating imports / {total} total";', "}"]
    return "\n".join(out) + "\n"


def mermaid(es):
    def ident(p):
        return p.replace(".", "_")

    out = ["graph LR"]
    for layer, pkgs in by_layer(es).items():
        out.append(f'  subgraph L{layer}["{layer} {LAYER_TITLES[layer]}"]')
        out += [f'    {ident(p)}["{p}"]' for p in pkgs]
        out.append("  end")
    styles = {}
    shown = detailed(es)
    for i, e in enumerate(shown):
        out.append(f"  {ident(e.src)} -->|{e.count}| {ident(e.dst)}")
        if c := colour(e):
            styles.setdefault(c, []).append(i)
    for j, (layer, n) in enumerate(sorted(kernel_imports(es).items()), len(shown)):
        out.append(f"  L{layer} -->|{n}| L1")
        styles.setdefault(GREY, []).append(j)
    for c, idx in styles.items():
        width = "2px" if c == RED else "1px"
        out.append(f"  linkStyle {','.join(map(str, idx))} stroke:{c},stroke-width:{width},color:{c}")
    return "\n".join(out)


def markdown(es):
    bad = [e for e in es if e.bad]
    v, total = summary_line(es)
    lines = ["## Package layering", ""]
    if not bad:
        lines.append(f"No layering violations ({total} imports between packages).")
    else:
        lines += [
            f"**{v}** violating import{'s' * (v != 1)} over **{len(bad)}** edge{'s' * (len(bad) != 1)}, "
            f"of {total} imports between packages.",
            "",
            "| Imports | From | To | Why |",
            "|---:|---|---|---|",
        ]
        lines += [f"| {e.count} | `{e.src}` | `{e.dst}` | {e.why} |" for e in bad]
    # The whole graph, one box per layer. Open by default only when it has violations.
    lines += ["", f"<details{' open' if bad else ''}><summary>Import graph</summary>", "", "```mermaid",
              mermaid(es), "```", "", "</details>"]
    return "\n".join(lines) + "\n"


def text(es):
    rows = [f"{'VIOLATION' if e.bad else '':9} {e.count:5d}  {e.src} -> {e.dst}" for e in es]
    v, total = summary_line(es)
    return "\n".join(rows + [f"{v} violating imports / {total} total"]) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--text", action="store_true")
    mode.add_argument("--dot", action="store_true")
    mode.add_argument("--markdown", type=Path, metavar="FILE")
    p.add_argument("pdf", nargs="?", type=Path)
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = p.parse_args(argv)
    es = edges(args.root)

    if args.text:
        sys.stdout.write(text(es))
        return 1 if any(e.bad for e in es) else 0
    if args.dot:
        sys.stdout.write(dot(es))
        return 0
    if args.markdown:
        with args.markdown.open("a") as f:
            f.write(markdown(es))
        for e in es:
            if e.bad:
                print(f"::warning title=Layering violation::{e.src} imports {e.dst} "
                      f"({e.count} import{'s' * (e.count != 1)}): {e.why}")
        return 0
    if args.pdf:
        subprocess.run(["dot", "-Tpdf", "-o", str(args.pdf)], input=dot(es), text=True, check=True)
    else:
        pdf = subprocess.run(["dot", "-Tpdf"], input=dot(es), capture_output=True, check=True).stdout
        subprocess.run(["okular", "-"], input=pdf, check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
