#!/usr/bin/env bash
# Package import graph for src/main, laid out as the pipeline with layering violations in red.
#
#   kernel      ghistabs, ghistabs.diagnose       Ghidra/Kotlin extensions, diagnostics
#   generic     ghistabs.cpp                      C++ ABI and the passes that need no stabs
#   stabs       parse → harvest → index → materialize → scan → importer → render
#   shell       entrypoints                       the analyzers, plugin and exporter Ghidra loads
#
# An edge is a violation when it points up this stack: the kernel importing anything above it, the
# generic layer importing a stabs stage, or an earlier stage importing a later one. Counts are import
# lines, not distinct edges, so weight tracks how entangled a pair is — `render → harvest` is 22 and
# fine, `harvest → importer` is 3 and is the bug.
#
# Matches one package level, which folds subpackages into their parent (`cpp.abi` into `cpp`), and
# drops the self-loops that leaves. Imports of the root package's own declarations (`import ghistabs.x`)
# are not matched: everything may import the kernel.
#
# Usage: tools/import_graph2.sh [out.pdf]   — no argument opens it in okular.
#        tools/import_graph2.sh --text      — the edges as text, violations first; exits 1 on any.
set -euo pipefail

edges() {
    git grep --untracked -h -oP '^(package ghistabs(\.(\w+))?|import ghistabs\.[a-z]+(?=\.))' src/main/ |
        awk '$1 == "package" { pkg = $2; next } { print pkg, $2 }' |
        sort | uniq -c |
        awk '
            BEGIN {
                n = split("ghistabs ghistabs.diagnose", k, " ")
                for (i = 1; i <= n; i++) layer[k[i]] = 1
                layer["ghistabs.cpp"] = 2
                n = split("parse harvest index materialize scan importer render", s, " ")
                for (i = 1; i <= n; i++) { layer["ghistabs." s[i]] = 3; rank["ghistabs." s[i]] = i }
                layer["ghistabs.entrypoints"] = 4
            }
            {
                cnt = $1; from = $2; to = $3
                if (from == to) next                       # one-level matching folds subpackages in
                lf = layer[from]; lt = layer[to]
                bad = (lf && lt && lf < lt && !(lf == 1 && lt == 1)) ||
                      (rank[from] && rank[to] && rank[from] < rank[to])
                print cnt, from, to, bad
            }'
}

dot_source() {
    edges | awk '
        BEGIN {
            print "digraph {"
            print "  rankdir=LR; node [shape=box style=rounded]; edge [fontsize=10];"
        }
        {
            cnt = $1; from = $2; to = $3; bad = $4
            printf "  \"%s\" -> \"%s\" [label=%d penwidth=%.1f%s];\n",
                from, to, cnt, 0.5 + cnt / 8.0, bad ? " color=red fontcolor=red" : ""
            if (bad) v += cnt; else ok += cnt
        }
        END {
            printf "  labelloc=b; label=\"%d violating imports / %d total\";\n", v, v + ok
            print "}"
        }'
}

text() {
    edges | sort -k4,4nr -k1,1nr | awk '
        { printf "%s %5d  %s -> %s\n", $4 ? "VIOLATION" : "         ", $1, $2, $3; if ($4) v += $1; else ok += $1 }
        END { printf "%d violating imports / %d total\n", v, v + ok; exit v > 0 }'
}

case "${1:-}" in
    --text) text ;;
    "") dot_source | dot -Tpdf | okular - ;;
    *) dot_source | dot -Tpdf -o "$1" ;;
esac
