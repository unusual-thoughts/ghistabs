#!/usr/bin/env bash
# Package import graph for src/main, laid out as the layers with layering violations in red.
#
#   1 kernel        ghidrakt, ghidrakt.diagnose                 Ghidra/Kotlin extensions, diagnostics
#                   (ghistabs, ghistabs.diagnose before the rename)
#   2 C++           ghicpp, ghicpp.abi, .eh, .recover, .gui …   C++ ABI, class passes, window: no stabs
#   3 C++ shell     ghicpp.entrypoints                          the C++ analyzers and plugin
#   4 stabs         parse → harvest → index → materialize → scan → importer → render
#   5 stabs shell   ghistabs.entrypoints                        the stabs analyzer, plugin, exporters
#
# An edge is a violation when it points up this stack: a layer importing a higher one (so ghicpp
# importing any stabs stage or ghistabs.entrypoints), or an earlier stabs stage importing a later one.
# Packages within the C++ layer may import each other. A package in no layer is flagged too, so a
# new one has to be placed here. Counts are import lines, not distinct edges, so weight tracks how
# entangled a pair is.
#
# A package is folded to two levels (`ghicpp.abi.itanium` into `ghicpp.abi`) and self-loops dropped.
# An import is attributed to the deepest declared package it names, so `import ghicpp.isTemplated`
# counts as `ghicpp` and `import ghidrakt.at` as the kernel. Packages outside ghidrakt/ghistabs/ghicpp (the
# `ghidra.*` compat shims) are left out.
#
# Usage: import_graph.sh [out.pdf]   — no argument opens it in okular.
#        import_graph.sh --text      — the edges as text, violations first; exits 1 on any.
#        import_graph.sh --markdown FILE — appends a job-summary section listing the violations to FILE
#                                          (CI passes $GITHUB_STEP_SUMMARY) and prints a `::warning`
#                                          annotation for each; exits 0.
set -euo pipefail

ROOTS='ghidrakt|ghistabs|ghicpp'

edges() {
    # Every package line, not only ours: a file in a `ghidra.*` shim package must not have its imports
    # credited to whichever of our packages the previous file declared. build-logic is the build, not the code.
    git grep --untracked -h -oP "^(package [\w.]+|import (${ROOTS})(\.\w+)*)" -- \
        ":(glob)src/main/**" ":(glob)*/src/main/**" ":(exclude)build-logic/**" |
        awk '
            function fold(p,   n, a) { n = split(p, a, "."); return n > 2 ? a[1] "." a[2] : p }
            # The deepest declared package that prefixes the imported name, folded.
            function owner(name,   p) {
                p = name
                while (p != "") {
                    if (p in declared) return fold(p)
                    if (index(p, ".") == 0) return ""
                    sub(/\.[^.]*$/, "", p)
                }
                return ""
            }
            function ours(p) { return p ~ /^(ghidrakt|ghistabs|ghicpp)(\.|$)/ }
            { line[NR] = $0; if ($1 == "package" && ours($2)) declared[$2] = 1 }
            END {
                for (i = 1; i <= NR; i++) {
                    split(line[i], f, " ")
                    if (f[1] == "package") { pkg = ours(f[2]) ? fold(f[2]) : ""; continue }
                    to = owner(f[2])
                    if (pkg != "" && to != "" && to != pkg) print pkg, to
                }
            }' |
        sort | uniq -c |
        awk '
            function layerOf(p) {
                if (p == "ghidrakt" || p == "ghidrakt.diagnose" || p == "ghistabs" || p == "ghistabs.diagnose") return 1
                if (p == "ghicpp.entrypoints") return 3
                if (p == "ghicpp" || p ~ /^ghicpp\./) return 2
                if (p == "ghistabs.entrypoints") return 5
                if (p in rank) return 4
                return 0
            }
            BEGIN {
                n = split("parse harvest index materialize scan importer render", s, " ")
                for (i = 1; i <= n; i++) rank["ghistabs." s[i]] = i
            }
            {
                cnt = $1; from = $2; to = $3
                lf = layerOf(from); lt = layerOf(to)
                bad = (lf == 0 || lt == 0) || lf < lt ||
                      ((from in rank) && (to in rank) && rank[from] < rank[to])
                why = (lf == 0 || lt == 0) ? "package-in-no-layer" : lf < lt ? "imports-a-higher-layer" : bad ? "imports-a-later-stabs-stage" : "-"
                print cnt, from, to, bad, why
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

markdown() {
    local out="$1"
    edges | sort -k4,4nr -k1,1nr | awk -v out="$out" '
        function why(w) { gsub(/-/, " ", w); return w }
        { if ($4) { v += $1; bad[++n] = $0 } else ok += $1 }
        END {
            print "## Package layering" >> out
            print "" >> out
            if (n == 0) { printf "No layering violations (%d imports between packages).\n", ok >> out; exit 0 }
            printf "**%d** violating import%s over **%d** edge%s, of %d imports between packages.\n",
                v, v == 1 ? "" : "s", n, n == 1 ? "" : "s", v + ok >> out
            print "" >> out
            print "| Imports | From | To | Why |" >> out
            print "|---:|---|---|---|" >> out
            for (i = 1; i <= n; i++) {
                split(bad[i], f, " ")
                printf "| %d | `%s` | `%s` | %s |\n", f[1], f[2], f[3], why(f[5]) >> out
                printf "::warning title=Layering violation::%s imports %s (%d import%s): %s\n",
                    f[2], f[3], f[1], f[1] == 1 ? "" : "s", why(f[5])
            }
        }'
}

case "${1:-}" in
    --text) text ;;
    --markdown) markdown "${2:?--markdown needs the file to append to}" ;;
    "") dot_source | dot -Tpdf | okular - ;;
    *) dot_source | dot -Tpdf -o "$1" ;;
esac
