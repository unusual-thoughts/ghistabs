#!/usr/bin/env bash
# Package import graph for src/main, one cluster per layer, layering violations in red,
# other edges between layers in dark blue.
#
#   1 kernel        ghidrakt, ghidrakt.diagnose                 Ghidra/Kotlin extensions, diagnostics
#                   (ghistabs, ghistabs.diagnose before the rename)
#   2 C++           ghicpp, ghicpp.abi, .eh, .recover, .gui …   C++ ABI, class passes, analyzers, window: no stabs
#   3 stabs         parse → harvest → index → materialize → scan → importer → render → entrypoints
#                   (entrypoints: the stabs analyzer, plugin and exporters, the last stage)
#
#   C++ stages      ghicpp (model) → ghicpp.dissect, ghicpp.eh → ghicpp.abi → ghicpp.structs →
#                   ghicpp.recover → ghicpp.hierarchy → ghicpp.analyzers → ghicpp.gui
#
# An edge is a violation when it points up this stack: a layer importing a higher one (so ghicpp
# importing any stabs stage), or an earlier stage of a layer importing a later one. An edge that closes
# a cycle between packages of one stage is one too. A package in no layer, or a C++ or stabs
# package in no stage, is flagged too, so a new one has to be placed here. Counts are import lines, not distinct edges, so weight tracks how
# entangled a pair is.
#
# A package is folded to two levels (`ghicpp.abi.itanium` into `ghicpp.abi`) and self-loops dropped.
# An import is attributed to the deepest declared package it names, so `import ghicpp.isTemplated`
# counts as `ghicpp` and `import ghidrakt.at` as the kernel. Packages outside ghidrakt/ghistabs/ghicpp (the
# `ghidra.*` compat shims) are left out.
#
# Usage: import_graph.sh [out.pdf]   — no argument opens it in okular.
#        import_graph.sh --text      — the edges as text, violations first; exits 1 on any.
#        import_graph.sh --markdown FILE — appends a job-summary section to FILE (CI passes
#                                          $GITHUB_STEP_SUMMARY): the violations as a table, then the
#                                          graph as mermaid; prints a `::warning` annotation for each
#                                          violation; exits 0.
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
                if (p == "ghicpp" || p ~ /^ghicpp\./) return 2
                if (p ~ /^ghistabs\./) return 3
                return 0
            }
            # The stage of a C++ or stabs package; packages of one stage may import each other, short
            # of a cycle. Absent: a package of that layer no stage was given.
            function stageOf(p,   n) {
                if (p in stage) return stage[p]
                return ""
            }
            BEGIN {
                n = split("parse harvest index materialize scan importer render entrypoints", s, " ")
                for (i = 1; i <= n; i++) stage["ghistabs." s[i]] = i
                # model → dissect, eh → abi → structs → recover → hierarchy → analyzers → gui
                stage["ghicpp"] = 1
                stage["ghicpp.dissect"] = stage["ghicpp.eh"] = 2
                stage["ghicpp.abi"] = 3
                stage["ghicpp.structs"] = 4
                stage["ghicpp.recover"] = 5
                stage["ghicpp.hierarchy"] = 6
                stage["ghicpp.analyzers"] = 7
                stage["ghicpp.gui"] = 8
            }
            {
                cnt[++m] = $1; from[m] = $2; to[m] = $3; node[$2]; node[$3]
                if (layerOf($2) == layerOf($3) && stageOf($2) == stageOf($3)) reach[$2, $3] = 1
            }
            END {
                # Closure over the edges within a stage: an edge u → v of one stage closes a cycle when v
                # reaches u without leaving it. A cycle across stages has an edge up a stage already.
                for (k in node) for (i in node) if ((i, k) in reach) for (j in node) if ((k, j) in reach) reach[i, j] = 1
                for (e = 1; e <= m; e++) {
                    f = from[e]; t = to[e]
                    lf = layerOf(f); lt = layerOf(t)
                    sf = stageOf(f); st = stageOf(t)
                    if (lf == 0 || lt == 0) why = "package-in-no-layer"
                    else if (lf < lt) why = "imports-a-higher-layer"
                    else if (lf == lt && lf > 1 && (sf == "" || st == "")) why = "package-in-no-stage"
                    else if (lf == lt && lf > 1 && sf < st) why = "imports-a-later-stage"
                    else if (((f, t) in reach) && ((t, f) in reach)) why = "closes-a-cycle"
                    else why = "-"
                    print cnt[e], f, t, why != "-", why, lf, lt
                }
            }'
}

dot_source() {
    edges | awk '
        function q(p) { return "\"" p "\"" }
        {
            e[++m] = $0
            if (!($2 in layer)) order[++k] = $2
            if (!($3 in layer)) order[++k] = $3
            layer[$2] = $6; layer[$3] = $7
            if ($4) v += $1; else ok += $1
        }
        END {
            print "digraph {"
            # Counts go in xlabel: graphviz 2.42 fails in init_rank on labelled edges between clusters,
            # and newrank (the other way round it) lets the clusters drift apart.
            print "  rankdir=LR; compound=true; node [shape=box style=rounded]; edge [fontsize=10];"
            split("kernel|C++|stabs", title, "|")
            title[0] = "in no layer"
            # One cluster per layer, as in the mermaid render.
            for (L = 0; L <= 3; L++) {
                body = ""
                for (j = 1; j <= k; j++) if (layer[p = order[j]] == L) body = body "    " q(p) ";\n"
                # An invisible point per cluster anchors the layer-to-kernel edges below. Outside the
                # kernel it ranks after every package of its layer, so the kernel lands at the far end.
                if (body != "")
                    printf "  subgraph cluster_%d {\n    label=\"%d %s\"; style=\"rounded,dashed\"; color=gray50;\n    anchor_%d [shape=point style=invis width=0];\n%s  }\n",
                        L, L, title[L], L, body
            }
            for (i = 1; i <= m; i++) {
                split(e[i], f, " ")
                # Every layer may import the kernel, so those imports are drawn as one edge per layer,
                # cluster to cluster, below rather than package by package.
                if (!f[4] && f[7] == 1 && f[6] != 1) { tokernel[f[6]] += f[1]; continue }
                # A violation does not rank, so the layout keeps the layer order and the red edge points back.
                # An allowed edge between two layers is dark blue, to tell it from one within a layer.
                printf "  %s -> %s [xlabel=%d penwidth=%.1f%s];\n",
                    q(f[2]), q(f[3]), f[1], 0.5 + f[1] / 8.0,
                    f[4] ? " color=red fontcolor=red constraint=false" : f[6] != f[7] ? " color=navy fontcolor=navy" : ""
            }
            for (j = 1; j <= k; j++) if ((L = layer[p = order[j]]) in tokernel) printf "  %s -> anchor_%d [style=invis];\n", q(p), L
            for (L = 2; L <= 3; L++) if (L in tokernel)
                printf "  anchor_%d -> anchor_1 [ltail=cluster_%d lhead=cluster_1 xlabel=%d penwidth=%.1f color=gray50 fontcolor=gray40];\n",
                    L, L, tokernel[L], 0.5 + tokernel[L] / 40.0
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
        function id(p) { gsub(/\./, "_", p); return p }
        {
            e[++m] = $0
            if ($4) { v += $1; bad[++n] = $0 } else ok += $1
            if (!($2 in layer)) order[++k] = $2
            if (!($3 in layer)) order[++k] = $3
            layer[$2] = $6; layer[$3] = $7
        }
        END {
            print "## Package layering" >> out
            print "" >> out
            if (n == 0) printf "No layering violations (%d imports between packages).\n", ok >> out
            else {
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
            }

            # The whole graph, one box per layer, violations in red. Open by default only when it has some.
            print "" >> out
            printf "<details%s><summary>Import graph</summary>\n\n", n ? " open" : "" >> out
            print "```mermaid" >> out
            print "graph LR" >> out
            split("kernel|C++|stabs", title, "|")
            title[0] = "in no layer"
            for (L = 0; L <= 3; L++) {
                body = ""
                for (j = 1; j <= k; j++) if (layer[p = order[j]] == L) body = body sprintf("    %s[\"%s\"]\n", id(p), p)
                if (body != "") printf "  subgraph L%d[\"%d %s\"]\n%s  end\n", L, L, title[L], body >> out
            }
            red = ""
            for (i = 1; i <= m; i++) {
                split(e[i], f, " ")
                printf "  %s -->|%d| %s\n", id(f[2]), f[1], id(f[3]) >> out
                if (f[4]) red = red (red == "" ? "" : ",") (i - 1)
            }
            if (red != "") printf "  linkStyle %s stroke:#d1242f,stroke-width:2px,color:#d1242f\n", red >> out
            print "```" >> out
            print "" >> out
            print "</details>" >> out
        }'
}

case "${1:-}" in
    --text) text ;;
    --markdown) markdown "${2:?--markdown needs the file to append to}" ;;
    "") dot_source | dot -Tpdf | okular - ;;
    *) dot_source | dot -Tpdf -o "$1" ;;
esac
