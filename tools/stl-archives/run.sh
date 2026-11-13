#!/usr/bin/env bash
# Headless driver for the MSVC STL archive scripts, against $GHIDRA_INSTALL_DIR (default /opt/ghidra).
#   run.sh archive <out.gdt> <program> <pdb>       build an archive from <pdb>; <program> is any binary
#                                                  of the PDB's architecture, the script reads its language
#   run.sh compare <program> <archive> <reference> fail if the two disagree on a std layout
#   run.sh layouts <program> <archive> <out.txt>   write the archive as the text ghicpp bundles
#   run.sh gdt <program> <layouts.txt> <out.gdt>   build an archive from that text, on this Ghidra
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
ghidra=${GHIDRA_INSTALL_DIR:-/opt/ghidra}

headless() {
    local program=$1 scripts=$2 script=$3
    shift 3
    local project log
    project=$(mktemp -d)
    log=$(mktemp)
    "$ghidra/support/analyzeHeadless" "$project" stl -import "$program" -noanalysis \
        -scriptPath "$scripts" -postScript "$script" "$@" -deleteProject 2>&1 | tee "$log" |
        grep -E "$script>|ERROR" | grep -v "warning: \[removal\]" || true
    rm -rf "$project"
    # analyzeHeadless exits 0 when a script throws, so read the verdict off its log.
    if grep -q "REPORT SCRIPT ERROR" "$log"; then
        rm -f "$log"
        return 1
    fi
    rm -f "$log"
}

case ${1:-} in
    archive) headless "$3" "$here/../../ghicpp/ghidra_scripts" MsvcStlArchiveScript.java "$4" "$2" ;;
    compare) headless "$2" "$here" CompareStlArchives.java "$3" "$4" ;;
    layouts) headless "$2" "$here" ExportStlLayouts.java "$3" "$4" ;;
    gdt) headless "$2" "$here" LayoutsToGdt.java "$3" "$4" ;;
    *) sed -n '2,7p' "$0"; exit 2 ;;
esac
