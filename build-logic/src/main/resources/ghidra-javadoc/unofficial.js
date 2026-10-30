/*
 * Marks every link to, and the page of, a class or package Ghidra's own API javadoc leaves out: all
 * of a module whose build doesn't apply gradle/javadoc.gradle, and what one that does excludes (Base's
 * ghidra/app/plugin/core). ghidraUnofficial, from
 * unofficial-pages.js, lists them by path from the doc root, without `.html`, with their module.
 */
(function () {
    "use strict";
    const data = window.ghidraUnofficial;
    if (!data) return;
    let root;

    function moduleOf(url) {
        if (url.origin !== root.origin || !url.pathname.startsWith(root.pathname)) return undefined;
        const index = data.pages[url.pathname.slice(root.pathname.length).replace(/\.html$/, "")];
        return index === undefined ? undefined : data.modules[index];
    }

    function markLink(a) {
        const url = new URL(a.href, location.href);
        // Its own contents, members and breadcrumb: the banner says it once.
        if (url.pathname === location.pathname) return;
        const module = moduleOf(url);
        if (module === undefined) return;
        a.classList.add("unofficial");
        a.title = "Not in Ghidra's API javadoc (" + module + ")";
    }

    // The search box's results are no links: jQuery UI keeps each one's index entry on its <li>, and
    // search.js's getURL makes the page's path from the doc root of it.
    function markResult(li) {
        const item = window.jQuery && jQuery(li).data("ui-autocomplete-item");
        if (!item || !item.indexItem || typeof getURL !== "function") return;
        const module = moduleOf(new URL(getURL(item.indexItem, item.category), root));
        if (module === undefined) return;
        li.classList.add("unofficial");
        li.title = "Not in Ghidra's API javadoc (" + module + ")";
    }

    function mark() {
        // The page sets pathtoroot after the scripts javadoc adds have run.
        root = new URL(typeof pathtoroot === "string" ? pathtoroot : "./", location.href);
        const module = moduleOf(new URL(location.href));
        const main = document.querySelector("main");
        if (module !== undefined && main) {
            const banner = document.createElement("div");
            banner.className = "unofficial-banner";
            banner.textContent = "Not in Ghidra's published API javadoc (" + module + ")";
            main.prepend(banner);
        }
        document.querySelectorAll("a[href]").forEach(markLink);
        // The search box's results are added later.
        new MutationObserver(function (records) {
            records.forEach(function (r) {
                r.addedNodes.forEach(function (n) {
                    if (n.nodeType !== 1) return;
                    if (n.matches("a[href]")) markLink(n);
                    n.querySelectorAll("a[href]").forEach(markLink);
                    if (n.matches("li.result-item")) markResult(n);
                    n.querySelectorAll("li.result-item").forEach(markResult);
                });
            });
        }).observe(document.body, { childList: true, subtree: true });
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mark);
    else mark();
})();
