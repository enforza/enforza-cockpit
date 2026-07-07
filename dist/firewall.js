/*
 * firewall.js — enforza-cockpit firewall policy editor (vanilla, Cockpit-native).
 *
 * Edits a policy document (objects + to/through/from-firewall sections), renders
 * it to nftables JSON via render.js, and drives the privileged backend
 * (enforza-nft.py) to validate / apply / confirm / revert. The look & feel is the
 * enforza CCX console (tokens.css + base.css); the layout mirrors the CCX
 * PolicyDetailPage (tab strip → section cards → rule table + RuleSheet drawer).
 *
 * All kernel + persistence work happens in enforza-nft.py, invoked as root via
 * cockpit.spawn({superuser:"require"}); the browser only edits the document and
 * renders JSON. Applies are wrapped in confirm-or-revert so a lockout auto-heals.
 */
"use strict";

/* eslint-env browser */
/* global cockpit, enforzaRender */

const HELPER = "/usr/share/cockpit/enforza/enforza-nft.py";
const REVERT_TIMEOUT = 60;  // seconds the operator has to confirm before auto-revert

// ─── DOM helper ──────────────────────────────────────────────────────────────
function h(spec, props, children) {
    const [tag, ...classes] = spec.split(".");
    const el = document.createElement(tag || "div");
    if (classes.length) el.className = classes.join(" ");
    if (props) for (const k in props) {
        const v = props[k];
        if (v == null || v === false) continue;
        if (k === "onclick") el.addEventListener("click", v);
        else if (k === "oninput") el.addEventListener("input", v);
        else if (k === "onchange") el.addEventListener("change", v);
        else if (k === "value") el.value = v;
        else if (k === "checked") el.checked = !!v;
        else if (k === "html") el.innerHTML = v;
        else if (k === "style") el.setAttribute("style", v);
        else el.setAttribute(k, v);
    }
    for (const c of [].concat(children || [])) {
        if (c == null || c === false) continue;
        el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return el;
}

// ─── Icons (lucide paths) ────────────────────────────────────────────────────
const ICON_PATHS = {
    "to-firewall": ["M17 12H3", "m11 18 6-6-6-6", "M21 5v14"],
    "through-firewall": ["M5 12h14", "m12 5 7 7-7 7"],
    "from-firewall": ["M3 5v14", "M21 12H7", "m15 18 6-6-6-6"],
    objects: ["M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z", "m3.3 7 8.7 5 8.7-5", "M12 22V12"],
    refresh: ["M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8", "M21 3v5h-5", "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16", "M8 16H3v5"],
    moon: ["M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"],
    sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "M17.7 17.7l1.4 1.4", "M2 12h2", "M20 12h2", "M4.9 19.1l1.4-1.4", "M17.7 6.3l1.4-1.4"],
    plus: ["M5 12h14", "M12 5v14"],
    pencil: ["M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z", "m15 5 4 4"],
    trash: ["M3 6h18", "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2", "M10 11v6", "M14 11v6"],
    x: ["M18 6 6 18", "m6 6 12 12"],
    save: ["M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z", "M17 21v-8H7v8", "M7 3v5h8"],
    eye: ["M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z", "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z"],
    upload: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M17 8l-5-5-5 5", "M12 3v12"],
    check: ["M20 6 9 17l-5-5"],
    revert: ["M3 12a9 9 0 1 0 3-6.7L3 8", "M3 3v5h5"],
    grip: ["M9 5a1 1 0 1 0 .01 0", "M9 12a1 1 0 1 0 .01 0", "M9 19a1 1 0 1 0 .01 0", "M15 5a1 1 0 1 0 .01 0", "M15 12a1 1 0 1 0 .01 0", "M15 19a1 1 0 1 0 .01 0"],
};
function icon(name, size) {
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", String(size || 14));
    svg.setAttribute("height", String(size || 14));
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    for (const d of ICON_PATHS[name] || []) {
        const p = document.createElementNS(NS, "path");
        p.setAttribute("d", d);
        svg.appendChild(p);
    }
    return svg;
}

// ─── Section metadata (copy from CCX SECTION_META) ───────────────────────────
const SECTIONS = [
    { key: "to-firewall", hook: "input", label: "Management", title: "Management Rules",
      blurb: "Inbound traffic terminating on the firewall itself — SSH, management, health-check probes. Limit this section to known trusted networks; the default action should typically be DROP." },
    { key: "through-firewall", hook: "forward", label: "Network", title: "Network Rules",
      blurb: "Traffic passing through the firewall between protected hosts and the outside world. The bulk of your data-plane policy lives here. First-match wins; default drops anything not explicitly accepted." },
    { key: "from-firewall", hook: "output", label: "Local", title: "Local Rules",
      blurb: "Outbound traffic originating from the firewall host itself (config polls, log uploads, package updates). Loosen this only as far as the host actually needs to reach out." },
];
const SECTION_BY_KEY = Object.fromEntries(SECTIONS.map((s) => [s.key, s]));

// ─── Backend helper (root, JSON in/out) ──────────────────────────────────────
function helper(cmd, stdinObj) {
    const proc = cockpit.spawn(["python3", HELPER, cmd], { superuser: "require", err: "message" });
    proc.input(stdinObj !== undefined ? JSON.stringify(stdinObj) : "");
    return proc.then((txt) => {
        try { return JSON.parse(txt || "{}"); }
        catch (e) { throw new Error("Unexpected backend output: " + txt); }
    });
}

// ─── State ───────────────────────────────────────────────────────────────────
const state = {
    policy: null, savedJson: "", active: "to-firewall",
    drawer: null,     // { section, index }  (index -1 = new rule)
    objDlg: null,     // { kind: "network"|"port", index }  (index -1 = new)
    preview: null,    // { verdict, error, doc }
    revert: { armed: false, seconds_left: 0 },
    routing: { enabled: false, busy: false },
    loading: true, busy: false, error: null, notice: null, host: "",
};
let revertTicker = null;

function normalize(p) {
    const out = { objects: { networks: [], ports: [] }, sections: [] };
    if (p && p.objects) {
        out.objects.networks = p.objects.networks || [];
        out.objects.ports = p.objects.ports || [];
    }
    for (const meta of SECTIONS) {
        const found = (p && p.sections || []).find((s) => s.name === meta.key);
        out.sections.push(found || { name: meta.key, default_action: meta.key === "from-firewall" ? "accept" : "drop", rules: [] });
    }
    return out;
}
function sectionOf(key) { return state.policy.sections.find((s) => s.name === key); }
function dirty() { return state.policy && JSON.stringify(state.policy) !== state.savedJson; }

// ═══ Render ═══════════════════════════════════════════════════════════════════
function render() {
    const app = document.getElementById("app");
    app.innerHTML = "";
    app.appendChild(topBar());

    const main = h("div.ccx-main");
    if (state.error) main.appendChild(flash(state.error, () => { state.error = null; render(); }));
    if (state.notice) main.appendChild(notice(state.notice));
    if (state.revert.armed) main.appendChild(revertBanner());

    main.appendChild(h("div.efz-policy-head", null, [
        h("div", null, [
            h("div.efz-policy-title", null, "Local firewall policy"),
            h("div.efz-policy-host", null, state.host ? `inet enforza · ${state.host}` : "inet enforza"),
        ]),
        routingSwitch(),
    ]));

    if (state.loading) {
        main.appendChild(h("div.efz-empty", null, "Loading policy…"));
    } else {
        main.appendChild(tabStrip());
        if (state.active === "objects") main.appendChild(objectsTab());
        else main.appendChild(sectionCard(sectionOf(state.active)));
    }
    app.appendChild(main);
    app.appendChild(appBar());

    if (state.drawer) { app.appendChild(backdrop(closeDrawer)); app.appendChild(ruleDrawer()); }
    if (state.objDlg) { app.appendChild(backdrop(closeObjDlg)); app.appendChild(objDialog()); }
    if (state.preview) { app.appendChild(backdrop(() => { state.preview = null; render(); })); app.appendChild(previewDialog()); }
}

function topBar() {
    const isDark = document.documentElement.getAttribute("data-theme") !== "light";
    return h("div.efz-topbar", null, [
        h("div.efz-brand", null, [
            h("div.efz-brand__glyph", null, [h("img", { src: "assets/flame-square.svg", alt: "enforza" })]),
            h("div.efz-brand__text", null, [
                h("div.efz-brand__title", null, "Firewall"),
                h("div.efz-brand__sub", null, "nftables"),
            ]),
        ]),
        h("div.efz-topbar__actions", null, [
            h("a.efz-createdby", { href: "https://enforza.io", target: "_blank", rel: "noopener noreferrer", title: "enforza.io" }, [
                h("span.efz-createdby__label", null, "Created by"),
                h("img.efz-createdby__logo", { src: "assets/enforza-logo.png", alt: "enforza" }),
            ]),
            h("button.efz-iconbtn", { title: "Toggle theme", onclick: toggleTheme }, [icon(isDark ? "sun" : "moon", 16)]),
            h("button.efz-iconbtn", { title: "Reload policy", onclick: () => load() }, [icon("refresh", 16)]),
        ]),
    ]);
}

function tabStrip() {
    const tabs = h("div.efz-tabs", { style: "grid-template-columns: repeat(4, 1fr)" });
    for (const s of SECTIONS) {
        const active = s.key === state.active;
        tabs.appendChild(h("button.efz-tab" + (active ? ".is-active" : ""), {
            title: `${s.key} — ${s.hook} hook`, onclick: () => { state.active = s.key; render(); },
        }, [icon(s.key, 14), h("span", null, s.label), h("span.efz-tab__count", null, String(sectionOf(s.key).rules.length))]));
    }
    const objActive = state.active === "objects";
    const nobj = state.policy.objects.networks.length + state.policy.objects.ports.length;
    tabs.appendChild(h("button.efz-tab" + (objActive ? ".is-active" : ""), {
        title: "Reusable network + port objects", onclick: () => { state.active = "objects"; render(); },
    }, [icon("objects", 14), h("span", null, "Objects"), h("span.efz-tab__count", null, String(nobj))]));

    return h("div.efz-tabs-wrap", null, [
        h("div.efz-tabs-grouplabel", null, [h("span.rule"), h("span", null, "Firewall Rules"), h("span.rule")]),
        tabs,
    ]);
}

// ── Section card (editable) ──────────────────────────────────────────────────
function sectionCard(sec) {
    const meta = SECTION_BY_KEY[sec.name];
    const header = h("div.efz-section__header", null, [
        h("div", { style: "flex:1;min-width:0" }, [
            h("div.efz-section__title", null, [meta.title, h("span.efz-section__id", null, sec.name)]),
            h("p.efz-section__blurb", null, meta.blurb),
        ]),
        h("div.efz-section__tools", null, [
            h("span.efz-default__label", null, "Default"),
            defaultToggle(sec),
            h("button.efz-addbtn", { onclick: () => openDrawer(sec.name, -1) }, [icon("plus", 14), "Add rule"]),
        ]),
    ]);

    let body;
    if (sec.rules.length === 0) {
        body = h("div.efz-empty", null, "No rules — traffic falls through to the default action. Click “Add rule”.");
    } else {
        body = ruleTable(sec);
    }
    return h("div.efz-section", null, [header, body]);
}

function defaultToggle(sec) {
    const seg = h("div.efz-seg");
    for (const a of ["accept", "drop"]) {
        const on = sec.default_action === a;
        seg.appendChild(h("button" + (on ? (a === "accept" ? ".is-accept" : ".is-drop") : ""), {
            onclick: () => { sec.default_action = a; render(); },
        }, a));
    }
    return seg;
}

function ruleTable(sec) {
    const thead = h("thead", null, [h("tr", null, [
        h("th", { style: "width:28px" }), h("th", null, "#"), h("th", null, "Action"),
        h("th", null, "Src"), h("th", null, "Dst"), h("th", null, "Proto"),
        h("th", null, "Port"), h("th", null, "Flags"), h("th", null, "Comment"),
        h("th", { style: "text-align:right" }, "Actions"),
    ])]);
    const tbody = h("tbody");
    sec.rules.forEach((r, i) => tbody.appendChild(ruleRow(sec, r, i)));
    return h("table.gh-table", null, [thead, tbody]);
}

function ruleRow(sec, r, i) {
    const pill = r.action === "accept" ? "efz-pill--accept" : "efz-pill--drop";
    const flags = h("td", { style: "white-space:nowrap" });
    if (r.log) flags.appendChild(h("span.efz-flag", null, "LOG"));
    if (r.snat) flags.appendChild(h("span.efz-flag", null, "SNAT"));

    const grip = h("span.efz-grip", { draggable: "true", title: "Drag to reorder" }, [icon("grip", 14)]);
    grip.addEventListener("dragstart", (e) => { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", String(i)); });

    const tr = h("tr", null, [
        h("td", null, [grip]),
        h("td", null, String(i + 1)),
        h("td", null, [h("span.efz-pill." + pill, null, r.action || "drop")]),
        objOrText(r.src), objOrText(r.dst),
        h("td.efz-mono", null, r.protocol && r.protocol !== "any" ? r.protocol : anySpan()),
        h("td.efz-mono", null, r.port ? objOrPortText(r.port) : anySpan()),
        flags,
        h("td", { style: "color:var(--ccx-text-secondary)" }, r.comment || ""),
        h("td", { style: "text-align:right;white-space:nowrap" }, [
            h("button.efz-rowbtn", { title: "Edit", onclick: () => openDrawer(sec.name, i) }, [icon("pencil", 14)]),
            h("button.efz-rowbtn.danger", { title: "Delete", onclick: () => { sec.rules.splice(i, 1); render(); } }, [icon("trash", 14)]),
        ]),
    ]);
    tr.addEventListener("dragover", (e) => e.preventDefault());
    tr.addEventListener("drop", (e) => {
        e.preventDefault();
        const from = parseInt(e.dataTransfer.getData("text/plain"), 10);
        if (isNaN(from) || from === i) return;
        const [moved] = sec.rules.splice(from, 1);
        sec.rules.splice(i, 0, moved);
        render();
    });
    return tr;
}

function anySpan() { return h("span.efz-any", null, "any"); }
function objOrText(v) {
    if (!v || String(v).trim() === "" || String(v).toLowerCase() === "any") return h("td.efz-mono", null, [anySpan()]);
    const isObj = state.policy.objects.networks.some((n) => n.name === String(v).trim());
    return h("td.efz-mono", null, isObj ? [h("span.efz-tag", null, "@" + v)] : String(v));
}
function objOrPortText(v) {
    const isObj = state.policy.objects.ports.some((p) => p.name === String(v).trim());
    return isObj ? h("span.efz-tag", null, "@" + v) : document.createTextNode(String(v));
}

// ── Rule drawer (add / edit) ─────────────────────────────────────────────────
function openDrawer(section, index) {
    const base = { comment: "", action: "accept", protocol: "any", port: "", src: "", dst: "", log: false, snat: false };
    const existing = index >= 0 ? sectionOf(section).rules[index] : null;
    state.drawer = { section, index, form: Object.assign(base, existing ? JSON.parse(JSON.stringify(existing)) : {}) };
    render();
}
function closeDrawer() { state.drawer = null; render(); }

function ruleDrawer() {
    const d = state.drawer, f = d.form;
    const meta = SECTION_BY_KEY[d.section];
    const set = (k) => (e) => { f[k] = e.target.type === "checkbox" ? e.target.checked : e.target.value; };

    const netList = h("datalist", { id: "efz-netnames" }, state.policy.objects.networks.map((n) => h("option", { value: n.name })));
    const portList = h("datalist", { id: "efz-portnames" }, state.policy.objects.ports.map((p) => h("option", { value: p.name })));

    const actionSeg = h("div.efz-seg");
    for (const a of ["accept", "drop", "reject"]) {
        const on = f.action === a;
        const cls = on ? (a === "accept" ? ".is-accept" : a === "reject" ? ".is-reject" : ".is-drop") : "";
        actionSeg.appendChild(h("button" + cls, { onclick: () => { f.action = a; render(); } }, a));
    }

    return h("div.efz-drawer", null, [
        h("div.efz-drawer__head", null, [
            h("div.efz-drawer__title", null, (d.index < 0 ? "Add rule · " : "Edit rule · ") + meta.label),
            h("button.efz-rowbtn", { title: "Close", onclick: closeDrawer }, [icon("x", 16)]),
        ]),
        h("div.efz-drawer__body", null, [
            netList, portList,
            field("Action", actionSeg),
            field("Protocol", h("select.ccx-input", { onchange: set("protocol"), value: f.protocol },
                ["any", "tcp", "udp", "icmp"].map((p) => h("option", { value: p, selected: f.protocol === p }, p)))),
            field("Destination port", h("input.ccx-input", { value: f.port, oninput: set("port"), placeholder: "22, 80,443, 8000-8100, or object", list: "efz-portnames" }),
                "Number, range a-b, comma list, or a port object name."),
            field("Source", h("input.ccx-input", { value: f.src, oninput: set("src"), placeholder: "any, CIDR/IP, comma list, or object", list: "efz-netnames" }),
                d.section === "from-firewall" ? "This host is the source; usually leave as any." : "CIDR/IP, comma list, or a network object name."),
            // to-firewall (Management) traffic terminates on this host, so the
            // destination is always the firewall itself — no field to fill in.
            d.section === "to-firewall" ? null : field("Destination",
                h("input.ccx-input", { value: f.dst, oninput: set("dst"), placeholder: "any, CIDR/IP, comma list, or object", list: "efz-netnames" }),
                "CIDR/IP, comma list, or a network object name."),
            field("", h("label.efz-check", null, [h("input", { type: "checkbox", checked: f.log, onchange: set("log") }), "Log matches (nft log prefix)"])),
            // SNAT (masquerade) only applies to forwarded traffic, so it's offered
            // on Network rules only. Masquerade rewrites the source to the outbound
            // interface address in a postrouting nat chain.
            d.section === "through-firewall"
                ? field("", h("label.efz-check", null, [h("input", { type: "checkbox", checked: f.snat, onchange: set("snat") }), "SNAT — masquerade this flow's source"]),
                    "Rewrites the source address to the outbound interface (for traffic leaving to the internet). Applies to accept rules.")
                : null,
            field("Comment", h("input.ccx-input", { value: f.comment, oninput: set("comment"), placeholder: "Human-readable note" })),
        ]),
        h("div.efz-drawer__foot", null, [
            h("button.ccx-btn.ccx-btn-secondary", { onclick: closeDrawer }, "Cancel"),
            h("button.ccx-btn.ccx-btn-primary", { onclick: saveRule }, [icon("check", 14), d.index < 0 ? "Add rule" : "Save rule"]),
        ]),
    ]);
}
function saveRule() {
    const d = state.drawer;
    const sec = sectionOf(d.section);
    const rule = Object.assign({}, d.form);
    // Management traffic lands on this host — never carries an operator dst.
    if (d.section === "to-firewall") delete rule.dst;
    for (const k of ["comment", "port", "src", "dst"]) if (rule[k] === "") delete rule[k];
    if (rule.protocol === "any") delete rule.protocol;
    if (!rule.log) delete rule.log;
    // SNAT is a Network-section concept only.
    if (!rule.snat || d.section !== "through-firewall") delete rule.snat;
    if (d.index < 0) sec.rules.push(rule); else sec.rules[d.index] = rule;
    state.drawer = null;
    render();
}

// ── Objects tab + dialog ─────────────────────────────────────────────────────
function objectsTab() {
    return h("div.efz-objtab", null, [
        objCard("network", "Network objects", "Named CIDR/IP sets you can reference by name in a rule's Source or Destination.", state.policy.objects.networks,
            (n) => n.cidrs || []),
        objCard("port", "Port objects", "Named port sets you can reference by name in a rule's Destination port.", state.policy.objects.ports,
            (p) => (p.ports || []).map(String)),
    ]);
}
function objCard(kind, title, blurb, items, entriesOf) {
    const head = h("div.efz-objtab__head", null, [
        h("div", null, [h("div.efz-section__title", null, title), h("p.efz-section__blurb", null, blurb)]),
        h("button.efz-addbtn", { onclick: () => openObjDlg(kind, -1) }, [icon("plus", 14), "Add"]),
    ]);
    let body;
    if (items.length === 0) {
        body = h("div.efz-empty", null, "None yet.");
    } else {
        const tbody = h("tbody");
        items.forEach((it, i) => tbody.appendChild(h("tr", null, [
            h("td.efz-mono", null, it.name),
            kind === "port" ? h("td.efz-mono", null, it.protocol || "tcp") : null,
            h("td", null, entriesOf(it).map((e) => h("span.efz-tag", null, e))),
            h("td", { style: "text-align:right;white-space:nowrap" }, [
                h("button.efz-rowbtn", { title: "Edit", onclick: () => openObjDlg(kind, i) }, [icon("pencil", 14)]),
                h("button.efz-rowbtn.danger", { title: "Delete", onclick: () => { items.splice(i, 1); render(); } }, [icon("trash", 14)]),
            ]),
        ].filter(Boolean))));
        const headCells = [h("th", null, "Name")];
        if (kind === "port") headCells.push(h("th", null, "Proto"));
        headCells.push(h("th", null, "Entries"), h("th", { style: "text-align:right" }, "Actions"));
        body = h("table.gh-table", null, [h("thead", null, [h("tr", null, headCells)]), tbody]);
    }
    return h("div.efz-section", null, [head, body]);
}
function openObjDlg(kind, index) {
    const list = kind === "network" ? state.policy.objects.networks : state.policy.objects.ports;
    const existing = index >= 0 ? list[index] : null;
    const form = kind === "network"
        ? { name: existing ? existing.name : "", entries: existing ? (existing.cidrs || []).join(", ") : "" }
        : { name: existing ? existing.name : "", protocol: existing ? (existing.protocol || "tcp") : "tcp", entries: existing ? (existing.ports || []).join(", ") : "" };
    state.objDlg = { kind, index, form };
    render();
}
function closeObjDlg() { state.objDlg = null; render(); }
function objDialog() {
    const d = state.objDlg, f = d.form;
    const set = (k) => (e) => { f[k] = e.target.value; };
    const rows = [field("Name", h("input.ccx-input", { value: f.name, oninput: set("name"), placeholder: d.kind === "network" ? "vpn" : "web" }),
        "Referenced in rules as this name.")];
    if (d.kind === "port")
        rows.push(field("Protocol", h("select.ccx-input", { onchange: set("protocol"), value: f.protocol },
            ["tcp", "udp"].map((p) => h("option", { value: p, selected: f.protocol === p }, p)))));
    rows.push(field(d.kind === "network" ? "CIDRs / IPs" : "Ports",
        h("input.ccx-input", { value: f.entries, oninput: set("entries"), placeholder: d.kind === "network" ? "10.8.0.0/24, 192.168.1.0/24" : "80, 443, 8000-8100" }),
        "Comma-separated."));
    return h("div.efz-dialog", null, [
        h("div.efz-dialog__head", null, [
            h("div.efz-dialog__title", null, (d.index < 0 ? "Add " : "Edit ") + (d.kind === "network" ? "network object" : "port object")),
            h("button.efz-rowbtn", { title: "Close", onclick: closeObjDlg }, [icon("x", 16)]),
        ]),
        h("div.efz-dialog__body", null, rows),
        h("div.efz-dialog__foot", null, [
            h("button.ccx-btn.ccx-btn-secondary", { onclick: closeObjDlg }, "Cancel"),
            h("button.ccx-btn.ccx-btn-primary", { onclick: saveObj }, [icon("check", 14), "Save"]),
        ]),
    ]);
}
function saveObj() {
    const d = state.objDlg, f = d.form;
    const name = f.name.trim();
    if (!name) { state.error = "Object name is required."; render(); return; }
    const entries = f.entries.split(",").map((s) => s.trim()).filter(Boolean);
    const list = d.kind === "network" ? state.policy.objects.networks : state.policy.objects.ports;
    const obj = d.kind === "network"
        ? { name, cidrs: entries }
        : { name, protocol: f.protocol, ports: entries.map((p) => (/^\d+$/.test(p) ? parseInt(p, 10) : p)) };
    if (d.index < 0) list.push(obj); else list[d.index] = obj;
    state.objDlg = null;
    render();
}

// ── Apply bar ────────────────────────────────────────────────────────────────
function appBar() {
    const isDirty = dirty();
    return h("div.efz-appbar", null, [
        isDirty ? h("span.efz-dirty", null, [h("span.efz-dirty__dot"), "Unsaved changes"]) : h("span.efz-dirty", null, "Saved"),
        h("span.efz-appbar__spacer"),
        h("button.ccx-btn.ccx-btn-secondary", { disabled: state.busy || !isDirty ? "" : null, onclick: save }, [icon("save", 14), "Save"]),
        h("button.ccx-btn.ccx-btn-secondary", { disabled: state.busy ? "" : null, onclick: preview }, [icon("eye", 14), "Preview"]),
        h("button.ccx-btn.ccx-btn-primary", { disabled: state.busy ? "" : null, onclick: apply }, [icon("upload", 14), "Apply"]),
    ]);
}

// ── Preview (render + dry-run validate) ──────────────────────────────────────
function preview() {
    let doc;
    try { doc = enforzaRender.renderPolicy(state.policy); }
    catch (e) { state.error = "Render failed: " + e.message; render(); return; }
    state.busy = true; render();
    helper("validate", doc).then((r) => {
        state.busy = false;
        state.preview = { verdict: r.ok, error: r.error, doc };
        render();
    }).catch((err) => { state.busy = false; state.error = "Validate failed: " + err.message; render(); });
}
function previewDialog() {
    const p = state.preview;
    const count = p.doc.nftables.length;
    return h("div.efz-dialog.wide", null, [
        h("div.efz-dialog__head", null, [
            h("div.efz-dialog__title", null, "Preview — rendered nftables JSON"),
            h("button.efz-rowbtn", { title: "Close", onclick: () => { state.preview = null; render(); } }, [icon("x", 16)]),
        ]),
        h("div.efz-dialog__body", null, [
            p.verdict
                ? h("div.efz-preview-verdict.ok", null, [icon("check", 16), `Valid — the kernel accepts this ruleset (${count} commands, dry-run).`])
                : h("div.efz-preview-verdict.bad", null, [icon("x", 16), "Rejected by the kernel dry-run:"]),
            p.error ? h("pre.efz-preview-json", { style: "color:var(--ccx-danger);margin-bottom:12px" }, p.error) : null,
            h("pre.efz-preview-json", null, JSON.stringify(p.doc, null, 2)),
        ].filter(Boolean)),
        h("div.efz-dialog__foot", null, [
            h("button.ccx-btn.ccx-btn-secondary", { onclick: () => { state.preview = null; render(); } }, "Close"),
            h("button.ccx-btn.ccx-btn-primary", { disabled: !p.verdict ? "" : null, onclick: () => { state.preview = null; apply(); } }, [icon("upload", 14), "Apply"]),
        ]),
    ]);
}

// ── Apply + confirm-or-revert ────────────────────────────────────────────────
function apply() {
    let doc;
    try { doc = enforzaRender.renderPolicy(state.policy); }
    catch (e) { state.error = "Render failed: " + e.message; render(); return; }
    state.busy = true; state.error = null; render();
    helper("apply", { doc, timeout: REVERT_TIMEOUT }).then((r) => {
        state.busy = false;
        if (!r.ok) { state.error = "Apply rejected: " + (r.error || "unknown error"); render(); return; }
        state.revert = { armed: true, seconds_left: r.timeout || REVERT_TIMEOUT };
        startRevertTicker();
        render();
    }).catch((err) => { state.busy = false; state.error = "Apply failed: " + err.message; render(); });
}
function revertBanner() {
    return h("div.efz-revert", null, [
        icon("upload", 16),
        h("div", null, [
            h("strong", null, "Firewall applied — confirm to keep it."),
            h("div", { style: "font-size:12px;color:var(--ccx-text-secondary);margin-top:2px" },
                "If you don’t confirm, the previous ruleset is restored automatically — so a bad rule can’t lock you out."),
        ]),
        h("span.efz-revert__spacer"),
        h("span.efz-revert__count", null, `${state.revert.seconds_left}s`),
        h("button.ccx-btn.ccx-btn-secondary", { onclick: revertNow }, [icon("revert", 14), "Revert now"]),
        h("button.ccx-btn.ccx-btn-primary", { onclick: confirmApply }, [icon("check", 14), "Confirm"]),
    ]);
}
function startRevertTicker() {
    stopRevertTicker();
    revertTicker = setInterval(() => {
        helper("status").then((s) => {
            state.revert = { armed: s.armed, seconds_left: s.seconds_left };
            if (!s.armed) { stopRevertTicker(); state.notice = "Auto-reverted — the applied ruleset was rolled back after the timeout."; }
            render();
        }).catch(() => {});
    }, 1000);
}
function stopRevertTicker() { if (revertTicker) { clearInterval(revertTicker); revertTicker = null; } }
function confirmApply() {
    helper("confirm").then(() => { stopRevertTicker(); state.revert = { armed: false, seconds_left: 0 }; state.notice = "Confirmed — ruleset is now live."; render(); })
        .catch((err) => { state.error = "Confirm failed: " + err.message; render(); });
}
function revertNow() {
    helper("revert").then(() => { stopRevertTicker(); state.revert = { armed: false, seconds_left: 0 }; state.notice = "Reverted to the previous ruleset."; render(); })
        .catch((err) => { state.error = "Revert failed: " + err.message; render(); });
}

// ── Save ─────────────────────────────────────────────────────────────────────
function save() {
    state.busy = true; render();
    helper("save", state.policy).then((r) => {
        state.busy = false;
        if (r.ok) { state.savedJson = JSON.stringify(state.policy); state.notice = "Policy saved to " + r.path + "."; }
        else state.error = "Save failed: " + (r.error || "unknown");
        render();
    }).catch((err) => { state.busy = false; state.error = "Save failed: " + err.message; render(); });
}

// ── Small building blocks ────────────────────────────────────────────────────
function field(label, control, hint) {
    return h("div.efz-field", null, [label ? h("label", null, label) : null, control, hint ? h("div.hint", null, hint) : null].filter(Boolean));
}
function flash(msg, onClose) {
    return h("div.efz-flash", null, [
        h("div", { style: "flex:1" }, [h("strong", null, "Error"), h("pre", null, msg)]),
        onClose ? h("button.efz-rowbtn", { onclick: onClose, title: "Dismiss" }, [icon("x", 14)]) : null,
    ].filter(Boolean));
}
function notice(msg) {
    return h("div.efz-flash", { style: "background:var(--ccx-success-bg);border-color:var(--ccx-success)" }, [
        h("div", { style: "flex:1;color:var(--ccx-text-primary)" }, msg),
        h("button.efz-rowbtn", { onclick: () => { state.notice = null; render(); }, title: "Dismiss" }, [icon("x", 14)]),
    ]);
}
function backdrop(onClick) { return h("div.efz-backdrop", { onclick: onClick }); }

// ── Routing (IP forwarding) toggle ───────────────────────────────────────────
function routingSwitch() {
    const on = state.routing.enabled;
    return h("div.efz-switch", {
        role: "switch", "aria-checked": on ? "true" : "false", "aria-disabled": state.routing.busy ? "true" : null,
        title: "IP forwarding (net.ipv4.ip_forward). Required for the Network (forward) path and SNAT to route between interfaces. Persisted in /etc/sysctl.d/99-enforza-routing.conf.",
        onclick: state.routing.busy ? null : toggleRouting,
    }, [
        h("span.efz-switch__label", null, "Enable routing"),
        h("div.efz-switch__track" + (on ? ".on" : ""), null, [h("div.efz-switch__knob")]),
    ]);
}
function toggleRouting() {
    const next = !state.routing.enabled;
    state.routing.busy = true; render();
    helper("routing-set", { enabled: next }).then((r) => {
        state.routing = { enabled: !!r.enabled, busy: false };
        state.notice = "Routing " + (r.enabled ? "enabled" : "disabled") + " — persisted in /etc/sysctl.d/99-enforza-routing.conf.";
        render();
    }).catch((err) => { state.routing.busy = false; state.error = "Routing toggle failed: " + err.message; render(); });
}

// ── Theme ────────────────────────────────────────────────────────────────────
function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    const next = cur === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("enforza-console-theme", next); } catch (e) { /* private mode */ }
    render();
}

// ── Boot ─────────────────────────────────────────────────────────────────────
function load() {
    state.loading = true; state.error = null; render();
    cockpit.spawn(["hostname"]).then((o) => { state.host = (o || "").trim(); }).catch(() => {}).finally(() => { if (!state.loading) render(); });
    helper("load").then((r) => {
        state.policy = normalize(r.policy);
        state.savedJson = JSON.stringify(state.policy);
        state.loading = false;
        render();
        // Reflect the host's current IP-forwarding state in the routing toggle.
        helper("routing-status").then((s) => { state.routing.enabled = !!s.enabled; render(); }).catch(() => {});
        // If a prior apply is still pending (e.g. page reloaded mid-window), resume the banner.
        helper("status").then((s) => { if (s.armed) { state.revert = { armed: true, seconds_left: s.seconds_left }; startRevertTicker(); render(); } }).catch(() => {});
    }).catch((err) => {
        state.loading = false;
        state.error = "Could not load policy. Ensure you have administrative access in Cockpit.\n" + err.message;
        render();
    });
}

try {
    const saved = localStorage.getItem("enforza-console-theme");
    if (saved === "light" || saved === "dark") document.documentElement.setAttribute("data-theme", saved);
} catch (e) { /* ignore */ }

document.addEventListener("DOMContentLoaded", load);
if (document.readyState !== "loading") load();
