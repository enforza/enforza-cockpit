/*
 * render.js — enforza-cockpit policy → nftables JSON renderer.
 *
 * Turns the plugin's policy document (objects + to/through/from-firewall
 * sections) into a libnftables JSON *command* document — the same JSON shape
 * `nft -j list ruleset` emits, wrapped in add/delete verbs — which we apply with
 * the python3-nftables module (json_cmd). Modelled on the enforza engine's
 * l3l4compiler.emitVerdict, minus the cloud-only ct-mark / nflog-group / verdict
 * fast-path machinery a local firewall doesn't need.
 *
 * Design choices:
 *   - We own a dedicated `inet enforza` table so an apply never touches other
 *     tables (docker, libvirt, a hand-rolled `filter`). Each apply is an atomic
 *     replace via the add;delete;add-table idiom (all in one json_cmd txn).
 *   - Network objects → named sets (ipv4_addr / ipv6_addr, interval flag).
 *     Port objects   → named sets (inet_service).
 *     Rules reference an object by name as `@name`; literals render inline.
 *
 * Pure + node-testable: no DOM, no cockpit. Exported for the browser as
 * window.enforzaRender and for node as module.exports.
 */
(function (global) {
    "use strict";

    const TABLE = { family: "inet", name: "enforza" };

    // Section name → base-chain hook.
    const HOOK = { "to-firewall": "input", "through-firewall": "forward", "from-firewall": "output" };

    // ── Literal parsing helpers ──────────────────────────────────────────────
    const isV6 = (s) => s.indexOf(":") !== -1;

    // "10.0.0.0/24" / "10.0.0.1" / "10.0.0.1-10.0.0.9" → nft right-value.
    function addrValue(spec) {
        const s = String(spec).trim();
        if (s.indexOf("/") !== -1) {
            const [addr, len] = s.split("/");
            return { prefix: { addr: addr.trim(), len: parseInt(len, 10) } };
        }
        if (s.indexOf("-") !== -1 && !isV6(s)) {
            const [a, b] = s.split("-");
            return { range: [a.trim(), b.trim()] };
        }
        return s; // bare address
    }

    // Split a comma list; "any"/""/"0.0.0.0/0"/"::/0" mean "no constraint".
    function isAnyAddr(field) {
        if (field == null) return true;
        const s = String(field).trim().toLowerCase();
        return s === "" || s === "any" || s === "0.0.0.0/0" || s === "::/0";
    }

    // Build the nft right-value for a src/dst field. Object ref (@name) passes
    // through; a single literal → its value; a comma list → an anonymous set.
    function addrRight(field, objectNames) {
        const raw = String(field).trim();
        if (objectNames && objectNames.has(raw)) return "@" + raw;
        const parts = raw.split(",").map((x) => x.trim()).filter(Boolean);
        if (parts.length === 1) return addrValue(parts[0]);
        return { set: parts.map(addrValue) };
    }

    // Address family a literal field needs; drives ip vs ip6 payload + set type.
    function addrProto(field) {
        return isV6(String(field)) ? "ip6" : "ip";
    }

    // Port token → int | {range:[a,b]}.
    function portValue(tok) {
        const s = String(tok).trim();
        if (s.indexOf("-") !== -1) {
            const [a, b] = s.split("-");
            return { range: [parseInt(a, 10), parseInt(b, 10)] };
        }
        return parseInt(s, 10);
    }
    function portRight(field, objectNames) {
        const raw = String(field).trim();
        if (objectNames && objectNames.has(raw)) return "@" + raw;
        const parts = raw.split(",").map((x) => x.trim()).filter(Boolean);
        if (parts.length === 1) return portValue(parts[0]);
        return { set: parts.map(portValue) };
    }

    function match(op, left, right) { return { match: { op: op || "==", left, right } }; }

    // ── Rule expressions ─────────────────────────────────────────────────────
    // The L3/L4 match clauses (src, dst, proto/port, ct state) shared by both
    // filter rules and their NAT counterpart, so a snat rule masquerades exactly
    // the flow its filter rule accepts.
    function matchExprs(rule, objIndex) {
        const expr = [];
        const netNames = objIndex.networks;
        const portNames = objIndex.ports;

        if (!isAnyAddr(rule.src)) {
            const proto = netNames.has(String(rule.src).trim()) ? objIndex.netFamily.get(String(rule.src).trim()) : addrProto(rule.src);
            expr.push(match("==", { payload: { protocol: proto, field: "saddr" } }, addrRight(rule.src, netNames)));
        }
        if (!isAnyAddr(rule.dst)) {
            const proto = netNames.has(String(rule.dst).trim()) ? objIndex.netFamily.get(String(rule.dst).trim()) : addrProto(rule.dst);
            expr.push(match("==", { payload: { protocol: proto, field: "daddr" } }, addrRight(rule.dst, netNames)));
        }

        const proto = rule.protocol && rule.protocol !== "any" ? rule.protocol : null;
        const hasPort = rule.port != null && String(rule.port).trim() !== "";
        if (proto === "tcp" || proto === "udp") {
            if (hasPort) expr.push(match("==", { payload: { protocol: proto, field: "dport" } }, portRight(rule.port, portNames)));
            else expr.push(match("==", { meta: { key: "l4proto" } }, proto));
        } else if (proto === "icmp" || proto === "icmpv6") {
            expr.push(match("==", { meta: { key: "l4proto" } }, proto));
        } else if (hasPort) {
            // Port given without a protocol — default to tcp so the match is valid.
            expr.push(match("==", { payload: { protocol: "tcp", field: "dport" } }, portRight(rule.port, portNames)));
        }

        // ct state (Flow). "established,related" → set.
        if (rule.state && String(rule.state).trim() !== "") {
            const states = String(rule.state).split(",").map((s) => s.trim()).filter(Boolean);
            expr.push(match("in", { ct: { key: "state" } }, states.length === 1 ? states[0] : { set: states }));
        }
        return expr;
    }

    // A filter rule: matches + counter + optional log + verdict.
    function ruleExpr(rule, sectionName, objIndex) {
        const expr = matchExprs(rule, objIndex);
        expr.push({ counter: null });
        if (rule.log) expr.push({ log: { prefix: `enforza ${sectionName}: ` } });
        const action = rule.action === "accept" ? "accept" : rule.action === "reject" ? "reject" : "drop";
        expr.push(action === "reject" ? { reject: null } : { [action]: null });
        return expr;
    }

    // A postrouting NAT rule for a snat:true forward rule: same match + masquerade.
    function natExpr(rule, objIndex) {
        const expr = matchExprs(rule, objIndex);
        expr.push({ counter: null });
        expr.push({ masquerade: null });
        return expr;
    }

    // A forward rule earns a masquerade only when it actually accepts traffic —
    // masquerading a dropped flow is meaningless (the flow never leaves).
    function snatEligible(rule) {
        return !!rule.snat && (rule.action === "accept" || !rule.action);
    }

    // ── Baseline ("safety net") rules ────────────────────────────────────────
    // The boilerplate every working nftables firewall needs, prepended to each
    // base chain BEFORE the operator's rules (first-match wins). Mirrors the
    // enforza engine's per-chain baseline (internal/nft/nft.go):
    //   1. drop invalid conntrack state
    //   2. accept established,related  (return traffic — without this a default-
    //      drop chain kills the replies to connections the box/hosts initiated)
    //   3. accept loopback            (iif lo on input, oif lo on output; the
    //      forward path never carries loopback so it's omitted there)
    // These are engine-managed, not operator-editable — the UI shows them read-only.
    const CT_INVALID = { match: { op: "in", left: { ct: { key: "state" } }, right: "invalid" } };
    const CT_ESTREL = { match: { op: "in", left: { ct: { key: "state" } }, right: { set: ["established", "related"] } } };
    const ifMatch = (key, name) => ({ match: { op: "==", left: { meta: { key } }, right: name } });

    function baselineRuleCmds(hook) {
        const cmds = [];
        const rule = (expr, comment) => cmds.push({ add: { rule: {
            family: TABLE.family, table: TABLE.name, chain: hook, expr, comment,
        } } });
        rule([CT_INVALID, { counter: null }, { drop: null }], "baseline: drop invalid ct state");
        rule([CT_ESTREL, { counter: null }, { accept: null }], "baseline: accept established,related");
        if (hook === "input") rule([ifMatch("iifname", "lo"), { counter: null }, { accept: null }], "baseline: accept loopback (iif lo)");
        else if (hook === "output") rule([ifMatch("oifname", "lo"), { counter: null }, { accept: null }], "baseline: accept loopback (oif lo)");
        return cmds;
    }

    // Loopback / localhost is never masqueraded — rewriting the source of
    // locally-generated traffic (DNS to 127.0.0.53, health checks, the box's
    // own heartbeat) breaks it. These `return` rules run before any masquerade.
    function natExemptionCmds() {
        const rule = (expr, comment) => ({ add: { rule: {
            family: TABLE.family, table: TABLE.name, chain: "postrouting", expr, comment,
        } } });
        const lo = (addr) => ({ match: { op: "==", left: { payload: { protocol: "ip", field: addr } }, right: { prefix: { addr: "127.0.0.0", len: 8 } } } });
        return [
            rule([ifMatch("iifname", "lo"), { return: null }], "baseline: skip SNAT when iif lo"),
            rule([ifMatch("oifname", "lo"), { return: null }], "baseline: skip SNAT when oif lo"),
            rule([lo("saddr"), { return: null }], "baseline: skip SNAT when saddr 127.0.0.0/8"),
            rule([lo("daddr"), { return: null }], "baseline: skip SNAT when daddr 127.0.0.0/8"),
        ];
    }

    // Index object names → membership sets + per-network address family.
    function indexObjects(objects) {
        const networks = new Set();
        const ports = new Set();
        const netFamily = new Map();
        for (const n of (objects && objects.networks) || []) {
            networks.add(n.name);
            const anyV6 = (n.cidrs || []).some((c) => isV6(c));
            netFamily.set(n.name, anyV6 ? "ip6" : "ip");
        }
        for (const p of (objects && objects.ports) || []) ports.add(p.name);
        return { networks, ports, netFamily };
    }

    // ── Full policy → JSON command document ──────────────────────────────────
    function renderPolicy(policy) {
        const objects = policy.objects || { networks: [], ports: [] };
        const objIndex = indexObjects(objects);
        const cmds = [];

        // Atomic clean-slate recreate of OUR table only (idempotent on first run).
        cmds.push({ add: { table: Object.assign({}, TABLE) } });
        cmds.push({ delete: { table: Object.assign({}, TABLE) } });
        cmds.push({ add: { table: Object.assign({}, TABLE) } });

        // Named sets from objects.
        for (const n of objects.networks || []) {
            const anyV6 = (n.cidrs || []).some((c) => isV6(c));
            cmds.push({ add: { set: {
                family: TABLE.family, table: TABLE.name, name: n.name,
                type: anyV6 ? "ipv6_addr" : "ipv4_addr", flags: ["interval"],
                elem: (n.cidrs || []).map(addrValue),
            } } });
        }
        for (const p of objects.ports || []) {
            cmds.push({ add: { set: {
                family: TABLE.family, table: TABLE.name, name: p.name,
                type: "inet_service", flags: ["interval"],
                elem: (p.ports || []).map(portValue),
            } } });
        }

        // Chains + rules per section, in section then rule order.
        for (const section of policy.sections || []) {
            const hook = HOOK[section.name];
            if (!hook) continue;
            cmds.push({ add: { chain: {
                family: TABLE.family, table: TABLE.name, name: hook,
                type: "filter", hook, prio: 0,
                policy: section.default_action === "accept" ? "accept" : "drop",
            } } });
            // Baseline (invalid-drop / established-accept / loopback) goes first.
            for (const c of baselineRuleCmds(hook)) cmds.push(c);
            (section.rules || []).forEach((rule, i) => {
                cmds.push({ add: { rule: {
                    family: TABLE.family, table: TABLE.name, chain: hook,
                    expr: ruleExpr(rule, section.name, objIndex),
                    comment: rule.comment ? `rule ${i}: ${rule.comment}` : `rule ${i}`,
                } } });
            });
        }

        // Source NAT. Forward rules flagged snat:true masquerade their source to
        // the outbound interface's address. One postrouting nat chain, one
        // masquerade rule per snat rule — re-matching the rule's own criteria, so
        // there's no global fwmark/ct-mark that could perturb the host's routing.
        const fwd = (policy.sections || []).find((s) => s.name === "through-firewall");
        const snatRules = fwd ? (fwd.rules || []).filter(snatEligible) : [];
        if (snatRules.length) {
            cmds.push({ add: { chain: {
                family: TABLE.family, table: TABLE.name, name: "postrouting",
                type: "nat", hook: "postrouting", prio: 100, policy: "accept",
            } } });
            // Loopback/localhost exemptions run before any masquerade rule.
            for (const c of natExemptionCmds()) cmds.push(c);
            snatRules.forEach((rule, i) => {
                cmds.push({ add: { rule: {
                    family: TABLE.family, table: TABLE.name, chain: "postrouting",
                    expr: natExpr(rule, objIndex),
                    comment: rule.comment ? `snat ${i}: ${rule.comment}` : `snat ${i}`,
                } } });
            });
        }

        return { nftables: cmds };
    }

    const api = { renderPolicy, ruleExpr, addrValue, portValue, indexObjects, TABLE, HOOK };
    if (typeof module !== "undefined" && module.exports) module.exports = api;
    global.enforzaRender = api;
})(typeof window !== "undefined" ? window : globalThis);
