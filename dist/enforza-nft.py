#!/usr/bin/env python3
"""
enforza-nft.py — privileged backend for the enforza-cockpit firewall plugin.

The browser UI (firewall.js) can't touch netlink, so every operation that reads
or writes the kernel ruleset, or persists policy, goes through this helper. It is
invoked by cockpit.spawn(..., {superuser:"require"}) — i.e. as root — with a
subcommand and, where relevant, a JSON body on stdin. All output is a single JSON
object on stdout so the UI can parse one thing.

Subcommands:
    load                 → { policy }            read /etc/enforza/policy.json (or a default)
    save        <stdin: policy>                  persist policy doc to /etc/enforza/policy.json
    validate    <stdin: nft-json-doc> → {ok,error}   dry-run the render against the kernel
    apply       <stdin: {doc, timeout}> → {ok,error,timeout}
                                                snapshot ruleset, apply doc, arm a revert timer
    confirm              → {ok}                  cancel the pending revert (keep applied ruleset)
    revert               → {ok}                  restore the pre-apply snapshot now
    status               → {armed, seconds_left} is a revert currently pending?
    _do-revert           (internal)             executed by the systemd timer on timeout

Safety model (confirm-or-revert): apply() snapshots the FULL ruleset, applies the
new one, then arms a transient systemd timer to restore the snapshot after
`timeout` seconds. The UI must call confirm() within that window or the box rolls
back automatically — so a rule that locks you out can't be permanent. The timer is
a systemd transient unit, so it survives the browser tab closing or the cockpit
session dropping (which is exactly when a lockout would otherwise strand you).
"""

import json
import os
import subprocess
import sys
import time

POLICY_DIR = "/etc/enforza"
POLICY_PATH = os.path.join(POLICY_DIR, "policy.json")
RUN_DIR = "/run/enforza"
SNAPSHOT_PATH = os.path.join(RUN_DIR, "pre-apply.nft")
DEADLINE_PATH = os.path.join(RUN_DIR, "revert-deadline")
REVERT_UNIT = "enforza-revert"
SELF = os.path.realpath(__file__)

# A clean starting policy: lock down inbound + forwarded traffic, allow the box
# to reach out. Mirrors 06_engine/example-policy.yaml's default_actions.
DEFAULT_POLICY = {
    "objects": {"networks": [], "ports": []},
    "sections": [
        {"name": "to-firewall", "default_action": "drop", "rules": []},
        {"name": "through-firewall", "default_action": "drop", "rules": []},
        {"name": "from-firewall", "default_action": "accept", "rules": []},
    ],
}


def out(obj):
    """Emit one JSON object and exit 0 (errors travel inside the object)."""
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def read_stdin_json():
    data = sys.stdin.read()
    return json.loads(data) if data.strip() else None


def nft():
    """A configured Nftables handle (JSON in/out). Imported lazily so `load`/
    `save` still work on a box where python3-nftables isn't present."""
    from nftables import Nftables
    n = Nftables()
    n.set_json_output(True)
    return n


# ── policy persistence ───────────────────────────────────────────────────────
def cmd_load():
    try:
        with open(POLICY_PATH) as f:
            out({"policy": json.load(f), "path": POLICY_PATH, "exists": True})
    except FileNotFoundError:
        out({"policy": DEFAULT_POLICY, "path": POLICY_PATH, "exists": False})


def cmd_save():
    policy = read_stdin_json()
    if policy is None:
        out({"ok": False, "error": "no policy on stdin"})
        return
    os.makedirs(POLICY_DIR, mode=0o755, exist_ok=True)
    tmp = POLICY_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(policy, f, indent=2)
    os.replace(tmp, POLICY_PATH)  # atomic
    out({"ok": True, "path": POLICY_PATH})


# ── validate (dry-run) ───────────────────────────────────────────────────────
def cmd_validate():
    doc = read_stdin_json()
    if doc is None:
        out({"ok": False, "error": "no nft json doc on stdin"})
        return
    n = nft()
    n.set_dry_run(True)
    try:
        n.json_validate(doc)
    except Exception as e:  # schema error — never reached the kernel
        out({"ok": False, "error": "schema: %s" % e})
        return
    rc, _o, err = n.json_cmd(doc)
    out({"ok": rc == 0, "error": (err or "").strip() or None})


# ── apply + confirm-or-revert ────────────────────────────────────────────────
def _snapshot_ruleset():
    """Dump the current full ruleset as an nft script that restores it
    atomically (leading `flush ruleset`). Written to a root-only run dir."""
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    text = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, check=True).stdout
    with open(SNAPSHOT_PATH, "w") as f:
        f.write("flush ruleset\n")
        f.write(text)


def _restore_snapshot():
    if os.path.exists(SNAPSHOT_PATH):
        subprocess.run(["nft", "-f", SNAPSHOT_PATH], check=False)


def _disarm_timer():
    # Stop + clear the transient revert units if present. reset-failed keeps a
    # crashed prior run from blocking a fresh systemd-run of the same name.
    for unit in ("%s.timer" % REVERT_UNIT, "%s.service" % REVERT_UNIT):
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
        subprocess.run(["systemctl", "reset-failed", unit], capture_output=True)
    for p in (DEADLINE_PATH,):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


def cmd_apply():
    body = read_stdin_json() or {}
    doc = body.get("doc")
    timeout = int(body.get("timeout", 60))
    if doc is None:
        out({"ok": False, "error": "missing 'doc' in apply body"})
        return

    # Validate first so a broken render fails BEFORE we snapshot/apply anything.
    n = nft()
    n.set_dry_run(True)
    try:
        n.json_validate(doc)
    except Exception as e:
        out({"ok": False, "error": "schema: %s" % e})
        return
    rc, _o, err = n.json_cmd(doc)
    if rc != 0:
        out({"ok": False, "error": (err or "").strip() or "dry-run rejected"})
        return

    # Snapshot, then apply for real.
    try:
        _snapshot_ruleset()
    except Exception as e:
        out({"ok": False, "error": "snapshot failed: %s" % e})
        return
    n2 = nft()
    n2.set_dry_run(False)
    rc, _o, err = n2.json_cmd(doc)
    if rc != 0:
        out({"ok": False, "error": (err or "").strip() or "apply rejected"})
        return

    # Arm the auto-revert timer (transient, survives the browser closing).
    _disarm_timer()
    deadline = int(time.time()) + timeout
    with open(DEADLINE_PATH, "w") as f:
        f.write(str(deadline))
    subprocess.run([
        "systemd-run",
        "--unit=%s" % REVERT_UNIT,
        "--on-active=%ds" % timeout,
        "--timer-property=AccuracySec=1s",
        "/usr/bin/python3", SELF, "_do-revert",
    ], capture_output=True)
    out({"ok": True, "timeout": timeout, "deadline": deadline})


def cmd_confirm():
    _disarm_timer()
    out({"ok": True})


def cmd_revert():
    _restore_snapshot()
    _disarm_timer()
    out({"ok": True})


def cmd_status():
    armed = False
    seconds_left = 0
    try:
        with open(DEADLINE_PATH) as f:
            deadline = int(f.read().strip())
        seconds_left = max(0, deadline - int(time.time()))
        # Only "armed" if the timer unit is actually still queued.
        r = subprocess.run(["systemctl", "is-active", "%s.timer" % REVERT_UNIT], capture_output=True, text=True)
        armed = r.stdout.strip() == "active" and seconds_left > 0
    except FileNotFoundError:
        pass
    out({"armed": armed, "seconds_left": seconds_left})


def cmd_do_revert():
    # Executed by the systemd timer on timeout. No stdout consumer.
    _restore_snapshot()
    try:
        os.remove(DEADLINE_PATH)
    except FileNotFoundError:
        pass


# ── routing (IP forwarding) toggle ───────────────────────────────────────────
# Forwarding is what makes the through-firewall (FORWARD) path and SNAT actually
# route between interfaces. We persist it in a sysctl.d drop-in so it survives a
# reboot, and apply it live via `sysctl -w` so the toggle takes effect at once.
ROUTING_CONF = "/etc/sysctl.d/99-enforza-routing.conf"
ROUTING_KEYS = ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]


def cmd_routing_status():
    r = subprocess.run(["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True)
    out({"enabled": r.stdout.strip() == "1"})


def cmd_routing_set():
    body = read_stdin_json() or {}
    enabled = bool(body.get("enabled"))
    val = "1" if enabled else "0"
    with open(ROUTING_CONF, "w") as f:
        f.write("# Managed by enforza-cockpit — IP forwarding (routing) toggle.\n")
        for k in ROUTING_KEYS:
            f.write("%s = %s\n" % (k, val))
    for k in ROUTING_KEYS:
        subprocess.run(["sysctl", "-w", "%s=%s" % (k, val)], capture_output=True)
    out({"ok": True, "enabled": enabled})


DISPATCH = {
    "load": cmd_load, "save": cmd_save, "validate": cmd_validate,
    "apply": cmd_apply, "confirm": cmd_confirm, "revert": cmd_revert,
    "status": cmd_status, "_do-revert": cmd_do_revert,
    "routing-status": cmd_routing_status, "routing-set": cmd_routing_set,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in DISPATCH:
        out({"ok": False, "error": "usage: enforza-nft.py <%s>" % "|".join(k for k in DISPATCH if not k.startswith("_"))})
        sys.exit(2)
    DISPATCH[sys.argv[1]]()


if __name__ == "__main__":
    main()
