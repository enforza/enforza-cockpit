# enforza-cockpit

**A free, open web GUI for managing local `nftables` firewalls — built for homelabs
and small cloud instances.**

`enforza-cockpit` is a plugin for [Cockpit](https://cockpit-project.org/), the
web-based server manager that ships with most modern Linux distributions. It gives
you a clean, point-and-click interface for building and maintaining your
[`nftables`](https://wiki.nftables.org/) ruleset — no need to hand-edit rules over
SSH or remember the syntax.

It is a free community tool from the makers of **[enforza](https://enforza.io)** — a
managed cloud-firewall platform. `enforza-cockpit` is fully standalone: it needs no
account, no cloud connection, and no subscription. It runs entirely on your own box.

> ⚠️ **Status: early development.** The project is being built in the open. Expect
> rough edges and breaking changes until the first tagged release.

## Why

`nftables` is powerful, but the learning curve is steep and mistakes can lock you out
of your own server. Most homelabs and small single-instance cloud deployments don't
need a heavyweight firewall appliance — they just need a safe, visual way to:

- see what rules are currently loaded,
- add, edit, and reorder rules without syntax errors,
- open and close ports for the services they run,
- and keep an audit trail of what changed.

`enforza-cockpit` puts that in your browser, secured behind Cockpit's existing
authentication.

## Features (planned)

- **Ruleset viewer** — live view of the running `nftables` configuration, parsed from
  the native JSON output (`nft -j list ruleset`).
- **Visual rule editor** — build tables, chains, and rules through forms rather than raw
  syntax.
- **Safe apply** — validate changes before they go live, with a rollback timer so a bad
  rule can't permanently lock you out.
- **Service presets** — one-click open/close for common services (SSH, HTTP/S, WireGuard,
  etc.).
- **Logging** — optional per-rule logging via `ulogd2`, surfaced back in the dashboard.
- **Homelab-friendly defaults** — sensible starting policies for a single host on a home
  or small-cloud network.

## Requirements

- A Linux host running **Cockpit** (Debian/Ubuntu, Fedora, RHEL/Rocky/Alma, or similar).
- **`nftables`** as the active firewall backend.
- Root/administrator access (Cockpit handles privilege escalation for you).

## Getting started

Clone the repo and run the bootstrap script. It installs the packages the plugin
depends on — `nftables`, the `nftables` JSON/Python bindings, and `ulogd2` for logging.

```bash
git clone https://github.com/synvu/enforza-cockpit.git
cd enforza-cockpit
sudo ./bootstrap.sh
```

`bootstrap.sh` detects your package manager (apt / dnf / yum / zypper) and installs:

| Dependency | Purpose |
|------------|---------|
| `nftables` | The firewall engine this GUI manages |
| `nftables` JSON API (`libnftables` / `python3-nftables`) | Machine-readable rule read/write |
| `ulogd2` | Userspace logging for netfilter/nftables |
| `cockpit` | The web console the plugin plugs into (if not already present) |

Once dependencies are in place, open Cockpit at `https://<your-host>:9090` and look for
the **Firewall** (enforza) section.

📖 **See [docs/getting-started.md](docs/getting-started.md)** for the full step-by-step:
installing the plugin, building your first policy, and tailing per-rule logs in
`/var/log/syslog`.

## Security

`enforza-cockpit` runs inside Cockpit and inherits its authentication and TLS. It never
opens a network port of its own and never phones home. All firewall state stays on your
machine.

Because a misconfigured firewall can lock you out of a remote box, the plugin is being
designed around a **confirm-or-revert** model: risky changes must be re-confirmed within
a timeout, or they automatically roll back.

## About enforza

[enforza](https://enforza.io) builds managed, cloud-delivered firewall and egress-control
for teams that outgrow hand-rolled `iptables`/`nftables`. `enforza-cockpit` is our free
gift to the homelab and small-instance community — the same firewall mindset, running
locally, with no strings attached.

## License

Released under the [MIT License](LICENSE). Contributions welcome.
