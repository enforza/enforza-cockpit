#!/usr/bin/env bash
#
# bootstrap.sh — install the prerequisites for enforza-cockpit.
#
# enforza-cockpit is a Cockpit web GUI for managing local nftables firewalls on
# homelabs and small cloud instances. This script installs the packages the plugin
# depends on: nftables itself, the nftables JSON/Python bindings (so the GUI can
# read and write the ruleset programmatically), ulogd2 (userspace netfilter logging),
# and Cockpit (the web console the plugin plugs into).
#
# It detects the host's package manager (apt / dnf / yum / zypper) so it works across
# the common homelab and small-cloud Linux distributions.
#
# Usage:  sudo ./bootstrap.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers: coloured, prefixed logging so it's obvious what the script is doing.
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[enforza-cockpit]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[enforza-cockpit] WARN:\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[enforza-cockpit] ERROR:\033[0m %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Require root — every package manager below needs it, as does managing nftables.
# ---------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  err "This script must be run as root. Try: sudo ./bootstrap.sh"
  exit 1
fi

# ---------------------------------------------------------------------------
# Detect the available package manager. We support the four that cover the vast
# majority of homelab / small-cloud Linux hosts.
# ---------------------------------------------------------------------------
PKG_MGR=""
for candidate in apt-get dnf yum zypper; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    PKG_MGR="${candidate}"
    break
  fi
done

if [[ -z "${PKG_MGR}" ]]; then
  err "No supported package manager found (looked for apt-get, dnf, yum, zypper)."
  err "Please install the dependencies manually: nftables, python3-nftables, ulogd2, cockpit."
  exit 1
fi

log "Detected package manager: ${PKG_MGR}"

# ---------------------------------------------------------------------------
# Map the logical dependencies onto the package names each distro family uses.
#
#   nftables          - the firewall engine this GUI manages
#   <json bindings>    - Python/JSON bindings over libnftables so the GUI can
#                        read/write rules as structured data (nft -j)
#   ulogd2            - userspace logging daemon for netfilter/nftables
#   cockpit           - the web console the plugin plugs into
# ---------------------------------------------------------------------------
case "${PKG_MGR}" in
  apt-get)
    # Debian / Ubuntu. python3-nftables ships the JSON bindings; libnftables is
    # pulled in as a dependency of nftables.
    PACKAGES=(nftables python3-nftables ulogd2 cockpit)
    ;;
  dnf|yum)
    # Fedora / RHEL / Rocky / Alma. python3-nftables provides the JSON bindings.
    PACKAGES=(nftables python3-nftables ulogd cockpit)
    ;;
  zypper)
    # openSUSE. libnftables provides the JSON API; python3-nftables the bindings.
    PACKAGES=(nftables python3-nftables ulogd cockpit)
    ;;
esac

# ---------------------------------------------------------------------------
# Refresh package metadata, then install. Each manager has its own syntax for a
# non-interactive install.
# ---------------------------------------------------------------------------
log "Refreshing package metadata..."
case "${PKG_MGR}" in
  apt-get) apt-get update -y ;;
  dnf)     dnf makecache -y ;;
  yum)     yum makecache -y ;;
  zypper)  zypper --non-interactive refresh ;;
esac

log "Installing: ${PACKAGES[*]}"
case "${PKG_MGR}" in
  apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}" ;;
  dnf)     dnf install -y "${PACKAGES[@]}" ;;
  yum)     yum install -y "${PACKAGES[@]}" ;;
  zypper)  zypper --non-interactive install "${PACKAGES[@]}" ;;
esac

# ---------------------------------------------------------------------------
# Enable the core services so the firewall and web console survive a reboot.
# We enable but only start Cockpit's socket; nftables is left for the user/plugin
# to load a ruleset into, so we don't accidentally apply an empty (lock-you-out)
# policy here.
# ---------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  log "Enabling nftables and cockpit services..."
  systemctl enable nftables.service        2>/dev/null || warn "Could not enable nftables.service"
  systemctl enable --now cockpit.socket     2>/dev/null || warn "Could not enable cockpit.socket"
  systemctl enable ulogd2.service 2>/dev/null \
    || systemctl enable ulogd.service 2>/dev/null \
    || warn "Could not enable ulogd service (name varies by distro)"
else
  warn "systemctl not found — skipping service enablement. Enable nftables/cockpit/ulogd manually."
fi

# ---------------------------------------------------------------------------
# Quick sanity check that the key tooling is present.
# ---------------------------------------------------------------------------
log "Verifying installation..."
MISSING=()
command -v nft     >/dev/null 2>&1 || MISSING+=("nft")
command -v cockpit-bridge >/dev/null 2>&1 || MISSING+=("cockpit-bridge")
# The Python JSON bindings are importable as the 'nftables' module.
python3 -c "import nftables" >/dev/null 2>&1 || MISSING+=("python3 nftables module")

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "Some components could not be verified: ${MISSING[*]}"
  warn "The install may still be usable; check the messages above."
else
  log "All core dependencies present."
fi

log "Done. Open Cockpit at https://<your-host>:9090 and look for the Firewall (enforza) section."
log "Plugin installation steps will be documented as the UI lands."
