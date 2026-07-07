#!/usr/bin/env bash
#
# deploy.sh — publish the enforza-cockpit plugin to Cockpit's system package dir.
#
# The plugin is plain static files (dist/), so "building" is just copying them to
# /usr/share/cockpit/enforza where cockpit-ws serves them to every logged-in user.
#
# We copy real files (not a symlink into $HOME) on purpose: Cockpit serves package
# files AS the logged-in user, and a home dir at mode 0750 can't be traversed by
# other users — so a symlink into ~/ makes the plugin invisible to everyone but the
# owner. Copying into /usr/share/cockpit with world-read perms fixes that.
#
# Usage:  ./deploy.sh        (re-run after editing anything under dist/)
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/dist"
DEST="/usr/share/cockpit/enforza"

SUDO=""
[[ "${EUID}" -ne 0 ]] && SUDO="sudo"

echo "[enforza-cockpit] deploying ${SRC} -> ${DEST}"
${SUDO} mkdir -p "${DEST}"
# --delete so removed files don't linger; rsync if present, else cp.
if command -v rsync >/dev/null 2>&1; then
  ${SUDO} rsync -a --delete "${SRC}/" "${DEST}/"
else
  ${SUDO} rm -rf "${DEST:?}/"*
  ${SUDO} cp -r "${SRC}/." "${DEST}/"
fi
${SUDO} chmod -R a+rX "${DEST}"

echo "[enforza-cockpit] done. Reload Cockpit in the browser (Ctrl/Cmd+R) to pick up changes."
