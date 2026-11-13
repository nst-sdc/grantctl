#!/usr/bin/env bash
# Install or remove nst-cockpit.   ./install.sh [--uninstall]   PREFIX=/usr/local by default
set -euo pipefail
PREFIX=${PREFIX:-/usr/local}
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || exec sudo PREFIX="$PREFIX" bash "$0" "$@"
if [ "${1:-}" = --uninstall ]; then
  rm -f "$PREFIX/sbin/nst-cockpit" "$PREFIX/share/man/man8/nst-cockpit.8"
  command -v mandb >/dev/null && mandb -q 2>/dev/null || true
  echo "removed. Config in /etc/nst-cockpit and files on the nodes are left in place."
  exit 0
fi
install -D -m 0755 bin/nst-cockpit "$PREFIX/sbin/nst-cockpit"
install -D -m 0644 man/nst-cockpit.8 "$PREFIX/share/man/man8/nst-cockpit.8"
command -v mandb >/dev/null && mandb -q 2>/dev/null || true
echo "installed $("$PREFIX/sbin/nst-cockpit" version 2>/dev/null || echo nst-cockpit) to $PREFIX"
echo "next (as your own user, on the control node): nst-cockpit init <control-node> <node>...   docs: man nst-cockpit"
