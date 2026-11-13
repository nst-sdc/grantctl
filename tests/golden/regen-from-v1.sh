#!/usr/bin/env bash
# Regenerate tests/golden/teaching.golden from the bash v1 implementation (nst-cockpit).
# usage: tests/golden/regen-from-v1.sh /path/to/nst-cockpit tests/fixtures/teaching > tests/golden/teaching.golden
# The fixture directory must contain v1-style files: nodes, roles.ini, access.conf.
# Needs Linux, bash >= 4.4 and awk. v1 lives on the main branch: git show main:bin/nst-cockpit
set -euo pipefail
V1=$1; FX=$(cd "$2" && pwd); export LC_ALL=C
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
sed -e '/^case "\${1:-}" in$/,$d' "$V1" > "$T/lib.sh"
export NST_COCKPIT_CONF=$FX
# shellcheck disable=SC1091
source "$T/lib.sh"; set +e
ME=alice; SELF=node1; CONTROL=node1; PASSMAP_ALL=""; CONTROL_IPS="192.0.2.10,192.0.2.11"
for g in $(role_groups); do GIDMAP[$g]=""; done
for n in $(all_nodes); do
  eval "$(build_payload "$n" 1 | sed '/^set -euo pipefail$/,$d')"
  echo "=== $n"
  echo "accounts=$(echo $ACCOUNTS)"
  echo "managed=$MANAGED"
  echo "locked=$LOCKED"
  echo "allow=$ALLOW"
  for spec in $GROUPSPEC; do
    echo "group ${spec%%:*}=$(echo "${spec##*:}" | tr ',' '\n' | sort | paste -sd, -)"
  done
  echo "slices=$(echo $SLICES)"
  echo "quotas=$(echo $QUOTAS)"
  echo "--- match";   printf '%s' "$MATCH"
  echo "--- sudoers"; printf '%s' "$SUDOERS"
  echo "--- limits";  printf '%s' "$LIMITS"
done
