#!/usr/bin/env bash
# End-to-end test over real SSH: a control container and two node containers.
#
#   cargo build --release && tests/e2e/run.sh target/release/grantctl
#
# Needs docker. Everything happens inside throw-away containers.
set -uo pipefail
BIN=$(readlink -f "${1:?usage: tests/e2e/run.sh <grantctl binary>}")
IMAGE=${IMAGE:-ubuntu:26.04}
NET=gt-e2e
NODES="gt-ctl gt-n2 gt-gpu"

cleanup() {
  docker rm -f $NODES >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/     /'; }
has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1" "no [$3] in:
$2";; esac; }
hasnt() { case "$2" in *"$3"*) bad "$1" "unexpected [$3] in:
$2";; *) ok "$1";; esac; }
is()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected [$3], got [$2]"; }

echo "== building the node image"
docker build -q -t gt-e2e-node - >/dev/null <<EOF || { echo "image build failed"; exit 2; }
FROM $IMAGE
RUN apt-get update -qq && apt-get install -y -qq openssh-server sudo iproute2 sshpass >/dev/null \
 && mkdir -p /run/sshd && ssh-keygen -A >/dev/null
RUN useradd -m -s /bin/bash op && gpasswd -a op sudo >/dev/null \
 && echo 'op ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/00-bootstrap && chmod 0440 /etc/sudoers.d/00-bootstrap
CMD ["/usr/sbin/sshd", "-D", "-e"]
EOF
docker network create "$NET" >/dev/null
for n in $NODES; do docker run -d --name "$n" --hostname "$n" --network "$NET" gt-e2e-node >/dev/null; done

root() { local n=$1; shift; docker exec "$n" "$@"; }
ctl()  { docker exec -u op -e USER=op -e HOME=/home/op gt-ctl "$@"; }
# Run grantctl on the control node as the operator; capture output and exit code.
G() { OUT=$(ctl grantctl "$@" 2>&1); RC=$?; }
members() { root "$1" getent group "$2" | cut -d: -f4; }
hash_of() { root "$1" getent shadow "$2" | cut -d: -f2; }
# Try a password login from the control node; prints what ssh said.
login() { ctl sshpass -p "$3" ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no "$1@$2" true 2>&1; }

# The operator's key is on the control node and trusted on the other nodes.
ctl bash -c 'mkdir -p ~/.ssh && ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519 \
  && printf "Host *\n  StrictHostKeyChecking accept-new\n  LogLevel ERROR\n" > ~/.ssh/config'
pub=$(ctl cat /home/op/.ssh/id_ed25519.pub)
for n in gt-n2 gt-gpu; do
  docker exec -u op "$n" bash -c "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$pub' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
done
root gt-gpu mkdir -p /srv/gpu-home
docker cp "$BIN" gt-ctl:/usr/local/bin/grantctl >/dev/null

echo "== init and node install"
G version;                              has "the binary runs in the container" "$OUT" "grantctl "
G init gt-ctl gt-n2 gt-gpu;             is  "init: exit code" "$RC" 0
has "init: nodes without grantctl are named" "$OUT" "[gt-n2] grantctl is not installed there. Run: grantctl node install gt-n2"
has "init: drafted the operator from the control node" "$(ctl cat /etc/grantctl/access.conf)" "op "
is  "init: /etc/grantctl belongs to root" "$(root gt-ctl stat -c %U /etc/grantctl/access.conf)" root
G node install --copy gt-n2 gt-gpu;     is  "node install --copy: exit code" "$RC" 0
has "node install: version check over SSH" "$OUT" "[gt-gpu] grantctl "

echo "== configuration"
ctl sudo tee /etc/grantctl/roles.ini >/dev/null <<'ROLES'
[admin]
groups   = gt-staff,sudo
password = yes
[student]
groups   = gt-students
nodes    = gt-ctl
password = yes
[gpu]
groups   = gt-gpu-users
nodes    = gt-gpu
password = yes
from     = control
home     = /srv/gpu-home
slice    = CPUQuota=200%
ROLES
ctl sudo tee /etc/grantctl/access.conf >/dev/null <<'ROSTER'
op     admin nopasswd
bob    admin
carol  student
dave   student gpu
ROSTER
ctl sudo bash -c 'echo "LEGACY_SUDO=\"00-bootstrap\"" >> /etc/grantctl/grantctl.conf'
G check;                                is  "check: exit code" "$RC" 0

echo "== dry run"
G sync --dry-run;                       is  "dry run: exit code" "$RC" 0
has "dry run: plans accounts on a remote node" "$OUT" "[gt-n2] would: create account bob"
has "dry run: shows the bootstrap sudoers file going" "$OUT" "[gt-n2] would: remove /etc/sudoers.d/00-bootstrap"
is  "dry run: nothing created" "$(root gt-n2 getent passwd bob)" ""

echo "== sync"
G sync;                                 is  "sync: exit code" "$RC" 0
SYNC=$OUT
has "sync: temporary passwords printed" "$SYNC" "Temporary passwords"
is  "n2: sudo members"        "$(members gt-n2 sudo)" "op,bob"
is  "control: students"       "$(members gt-ctl gt-students)" "carol,dave"
is  "n2: no students there"   "$(members gt-n2 gt-students)" ""
is  "gpu: home under the role's base" "$(root gt-gpu getent passwd dave | cut -d: -f6)" /srv/gpu-home/dave
is  "bootstrap sudoers replaced on n2" "$(root gt-n2 ls /etc/sudoers.d | grep -v README | paste -sd, -)" "99-grantctl"
has "from = control became the control node's address" "$(root gt-gpu cat /etc/ssh/sshd_config.d/99-grantctl.conf)" \
    "Address *,!$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' gt-ctl)"
has "sshd on n2 was reloaded with the new rules" "$(root gt-n2 sshd -T 2>/dev/null | grep -i '^allowgroups')" "gt-staff"
is  "the operator can still log in and sudo over SSH" "$(ctl ssh gt-n2 sudo -n id -u 2>&1)" 0
h=$(hash_of gt-ctl bob)
has "bob has a real password hash" "$h" '$'
is  "same password on n2"  "$(hash_of gt-n2 bob)"  "$h"
is  "same password on gpu" "$(hash_of gt-gpu bob)" "$h"
is  "forced change on n2"  "$(root gt-n2 getent shadow bob | cut -d: -f3)" 0
pw=$(echo "$SYNC" | awk '$1=="bob"{print $2}')
# The running sshd must accept the printed password on a node that only
# copied the hash. The change is forced, so the login stops after that.
hasnt "password login on n2 accepts the printed password" "$(login bob gt-n2 "$pw")" "Permission denied"
has   "password login on n2 rejects a wrong password"     "$(login bob gt-n2 "not-$pw")" "Permission denied"

G sync;                                 is  "second sync: exit code" "$RC" 0
is  "second sync: every node in sync" "$(grep -c 'in sync' <<<"$OUT")" 3
hasnt "second sync: nothing done" "$OUT" "create account"

echo "== day-to-day commands"
G grant erin student;                   is  "grant: exit code" "$RC" 0
has "grant: account on the control node" "$(members gt-ctl gt-students)" "erin"
G grant erin gpu;                       is  "grant a second role: exit code" "$RC" 0
is  "erin has the same password on the new node" "$(hash_of gt-gpu erin)" "$(hash_of gt-ctl erin)"
G where erin;                           has "where: per node state" "$OUT" "[gt-gpu] uid="
has "where: nodes without the account" "$OUT" "[gt-n2] no account"
G passwd erin;                          is  "passwd: exit code" "$RC" 0
has "passwd: prints the temporary password" "$OUT" "Temporary password for erin:"
G lock erin;                            is  "lock: exit code" "$RC" 0
is  "lock: expiry marker on the gpu node" "$(root gt-gpu getent shadow erin | cut -d: -f8)" 1
G unlock erin;                          is  "unlock: marker cleared" "$(root gt-gpu getent shadow erin | cut -d: -f8)" ""
G revoke erin gpu;                      is  "revoke: exit code" "$RC" 0
has "revoke: the account left behind is reported" "$OUT" "[gt-gpu] STRAY accounts (no access here, not locked): erin"
G prune;                                is  "prune: stray account locked" "$(root gt-gpu getent shadow erin | cut -d: -f8)" 1
G delete erin --purge --yes;            is  "delete: exit code" "$RC" 0
is  "delete: gone from every node" "$(root gt-ctl getent passwd erin)$(root gt-gpu getent passwd erin)" ""
G status;                               has "status: groups per node" "$OUT" "[gt-n2] sudo: op,bob"
G audit;                                is  "audit: exit code" "$RC" 0
has "audit: reports per node" "$OUT" "[gt-gpu] info sshd effective:"
G revoke op admin;                      is  "the operator cannot remove their own sudo" "$RC" 1
has "... and is told why" "$OUT" "need sudo on every node"

echo "== an unreachable node"
docker stop gt-n2 >/dev/null
G grant frank admin;                    is  "sync with a node down: exit code" "$RC" 1
has "the node is reported" "$OUT" "[gt-n2] UNREACHABLE, skipped"
has "the rest is synced"   "$(members gt-gpu sudo)" "frank"
docker start gt-n2 >/dev/null; sleep 2
G sync gt-n2;                           is  "catching up: exit code" "$RC" 0
has "frank arrives on n2" "$(members gt-n2 sudo)" "frank"
is  "... with the same password" "$(hash_of gt-n2 frank)" "$(hash_of gt-ctl frank)"

echo
echo "passed: $pass   failed: $fail"
[ "$fail" = 0 ]
