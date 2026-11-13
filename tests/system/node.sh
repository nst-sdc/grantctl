#!/usr/bin/env bash
# Real-system test of the node side: real useradd, gpasswd, visudo, sshd -t.
#
# DESTRUCTIVE. It creates accounts and rewrites sshd_config.d and sudoers.d
# of the machine it runs on. Run it only in a disposable container or VM:
#
#   docker run --rm -v "$PWD":/src -w /src ubuntu:26.04 bash -c '
#     apt-get update -qq && apt-get install -y -qq openssh-server sudo jq openssl >/dev/null &&
#     GRANTCTL_DISPOSABLE=1 tests/system/node.sh target/release/grantctl'
set -uo pipefail
BIN=$(readlink -f "${1:-target/debug/grantctl}")
if [ "$(id -u)" != 0 ] || [ "${GRANTCTL_DISPOSABLE:-}" != 1 ]; then
  echo "refusing: run as root with GRANTCTL_DISPOSABLE=1, in a disposable machine only" >&2; exit 2
fi
for tool in jq openssl visudo sshd useradd; do command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 2; }; done

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; [ -n "${2:-}" ] && echo "     $2"; }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name" "command: $*"; fi; }
is()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected [$3], got [$2] ${4:-}"; }
has() { case "$2" in *"$3"*) ok "$1";; *) bad "$1" "no [$3] in [$2]";; esac; }
members() { getent group "$1" | cut -d: -f4 | tr ',' '\n' | sort | paste -sd, -; }
hash_of() { getent shadow "$1" | cut -d: -f2; }

HOST=$(hostname); C=$(mktemp -d)
SSHD=/etc/ssh/sshd_config.d; SUDO=/etc/sudoers.d
ssh-keygen -A >/dev/null 2>&1; mkdir -p /run/sshd /srv/gt-home
printf '%s\nother-node\n' "$HOST" > "$C/nodes"
cat > "$C/roles.ini" <<ROLES
[admin]
groups   = gt-staff,sudo
password = yes
[student]
groups   = gt-students
nodes    = $HOST
password = yes
[gpu]
groups   = gt-gpu
nodes    = $HOST
password = yes
from     = 10.9.9.9
sshd     = MaxSessions=4,X11Forwarding=no
home     = /srv/gt-home
slice    = CPUQuota=200%,MemoryMax=1G
limits   = nproc=512,maxlogins=4
ROLES
roster() { printf '%s\n' "op admin nopasswd" "$@" > "$C/access.conf"; }
echo 'LEGACY_SSHD="00-gt-lockdown.conf"' > "$C/grantctl.conf"
plan()  { "$BIN" --config-dir "$C" --operator op plan "$HOST" --json; }
apply() { plan | "$BIN" node apply "$@"; }

# A machine as an admin left it: operator with sudo, an allow-list by name,
# a student who is not in the roster any more, an account to be locked.
useradd -m -s /bin/bash op; gpasswd -a op sudo >/dev/null
useradd -m -s /bin/bash gt_erin; groupadd gt-students; gpasswd -a gt_erin gt-students >/dev/null
useradd -m -s /bin/bash gt_frank; echo 'gt_frank:Frank-pw-1' | chpasswd
echo "AllowUsers op gt_erin" > "$SSHD/00-gt-lockdown.conf"
roster "gt_bob admin" "gt_carol student" "gt_dave student gpu" "gt_frank locked"

echo "== version and root check"
has "node version answers"           "$("$BIN" node version)" '"protocol":1'
has "plan is valid JSON with the node name" "$(plan | jq -r .node)" "$HOST"

echo "== dry run"
R=$(apply --dry-run)
is  "dry run reports ok"             "$(jq -r .ok <<<"$R")" true
is  "dry run plans steps"            "$(jq -r '.steps|length > 5' <<<"$R")" true
is  "dry run: who loses SSH"         "$(jq -r '.ssh_lose|join(",")' <<<"$R")" "gt_erin"
check "dry run created no account"   bash -c '! getent passwd gt_bob'
check "dry run wrote no file"        bash -c "! test -e $SUDO/99-grantctl && ! test -e $SSHD/10-grantctl.conf"
check "dry run kept the legacy file" test -e "$SSHD/00-gt-lockdown.conf"

echo "== apply"
R=$(apply)
is  "apply reports ok"               "$(jq -r .ok <<<"$R")" true "$(jq -r .error <<<"$R")"
is  "every step is done"             "$(jq -r '[.steps[].status]|unique|join(",")' <<<"$R")" done
is  "accounts created"               "$(jq -r '.created|join(",")' <<<"$R")" "gt_bob,gt_carol,gt_dave"
is  "sudo members"                   "$(members sudo)" "gt_bob,op"
is  "staff members"                  "$(members gt-staff)" "gt_bob,op"
is  "students exact (erin removed)"  "$(members gt-students)" "gt_carol,gt_dave"
is  "gpu home base"                  "$(getent passwd gt_dave | cut -d: -f6)" /srv/gt-home/gt_dave
check "gpu home exists"              test -d /srv/gt-home/gt_dave
check "sudoers tree valid (visudo -c)" visudo -c
is  "sudoers file mode"              "$(stat -c %a "$SUDO/99-grantctl")" 440
has "operator NOPASSWD rule"         "$(cat "$SUDO/99-grantctl")" "op ALL=(ALL:ALL) NOPASSWD: ALL"
check "sshd accepts the config (sshd -t)" sshd -t
has "AllowGroups written"            "$(cat "$SSHD/10-grantctl.conf")" "AllowGroups gt-gpu gt-staff gt-students sudo"
has "effective AllowGroups (sshd -T)" "$(sshd -T 2>/dev/null | grep -i '^allowgroups' | sort | paste -sd' ' -)" "gt-students"
has "source restriction written"     "$(cat "$SSHD/99-grantctl.conf")" "Match Group gt-gpu,!gt-staff,!gt-students,!sudo Address *,!10.9.9.9"
check "legacy allow-list removed"    bash -c "! test -e $SSHD/00-gt-lockdown.conf"
has "pam limits written"             "$(cat /etc/security/limits.d/60-grantctl.conf)" "@gt-gpu hard nproc 512"
uid=$(id -u gt_dave)
has "slice limits written"           "$(cat /etc/systemd/system/user-$uid.slice.d/50-grantctl.conf)" "CPUQuota=200%"
is  "locked account: expiry marker"  "$(getent shadow gt_frank | cut -d: -f8)" 1
has "locked account: password locked" "$(hash_of gt_frank)" '!'
check "backup taken"                 bash -c "test -e $(jq -r .backup <<<"$R")/sshd_config.d/00-gt-lockdown.conf"

echo "== idempotence"
R=$(apply)
is  "second apply: ok"               "$(jq -r .ok <<<"$R")" true
is  "second apply: nothing to do"    "$(jq -r '.steps|length' <<<"$R")" 0

echo "== a failing switch restores the files and removes no access"
useradd -m -s /bin/bash gt_gina; gpasswd -a gt_gina gt-students >/dev/null   # not in the roster
before=$(cat "$SSHD"/* "$SUDO"/99-grantctl | sha256sum)
printf 'PermitRootLogin no\nNoSuchSshdKeyword yes\n' > "$C/sshd-baseline"
roster "gt_bob admin" "gt_carol student" "gt_dave student gpu" "gt_frank locked" "gt_new student"
R=$(apply)
is  "apply reports failure"          "$(jq -r .ok <<<"$R")" false
has "error names the sshd check"     "$(jq -r .error <<<"$R")" "sshd -t rejects"
has "error says files were restored" "$(jq -r .error <<<"$R")" "restored the previous files"
is  "files are byte-identical again" "$(cat "$SSHD"/* "$SUDO"/99-grantctl | sha256sum)" "$before"
check "sshd still accepts the config" sshd -t
check "sudoers still valid"          visudo -c
has "gina kept her group (no narrowing)" "$(members gt-students)" "gt_gina"
is  "narrow steps were skipped"      "$(jq -r '[.steps[]|select(.phase=="narrow")|.status]|unique|join(",")' <<<"$R")" skipped
check "widening had happened (account exists)" getent passwd gt_new
rm "$C/sshd-baseline"
R=$(apply)
is  "after the fix: ok"              "$(jq -r .ok <<<"$R")" true "$(jq -r .error <<<"$R")"
is  "after the fix: gina removed"    "$(members gt-students)" "gt_carol,gt_dave,gt_new"

echo "== an invalid sudoers file never reaches /etc/sudoers.d"
before=$(sha256sum < "$SUDO/99-grantctl")
R=$(plan | jq '.sudoers += "this is not sudoers syntax\n"' | "$BIN" node apply)
is  "apply reports failure"          "$(jq -r .ok <<<"$R")" false
has "error names the candidate check" "$(jq -r .error <<<"$R")" "generated sudoers file is invalid"
is  "installed sudoers untouched"    "$(sha256sum < "$SUDO/99-grantctl")" "$before"
check "sudoers still valid"          visudo -c

echo "== guards"
R=$(plan | jq '.groups |= map(if .name=="sudo" then .members -= ["op"] else . end)' | "$BIN" node apply)
has "refuses to drop the operator's sudo" "$(jq -r .error <<<"$R")" "operator op would lose group sudo"
R=$(plan | jq '.is_control=false | .sudoers |= sub("op ALL=\\(ALL:ALL\\) NOPASSWD: ALL\n";"")' | "$BIN" node apply)
has "refuses to drop the operator's NOPASSWD" "$(jq -r .error <<<"$R")" "would lose passwordless sudo"
is  "nothing changed by refused states" "$(members sudo)" "gt_bob,op"

echo "== passwords follow the control node"
H1=$(openssl passwd -6 -salt gtsalt1 'First-pw-1'); H2=$(openssl passwd -6 -salt gtsalt2 'Second-pw-2')
with_pw() { plan | jq --arg h "$1" --arg lc "$2" '.passwords=[{user:"gt_fresh",hash:$h,last_change:$lc}]' | "$BIN" node apply; }
roster "gt_bob admin" "gt_carol student" "gt_dave student gpu" "gt_frank locked" "gt_new student" "gt_fresh student"
R=$(with_pw "$H1" 0)
is  "apply with a password: ok"      "$(jq -r .ok <<<"$R")" true "$(jq -r .error <<<"$R")"
is  "new account has the control node's hash" "$(hash_of gt_fresh)" "$H1"
is  "forced change is copied"        "$(getent shadow gt_fresh | cut -d: -f3)" 0
check "the hash is not in the report" bash -c "! grep -q gtsalt1 <<<'$R'"
R=$(with_pw "$H2" 20000)
is  "a changed control password is copied" "$(hash_of gt_fresh)" "$H2"
check "forced change is cleared"     bash -c "[ \"\$(getent shadow gt_fresh | cut -d: -f3)\" != 0 ]"
echo 'gt_fresh:Own-pw-3' | chpasswd; own=$(hash_of gt_fresh)
R=$(with_pw "$H1" 20000)
is  "a password changed on the node stays" "$(hash_of gt_fresh)" "$own"
is  "state file is root-only"        "$(stat -c %a /var/lib/grantctl/passwords)" 600

echo "== single-account operations"
acct() { echo "$1" | "$BIN" node account; }
R=$(acct '{"op":"passwd","user":"gt_carol","password":"Temp-pw-4","must_change":true}')
is  "passwd: ok"                     "$(jq -r .ok <<<"$R")" true
is  "passwd: must change"            "$(jq -r .fact.must_change <<<"$R")" true
R=$(acct '{"op":"lock","user":"gt_carol"}')
is  "lock: locked"                   "$(jq -r .fact.locked <<<"$R")" true
R=$(acct '{"op":"unlock","user":"gt_carol"}')
is  "unlock: unlocked"               "$(jq -r .fact.locked <<<"$R")" false
R=$(acct '{"op":"where","user":"gt_dave"}')
has "where: groups"                  "$(jq -r '.fact.groups|join(",")' <<<"$R")" "gt-gpu"
R=$(acct '{"op":"where","user":"gt_nobody"}')
is  "where: missing account"         "$(jq -r .exists <<<"$R")" false
R=$(acct '{"op":"delete","user":"gt_dave","purge":true}')
is  "delete --purge: ok"             "$(jq -r .ok <<<"$R")" true
check "delete: account gone"         bash -c '! getent passwd gt_dave'
check "delete: home gone"            bash -c '! test -e /srv/gt-home/gt_dave'
check "delete: slice limits gone"    bash -c "! test -e /etc/systemd/system/user-$uid.slice.d"

echo "== facts, hashes, audit (read-only)"
F=$("$BIN" node facts </dev/null)
has "facts: accounts"                "$(jq -r '[.accounts[].user]|join(",")' <<<"$F")" "gt_bob"
has "facts: owned sudoers file"      "$(jq -r '.sudoers_files|join(",")' <<<"$F")" "99-grantctl"
has "facts: nopasswd user"           "$(jq -r '.nopasswd_users|join(",")' <<<"$F")" "op"
Hs=$(echo '{"users":["gt_fresh","gt_frank","gt_nobody"]}' | "$BIN" node hashes)
is  "hashes: only usable passwords"  "$(jq -r '[.passwords[].user]|join(",")' <<<"$Hs")" "gt_fresh"
A=$(echo '{"managed":["op","gt_bob"],"sudo_group":"sudo","legacy_managers":[]}' | "$BIN" node audit)
has "audit: unmanaged account"       "$(jq -r '[.findings[].text]|join("|")' <<<"$A")" "unmanaged account: gt_erin"
has "audit: effective sshd settings" "$(jq -r '[.findings[].text]|join("|")' <<<"$A")" "permitrootlogin no"

echo "== must be root"
if command -v runuser >/dev/null; then
  has "node apply refuses a non-root caller" "$(runuser -u op -- "$BIN" node facts 2>&1 </dev/null)" "must run as root"
fi

echo
echo "passed: $pass   failed: $fail"
[ "$fail" = 0 ]
