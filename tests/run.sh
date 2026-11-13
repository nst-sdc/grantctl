#!/usr/bin/env bash
# Unit tests for nst-cockpit's pure logic (no root, no SSH, no node changes).
# Usage: tests/run.sh            (needs bash, awk, sed; mawk and gawk both supported)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); BIN=$HERE/../bin/nst-cockpit
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if [ "$2" = "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); printf 'FAIL %s\n  want: %s\n  got:  %s\n' "$1" "$3" "$2"; fi; }
has(){ if grep -qF -- "$3" <<<"$2"; then pass=$((pass+1)); else fail=$((fail+1)); printf 'FAIL %s\n  missing: %s\n' "$1" "$3"; fi; }

# library = the tool without its root guard and dispatcher
sed -e '/^case "\${1:-}" in$/,$d' "$BIN" > "$T/lib.sh"
export NST_COCKPIT_CONF=$T/etc; mkdir -p "$T/etc"
printf '%s\n' node1 node2 node3 gpu1 > "$T/etc/nodes"
cat > "$T/etc/roles.ini" <<'EOF'
[admin]
groups   = staff,sudo
password = yes
[user]
groups   = shell-users
[student]
groups   = students
nodes    = node1
password = yes
[gpu]
groups   = gpu-users
nodes    = gpu1
password = yes
from     = control
sshd     = MaxSessions=4,X11Forwarding=no
home     = /srv/gpu-home
slice    = CPUQuota=800%,MemoryMax=20G
quota    = 90G
limits   = nproc=1024,maxlogins=4
EOF
cat > "$T/etc/access.conf" <<'EOF'
alice    admin nopasswd
bob      admin
carol    student
dave     student gpu pwonly@node1
erin     user@node3
frank    locked
EOF
run(){ ( set +e; source "$T/lib.sh"; set +e; ME=alice; SELF=node1; CONTROL=node1; write_file(){ cp "$1" "$2"; rm -f "$1"; }; eval "$1" ) 2>&1; }

# roles + validation
ok  "roles parse"            "$(run 'roles_tsv | cut -f1 | tr "\n" " "')" "admin user student gpu "
ok  "validate ok"            "$(run 'validate && echo OK')" "OK"
cp "$T/etc/access.conf" "$T/a.bak"
printf 'x1 wizard\nx2 user@node9\nx3 review\nx1 user\nx4 nopasswd\n' >> "$T/etc/access.conf"
v=$(run validate)
has "validate unknown role"  "$v" "x1: unknown role/flag wizard"
has "validate unknown node"  "$v" "x2: unknown node node9"
has "validate review"        "$v" "x3: unresolved review"
has "validate duplicate"     "$v" "duplicate user: x1"
has "validate no role"       "$v" "x4: no role"
cp "$T/a.bak" "$T/etc/access.conf"
sed -i 's/^alice.*/alice user/' "$T/etc/access.conf"
has "validate operator admin" "$(run validate)" "need an unscoped admin token"
cp "$T/a.bak" "$T/etc/access.conf"

# token editing
run 'edit_tokens add erin node2 user' >/dev/null
ok  "grant --on merges"      "$(grep '^erin' "$T/etc/access.conf" | awk '{print $2}')" "user@node2,node3"
run 'edit_tokens add erin "" user' >/dev/null
ok  "grant all -> plain"     "$(grep '^erin' "$T/etc/access.conf" | awk '{print $2}')" "user"
run 'edit_tokens del erin "node1,gpu1" user' >/dev/null
ok  "revoke --on subtracts"  "$(grep '^erin' "$T/etc/access.conf" | awk '{print $2}')" "user@node2,node3"
run 'edit_tokens add dave gpu1 locked' >/dev/null
has "scoped flag"            "$(grep '^dave' "$T/etc/access.conf")" "locked@gpu1"
run 'edit_tokens del dave "" locked' >/dev/null
run 'edit_tokens add gina "" student' >/dev/null
ok  "new user line"          "$(grep '^gina' "$T/etc/access.conf" | awk '{print $2}')" "student"
run 'edit_tokens del gina ""' >/dev/null
ok  "drop user"              "$(grep -c '^gina' "$T/etc/access.conf")" "0"
ok  "short node name"        "$(run 'norm_node 3')" "node3"

# per-node plans
p1=$(run 'plan_node node1'); pg=$(run 'plan_node gpu1'); p3=$(run 'plan_node node3')
has "node1 student group"    "$p1" "GROUP students carol,dave"
has "node1 pwonly"           "$p1" "PWONLY dave"
has "node1 nopasswd"         "$p1" "NOPASSWD alice"
has "gpu1 home"              "$pg" "ACCOUNT dave /srv/gpu-home"
has "gpu1 slice"             "$pg" "SLICE dave CPUQuota=800%,MemoryMax=20G"
has "gpu1 quota"             "$pg" "QUOTA dave 90G /srv/gpu-home"
has "gpu1 from"              "$pg" "FROM gpu-users control"
has "node3 shell user"       "$p3" "GROUP shell-users erin"
has "locked everywhere"      "$p3" "LOCK frank"
ok  "no student off node1"   "$(grep -c 'ACCOUNT carol' <<<"$p3")" "0"

# rendered payload
pl=$(run 'PASSMAP_ALL=""; CONTROL_IPS="10.0.0.1,10.0.0.2"; for g in $(role_groups); do GIDMAP[$g]=""; done; build_payload gpu1 1 | grep -E "^(MATCH|SUDOERS|LIMITS|ALLOW|IS_CONTROL)="')
eval "$(grep -E '^(MATCH|SUDOERS|LIMITS|ALLOW|IS_CONTROL)=' <<<"$pl")"
has "match from control"     "$MATCH" 'Match Group gpu-users,!shell-users,!staff,!sudo Address *,!10.0.0.1,!10.0.0.2'
has "match opts"             "$MATCH" "    MaxSessions 4"
has "sudoers group"          "$SUDOERS" "%sudo ALL=(ALL:ALL) ALL"
has "sudoers nopasswd"       "$SUDOERS" "alice ALL=(ALL:ALL) NOPASSWD: ALL"
has "limits"                 "$LIMITS" "@gpu-users hard maxlogins 4"
ok  "allow groups"           "$ALLOW" "gpu-users shell-users staff sudo"
ok  "not control"            "$IS_CONTROL" "0"

# init draft from evidence
cat > "$T/raw" <<'EOF'
alice acct@node1
alice grp:staff@node1
alice grp:sudo@node1
alice grp:staff@node2
alice grp:sudo@node2
alice grp:staff@node3
alice grp:sudo@node3
alice grp:staff@gpu1
alice grp:sudo@gpu1
alice nopasswd@node2
carol grp:students@node1
carol grp:sudo@node3
dave grp:students@node1
dave grp:gpu-users@gpu1
dave ssh@node2
ghost acct@node3
EOF
d=$(run 'draft "'"$T"'/raw"')
ok  "draft admin"            "$(awk '$1=="alice"{print $2, $3}' <<<"$d")" "admin nopasswd@node2"
has "draft sudo review"      "$(grep '^carol' <<<"$d")" "student review"
has "draft shell role"       "$(grep '^dave' <<<"$d")" "student gpu user@node2"
has "draft account only"     "$(grep '^ghost' <<<"$d")" "review"

echo "passed: $pass  failed: $fail"
[ "$fail" = 0 ]
