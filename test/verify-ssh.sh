#!/usr/bin/env bash
# Bukti hardening SSH: login pakai key berhasil, login password & root ditolak.
# Usage: ./verify-ssh.sh <user-admin> <private-key> [host] [port]
USER_ADMIN=${1:?user admin}
KEY=${2:?private key}
HOST=${3:-127.0.0.1}
PORT=${4:-22}
OPTS=(-p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5)
if [[ -t 1 || -n ${FORCE_COLOR:-} ]]; then G=$'\e[32m' R=$'\e[31m' N=$'\e[0m'; else G='' R='' N=''; fi
ok=0
pass() { echo "${G}[PASS]${N} $*"; }
fail() { echo "${R}[FAIL]${N} $*"; ok=1; }

if out=$(ssh "${OPTS[@]}" -i "$KEY" "$USER_ADMIN@$HOST" whoami 2>/dev/null) && [[ $out == "$USER_ADMIN" ]]; then
  pass "$USER_ADMIN login dengan SSH key"
else fail "$USER_ADMIN tidak bisa login dengan key"; fi

methods=$(ssh "${OPTS[@]}" -o PubkeyAuthentication=no "$USER_ADMIN@$HOST" true 2>&1 | grep -o 'Permission denied (.*)')
if [[ $methods == "Permission denied (publickey)" ]]; then
  pass "login password ditolak -> $methods"
else fail "login password masih diterima: $methods"; fi

if ! ssh "${OPTS[@]}" -i "$KEY" "root@$HOST" true 2>/dev/null; then
  pass "login root ditolak (walau pakai key)"
else fail "root masih bisa login"; fi

exit $ok
