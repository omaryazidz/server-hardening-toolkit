#!/usr/bin/env bash
# Jalankan uji lengkap di VM lab: audit -> apply -> audit -> verifikasi.
# Layar tetap berwarna (untuk direkam), salinan polos disimpan ke results/.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
KEY=/root/vmlab/lab_key
SSH=(ssh -tt -q -i "$KEY" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null sysadmin@127.0.0.1)
save() { tee >(sed 's/\x1b\[[0-9;]*m//g; s/\r$//' >"results/$1"); }
step() { echo; echo "##### $* #####"; }

scp -q -i "$KEY" -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null linux/harden.sh sysadmin@127.0.0.1:
step "1. AUDIT SEBELUM HARDENING"
"${SSH[@]}" 'sudo bash harden.sh audit' | save linux-before.txt
step "2. APPLY HARDENING"
"${SSH[@]}" 'time sudo bash harden.sh apply' | save linux-apply.txt
step "3. VERIFIKASI DARI LUAR SERVER"
{
  FORCE_COLOR=1 bash test/verify-ssh.sh sysadmin "$KEY" 127.0.0.1 2222
  # bukti auditd mencatat: tambah user baru, lalu cari event-nya di audit log
  "${SSH[@]}" 'sudo useradd lab-test-user && sudo userdel lab-test-user
    n=$(sudo ausearch --input-logs -k identity -i 2>/dev/null | grep -c "type=SYSCALL")
    [ "$n" -gt 0 ] && printf "\033[32m[PASS]\033[0m auditd mencatat perubahan /etc/passwd ($n event)\n" || printf "\033[31m[FAIL]\033[0m auditd tidak mencatat\n"'
} | save linux-verify.txt
sleep 1 # tunggu tee di process substitution selesai menulis
