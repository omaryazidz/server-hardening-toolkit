#!/usr/bin/env bash
# Linux server hardening: audit atau apply baseline keamanan (terinspirasi CIS Benchmark).
# Distro: Ubuntu/Debian (apt) dan RHEL/Rocky/Alma (dnf).
#
#   sudo ./harden.sh audit                      # cek saja, tidak mengubah apa pun
#   sudo ALLOW_PORTS="80,443" ./harden.sh apply # perbaiki yang FAIL, port tambahan dibuka di firewall
set -uo pipefail

MODE="${1:-audit}"
ALLOW_PORTS="${ALLOW_PORTS:-}"
BACKUP_DIR="/var/backups/hardening-$(date +%Y%m%d-%H%M%S)"
SSH_DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf # 00- supaya menang dari 50-cloud-init.conf (sshd: nilai pertama yang dipakai)
SYSCTL_FILE=/etc/sysctl.d/99-zz-hardening.conf      # zz- supaya dibaca setelah 99-sysctl.conf
F2B_JAIL=/etc/fail2ban/jail.d/sshd-hardening.local
AUDIT_RULES=/etc/audit/rules.d/hardening.rules

if [[ -t 1 ]]; then G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' N=$'\e[0m'; else G='' R='' Y='' N=''; fi
warn() { echo "  ${Y}[WARN]${N} $*"; }

[[ $EUID -eq 0 ]] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
case "$MODE" in audit|apply) ;; *) echo "Usage: $0 audit|apply"; exit 1 ;; esac
if command -v apt-get >/dev/null; then PKG=apt
elif command -v dnf >/dev/null; then PKG=dnf
else echo "Distro tidak didukung (butuh apt atau dnf)."; exit 1; fi

pkg_install() {
  if [[ $PKG == apt ]]; then DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -qq "$@" >/dev/null
  else dnf install -y -q "$@" >/dev/null; fi
}
backup() { # simpan salinan file sebelum diubah, path asli dipertahankan
  local f
  for f in "$@"; do
    [[ -e $f ]] || continue
    mkdir -p "$BACKUP_DIR$(dirname "$f")" && cp -a "$f" "$BACKUP_DIR$f"
  done
}
svc_on() { systemctl enable --now "$1" >/dev/null 2>&1 || warn "gagal enable service $1"; }
svc_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# ---------- SSH ----------
sshd_val() { sshd -T 2>/dev/null | awk -v k="$1" '$1==k {print $2; exit}'; }
ssh_port() { local p; p=$(sshd_val port); echo "${p:-22}"; }

# Password login & root login hanya dimatikan kalau ada admin non-root yang sudah pakai SSH key,
# supaya klien tidak terkunci dari servernya sendiri.
admin_has_key() {
  local u home
  for u in $(getent group sudo wheel | cut -d: -f4 | tr ',' ' '); do
    home=$(getent passwd "$u" | cut -d: -f6)
    [[ -s $home/.ssh/authorized_keys ]] && return 0
  done
  return 1
}

write_ssh_dropin() {
  backup /etc/ssh/sshd_config "$SSH_DROPIN" /etc/issue.net
  grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config ||
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  mkdir -p /etc/ssh/sshd_config.d
  echo "Authorized access only. All activity is logged and monitored." >/etc/issue.net
  {
    echo "# Managed by harden.sh"
    if admin_has_key; then
      printf '%s\n' "PermitRootLogin no" "PasswordAuthentication no" "KbdInteractiveAuthentication no"
    fi
    printf '%s\n' "PermitEmptyPasswords no" "MaxAuthTries 3" "LoginGraceTime 30" "X11Forwarding no" \
      "ClientAliveInterval 300" "ClientAliveCountMax 2" "Banner /etc/issue.net"
  } >"$SSH_DROPIN"
  if ! sshd -t; then
    warn "konfigurasi sshd tidak valid, rollback"
    rm -f "$SSH_DROPIN"
    [[ -e $BACKUP_DIR$SSH_DROPIN ]] && cp -a "$BACKUP_DIR$SSH_DROPIN" "$SSH_DROPIN"
    cp -a "$BACKUP_DIR/etc/ssh/sshd_config" /etc/ssh/sshd_config
    return 1
  fi
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
}

audit_ssh_auth() {
  command -v sshd >/dev/null || return 2
  [[ $(sshd_val permitrootlogin) == no && $(sshd_val passwordauthentication) == no ]]
}
fix_ssh_auth() {
  if ! admin_has_key; then
    warn "belum ada user sudo dengan SSH key -> login password/root TIDAK dimatikan (cegah terkunci)."
    warn "tambahkan key ke ~/.ssh/authorized_keys user admin, lalu jalankan apply lagi."
    return 1
  fi
  write_ssh_dropin
}

audit_ssh_config() {
  command -v sshd >/dev/null || return 2
  [[ $(sshd_val permitemptypasswords) == no && $(sshd_val maxauthtries) -le 3 &&
     $(sshd_val x11forwarding) == no && $(sshd_val logingracetime) -le 60 &&
     $(sshd_val clientaliveinterval) -gt 0 && $(sshd_val banner) != none ]]
}
fix_ssh_config() { write_ssh_dropin; }

# ---------- Firewall ----------
audit_firewall() {
  if [[ $PKG == apt ]]; then command -v ufw >/dev/null && ufw status | grep "Status: active" >/dev/null
  else svc_active firewalld; fi
}
fix_firewall() {
  local port p
  port=$(ssh_port)
  if [[ $PKG == apt ]]; then
    pkg_install ufw
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow "$port/tcp" >/dev/null # port SSH dibuka dulu sebelum enable
    for p in ${ALLOW_PORTS//,/ }; do ufw allow "$p/tcp" >/dev/null; done
    ufw --force enable >/dev/null
  else
    pkg_install firewalld
    svc_on firewalld
    firewall-cmd -q --permanent --add-port="$port/tcp"
    for p in ${ALLOW_PORTS//,/ }; do firewall-cmd -q --permanent --add-port="$p/tcp"; done
    firewall-cmd -q --reload
  fi
}

# ---------- Fail2ban ----------
audit_fail2ban() { command -v fail2ban-client >/dev/null && fail2ban-client status sshd >/dev/null 2>&1; }
fix_fail2ban() {
  [[ $PKG == dnf ]] && pkg_install epel-release
  pkg_install fail2ban python3-systemd
  backup "$F2B_JAIL"
  cat >"$F2B_JAIL" <<EOF
# Managed by harden.sh
[sshd]
enabled  = true
port     = $(ssh_port)
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
  svc_on fail2ban
  systemctl restart fail2ban
  sleep 2 # fail2ban butuh waktu sebentar sebelum jail aktif
}

# ---------- Kernel / network (sysctl) ----------
# ip_forward sengaja tidak disentuh: server Docker/Kubernetes membutuhkannya.
SYSCTL="net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.log_martians=1 net.ipv4.tcp_syncookies=1 net.ipv4.icmp_echo_ignore_broadcasts=1
kernel.randomize_va_space=2 kernel.kptr_restrict=2 kernel.dmesg_restrict=1
fs.protected_hardlinks=1 fs.protected_symlinks=1 fs.suid_dumpable=0"

audit_sysctl() {
  local kv
  for kv in $SYSCTL; do
    [[ $(sysctl -n "${kv%%=*}" 2>/dev/null) == "${kv#*=}" ]] || return 1
  done
}
fix_sysctl() {
  backup "$SYSCTL_FILE"
  { echo "# Managed by harden.sh"; printf '%s\n' $SYSCTL; } >"$SYSCTL_FILE"
  sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || warn "sebagian parameter sysctl tidak bisa diterapkan di kernel ini"
}

# ---------- Update keamanan otomatis ----------
audit_autoupdate() {
  if [[ $PKG == apt ]]; then
    dpkg -s unattended-upgrades >/dev/null 2>&1 && apt-config dump | grep 'APT::Periodic::Unattended-Upgrade "1"' >/dev/null
  else systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null; fi
}
fix_autoupdate() {
  if [[ $PKG == apt ]]; then
    pkg_install unattended-upgrades
    backup /etc/apt/apt.conf.d/20auto-upgrades
    printf '%s\n' 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' \
      >/etc/apt/apt.conf.d/20auto-upgrades
  else
    pkg_install dnf-automatic
    backup /etc/dnf/automatic.conf
    sed -i -E 's/^upgrade_type\s*=.*/upgrade_type = security/' /etc/dnf/automatic.conf
    svc_on dnf-automatic-install.timer
  fi
}

# ---------- Audit log (auditd) ----------
audit_auditd() { svc_active auditd && [[ -f $AUDIT_RULES ]]; }
fix_auditd() {
  if [[ $PKG == apt ]]; then pkg_install auditd; else pkg_install audit; fi
  backup "$AUDIT_RULES"
  cat >"$AUDIT_RULES" <<'EOF'
# Managed by harden.sh - catat perubahan file identitas, sudo, dan SSH
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
EOF
  svc_on auditd
  augenrules --load >/dev/null 2>&1 || true
}

# ---------- Permission file sensitif ----------
mode_of() { stat -c %a "$1"; }
audit_perms() {
  (( (8#$(mode_of /etc/shadow) & 8#007) == 0 && (8#$(mode_of /etc/gshadow) & 8#007) == 0 &&
     (8#$(mode_of /etc/passwd) & 8#022) == 0 && (8#$(mode_of /etc/group) & 8#022) == 0 ))
}
fix_perms() { chmod o-rwx /etc/shadow /etc/gshadow && chmod go-w /etc/passwd /etc/group; }

# ---------- Kebijakan umur password ----------
logindef() { awk -v k="$1" '$1==k {print $2}' /etc/login.defs; }
audit_login_defs() { [[ $(logindef PASS_MAX_DAYS) -le 90 && $(logindef PASS_MIN_DAYS) -ge 1 ]]; }
fix_login_defs() {
  backup /etc/login.defs
  sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
}

# ---------- Runner ----------
CHECKS=(ssh_auth ssh_config firewall fail2ban sysctl autoupdate auditd perms login_defs)
declare -A DESC=(
  [ssh_auth]="SSH: root login & password login dimatikan (key only)"
  [ssh_config]="SSH: MaxAuthTries, timeout, X11 off, banner"
  [firewall]="Firewall aktif, default deny incoming"
  [fail2ban]="Fail2ban melindungi SSH dari brute force"
  [sysctl]="Kernel & network hardening (sysctl)"
  [autoupdate]="Update keamanan otomatis"
  [auditd]="Audit log (auditd) untuk file sensitif"
  [perms]="Permission /etc/shadow, /etc/passwd aman"
  [login_defs]="Umur password maks 90 hari"
)

run_audit() {
  local c rc pass=0 total=0
  echo "== Audit $(hostname) ($(. /etc/os-release && echo "$PRETTY_NAME")) - $(date '+%d %b %Y %H:%M:%S %Z') =="
  for c in "${CHECKS[@]}"; do
    "audit_$c"; rc=$?
    case $rc in
      0) echo "  ${G}[PASS]${N} ${DESC[$c]}"; pass=$((pass + 1)); total=$((total + 1)) ;;
      2) echo "  ${Y}[SKIP]${N} ${DESC[$c]} (tidak berlaku)" ;;
      *) echo "  ${R}[FAIL]${N} ${DESC[$c]}"; total=$((total + 1)) ;;
    esac
  done
  echo "== Skor: $pass/$total =="
}

run_apply() {
  local c rc
  [[ $PKG == apt ]] && apt-get update -qq
  for c in "${CHECKS[@]}"; do
    "audit_$c"; rc=$?
    [[ $rc -eq 0 || $rc -eq 2 ]] && continue # 2 = tidak berlaku; selain itu FAIL (systemctl bisa return 3)
    echo "  [FIX ] ${DESC[$c]}"
    "fix_$c" || warn "${DESC[$c]} belum berhasil diperbaiki"
  done
  [[ -d $BACKUP_DIR ]] && echo "Backup file lama: $BACKUP_DIR"
  echo
  run_audit
}

"run_$MODE"
