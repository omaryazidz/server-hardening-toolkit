# Server Hardening Toolkit (Linux & Windows)

Script untuk **mengaudit** lalu **mengamankan** server baru dalam sekali jalan. Baseline-nya mengacu ke CIS Benchmark, dan setiap perubahan bisa di-rollback.

Kasus yang ditangani: VPS baru dari provider biasanya masih membuka login root, menerima login password, tidak punya firewall, dan tidak punya proteksi brute force. Di internet, server seperti ini mulai dicoba dibobol bot dalam hitungan menit.

## Hasil uji (lab)

Diuji di VM **Ubuntu 24.04 LTS** dari cloud image resmi Ubuntu (image yang sama dengan yang dipakai provider VPS), dijalankan dengan QEMU/KVM. VM dikondisikan seperti VPS baru: root login dibuka dan login password aktif lewat cloud-init. Lab-nya bisa dibuat ulang dengan [`test/lab-vm.sh`](test/lab-vm.sh).

| Pemeriksaan | Sebelum | Sesudah |
|---|:---:|:---:|
| SSH: root & password login dimatikan (key only) | ❌ | ✅ |
| SSH: MaxAuthTries 3, timeout, X11 off, banner | ❌ | ✅ |
| Firewall aktif, default deny incoming | ❌ | ✅ |
| Fail2ban melindungi SSH | ❌ | ✅ |
| Kernel & network hardening (sysctl) | ❌ | ✅ |
| Update keamanan otomatis | ✅ | ✅ |
| Audit log (auditd) | ❌ | ✅ |
| Permission `/etc/shadow`, `/etc/passwd` | ✅ | ✅ |
| Umur password maks 90 hari | ❌ | ✅ |
| **Skor** | **2/9** | **9/9** |

Setelah hardening, hasilnya diuji dari luar VM, tidak cukup dengan membaca config ([`test/run-lab.sh`](test/run-lab.sh)):

```
[PASS] sysadmin login dengan SSH key
[PASS] login password ditolak -> Permission denied (publickey)
[PASS] login root ditolak (walau pakai key)
[PASS] auditd mencatat perubahan /etc/passwd (15 event)
```

Proses apply selesai dalam kurang dari 1 menit, termasuk instalasi paket. Kalau dijalankan ulang, skornya tetap 9/9 tanpa ada yang diubah. Output mentahnya ada di folder [`results/`](results/).

## Linux: `linux/harden.sh`

Mendukung Ubuntu/Debian (apt) dan RHEL/Rocky/AlmaLinux (dnf).

```bash
sudo ./harden.sh audit                        # cek saja, tidak mengubah apa pun
sudo ALLOW_PORTS="80,443" ./harden.sh apply   # perbaiki yang FAIL, buka port web di firewall
```

Yang dikerjakan:

- **SSH**: root login dan password login dimatikan, MaxAuthTries 3, idle timeout, X11 forwarding off, banner legal. Config ditulis ke drop-in `00-hardening.conf` supaya tidak ditimpa `50-cloud-init.conf` (sshd memakai nilai yang dibaca pertama).
- **Firewall**: UFW atau firewalld, default deny incoming. Port SSH (dibaca dari config sshd, bukan diasumsikan 22) dibuka sebelum firewall diaktifkan.
- **Fail2ban**: IP di-ban 1 jam setelah 5 kali gagal login dalam 10 menit.
- **sysctl**: anti IP spoofing, ICMP redirect, dan source routing, SYN cookies, ASLR, serta pembatasan akses kptr dan dmesg.
- **Update keamanan otomatis**: unattended-upgrades atau dnf-automatic (khusus security update).
- **auditd**: mencatat setiap perubahan pada `passwd`, `shadow`, `sudoers`, dan config SSH.
- **Permission file sensitif** dan **kebijakan umur password**.

Pengaman supaya server klien tidak rusak:

| Risiko | Pengaman |
|---|---|
| Klien terkunci dari server sendiri | Password login & root login **hanya** dimatikan kalau sudah ada user sudo yang memakai SSH key. Kalau belum ada, script memberi peringatan dan melewati langkah itu. |
| Config SSH rusak | Divalidasi dengan `sshd -t` sebelum reload. Kalau gagal, otomatis di-rollback. |
| Server Docker/Kubernetes rusak | `ip_forward` sengaja tidak disentuh. |
| Butuh kembali ke kondisi awal | Setiap file disalin ke `/var/backups/hardening-<waktu>/` sebelum diubah. |
| Dijalankan berulang | Idempotent: yang sudah PASS dilewati. |

## Windows: `windows/Harden-Windows.ps1`

Untuk Windows Server 2016+ dan Windows 10/11. Jalankan dari PowerShell **as Administrator**.

```powershell
.\Harden-Windows.ps1 -Mode Audit
.\Harden-Windows.ps1 -Mode Apply
```

Yang dikerjakan: firewall aktif di semua profil, SMBv1 dimatikan (celah WannaCry), SMB signing diwajibkan, RDP wajib NLA, akun Guest dinonaktifkan, password minimal 12 karakter dan kompleks, lockout setelah 5 kali gagal, TLS 1.0/1.1 dimatikan, Defender real-time aktif, audit log logon dan perubahan akun, UAC, AutoRun off, serta LLMNR off (mencegah serangan Responder).

- Sebelum diubah, registry di-export ke `C:\HardeningBackup\<waktu>\*.reg` dan security policy ke `secpol-before.inf`.
- Audit policy diatur memakai GUID, jadi tetap jalan di Windows berbahasa Indonesia.
- Mematikan TLS 1.0/1.1 butuh reboot, dan aplikasi lama yang belum mendukung TLS 1.2 bisa ikut terputus. Periksa dulu sebelum dipakai di production.

> Status uji: script Windows sudah lolos syntax check, tapi belum dijalankan di Windows Server sungguhan.

## Struktur

```
linux/harden.sh              audit + apply (Linux)
windows/Harden-Windows.ps1   audit + apply (Windows)
test/lab-vm.sh               boot VM Ubuntu "VPS baru" via QEMU/KVM
test/run-lab.sh              uji lengkap: audit -> apply -> audit -> verifikasi
test/verify-ssh.sh           bukti login key OK, password & root ditolak
results/                     output asli dari lab
```
