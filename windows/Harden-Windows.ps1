<#
.SYNOPSIS
    Audit atau apply baseline keamanan Windows Server / Windows 10-11.
.EXAMPLE
    .\Harden-Windows.ps1 -Mode Audit    # cek saja
.EXAMPLE
    .\Harden-Windows.ps1 -Mode Apply    # perbaiki yang FAIL, backup registry & secpol dulu
.NOTES
    Mesin yang join domain: Group Policy domain bisa menimpa pengaturan lokal ini.
#>
#Requires -RunAsAdministrator
param([ValidateSet('Audit', 'Apply')][string]$Mode = 'Audit')

$ErrorActionPreference = 'Stop'
$BackupDir = Join-Path $env:SystemDrive "HardeningBackup\$(Get-Date -Format yyyyMMdd-HHmmss)"
$Exported = @{}

function Get-Reg($Path, $Name) {
    (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

function Set-Reg($Path, $Name, [int]$Value) {
    # export key sekali sebelum diubah, supaya bisa di-restore dengan double-click .reg
    if (-not $Exported[$Path] -and (Test-Path $Path)) {
        New-Item -ItemType Directory -Force $BackupDir | Out-Null
        $file = Join-Path $BackupDir "reg-$($Exported.Count).reg"
        reg export ($Path -replace '^HKLM:\\', 'HKLM\') $file /y | Out-Null
        $Exported[$Path] = $true
    }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Get-SecPolicy {
    $f = [IO.Path]::GetTempFileName()
    secedit /export /cfg $f /areas SECURITYPOLICY | Out-Null
    $policy = @{}
    foreach ($line in Get-Content $f) {
        if ($line -match '^\s*(\w+)\s*=\s*(.+?)\s*$') { $policy[$Matches[1]] = $Matches[2] }
    }
    Remove-Item $f
    $policy
}

# Subcategory pakai GUID karena nama subcategory berbeda di Windows bahasa lain
$AuditSubcategories = @(
    '{0CCE9215-69AE-11D9-BED3-505054503030}'  # Logon
    '{0CCE9217-69AE-11D9-BED3-505054503030}'  # Account Lockout
    '{0CCE9235-69AE-11D9-BED3-505054503030}'  # User Account Management
)

$Tls = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$Rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$PolSystem = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$PolExplorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$PolDns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'

# Test: $true = PASS, $false = FAIL, $null = SKIP (tidak berlaku di mesin ini)
$Checks = @(
    @{  Name = 'Windows Firewall aktif di semua profil'
        Test = { -not (Get-NetFirewallProfile | Where-Object Enabled -ne 'True') }
        Fix  = { Set-NetFirewallProfile -All -Enabled True } }

    @{  Name = 'SMBv1 dimatikan (celah WannaCry/EternalBlue)'
        Test = { -not (Get-SmbServerConfiguration).EnableSMB1Protocol }
        Fix  = { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } }

    @{  Name = 'SMB signing diwajibkan'
        Test = { (Get-SmbServerConfiguration).RequireSecuritySignature }
        Fix  = { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force } }

    @{  Name = 'RDP wajib Network Level Authentication'
        Test = { (Get-Reg $Rdp UserAuthentication) -eq 1 }
        Fix  = { Set-Reg $Rdp UserAuthentication 1 } }

    @{  Name = 'Akun Guest dinonaktifkan'
        Test = { -not (Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Enabled }
        Fix  = { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser } }

    @{  Name = 'Password min 12 karakter, kompleks, lockout setelah 5x gagal'
        Test = {
            $p = Get-SecPolicy
            [int]$p.MinimumPasswordLength -ge 12 -and [int]$p.PasswordComplexity -eq 1 -and
            [int]$p.LockoutBadCount -in 1..5
        }
        Fix  = {
            New-Item -ItemType Directory -Force $BackupDir | Out-Null
            secedit /export /cfg (Join-Path $BackupDir 'secpol-before.inf') /areas SECURITYPOLICY | Out-Null
            $inf = Join-Path $env:TEMP 'hardening-secpol.inf'
            @'
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
MaximumPasswordAge = 90
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
[Version]
signature="$CHICAGO$"
Revision=1
'@ | Set-Content -Path $inf -Encoding Unicode
            secedit /configure /db (Join-Path $env:TEMP 'hardening-secpol.sdb') /cfg $inf /areas SECURITYPOLICY | Out-Null
            Remove-Item $inf
        } }

    @{  Name = 'TLS 1.0 & 1.1 dimatikan (butuh reboot)'
        Test = { (Get-Reg "$Tls\TLS 1.0\Server" Enabled) -eq 0 -and (Get-Reg "$Tls\TLS 1.1\Server" Enabled) -eq 0 }
        Fix  = {
            foreach ($v in 'TLS 1.0', 'TLS 1.1') {
                Set-Reg "$Tls\$v\Server" Enabled 0
                Set-Reg "$Tls\$v\Server" DisabledByDefault 1
            }
        } }

    @{  Name = 'Microsoft Defender real-time protection aktif'
        Test = {
            if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return $null }
            (Get-MpComputerStatus).RealTimeProtectionEnabled
        }
        Fix  = { Set-MpPreference -DisableRealtimeMonitoring $false } }

    @{  Name = 'Audit log: logon, lockout, perubahan akun (success+failure)'
        Test = {
            $f = [IO.Path]::GetTempFileName()
            auditpol /backup /file:$f | Out-Null
            $rows = Import-Csv $f
            Remove-Item $f
            -not ($AuditSubcategories | Where-Object {
                    $g = $_; ($rows | Where-Object 'Subcategory GUID' -eq $g).'Setting Value' -ne '3' })
        }
        Fix  = {
            foreach ($g in $AuditSubcategories) { auditpol /set /subcategory:$g /success:enable /failure:enable | Out-Null }
        } }

    @{  Name = 'UAC aktif'
        Test = { (Get-Reg $PolSystem EnableLUA) -eq 1 }
        Fix  = { Set-Reg $PolSystem EnableLUA 1 } }

    @{  Name = 'AutoRun dimatikan untuk semua drive'
        Test = { (Get-Reg $PolExplorer NoDriveTypeAutoRun) -eq 255 }
        Fix  = { Set-Reg $PolExplorer NoDriveTypeAutoRun 255 } }

    @{  Name = 'LLMNR dimatikan (cegah serangan Responder)'
        Test = { (Get-Reg $PolDns EnableMulticast) -eq 0 }
        Fix  = { Set-Reg $PolDns EnableMulticast 0 } }
)

function Test-Check($Check) {
    try { $r = & $Check.Test; if ($null -eq $r) { 'SKIP' } elseif ($r) { 'PASS' } else { 'FAIL' } }
    catch { 'ERROR' }
}

function Invoke-Audit {
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    Write-Host "== Audit $env:COMPUTERNAME ($os) =="
    $pass = 0; $total = 0
    foreach ($c in $Checks) {
        $status = Test-Check $c
        $color = @{ PASS = 'Green'; FAIL = 'Red'; SKIP = 'Yellow'; ERROR = 'Magenta' }[$status]
        Write-Host ("  [{0,-5}] {1}" -f $status, $c.Name) -ForegroundColor $color
        if ($status -ne 'SKIP') { $total++ }
        if ($status -eq 'PASS') { $pass++ }
    }
    Write-Host "== Skor: $pass/$total =="
}

if ($Mode -eq 'Apply') {
    foreach ($c in $Checks) {
        if ((Test-Check $c) -ne 'FAIL') { continue }
        Write-Host "  [FIX  ] $($c.Name)"
        try { & $c.Fix } catch { Write-Warning "$($c.Name): $_" }
    }
    if (Test-Path $BackupDir) { Write-Host "Backup: $BackupDir" }
    Write-Host ''
}
Invoke-Audit
