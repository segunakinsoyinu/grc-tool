# baseline-audit.ps1
# Layer 2 ground-truth baseline audit.
#
# Records the ACTUAL state of a lab host for the controls the GRC tool flagged
# that Table 3.1 does not cover. Every section is a reproducible machine fact
# with the command visible, so a flag can be classified as a confirmed failure
# or a genuine false positive without researcher judgement.
#
# Run on BOTH Windows-Server-2022 (10.0.2.20) and Windows-10-Workstation
# (10.0.2.30). Output goes to C:\baseline-audit-<HOSTNAME>.txt for the appendix.
#
# 7005SCN Individual Research Project - Segun Akinsoyinu

$out = "C:\baseline-audit-$env:COMPUTERNAME.txt"

"BASELINE AUDIT" | Out-File $out -Encoding utf8
"Host      : $env:COMPUTERNAME" | Out-File $out -Append -Encoding utf8
"Captured  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $out -Append -Encoding utf8
"OS        : $((Get-CimInstance Win32_OperatingSystem).Caption)" | Out-File $out -Append -Encoding utf8

function Sec($title, $cmdText, $script) {
    "" | Out-File $out -Append -Encoding utf8
    ("=" * 78) | Out-File $out -Append -Encoding utf8
    "CONTROLS : $title" | Out-File $out -Append -Encoding utf8
    "COMMAND  : $cmdText" | Out-File $out -Append -Encoding utf8
    ("=" * 78) | Out-File $out -Append -Encoding utf8
    try { & $script 2>&1 | Out-String | Out-File $out -Append -Encoding utf8 }
    catch { "ERROR: $($_.Exception.Message)" | Out-File $out -Append -Encoding utf8 }
}

Sec "CE-UAC-5, ISO-A.5.17  (password policy)" `
    "net accounts" `
    { net accounts }

Sec "CE-SC-2, CE-UAC-1, ISO-A.8.2, ISO-A.5.16  (local accounts)" `
    "Get-LocalUser" `
    { Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet | Format-Table -AutoSize }

Sec "CE-UAC-1, CE-UAC-2, ISO-A.8.2, ISO-A.5.18  (privileged access)" `
    "Get-LocalGroupMember -Group Administrators" `
    { Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass | Format-Table -AutoSize }

Sec "CE-FW-1, CE-FW-2  (firewall state)" `
    "Get-NetFirewallProfile" `
    { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize }

Sec "CE-FW-3  (firewall rule documentation proxy)" `
    "Get-NetFirewallRule -Direction Inbound -Enabled True" `
    { "Enabled inbound rules: " + @(Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue).Count }

Sec "CE-PM-2, CE-PM-4, GDPR-32-8, ISO-A.8.8  (patch currency)" `
    "Get-HotFix" `
    { Get-HotFix | Select-Object HotFixID, Description, InstalledOn | Sort-Object InstalledOn | Format-Table -AutoSize }

Sec "CE-PM-4, ISO-A.8.19  (update service state)" `
    "Get-Service wuauserv" `
    { Get-Service wuauserv | Select-Object Name, Status, StartType | Format-Table -AutoSize }

Sec "CE-SC-4, CE-SC-5, CE-FW-2  (listening ports)" `
    "Get-NetTCPConnection -State Listen" `
    { Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object }

Sec "CE-SC-4, CE-SC-5  (running services)" `
    "Get-Service | Where-Object Status -eq Running" `
    { Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName | Format-Table -AutoSize }

Sec "CE-MP-1, CE-MP-2, CE-MP-3, ISO-A.8.7  (anti-malware)" `
    "Get-MpComputerStatus" `
    { Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureVersion, AntivirusSignatureLastUpdated | Format-List }

Sec "CE-SC-3  (autorun policy)" `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer NoDriveTypeAutoRun" `
    { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue | Select-Object NoDriveTypeAutoRun | Format-List }

Sec "CE-UAC-3, CE-UAC-4, ISO-A.8.5, GDPR-32-9  (RDP authentication)" `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server  fDenyTSConnections / UserAuthenticationRequired" `
    {
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        [pscustomobject]@{
            fDenyTSConnections         = (Get-ItemProperty $ts -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
            UserAuthenticationRequired = (Get-ItemProperty "$ts\WinStations\RDP-Tcp" -Name UserAuthenticationRequired -ErrorAction SilentlyContinue).UserAuthenticationRequired
        } | Format-List
    }

Sec "ISO-A.8.24, GDPR-32-2  (encryption at rest)" `
    "Get-BitLockerVolume" `
    { Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod | Format-Table -AutoSize }

Sec "ISO-A.8.22, CE-FW-4  (SMB configuration)" `
    "Get-SmbServerConfiguration" `
    { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EnableSecuritySignature, RequireSecuritySignature | Format-List }

Sec "ISO-A.8.15, ISO-A.8.16  (audit and logging policy)" `
    "auditpol /get /category:*" `
    { auditpol.exe /get /category:* }

Sec "ISO-A.8.13, ISO-A.8.14, GDPR-32-5  (backup and recovery)" `
    "vssadmin list shadows" `
    { vssadmin.exe list shadows }

Sec "CE-SC-4, CE-SC-5  (installed roles and features, server only)" `
    "Get-WindowsFeature | Where-Object Installed" `
    {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            Get-WindowsFeature | Where-Object { $_.Installed } | Select-Object Name, DisplayName | Format-Table -AutoSize
        } else {
            "Get-WindowsFeature is not available on this edition (client OS)."
        }
    }

"" | Out-File $out -Append -Encoding utf8
("=" * 78) | Out-File $out -Append -Encoding utf8
"END OF BASELINE AUDIT" | Out-File $out -Append -Encoding utf8

Write-Host "Baseline audit written to $out"
