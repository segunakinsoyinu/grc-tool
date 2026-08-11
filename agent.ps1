# agent.ps1
# GRC evidence agent - runs on Windows-Server-2022 (10.0.2.20)
# Polls the GRC tool on the Ubuntu host for a pending assessment, collects local
# host evidence, and POSTs it back. Register as a Scheduled Task (see setup notes).
# 7005SCN Individual Research Project - Segun Akinsoyinu

$GrcUrl   = "http://10.0.2.10:8000"
$PollSecs = 5

function Get-HostEvidence {
    # Installed patches (Windows Update history)
    $patches = Get-HotFix | ForEach-Object {
        $installed = ""
        if ($_.InstalledOn) { $installed = $_.InstalledOn.ToString("MM/dd/yyyy") }
        [PSCustomObject]@{
            HotFixID    = $_.HotFixID
            Description = $_.Description
            InstalledOn = $installed
        }
    }

    # Firewall state per profile (true = enabled)
    $firewall = @{}
    Get-NetFirewallProfile | ForEach-Object { $firewall[$_.Name] = [bool]$_.Enabled }

    # Local user accounts
    $users = Get-LocalUser | ForEach-Object {
        [PSCustomObject]@{ Name = $_.Name; Enabled = [bool]$_.Enabled }
    }

    # Password policy (raw output of 'net accounts')
    $policy = (net accounts) -join "`n"

    # Listening TCP ports
    $ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
             Select-Object -ExpandProperty LocalPort -Unique | Sort-Object

    # RDP security posture. Network Level Authentication forces the client to
    # authenticate before a session is established; with it disabled, remote access
    # has no pre-session authentication step. This is the only local evidence source
    # for the remote-access authentication controls, which were previously assessed
    # from the questionnaire answer alone.
    $rdp = @{}
    try {
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $deny = (Get-ItemProperty -Path $ts -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
        $rdp['rdp_enabled'] = ($deny -eq 0)
        $nla = (Get-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name UserAuthenticationRequired -ErrorAction Stop).UserAuthenticationRequired
        $rdp['nla_required'] = ($nla -eq 1)
    } catch {
        $rdp['error'] = $_.Exception.Message
    }

    return @{
        hostname        = $env:COMPUTERNAME
        patches         = @($patches)
        firewall_state  = $firewall
        local_users     = @($users)
        password_policy = $policy
        open_ports      = @($ports)
        rdp_security    = $rdp
    }
}

Write-Host "GRC evidence agent started. Polling $GrcUrl every $PollSecs s ..."
while ($true) {
    try {
        $pending = Invoke-RestMethod -Uri "$GrcUrl/api/pending-assessment" -Method Get -TimeoutSec 10
        if ($pending.pending) {
            $aid = $pending.assessment_id
            Write-Host "Pending assessment $aid detected - collecting evidence..."
            $ev = Get-HostEvidence
            $ev.assessment_id = $aid
            $json = $ev | ConvertTo-Json -Depth 6
            Invoke-RestMethod -Uri "$GrcUrl/api/upload-evidence" -Method Post -Body $json -ContentType "application/json" | Out-Null
            Write-Host "Evidence for assessment $aid submitted."
        }
    } catch {
        Write-Host "Poll error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $PollSecs
}
