# Exports Windows Event Log entries as syslog-style lines that `sentinel train/detect --file` can read.
# Run in PowerShell *as Administrator* (the Security log needs it). EXPERIMENTAL: not yet tested on a real Windows host.
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\scripts\win2log.ps1 -Days 14 -Out windows.log
param([int]$Days = 7, [string]$Out = "windows.log")

$since = (Get-Date).AddDays(-$Days)
$hostName = $env:COMPUTERNAME
$lines = New-Object System.Collections.Generic.List[string]

function Get-Data($e) {
    $d = @{}
    ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    return $d
}

$queries = @(
    @{ LogName = 'Security'; Id = 4624, 4625, 4672, 4720, 4732 },   # logon ok/failed, privileges, user created, group member added
    @{ LogName = 'System';   Id = 7045, 6008 }                      # new service installed, unexpected shutdown
)

foreach ($q in $queries) {
    $q.StartTime = $since
    Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue | ForEach-Object {
        $d = Get-Data $_
        $ip = if ($d.IpAddress) { $d.IpAddress } else { '-' }
        switch ($_.Id) {
            4625 { $p = 'winlogon'; $m = "Failed password for $($d.TargetUserName) from $ip logontype $($d.LogonType) (authentication failure)" }
            4624 { $p = 'winlogon'; $m = "Accepted logon for $($d.TargetUserName) from $ip logontype $($d.LogonType)" }
            4672 { $p = 'winlogon'; $m = "Special privileges assigned to $($d.SubjectUserName)" }
            4720 { $p = 'useradd';  $m = "useradd: new account $($d.TargetUserName) created by $($d.SubjectUserName)" }
            4732 { $p = 'groupadd'; $m = "member added to group $($d.TargetUserName) by $($d.SubjectUserName)" }
            7045 { $p = 'services'; $m = "New service installed $($d.ServiceName) $($d.ImagePath)" }
            6008 { $p = 'system';   $m = "Unexpected shutdown error" }
        }
        $m = $m -replace '\s+', ' '
        $lines.Add(("{0:yyyy-MM-ddTHH:mm:ss} {1} {2}: {3}" -f $_.TimeCreated, $hostName, $p, $m))
    }
}

$sorted = $lines | Sort-Object
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) $Out), $sorted, [System.Text.Encoding]::ASCII)
"Wrote $($sorted.Count) events to $Out"
