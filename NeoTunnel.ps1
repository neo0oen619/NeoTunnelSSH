<# builder.ps1 – new-PC wizard  
#>

function Read-PlainPassword ($msg) {
    $ss = Read-Host $msg -AsSecureString
    [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
}

# ── banner ───────────────────────────────────────────────────────────
$banner     = 'made with love by neo0oen'
$bannerLine = "# ===== $banner ====="
Write-Host "`n    $banner`n" -ForegroundColor Magenta

# ── transcript ───────────────────────────────────────────────────────
$log = "$PSScriptRoot\build_$(Get-Date -Format yyyyMMdd_HHmmss).log"
Start-Transcript -Path $log -Verbose

# ═════════════════ 1. PICK / CREATE USER ═════════════════════════════
$users = @(Get-LocalUser | Sort-Object Name | Select-Object -Expand Name)
do {
    Write-Host 'Existing local users:'
    for ($i=0; $i -lt $users.Count; $i++) { Write-Host " [$i] $($users[$i])" }
    Write-Host ' [N]  <create new user>'
    $pick = Read-Host 'Choose user number or N'
} until ( ($pick -match '^\d+$' -and [int]$pick -lt $users.Count) -or ($pick -match '^[Nn]$') )

if ($pick -match '^\d+$') {
    $localUser = $users[[int]$pick]
    Write-Host 'WARNING: this will also change the Windows sign-in password!' -ForegroundColor Yellow
} else {
    do { $localUser = Read-Host 'Enter NEW username' } until ($localUser.Trim().Length -gt 0)
}

# ── password ─────────────────────────────────────────────────────────
do {
    $pw1 = Read-PlainPassword "Enter password for '$localUser'  (Enter twice for none)"
    $pw2 = Read-PlainPassword 'Re-enter the password            (Enter twice for none)'
    if ($pw1 -ne $pw2) { Write-Host 'Passwords do not match — try again!' -ForegroundColor Yellow }
} until ($pw1 -eq $pw2)
$localPass = $pw1

# ═════════════════ 2. GET TAILSCALE IP / DNS ═════════════════════════
function Get-TailscalePeer {
    $cmd = Get-Command tailscale -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    try { $json = & $cmd.Source status --json | Out-String | ConvertFrom-Json } catch { return $null }

    $list = @()

    if ($json.Self) {
        $selfIP = $json.Self.TailscaleIPs | Where-Object { $_ -like '100.*' } | Select-Object -First 1
        if ($selfIP) {
            $selfName = if ($json.Self.DNSName) { $json.Self.DNSName } else { $json.Self.HostName }
            $list += [PSCustomObject]@{ Display="$selfName  (this PC)"; IP=$selfIP }
        }
    }

    if ($json.Peer) {
        $json.Peer.PSObject.Properties | ForEach-Object {
            $p  = $_.Value
            $ip = $p.TailscaleIPs | Where-Object { $_ -like '100.*' } | Select-Object -First 1
            if ($ip) {
                $name = if ($p.DNSName) { $p.DNSName } else { $p.HostName }
                $list += [PSCustomObject]@{ Display=$name; IP=$ip }
            }
        }
    }

    if (-not $list) { return $null }

    Write-Host "`nTailscale nodes:" -ForegroundColor Cyan
    for ($i=0; $i -lt $list.Count; $i++) {
        Write-Host " [$i] $($list[$i].Display)  ($($list[$i].IP))"
    }
    do { $pick = Read-Host 'Select node number' }
    until ($pick -match '^\d+$' -and [int]$pick -lt $list.Count)

    return @{ Name=$list[$pick].Display; IP=$list[$pick].IP }
}

do { $mode = Read-Host "`nDo you want to (L)ist Tailscale nodes or (M)anual IP? [L/M]" } until ($mode -match '^[LlMm]$')
if ($mode -match '^[Ll]$') {
    $choice = Get-TailscalePeer
    if ($choice) { $tsName=$choice.IP; Write-Host "Picked $($choice.Name) at $tsName.`n" } else {
        Write-Host 'Could not retrieve node list; falling back to manual IP.' -ForegroundColor Yellow
    }
}
if (-not $tsName) {
    do {
        $tsName = Read-Host "Enter this PC's Tailnet DNS name OR its 100.x.x.x IP"
        $isDNS  = $tsName -match '^[\w\.-]+$'
        $isIP   = $tsName -match '^100\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if (-not ($isDNS -or $isIP)) { Write-Host 'Invalid DNS or Tailnet IP — try again.' -ForegroundColor Yellow }
    } until ($isDNS -or $isIP)
}

# ── safe file base name ──────────────────────────────────────────────
$baseName = "$localUser" + '_' + ($tsName -replace '[^\w\-]','-')

# ── output filenames (define early for replacement) ──────────────────
$hostOut   = "host_setup_$baseName.ps1"
$clientOut = "client_use_$baseName.ps1"
$rdpOut    = "$baseName.rdp"

# ═════════ host_setup template (deps + tailscale) ════════════════════
$hostTemplate = @'
__BANNER__

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Write-Host 'Elevating privileges…' -ForegroundColor Yellow
  Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  exit
}

Start-Transcript -Path "$env:USERPROFILE\host_setup.log" -Append
function Skip ($m){ Write-Host $m -ForegroundColor Yellow }

$svr="__SVR__";$User="__USER__";$Pass="__PASS__"

# 1) Local user & groups ─────────────────────────────────────────────
if (-not (Get-LocalUser -Name $User -EA 0))      { net user $User $Pass /add }
else                                             { Skip "User '$User' already exists."; if($Pass){ net user $User $Pass } }
if (-not (Get-LocalGroupMember Administrators -Member $User -EA 0)){ net localgroup Administrators $User /add }
else                                             { Skip 'User already in Administrators.' }
if (-not (Get-LocalGroupMember 'Remote Desktop Users' -Member $User -EA 0)){ Add-LocalGroupMember 'Remote Desktop Users' -Member $User }
else                                             { Skip 'User already in RDP group.' }

# 2) RDP & firewall ─────────────────────────────────────────────────
$rdpKey='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
if ((Get-ItemProperty $rdpKey).fDenyTSConnections -ne 0){ Set-ItemProperty $rdpKey -Name fDenyTSConnections -Value 0 }
else                                                   { Skip 'RDP already enabled.' }
if (-not (Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Where-Object Enabled -eq 'True')){ Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' }
else                                                   { Skip 'Remote-Desktop firewall rules already enabled.' }

# 3) OpenSSH ─────────────────────────────────────────────────────────
$cap = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
if ($cap.State -ne 'Installed'){ Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 }
else                           { Skip 'OpenSSH capability already installed.' }

cd "$env:ProgramFiles\OpenSSH" 2>$null
if (-not (Get-Service sshd -EA 0)){ .\install-sshd.ps1 }
else                               { Skip 'SSHD service already present.' }

try { & "$env:ProgramFiles\OpenSSH\ssh-keygen.exe" -A 2>$null } catch {}
if ((Get-Service sshd).StartupType -ne 'Automatic'){ Set-Service sshd -StartupType Automatic; Skip 'SSHD set to Automatic.' }
if ((Get-Service sshd).Status -ne 'Running'){ Start-Service sshd } else { Skip 'SSHD already running.' }
if (-not (Get-NetFirewallRule -DisplayName 'OpenSSH Server (sshd)' -EA 0)){ New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 }
else { Skip 'SSHD firewall rule already exists.' }

# 4) Tailscale + dependency services ────────────────────────────────
$deps = @('iphlpsvc','netprofm','WinHttpAutoProxySvc')
foreach($svcName in $deps){
    $svc = Get-Service -Name $svcName -EA SilentlyContinue
    if($svc){
        if($svc.StartType -ne 'Automatic'){ Set-Service $svcName -StartupType Automatic; Skip "$svcName set to Automatic." }
        if($svc.Status  -ne 'Running'){ Start-Service $svcName; Skip "$svcName started." }
    }else{ Skip "$svcName not found." }
}

$tSvc = Get-Service -Name 'Tailscale' -EA SilentlyContinue
if ($tSvc) {
    if ($tSvc.StartType -ne 'Automatic'){ Set-Service Tailscale -StartupType Automatic; Skip 'Tailscale set to Automatic.' }
    if ($tSvc.Status -ne 'Running'){ Start-Service Tailscale } else { Skip 'Tailscale already running.' }
} else {
    Skip 'Tailscale service not found – attempting install.'
    try {
        $tmp = "$env:TEMP\tailscale-setup-latest.exe"
        Invoke-WebRequest -Uri 'https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe' -OutFile $tmp -UseBasicParsing
        Start-Process -FilePath $tmp -ArgumentList '/quiet' -Wait
    } catch { Skip "Tailscale install failed: $($_.Exception.Message)" }
}

# 4b) Bring interface UP every run (unattended) ─────────────────────
$tsCmd = Get-Command tailscale -ErrorAction SilentlyContinue
if ($tsCmd) {
    Write-Host 'Running: tailscale up --unattended' -ForegroundColor Cyan
    try {
        & $tsCmd.Source up --unattended 2>$null
        Skip 'tailscale up completed.'
    } catch {
        Skip "tailscale up failed: $($_.Exception.Message)"
    }
} else {
    Skip 'tailscale CLI not found in PATH.'
}

Write-Host '';Write-Host 'HOST READY — copy either line on a client:'
Write-Host "ssh -L 3389:localhost:3389 $User@$svr"
Write-Host "mstsc /v:$svr"
Stop-Transcript
'@

# ═════════ client_use template (now includes username) ══════════════
$clientTemplate = @'
__BANNER__
$server="__SVR__"
$user  ="__USER__"
$rdp   = Join-Path $PSScriptRoot "__RDP__"

Write-Host ''
Write-Host '1) SSH + tunnel (opens 3389 locally)'
Write-Host '2) Direct RDP'
$choice = Read-Host 'Pick 1 or 2'

if ($choice -eq '1') {
    $cmd = "ssh -L 3389:localhost:3389 $user@$server"
    Write-Host "`nRunning:`n  $cmd`n"
    & ssh -L 3389:localhost:3389 "$user@$server"
    Write-Host "`nYou can re-run that command manually anytime."
}
elseif ($choice -eq '2') {
    if (Test-Path $rdp) {
        Write-Host "`nLaunching:  mstsc `"$rdp`"`n"
        Start-Process mstsc.exe -ArgumentList "`"$rdp`""
    } else {
        Write-Host "`nLaunching:  mstsc /v:$server`n"
        Start-Process mstsc.exe -ArgumentList "/v:$server"
    }
}
else {
    Write-Host 'No action.'
}
'@

# ── fill templates & write files ─────────────────────────────────────
$hostScript   = $hostTemplate  -replace '__BANNER__', $bannerLine `
                               -replace '__SVR__',    $tsName `
                               -replace '__USER__',   $localUser `
                               -replace '__PASS__',   $localPass
$clientScript = $clientTemplate -replace '__BANNER__', $bannerLine `
                                -replace '__SVR__',    $tsName `
                                -replace '__USER__',   $localUser `
                                -replace '__RDP__',    $rdpOut

Set-Content $hostOut   -Value $hostScript   -Encoding utf8
Set-Content $clientOut -Value $clientScript -Encoding utf8

@"
full address:s:$tsName
username:s:$localUser
prompt for credentials:i:1
"@ | Set-Content $rdpOut -Encoding ascii

Write-Host "`r`nCreated:" -ForegroundColor Green
$hostOut,$clientOut,$rdpOut | ForEach-Object { Write-Host "  $_" }

Write-Host "`r`nRun $hostOut (elevated) on the host, reboot once,"
Write-Host "then run $clientOut on any client and pick 1 or 2."
Write-Host "Or simply double-click $rdpOut for a quick RDP session."

Stop-Transcript
