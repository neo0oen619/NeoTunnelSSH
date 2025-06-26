<#  builder.ps1 – new-PC wizard
    Iteration 21 · help text trimmed (no -help example line)
#>

[CmdletBinding()]
param(
    [Alias('du')]
    [switch]$DeleteUser,
    [switch]$Help          # PowerShell uses single dash: -help
)

# ────────────────────────────────────────────────────────────────────
#region COMMON HELP / LOGGING
# ────────────────────────────────────────────────────────────────────
function Show-Help {
@"
USAGE
  builder.ps1                 Interactive wizard to prepare host + client scripts
  builder.ps1 -du             Secure delete-user wizard (pick + confirm twice + YES)
  builder.ps1 -help           Show this help text

EXAMPLES
  ./builder.ps1
  ./builder.ps1 -du
"@ | Write-Host
}

function Write-Log {
    param(
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO',
        [string]$Message
    )
    $c = @{INFO='Gray'; WARN='Yellow'; ERROR='Red'}
    Write-Host "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $c[$Level]
}

function Ensure-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                   [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host 'Re-launching with Administrator rights …' -ForegroundColor Yellow
        $quoted  = '"' + $PSCommandPath + '"'
        $argList = "-ExecutionPolicy Bypass -File $quoted"
        if ($DeleteUser) { $argList += ' -du'   }
        if ($Help)       { $argList += ' -help' }
        Start-Process powershell -Verb RunAs -ArgumentList $argList
        exit
    }
}
#endregion COMMON HELP / LOGGING
# ────────────────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────────────
#region HELP / DELETE MODE
# ────────────────────────────────────────────────────────────────────
if ($Help) { Show-Help; return }

if ($DeleteUser) {
    Ensure-Admin
    $deleteLog = "$PSScriptRoot\delete_$(Get-Date -f yyyyMMdd_HHmmss).log"
    Start-Transcript -Path $deleteLog -Verbose
    Write-Log INFO "Delete-user mode started → $deleteLog"

    $builtIns = 'Administrator','DefaultAccount','Guest','WDAGUtilityAccount'
    $allUsers = @(Get-LocalUser | Where-Object { $_.Name -notin $builtIns } |
                  Sort-Object Name | Select-Object -Expand Name)
    if (-not $allUsers) {
        Write-Log ERROR 'No deletable local users were found.'
        Stop-Transcript; return
    }

    Write-Host "`nExisting local users:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $allUsers.Count; $i++) {
        Write-Host " [$i] $($allUsers[$i])"
    }
    do { $pick = Read-Host 'Choose user number to delete' }
    until ($pick -match '^\d+$' -and [int]$pick -lt $allUsers.Count)
    $targetUser = $allUsers[[int]$pick]

    # double-name confirmation
    do {
        $c1 = Read-Host "Type the username '$targetUser' to confirm deletion"
        $c2 = Read-Host 'Re-type the username to confirm'
        if ($c1 -ne $targetUser -or $c2 -ne $targetUser) {
            Write-Host 'Confirmation failed — try again!' -ForegroundColor Yellow
        }
    } until ($c1 -eq $targetUser -and $c2 -eq $targetUser)

    # final YES gate
    Write-Host "`n*** WARNING ***" -ForegroundColor Red
    Write-Host "Deleting '$targetUser' is IRREVERSIBLE!" -ForegroundColor Red
    Write-Host 'All home data and generated script files will be removed.' -ForegroundColor Red
    $hard = Read-Host "Type 'YES' (all caps) to proceed or anything else to abort"
    if ($hard -cne 'YES') {
        Write-Log WARN 'User aborted deletion.'
        Stop-Transcript; return
    }

    # deletion + cleanup
    try {
        Write-Log WARN "Removing local user '$targetUser' …"
        Get-LocalGroup | ForEach-Object {
            try { Remove-LocalGroupMember $_.Name -Member $targetUser -ErrorAction SilentlyContinue } catch {}
        }
        Remove-LocalUser -Name $targetUser
        Get-ChildItem -Path . -Recurse -Include "*$targetUser*.ps1","*$targetUser*.rdp" -EA 0 |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log INFO "User '$targetUser' deleted."
    } catch {
        Write-Log ERROR "Deletion failed: $($_.Exception.Message)"
    } finally {
        Write-Log INFO 'Stopping transcript.'; Stop-Transcript
    }
    return
}
#endregion HELP / DELETE MODE
# ────────────────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────────────
#region INTERACTIVE WIZARD (create-user and file generator)
# ────────────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Rotate-Logs ([string]$Base,[int]$Keep=3) {
    Get-ChildItem $Base -Filter 'build_*.log' | Sort-Object CreationTime -Desc |
        Select-Object -Skip $Keep | Remove-Item -Force
}

function Read-PlainPassword ($msg) {
    $ss = Read-Host $msg -AsSecureString
    [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
}

function Save-Credential ($Username,$Password) {
    if (-not (Get-Module -ListAvailable CredentialManager)) {
        Write-Log WARN 'CredentialManager module not found – password kept in memory only.'; return
    }
    Import-Module CredentialManager -Force
    try {
        New-StoredCredential -Target "new-pc-wizard\$Username" -Username $Username `
                             -Password $Password -Persist LocalMachine | Out-Null
        Write-Log INFO 'Password stored in Windows CredentialManager.'
    } catch {
        Write-Log WARN "Credential save failed: $($_.Exception.Message)"
    }
}

# banner & transcript
$banner     = 'made with love by neo0oen'
$bannerLine = "# ===== $banner ====="
Write-Host "`n    $banner`n" -ForegroundColor Magenta
Rotate-Logs $PSScriptRoot
$buildLog = "$PSScriptRoot\build_$(Get-Date -f yyyyMMdd_HHmmss).log"
Start-Transcript -Path $buildLog -Verbose
Write-Log INFO "Transcript started → $buildLog"

try {
#═════════════════ 1. PICK / CREATE USER ══════════════════════════════
$users = @(Get-LocalUser | Sort-Object Name | Select-Object -Expand Name)
do {
    Write-Host 'Existing local users:'
    for ($i=0;$i -lt $users.Count;$i++) { Write-Host " [$i] $($users[$i])" }
    Write-Host ' [N]  <create new user>'
    $pick = Read-Host 'Choose user number or N'
} until (($pick -match '^\d+$' -and [int]$pick -lt $users.Count) -or $pick -match '^[Nn]$')

if ($pick -match '^\d+$') {
    $localUser = $users[[int]$pick]
    Write-Log WARN "This will change the Windows sign-in password for '$localUser'."
} else {
    do { $localUser = Read-Host 'Enter NEW username' } until ($localUser.Trim())
}

#═════════════════ 2. PASSWORD ════════════════════════════════════════
Stop-Transcript
do {
    $pw1 = Read-PlainPassword "Enter password for '$localUser'  (Enter twice for none)"
    $pw2 = Read-PlainPassword 'Re-enter the password            (Enter twice for none)'
    if ($pw1 -ne $pw2) { Write-Host 'Passwords do not match — try again!' -ForegroundColor Yellow }
} until ($pw1 -eq $pw2)
Start-Transcript -Path $buildLog -Append

$localPass = $pw1
Save-Credential $localUser $localPass
$encPass = if ($localPass) {
              ConvertFrom-SecureString (ConvertTo-SecureString $localPass -AsPlainText -Force)
          } else { '' }

#═════════════════ 3. GET TAILSCALE NODE ══════════════════════════════
function Get-TailscalePeer {
    $ts = Get-Command tailscale -EA SilentlyContinue; if (-not $ts) { return $null }
    try { $json = & $ts.Source status --json | Out-String | ConvertFrom-Json } catch { return $null }
    $list = @()
    if ($json.Self) {
        $ip = $json.Self.TailscaleIPs | Where-Object { $_ -like '100.*' } | Select-Object -First 1
        if ($ip) {
            $name = if ($json.Self.DNSName) { $json.Self.DNSName } else { $json.Self.HostName }
            $list += [pscustomobject]@{ Display="$name (this PC)"; IP=$ip }
        }
    }
    if ($json.Peer) {
        $json.Peer.PSObject.Properties | ForEach-Object {
            $p  = $_.Value
            $ip = $p.TailscaleIPs | Where-Object { $_ -like '100.*' } | Select-Object -First 1
            if ($ip) {
                $pName = if ($p.DNSName) { $p.DNSName } else { $p.HostName }
                $list += [pscustomobject]@{ Display=$pName; IP=$ip }
            }
        }
    }
    if (-not $list) { return $null }
    Write-Host "`nTailscale nodes:" -ForegroundColor Cyan
    for ($i=0;$i -lt $list.Count;$i++) {
        Write-Host " [$i] $($list[$i].Display)  ($($list[$i].IP))"
    }
    do { $sel = Read-Host 'Select node number' }
    until ($sel -match '^\d+$' -and [int]$sel -lt $list.Count)
    return @{ Name=$list[$sel].Display; IP=$list[$sel].IP }
}

do { $mode = Read-Host "`n(L)ist Tailscale nodes or (M)anual IP? [L/M]" }
until ($mode -match '^[LlMm]$')
if ($mode -match '^[Ll]') {
    $choice = Get-TailscalePeer
    if ($choice) {
        $tsName = $choice.IP
        Write-Log INFO "Picked $($choice.Name) at $tsName."
    } else {
        Write-Log WARN 'Could not retrieve list; falling back to manual IP.'
    }
}
if (-not $tsName) {
    do {
        $tsName = Read-Host 'Enter this PC''s Tailnet DNS name OR its 100.x.x.x IP'
        $ok     = ($tsName -match '^[\w\.-]+$') -or ($tsName -match '^100\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if (-not $ok) { Write-Log WARN 'Invalid DNS or Tailnet IP — try again.' }
    } until ($ok)
}

#═════════════════ 4. OUTPUT FILES ════════════════════════════════════
$baseName  = "$localUser"+"_"+($tsName -replace '[^\w\-]','-')
$hostOut   = "host_setup_$baseName.ps1"
$clientOut = "client_use_$baseName.ps1"
$rdpOut    = "$baseName.rdp"

# ── host setup template ──────────────────────────────────────────────
$hostTemplate=@'
__BANNER__

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Write-Host 'Elevating privileges…' -ForegroundColor Yellow
  Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -File ""$PSCommandPath""" -Verb RunAs
  exit
}

Start-Transcript -Path "$env:USERPROFILE\host_setup.log" -Append
function Skip($m){ Write-Host $m -ForegroundColor Yellow }

$svr="__SVR__"; $User="__USER__"; $Enc="__PASSENC__"; $PassPlain=$null
if($Enc){
  try{
    $sec=$Enc|ConvertTo-SecureString
    $PassPlain=[Runtime.InteropServices.Marshal]::PtrToStringAuto(
                  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
  }catch{}
}

# 1) local user
if(-not(Get-LocalUser $User -EA 0)){
  if($PassPlain){ net user $User $PassPlain /add }else{ net user $User /add }
}else{
  Skip "User already exists."
  if($PassPlain){ net user $User $PassPlain }
}

if(-not(Get-LocalGroupMember Administrators -Member $User -EA 0)){
  net localgroup Administrators $User /add
}else{ Skip 'User in Administrators' }

if(-not(Get-LocalGroupMember "Remote Desktop Users" -Member $User -EA 0)){
  Add-LocalGroupMember "Remote Desktop Users" -Member $User
}else{ Skip 'User in RDP group' }

# 2) RDP & firewall
$rdp="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
if((Get-ItemProperty $rdp).fDenyTSConnections -ne 0){
  Set-ItemProperty $rdp -Name fDenyTSConnections -Value 0
}else{ Skip 'RDP enabled' }

if(-not(Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Where Enabled -eq "True")){
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}else{ Skip 'RDP firewall rules on' }

# 3) OpenSSH (tolerant)
$cap=Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
try{
  if($cap.State -ne 'Installed'){
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -EA Stop
    Skip 'OpenSSH installed'
  }else{ Skip 'OpenSSH already' }
}catch{ Skip "OpenSSH install failed: $($_.Exception.Message)" }

cd "$env:ProgramFiles\OpenSSH" 2>$null
if(-not(Get-Service sshd -EA 0)){ .\install-sshd.ps1 }else{ Skip 'SSHD present' }
try{ & "$env:ProgramFiles\OpenSSH\ssh-keygen.exe" -A 2>$null }catch{}
if((Get-Service sshd).StartupType -ne 'Automatic'){
  Set-Service sshd -StartupType Automatic; Skip 'SSHD auto'
}
if((Get-Service sshd).Status -ne 'Running'){ Start-Service sshd }else{ Skip 'SSHD running' }
if(-not(Get-NetFirewallRule -DisplayName "OpenSSH Server (sshd)" -EA 0)){
  New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}else{ Skip 'SSHD rule' }

# 4) Tailscale + deps
$deps=@('iphlpsvc','netprofm','WinHttpAutoProxySvc')
foreach($d in $deps){
  $s=Get-Service $d -EA 0
  if($s){
    if($s.StartType -ne 'Automatic'){ Set-Service $d -StartupType Automatic; Skip "$d auto" }
    if($s.Status -ne 'Running'){ Start-Service $d; Skip "$d running" }
  }
}
$t=Get-Service Tailscale -EA SilentlyContinue
if($t){
  if($t.StartType -ne 'Automatic'){ Set-Service Tailscale -StartupType Automatic; Skip 'Tailscale auto' }
  if($t.Status -ne 'Running'){ Start-Service Tailscale }else{ Skip 'Tailscale running' }
}else{
  Skip 'Installing Tailscale'
  try{
    $tmp="$env:TEMP\tailscale.exe"
    Invoke-WebRequest 'https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe' -OutFile $tmp
    Start-Process $tmp -ArgumentList '/quiet' -Wait
  }catch{ Skip "Tailscale install failed: $($_.Exception.Message)" }
}

# 4b) tailscale up
$ts=Get-Command tailscale -EA 0
if($ts){
  try{ & $ts.Source up --unattended 2>$null; Skip 'tailscale up' }
  catch{ Skip "tailscale up failed: $($_.Exception.Message)" }
}

# pretty banner
Write-Host ''
$txt='HOST READY – MADE WITH LOVE BY neo0oen'
$col=@('Magenta','DarkMagenta')
for($i=0;$i -lt $txt.Length;$i++){
  $ch=$txt[$i]
  if($ch -eq ' '){
    Write-Host -NoNewline ' '
  }else{
    Write-Host -NoNewline $ch -ForegroundColor $col[$i % $col.Count]
  }
}
Write-Host ''
Write-Host 'Copy either line on a client:' -ForegroundColor Magenta
Write-Host "ssh -L 3389:localhost:3389 $User@$svr"
Write-Host "mstsc /v:$svr"
Stop-Transcript
'@

# ── client template ──────────────────────────────────────────────────
$clientTemplate=@'
__BANNER__
$server="__SVR__"; $user="__USER__"; $rdp=Join-Path $PSScriptRoot "__RDP__"
Write-Host ''
Write-Host '1) SSH + tunnel (opens 3389 locally)'
Write-Host '2) Direct RDP'
$ch=Read-Host 'Pick 1 or 2'
if($ch -eq '1'){
  & ssh -L 3389:localhost:3389 "$user@$server"
}elseif($ch -eq '2'){
  if(Test-Path $rdp){
    Start-Process mstsc "$rdp"
  }else{
    Start-Process mstsc "/v:$server"
  }
}
'@

# write generated files
$hostScript   = $hostTemplate   -replace '__BANNER__',$bannerLine -replace '__SVR__',$tsName `
                                -replace '__USER__',$localUser    -replace '__PASSENC__',$encPass
$clientScript = $clientTemplate -replace '__BANNER__',$bannerLine -replace '__SVR__',$tsName `
                                -replace '__USER__',$localUser    -replace '__RDP__',$rdpOut

Set-Content $hostOut   -Value $hostScript   -Encoding utf8 -Force
Set-Content $clientOut -Value $clientScript -Encoding utf8 -Force

@"
full address:s:$tsName
username:s:$localUser
prompt for credentials:i:1
"@ | Set-Content $rdpOut -Encoding ascii -Force

Write-Log INFO "Created: $hostOut, $clientOut, $rdpOut"
Write-Log INFO 'Run host script elevated, reboot once, then run client script.'
}
catch {
    Write-Log ERROR "Fatal error: $($_.Exception.Message)"
    Write-Log ERROR "StackTrace: $($_.ScriptStackTrace)"
    exit 1
}
finally {
    Write-Log INFO 'Stopping transcript.'
    Stop-Transcript
}
#endregion INTERACTIVE WIZARD
# ────────────────────────────────────────────────────────────────────
