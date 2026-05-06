# MCP Bridge — Windows installer
#
# To inspect first:
#   Invoke-WebRequest -UseBasicParsing https://<domain>/install.ps1 | Select-Object -ExpandProperty Content | more
#
# Run:
#   powershell -ExecutionPolicy Bypass -File install.ps1
# or:
#   irm https://<domain>/install.ps1 | iex
#
# Installs the latest mcp_bridge on Windows Server / Windows 10+.
# Verifies SHA-256, drops binaries under Program Files, generates a salt
# and admin token, registers two Windows Services (daemon + priv), and
# prints the token once.
#
# Two install modes (auto-detected, override with -Mode):
#   binary  — fetch the standalone .exes (default until MSI is published)
#   msi     — fetch and run the .msi via msiexec (use -Mode msi)
#
# Once an MSI is published, prefer that path; this script becomes a thin
# wrapper for users who want the curl-pipe-bash UX.

[CmdletBinding()]
param(
    [string] $Version  = $env:MCP_INSTALL_VERSION,
    [string] $BaseUrl  = $env:MCP_INSTALL_BASE,
    [string] $InstallRoot = "$env:ProgramFiles\mcp_bridge",
    [string] $ConfigRoot  = "$env:ProgramData\mcp_bridge",
    [ValidateSet('binary','msi','auto')] [string] $Mode = 'auto'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $Version) { $Version = '2.0.0~rc1-1' }
if (-not $BaseUrl) { $BaseUrl = 'https://github.com/TheParadox20/server-mcp-bridge/releases/latest/download' }

# ----- helpers -----

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Not elevated — re-launching as Administrator…' -ForegroundColor Yellow
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        if ($Version) { $args += @('-Version',$Version) }
        if ($BaseUrl) { $args += @('-BaseUrl',$BaseUrl) }
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args
        exit 0
    }
}

function Assert-Arch {
    if ([Environment]::Is64BitOperatingSystem -eq $false) {
        throw 'mcp_bridge currently ships amd64 only; this host is 32-bit.'
    }
}

function Get-WithChecksum {
    param([string] $Url, [string] $OutPath)
    $shaUrl = "$Url.sha256"
    Write-Host "  fetching  $Url"
    Invoke-WebRequest -UseBasicParsing -Uri $Url    -OutFile $OutPath
    Write-Host "  fetching  $shaUrl"
    Invoke-WebRequest -UseBasicParsing -Uri $shaUrl -OutFile "$OutPath.sha256"

    # Sidecar is "<hash>  <filename>"; we only check the hash field.
    $expected = (Get-Content "$OutPath.sha256" -First 1).Split(' ')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $OutPath).Hash.ToLower()
    if ($expected -ne $actual) {
        Write-Host 'ERROR: checksum mismatch' -ForegroundColor Red
        Write-Host "  expected: $expected"
        Write-Host "  actual:   $actual"
        throw 'Aborting install.'
    }
    Write-Host '  checksum  ok'
}

function New-RandomHex {
    param([int] $Bytes = 32)
    $buf = New-Object byte[] $Bytes
    [Security.Cryptography.RandomNumberGenerator]::Fill($buf)
    -join ($buf | ForEach-Object { '{0:x2}' -f $_ })
}

function Get-Sha256Hex {
    param([string] $Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        -join ($sha.ComputeHash($bytes) | ForEach-Object { '{0:x2}' -f $_ })
    } finally { $sha.Dispose() }
}

function Render-Config {
    param([string] $Salt, [string] $Hash, [string] $ConfigDir)
    @"
{
  "server":   { "host": "127.0.0.1", "port": 8080, "enable_ssl": false, "ssl_cert": "", "ssl_key": "" },
  "auth":     { "global_token_salt": "$Salt", "admin_token_hash": "$Hash" },
  "paths":    {
    "users_dir":        "$($ConfigDir.Replace('\','/'))/users",
    "users_state_dir":  "$($ConfigDir.Replace('\','/'))/users_state",
    "state_dir":        "$($ConfigDir.Replace('\','/'))/state",
    "sudoers_dir":      "$($ConfigDir.Replace('\','/'))/grants",
    "helper_path":      "$($InstallRoot.Replace('\','/'))/mcp_bridge_priv.exe",
    "cron_runner_path": "$($InstallRoot.Replace('\','/'))/mcp_bridge-cron-runner.ps1"
  },
  "grant_sweep_interval_seconds": 30,
  "security": { "allowed_ips": [], "rate_limit": 60, "allowed_root": "C:/", "dangerous_tools_enabled": false, "enable_raw_queries": false },
  "logging":  { "file": "$($ConfigDir.Replace('\','/'))/logs/server.log", "level": "info" },
  "sudo_grant_templates": []
}
"@
}

function Style-Banner {
@"

      ******         ******
    **      **     **      **
   *          *****          *
   *           ***           *
   *          *****          *
    **      **     **      **
      ******         ******

  MCP Bridge installed.

"@
}

function Install-FromMsi {
    param([string] $BaseUrl, [string] $Version)
    $msiName = if ($Version) { "mcp-bridge-$Version-windows-amd64.msi" } else { "mcp-bridge-windows-amd64.msi" }
    $msiUrl = "$BaseUrl/$msiName"
    $tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "mcp_bridge_msi_$([guid]::NewGuid().ToString('N'))")
    try {
        $tmpMsi = Join-Path $tmp $msiName
        Get-WithChecksum -Url $msiUrl -OutPath $tmpMsi
        Write-Host "  running msiexec /i $msiName /qb"
        $proc = Start-Process -Wait -PassThru -NoNewWindow -FilePath msiexec.exe -ArgumentList @('/i', "`"$tmpMsi`"", '/qb', '/L*v', "$env:TEMP\mcp_bridge_msi.log")
        if ($proc.ExitCode -ne 0) {
            throw "msiexec exited $($proc.ExitCode); see $env:TEMP\mcp_bridge_msi.log"
        }
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ----- flow -----

Assert-Admin
Assert-Arch

# MSI mode short-circuits the rest of the script — the MSI does its own
# service install + token provisioning via the WiX custom action.
if ($Mode -eq 'msi') {
    Install-FromMsi -BaseUrl $BaseUrl -Version $Version
    Style-Banner
    Write-Host '  MSI install complete. Token (if first install) was printed in the verbose log.'
    Write-Host '  Re-run installer/wix/postinstall.ps1 elevated to provision the admin user manually.'
    return
}

$exeName     = 'mcp-bridge-windows-amd64.exe'
$privExeName = 'mcp-bridge-windows-amd64-priv.exe'
$exeUrl      = "$BaseUrl/$exeName"
$privExeUrl  = "$BaseUrl/$privExeName"

Write-Host 'MCP Bridge installer'
Write-Host "  release:    $exeUrl"
Write-Host "  priv:       $privExeUrl"
Write-Host "  install:    $InstallRoot"
Write-Host "  config:     $ConfigRoot"
Write-Host ''

# 1. Layout directories
foreach ($d in @($InstallRoot, $ConfigRoot,
                 "$ConfigRoot\users","$ConfigRoot\state",
                 "$ConfigRoot\grants","$ConfigRoot\logs",
                 "$ConfigRoot\users_state")) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# Tighten permissions on data subdirs that hold sensitive material — only
# SYSTEM + Administrators may read/write. The MSI does the same via WiX
# PermissionEx; this is the binary-mode equivalent.
foreach ($d in @("$ConfigRoot\grants","$ConfigRoot\state",
                 "$ConfigRoot\users","$ConfigRoot\users_state")) {
    $acl = Get-Acl $d
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators','FullControl','ContainerInherit, ObjectInherit','None','Allow')))
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM','FullControl','ContainerInherit, ObjectInherit','None','Allow')))
    Set-Acl $d $acl
}

# 2. Download + verify binaries (daemon and priv service)
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "mcp_bridge_install_$([guid]::NewGuid().ToString('N'))")
try {
    $tmpExe     = Join-Path $tmp $exeName
    $tmpPrivExe = Join-Path $tmp $privExeName
    Get-WithChecksum -Url $exeUrl     -OutPath $tmpExe
    Get-WithChecksum -Url $privExeUrl -OutPath $tmpPrivExe
    Copy-Item $tmpExe     -Destination "$InstallRoot\mcp_bridge.exe"      -Force
    Copy-Item $tmpPrivExe -Destination "$InstallRoot\mcp_bridge_priv.exe" -Force

    # Cron-runner script — invoked by Task Scheduler as the per-tenant user.
    # Embed it at install time; if a release ships a newer copy alongside the
    # binaries, prefer that one.
    $runnerUrl = "$BaseUrl/mcp_bridge-cron-runner.ps1"
    $runnerLocal = "$InstallRoot\mcp_bridge-cron-runner.ps1"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $runnerUrl -OutFile $runnerLocal
    } catch {
        Write-Host "  cron-runner: release artifact unavailable, leaving any existing copy in place" -ForegroundColor Yellow
    }
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# 3. Generate config (only if not already present — preserve token across reinstalls)
$configPath = Join-Path $ConfigRoot 'mcp.json'
if (-not (Test-Path $configPath)) {
    $salt  = New-RandomHex
    $token = New-RandomHex
    $hash  = Get-Sha256Hex -Text "$salt$token"

    Render-Config -Salt $salt -Hash $hash -ConfigDir $ConfigRoot |
        Set-Content -Path $configPath -Encoding UTF8

    # Lock down config — only Administrators + SYSTEM should read.
    $acl = Get-Acl $configPath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators','FullControl','Allow')))
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM','FullControl','Allow')))
    Set-Acl $configPath $acl

    $newConfig = $true
} else {
    Write-Host "  config exists — preserving $configPath" -ForegroundColor Yellow
    $newConfig = $false
}

# 4. Register / re-register Windows Services
function Reset-Service {
    param([string] $Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  stopping existing service: $Name"
        if ($svc.Status -eq 'Running') { Stop-Service $Name -Force -ErrorAction SilentlyContinue }
        Start-Process -Wait -NoNewWindow -FilePath sc.exe -ArgumentList @('delete', $Name)
        Start-Sleep -Seconds 1
    }
}

$svcName     = 'mcp-bridge'
$privSvcName = 'mcp_bridge_priv'

# Order matters: stop the daemon first (it has the priv pipe open), then the
# priv service. Recreate priv first so the daemon can connect to it on start.
Reset-Service -Name $svcName
Reset-Service -Name $privSvcName

# 4a. Priv service — LocalSystem.
$privBinPath = "`"$InstallRoot\mcp_bridge_priv.exe`""
Start-Process -Wait -NoNewWindow -FilePath sc.exe -ArgumentList @(
    'create', $privSvcName,
    'binPath=', $privBinPath,
    'start=', 'auto',
    'obj=', 'LocalSystem',
    'DisplayName=', 'MCP Bridge Privileged Service'
)
Start-Process -Wait -NoNewWindow -FilePath sc.exe -ArgumentList @(
    'description', $privSvcName,
    'Performs privileged operations on behalf of the MCP Bridge daemon over a SID-restricted named pipe.'
)
Start-Service -Name $privSvcName

# 4b. Daemon — virtual service account so its SID is distinct from LocalSystem.
$binPath = "`"$InstallRoot\mcp_bridge.exe`" daemon --config `"$configPath`""
Start-Process -Wait -NoNewWindow -FilePath sc.exe -ArgumentList @(
    'create', $svcName,
    'binPath=', $binPath,
    'start=', 'auto',
    'obj=', "NT SERVICE\$svcName",
    'DisplayName=', 'MCP Bridge'
)
Start-Process -Wait -NoNewWindow -FilePath sc.exe -ArgumentList @(
    'description', $svcName,
    'MCP Bridge — JSON-RPC server for AI tool dispatch.'
)
# Make the daemon depend on the priv service: the SCM brings priv up first,
# so the daemon's first call into the named pipe sees a listener.
Start-Process -Wait -NoNewWindow -FilePath sc.exe -ArgumentList @(
    'config', $svcName, "depend=", $privSvcName
)
Start-Service -Name $svcName

# 5. Summary banner
Style-Banner

if ($newConfig) {
    Write-Host '==========================================' -ForegroundColor Green
    Write-Host ' Admin API token (save this — shown once):'
    Write-Host "   $token" -ForegroundColor Cyan
    Write-Host '=========================================='
    Write-Host ''
}
Write-Host "  config:     $configPath"
Write-Host "  endpoint:   http://127.0.0.1:8080/"
Write-Host "  daemon:     Get-Service $svcName"
Write-Host "  priv:       Get-Service $privSvcName"
Write-Host "  pipe:       \\.\pipe\mcp_bridge_priv (DACL gated on $svcName SID)"
Write-Host "  logs:       $ConfigRoot\logs\server.log"
Write-Host "  audit log:  Event Viewer → Application → source MCP-Bridge-Priv"
Write-Host ''
