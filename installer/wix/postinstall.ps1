# Post-install actions for the MCP Bridge MSI.
#
# Invoked by the WiX custom action `caPostInstall` after the daemon and priv
# services are installed and started. Runs as LocalSystem (deferred,
# no-impersonate). Idempotent — safe to re-run.
#
# Responsibilities:
#   1. Generate salt + admin token if mcp.json doesn't yet exist.
#   2. Provision the install-time admin user `mcpadmin` via the priv service.
#   3. Install the system_admin wildcard grant for `mcpadmin`.
#   4. Print the admin token once via Write-Host (visible in MSI verbose log).
#
# Failure semantics: never fail the install. The user can re-run via
#   powershell -File "C:\Program Files\mcp_bridge\postinstall.ps1"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string] $InstallDir,
    [Parameter(Mandatory=$true)] [string] $DataDir
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

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

$configPath = Join-Path $DataDir 'mcp.json'
if (-not (Test-Path $configPath)) {
    $salt  = New-RandomHex
    $token = New-RandomHex
    $hash  = Get-Sha256Hex -Text "$salt$token"

    $cfgDir = $DataDir.Replace('\','/')
    $instDir = $InstallDir.Replace('\','/')
    $body = @"
{
  "server":   { "host": "127.0.0.1", "port": 8080, "enable_ssl": false, "ssl_cert": "", "ssl_key": "" },
  "auth":     { "global_token_salt": "$salt", "admin_token_hash": "$hash" },
  "paths":    {
    "users_dir":        "$cfgDir/users",
    "users_state_dir":  "$cfgDir/users_state",
    "state_dir":        "$cfgDir/state",
    "sudoers_dir":      "$cfgDir/grants",
    "helper_path":      "$instDir/mcp_bridge_priv.exe",
    "cron_runner_path": "$instDir/mcp_bridge-cron-runner.ps1"
  },
  "grant_sweep_interval_seconds": 30,
  "security": { "allowed_ips": [], "rate_limit": 60, "allowed_root": "C:/", "dangerous_tools_enabled": false, "enable_raw_queries": false },
  "logging":  { "file": "$cfgDir/logs/server.log", "level": "info" },
  "sudo_grant_templates": []
}
"@
    Set-Content -Path $configPath -Encoding UTF8 -Value $body

    # Lock down config to SYSTEM + Administrators only.
    $acl = Get-Acl $configPath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators','FullControl','Allow')))
    $acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM','FullControl','Allow')))
    Set-Acl $configPath $acl

    Write-Host "==========================================" -ForegroundColor Green
    Write-Host " Admin API token (save this — shown once):"
    Write-Host "   $token"                                   -ForegroundColor Cyan
    Write-Host "=========================================="

    # Provision the install-time admin via the daemon's CLI which talks to
    # the priv service for us. The CLI generates an 8-char shortid; we capture
    # it from stdout.
    $bridgeExe = Join-Path $InstallDir 'mcp_bridge.exe'
    if (Test-Path $bridgeExe) {
        try {
            $output = & $bridgeExe auth-create --config "$configPath" --label "mcpadmin" --admin 2>&1
            Write-Host "  $output"
            # Best-effort: if a shortid surfaces, push the system_admin grant.
            if ($output -match 'shortid[=: ]+([a-z2-7]{8})') {
                $shortid = $Matches[1]
                & $bridgeExe grant-install-system-admin --shortid $shortid --config "$configPath" 2>&1 | Out-Host
            }
        } catch {
            Write-Host "  postinstall: provisioning skipped: $_" -ForegroundColor Yellow
        }
    }
}
