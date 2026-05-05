# MCP Bridge — Windows uninstaller
#
# Mirrors the Linux `apt purge` flow:
#   - Stop and delete both Windows Services (mcp-bridge, mcp_bridge_priv).
#   - Remove the install directory (Program Files\mcp_bridge).
#   - Optionally (-PurgeData) wipe %ProgramData%\mcp_bridge — the analog of
#     `dpkg --purge`. Off by default so configs/tokens survive a reinstall.
#
# This script doesn't manage MSI installs — for those, prefer:
#   msiexec /x "{ProductCode}"     (or Settings → Apps → MCP Bridge → Uninstall)
# This script is for installs done via install.ps1 (binary mode) only, but it
# does try to clean up after either path on a best-effort basis.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1
#   powershell -ExecutionPolicy Bypass -File uninstall.ps1 -PurgeData

[CmdletBinding()]
param(
    [string] $InstallRoot = "$env:ProgramFiles\mcp_bridge",
    [string] $ConfigRoot  = "$env:ProgramData\mcp_bridge",
    [switch] $PurgeData
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Not elevated — re-launching as Administrator…' -ForegroundColor Yellow
        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        if ($PurgeData) { $args += '-PurgeData' }
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args
        exit 0
    }
}

function Remove-Svc {
    param([string] $Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    Write-Host "  stopping $Name…"
    if ($svc.Status -eq 'Running') {
        try { Stop-Service $Name -Force -ErrorAction Stop }
        catch { Write-Host "    stop failed: $_" -ForegroundColor Yellow }
    }
    Start-Process -Wait -NoNewWindow -FilePath sc.exe -ArgumentList @('delete', $Name)
}

Assert-Admin

Write-Host 'MCP Bridge uninstaller'
Write-Host "  install:   $InstallRoot"
Write-Host "  config:    $ConfigRoot"
Write-Host "  purge?     $PurgeData"
Write-Host ''

# 1. Services. Order: daemon first (releases the pipe handle), then priv.
Remove-Svc -Name 'mcp-bridge'
Remove-Svc -Name 'mcp_bridge_priv'

# 2. Binaries. Leave the directory if anything unrelated is in it.
if (Test-Path $InstallRoot) {
    Write-Host "  removing $InstallRoot"
    Remove-Item -Recurse -Force $InstallRoot -ErrorAction SilentlyContinue
}

# 3. Data. Default is to keep — token + grants survive a reinstall. Purge
#    only on explicit -PurgeData. Mirrors `dpkg --purge` (postrm purge) on
#    Linux, which removes /etc/mcp_bridge and /var/lib/mcp_bridge.
if ($PurgeData) {
    if (Test-Path $ConfigRoot) {
        Write-Host "  purging $ConfigRoot (config + grants + state)"
        Remove-Item -Recurse -Force $ConfigRoot -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "  $ConfigRoot kept (re-run with -PurgeData to delete)"
}

# 4. Event Log source — best-effort cleanup.
$eventReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\MCP-Bridge-Priv'
if (Test-Path $eventReg) {
    Remove-Item -Path $eventReg -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host '  done.'
