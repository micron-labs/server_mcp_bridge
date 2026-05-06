# mcp_bridge-cron-runner.ps1: invoked by Task Scheduler as the per-tenant
# user. Mirrors the Linux mcp_bridge-cron-runner shell script:
#   1. Read the job's metadata + the bridge's webhook config from the
#      user's state dir.
#   2. Run the command.
#   3. POST the captured stdout/stderr/exit_code plus metadata to the
#      configured webhook.
#
# Exits 0 even on webhook-delivery failure so a webhook outage doesn't
# leave Task Scheduler reporting failed runs forever — that channel is for
# real failures (exec failed, metadata missing).
#
# Layout (must match the priv service's defaults):
#   %ProgramData%\mcp_bridge\users_state\<user>\runtime.json
#       { webhook_url, webhook_secret_token }
#   %ProgramData%\mcp_bridge\users_state\<user>\crons\<job_id>.json
#       { job_id, user_id, schedule, command, description, context_id }

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)] [string] $JobId
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

if ($JobId -notmatch '^[0-9a-f]{16}$') {
    Write-Error "usage: mcp_bridge-cron-runner.ps1 <job_id>"
    exit 64
}

$user = $env:USERNAME
if (-not $user) {
    Write-Error "USERNAME not set"
    exit 64
}

$stateBase = Join-Path $env:ProgramData "mcp_bridge\users_state\$user"
$metaFile  = Join-Path $stateBase "crons\$JobId.json"
$rtFile    = Join-Path $stateBase "runtime.json"

if (-not (Test-Path $metaFile)) {
    Write-Error "no metadata at $metaFile"
    exit 65
}

$meta = $null
try {
    $meta = Get-Content -Raw -Path $metaFile | ConvertFrom-Json
} catch {
    Write-Error "metadata parse failed: $_"
    exit 65
}

if (-not $meta.command) {
    Write-Error "no command in $metaFile"
    exit 66
}

$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "mcp_cron_$([guid]::NewGuid().ToString('N'))")
$outPath = Join-Path $tmp 'stdout'
$errPath = Join-Path $tmp 'stderr'
try {
    $startedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Use cmd /c so the user-supplied command can use shell features
    # (pipes, redirection) the way the bash runner does. -PassThru gives us
    # the exit code; the >/2> redirects capture stdout/stderr separately.
    $proc = Start-Process -FilePath 'cmd.exe' `
                          -ArgumentList @('/c', $meta.command) `
                          -Wait -PassThru -NoNewWindow `
                          -RedirectStandardOutput $outPath `
                          -RedirectStandardError  $errPath
    $exitCode    = $proc.ExitCode
    $completedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Cap each stream at 64 KiB so a runaway job can't make the webhook
    # payload unbounded — same limit the Linux runner uses.
    function Read-Capped {
        param([string] $Path, [int] $Max = 65536)
        if (-not (Test-Path $Path)) { return "" }
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -gt $Max) { $bytes = $bytes[0..($Max-1)] }
        return [Text.Encoding]::UTF8.GetString($bytes)
    }
    $stdout = Read-Capped -Path $outPath
    $stderr = Read-Capped -Path $errPath

    # Webhook config is best-effort; if runtime.json is missing or unparseable
    # we just exit 0 (the run still happened, Task Scheduler logs it).
    $webhookUrl    = $null
    $webhookSecret = $null
    if (Test-Path $rtFile) {
        try {
            $rt = Get-Content -Raw -Path $rtFile | ConvertFrom-Json
            $webhookUrl    = $rt.webhook_url
            $webhookSecret = $rt.webhook_secret_token
        } catch { }
    }
    if (-not $webhookUrl) { exit 0 }

    $payload = @{
        job_id       = $meta.job_id
        user_id      = $meta.user_id
        description  = $meta.description
        context_id   = $meta.context_id
        schedule     = $meta.schedule
        command      = $meta.command
        exit_code    = [int]$exitCode
        stdout       = $stdout
        stderr       = $stderr
        started_at   = $startedAt
        completed_at = $completedAt
    } | ConvertTo-Json -Depth 5 -Compress

    $headers = @{ 'Content-Type' = 'application/json' }
    if ($webhookSecret) { $headers['Authorization'] = "Bearer $webhookSecret" }

    try {
        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload `
                          -Headers $headers -TimeoutSec 30 | Out-Null
    } catch {
        # Webhook outage: swallow per the contract above.
    }
    exit 0
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
