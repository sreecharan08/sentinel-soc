# Starts the Sentinel SOC stack on this laptop: Redis (Docker), the ASGI web server (Daphne),
# the Celery worker, and a USB reverse tunnel so the phone can reach http://127.0.0.1:9000.
#   powershell -ExecutionPolicy Bypass -File scripts\start-stack.ps1
param(
    [string]$AdbPath = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
    [int]$Port = 9000,
    [int]$LegacyPhonePort = 8000   # the phone app's old default; tunnelled to $Port so existing pairings keep working
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$py = Join-Path $backend ".venv\Scripts\python.exe"
$logs = Join-Path $backend "logs"
New-Item -ItemType Directory -Force -Path $logs | Out-Null

$env:REDIS_URL = "redis://127.0.0.1:6379/0"
Set-Location $backend

docker start sentinel-redis | Out-Null
& $py manage.py migrate --noinput | Out-Null

Start-Process -FilePath $py -ArgumentList @("-m", "daphne", "-b", "0.0.0.0", "-p", "$Port", "sentinel.asgi:application") `
    -WorkingDirectory $backend -RedirectStandardOutput (Join-Path $logs "web.log") `
    -RedirectStandardError (Join-Path $logs "web.err.log") -WindowStyle Hidden

Start-Process -FilePath $py -ArgumentList @("-m", "celery", "-A", "sentinel", "worker", "-l", "info", "-Q", "default,analysis,reasoning", "-P", "solo") `
    -WorkingDirectory $backend -RedirectStandardOutput (Join-Path $logs "worker.log") `
    -RedirectStandardError (Join-Path $logs "worker.err.log") -WindowStyle Hidden

if (Test-Path $AdbPath) {
    & $AdbPath reverse "tcp:$Port" "tcp:$Port" | Out-Null
    if ($LegacyPhonePort -ne $Port) { & $AdbPath reverse "tcp:$LegacyPhonePort" "tcp:$Port" | Out-Null }
    Write-Output "adb reverse set (phone reaches the laptop at http://127.0.0.1:$Port, and :$LegacyPhonePort -> :$Port)"
} else {
    Write-Output "adb not found at $AdbPath; use the laptop LAN address in the phone app instead"
}

Start-Sleep -Seconds 6
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 10
    Write-Output ("healthz: " + ($health | ConvertTo-Json -Compress))
} catch {
    Write-Output "healthz not ready yet: $($_.Exception.Message)"
}
