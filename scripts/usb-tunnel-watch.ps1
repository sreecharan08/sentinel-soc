# Keeps the USB tunnel (phone 127.0.0.1:9000 -> laptop :9000) alive without manual steps.
# The phone's old default port 8000 is tunnelled to the same laptop port, so an app that was paired against
# http://127.0.0.1:8000 keeps working without re-pairing.
# Every few seconds it checks for a connected phone and, if the tunnel is missing, restores it.
#   powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File scripts\usb-tunnel-watch.ps1
param(
    [int]$Port = 9000,
    [int]$LegacyPhonePort = 8000,
    [string]$AdbPath = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
    [int]$IntervalSeconds = 5
)

$ErrorActionPreference = "SilentlyContinue"
$log = Join-Path (Split-Path -Parent $PSScriptRoot) "backend\logs\usb-tunnel.log"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $log) | Out-Null

function Write-Log($msg) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format "HH:mm:ss"), $msg) }

Write-Log "watcher started (port $Port)"
$wasConnected = $false
while ($true) {
    $devices = & $AdbPath devices 2>$null | Select-String -Pattern "\tdevice$"
    $connected = [bool]$devices
    if ($connected) {
        $reverse = & $AdbPath reverse --list 2>$null | Out-String
        # each line is "<serial> tcp:<phone port> tcp:<laptop port>"
        $want = @("tcp:$Port tcp:$Port")
        if ($LegacyPhonePort -ne $Port) { $want += "tcp:$LegacyPhonePort tcp:$Port" }
        $missing = $want | Where-Object { $reverse -notmatch [regex]::Escape($_) }
        if ($missing) {
            foreach ($m in $want) {
                $p = $m -split " "
                & $AdbPath reverse $p[0] $p[1] | Out-Null
            }
            Write-Log "phone connected: tunnel restored ($($want -join ', '))"
        } elseif (-not $wasConnected) {
            Write-Log "phone connected: tunnel already active"
        }
    } elseif ($wasConnected) {
        Write-Log "phone disconnected"
    }
    $wasConnected = $connected
    Start-Sleep -Seconds $IntervalSeconds
}
