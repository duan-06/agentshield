param(
    [int]$LlamaPort = 18000,
    [int]$BackendPort = 3001,
    [int]$FrontendPort = 5173
)

$ErrorActionPreference = 'Stop'

function Stop-ListeningProcess {
    param([int]$Port)

    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if (-not $conns) {
        Write-Host "[INFO] No process is listening on port $Port"
        return
    }

    foreach ($conn in $conns) {
        try {
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction Stop
            Write-Host "[OK] Stopped PID $($conn.OwningProcess) on port $Port"
        }
        catch {
            Write-Warning ("Failed to stop PID {0} on port {1}: {2}" -f $conn.OwningProcess, $Port, $_.Exception.Message)
        }
    }
}

function Wait-Url {
    param(
        [string]$Url,
        [int]$TimeoutSec = 25
    )

    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
        try {
            $resp = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 4
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) {
                return $true
            }
        }
        catch {
            Start-Sleep -Milliseconds 700
        }
    }

    return $false
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$llamaDir = Join-Path $repoRoot "back\src\Llama Shield"
$backDir = Join-Path $repoRoot "back"
$frontDir = Join-Path $repoRoot "front"

Write-Host "[STEP] Stopping existing services..."
Stop-ListeningProcess -Port $LlamaPort
Stop-ListeningProcess -Port $BackendPort
Stop-ListeningProcess -Port $FrontendPort

Start-Sleep -Milliseconds 800

Write-Host "[STEP] Starting Llama Shield..."
Start-Process powershell -ArgumentList @(
    '-NoExit',
    '-Command',
    "Set-Location '$llamaDir'; .\venv311\Scripts\python.exe -m app.main"
) | Out-Null

Write-Host "[STEP] Starting backend..."
Start-Process powershell -ArgumentList @(
    '-NoExit',
    '-Command',
    "Set-Location '$backDir'; npm run dev"
) | Out-Null

Write-Host "[STEP] Starting frontend..."
Start-Process powershell -ArgumentList @(
    '-NoExit',
    '-Command',
    "Set-Location '$frontDir'; npm run dev"
) | Out-Null

Write-Host "[STEP] Running health checks..."
$llamaOk = Wait-Url -Url "http://127.0.0.1:$LlamaPort/health" -TimeoutSec 30
$backOk = Wait-Url -Url "http://127.0.0.1:$BackendPort/health" -TimeoutSec 30
$frontOk = (Wait-Url -Url "http://localhost:$FrontendPort/" -TimeoutSec 60) -or (Wait-Url -Url "http://127.0.0.1:$FrontendPort/" -TimeoutSec 15)

Write-Host ""
Write-Host "========== Restart Summary =========="
Write-Host "Llama Shield : $(if ($llamaOk) { 'OK' } else { 'FAILED' })  -> http://127.0.0.1:$LlamaPort/health"
Write-Host "Backend      : $(if ($backOk) { 'OK' } else { 'FAILED' })  -> http://127.0.0.1:$BackendPort/health"
Write-Host "Frontend     : $(if ($frontOk) { 'OK' } else { 'FAILED' })  -> http://127.0.0.1:$FrontendPort/"
Write-Host "====================================="

if (-not ($llamaOk -and $backOk -and $frontOk)) {
    exit 1
}
