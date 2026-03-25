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
        return 0
    }

    $count = 0
    foreach ($conn in $conns) {
        try {
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction Stop
            Write-Host "[OK] Stopped PID $($conn.OwningProcess) on port $Port"
            $count += 1
        }
        catch {
            Write-Warning ("Failed to stop PID {0} on port {1}: {2}" -f $conn.OwningProcess, $Port, $_.Exception.Message)
        }
    }

    return $count
}

Write-Host "[STEP] Stopping services on target ports..."

$totalStopped = 0
$totalStopped += Stop-ListeningProcess -Port $LlamaPort
$totalStopped += Stop-ListeningProcess -Port $BackendPort
$totalStopped += Stop-ListeningProcess -Port $FrontendPort

Start-Sleep -Milliseconds 600

$remaining = @()
foreach ($p in @($LlamaPort, $BackendPort, $FrontendPort)) {
    $conn = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        $remaining += $p
    }
}

Write-Host ""
Write-Host "========== Stop Summary =========="
Write-Host "Stopped process count: $totalStopped"
if ($remaining.Count -eq 0) {
    Write-Host "All target ports are free."
    Write-Host "=================================="
    exit 0
}

Write-Warning ("Ports still listening: {0}" -f ($remaining -join ', '))
Write-Host "=================================="
exit 1
