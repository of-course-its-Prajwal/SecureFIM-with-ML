# ============================================================================
#  SecureFIM Pro - Live-System Evaluation (M5 ransomware + M6 latency)
#
#  CORRECTED: ransomware verification now takes the MAXIMUM threat score across
#  all events for a file, not the most recent event. The previous version sorted
#  newest-first and could report a later low-scoring MODIFIED event instead of
#  the CREATED event that triggered the critical ransomware alert. file_path is
#  queried via the keyword sub-field file_path.raw.
#
#  PREREQUISITES (three terminals, venv active):
#    A: docker compose up -d opensearch
#    B: python -m server        (leave running)
#    C: python -m agent         (leave running)
#  Then run this script in a fourth terminal.
# ============================================================================

$ErrorActionPreference = "Continue"
$OS     = "http://localhost:9200"
$MONDIR = ".\monitored"
$TRIALS = 5

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  SecureFIM Pro - Live Evaluation (M5 + M6)" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[PREFLIGHT] Checking OpenSearch ..." -ForegroundColor Yellow
try {
    $null = Invoke-RestMethod -Uri "$OS/_cluster/health" -Method GET -TimeoutSec 5
    Write-Host "  OpenSearch reachable." -ForegroundColor Green
} catch {
    Write-Host "  ERROR: OpenSearch not reachable at $OS. Start it and retry." -ForegroundColor Red
    exit 1
}

Write-Host "[SETUP] Backing up monitored folder ..." -ForegroundColor Yellow
$BACKUP = ".\_eval_backup2"
if (Test-Path $BACKUP) { Remove-Item $BACKUP -Recurse -Force }
Copy-Item $MONDIR $BACKUP -Recurse
Write-Host "  Backed up." -ForegroundColor Green
Write-Host ""

# ============================== M6 - LATENCY ================================
Write-Host "[M6] Measuring end-to-end detection latency ($TRIALS trials) ..." -ForegroundColor Yellow
$latencies = @()
for ($i = 1; $i -le $TRIALS; $i++) {
    $latFile = "lat_probe_$($i)_$(Get-Random).txt"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    "latency probe $i" | Out-File "$MONDIR\$latFile" -Encoding utf8
    $found = $false
    while (-not $found -and $sw.Elapsed.TotalSeconds -lt 60) {
        Start-Sleep -Milliseconds 500
        $q = @{ query = @{ wildcard = @{ "file_path.raw" = "*$latFile" } }; size = 1 } | ConvertTo-Json -Depth 6
        try {
            $r = Invoke-RestMethod -Uri "$OS/fim-events/_search" -Method POST -Body $q -ContentType "application/json"
            if ($r.hits.hits.Count -gt 0) { $found = $true }
        } catch {}
    }
    $sw.Stop()
    if ($found) {
        $lat = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        $latencies += $lat
        Write-Host "    Trial $i : $lat s" -ForegroundColor Gray
    } else {
        Write-Host "    Trial $i : NOT DETECTED within 60s" -ForegroundColor Red
    }
    Start-Sleep -Seconds 3
}
if ($latencies.Count -gt 0) {
    $avgLat = [math]::Round(($latencies | Measure-Object -Average).Average, 2)
    $maxLat = ($latencies | Measure-Object -Maximum).Maximum
    $minLat = ($latencies | Measure-Object -Minimum).Minimum
    if ($latencies.Count -gt 1) {
        $var = ($latencies | ForEach-Object { [math]::Pow($_ - $avgLat, 2) } | Measure-Object -Sum).Sum / ($latencies.Count - 1)
        $sd = [math]::Round([math]::Sqrt($var), 2)
    } else { $sd = 0 }
} else { $avgLat = "N/A"; $maxLat = "N/A"; $minLat = "N/A"; $sd = "N/A" }
Write-Host "  M6: mean ${avgLat}s  (min ${minLat}s, max ${maxLat}s, sd ${sd}s) - $($latencies.Count)/$TRIALS trials" -ForegroundColor Green
Write-Host ""

# ============================== M5 - RANSOMWARE =============================
Write-Host "[M5] Creating ransomware indicator files ..." -ForegroundColor Yellow
$ransomFiles = @{
    "evaltest_$(Get-Random).encrypted" = "encrypted blob data"
    "HOW_TO_DECRYPT_$(Get-Random).txt" = "PAY 1 BTC TO RECOVER YOUR FILES"
    "record_$(Get-Random).locked"      = "locked file"
}
foreach ($f in $ransomFiles.Keys) {
    $ransomFiles[$f] | Out-File "$MONDIR\$f" -Encoding utf8
    Write-Host "    Created: $f" -ForegroundColor Gray
}
Write-Host "  Waiting 30s for the agent batch-send ..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

$ransomCaught  = 0
$criticalCount = 0
$details = @()
foreach ($f in $ransomFiles.Keys) {
    $q = @{
        query = @{ wildcard = @{ "file_path.raw" = "*$f" } }
        size  = 20
    } | ConvertTo-Json -Depth 6
    try {
        $r = Invoke-RestMethod -Uri "$OS/fim-events/_search" -Method POST -Body $q -ContentType "application/json"
        if ($r.hits.hits.Count -gt 0) {
            $ransomCaught++
            $best = $r.hits.hits | Sort-Object { [int]$_._source.threat_score } -Descending | Select-Object -First 1
            $sev   = $best._source.severity
            $score = $best._source.threat_score
            if ($sev -eq "critical") { $criticalCount++ }
            $details += "    $f -> CAPTURED (max threat_score=$score, severity=$sev)"
        } else {
            $details += "    $f -> not captured"
        }
    } catch {
        $details += "    $f -> query error: $($_.Exception.Message)"
    }
}
$details | ForEach-Object { Write-Host $_ -ForegroundColor Gray }

$since  = (Get-Date).AddMinutes(-3).ToUniversalTime().ToString("o")
$alertQ = @{ query = @{ range = @{ timestamp = @{ gte = $since } } }; size = 100 } | ConvertTo-Json -Depth 8
$ransomAlerts = 0
try {
    $alerts = Invoke-RestMethod -Uri "$OS/fim-alerts/_search" -Method POST -Body $alertQ -ContentType "application/json"
    foreach ($h in $alerts.hits.hits) {
        $blob = ($h._source | ConvertTo-Json -Compress).ToLower()
        if ($blob -match "encrypt|ransom|decrypt|locked") { $ransomAlerts++ }
    }
} catch {}

Write-Host "  M5: $ransomCaught of 3 indicator files captured" -ForegroundColor Green
Write-Host "  M5: $criticalCount of 3 scored CRITICAL" -ForegroundColor Green
Write-Host "  M5: $ransomAlerts ransomware-related alerts raised" -ForegroundColor Green
Write-Host ""

Write-Host "[CLEANUP] Restoring monitored folder ..." -ForegroundColor Yellow
Get-ChildItem $MONDIR -File | Remove-Item -Force
Copy-Item "$BACKUP\*" $MONDIR -Force
Write-Host "  Restored." -ForegroundColor Green
Write-Host ""

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  RESULTS - PASTE THIS BACK" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "----- SECUREFIM PRO LIVE EVALUATION (M5 + M6) -----"
Write-Host "M6 Detection latency - mean   : $avgLat s"
Write-Host "M6 Detection latency - min    : $minLat s"
Write-Host "M6 Detection latency - max    : $maxLat s"
Write-Host "M6 Detection latency - sd     : $sd s"
Write-Host "M6 Trials succeeded           : $($latencies.Count) / $TRIALS"
Write-Host "M6 Individual trials          : $($latencies -join ', ') s"
Write-Host ""
Write-Host "M5 Ransomware files captured  : $ransomCaught / 3"
Write-Host "M5 Scored critical            : $criticalCount / 3"
Write-Host "M5 Ransomware alerts raised   : $ransomAlerts"
Write-Host "--------------------------------------------------"
Write-Host ""