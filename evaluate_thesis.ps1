# ============================================================================
#  SecureFIM Pro — Thesis Evaluation Script (RETRY for M5 + M6 only)
#
#  The first evaluation script confirmed M1-M4 already (100%, 0%, 100%, 100%).
#  This retry script ONLY tests M5 (ransomware detection) and M6 (latency)
#  with longer wait times to accommodate the agent's batch-send interval.
#
#  HOW TO RUN:
#    1. Server, agent, and OpenSearch all running
#    2. cd "E:\v7\securefimpro"
#    3. .\venv\Scripts\Activate
#    4. .\evaluate_thesis_retry.ps1
#    5. Paste the RESULTS TABLE back to Claude
# ============================================================================

$ErrorActionPreference = "Continue"
$OS    = "http://localhost:9200"
$MONDIR = ".\monitored"

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  SecureFIM Pro - Retry for M5 (ransomware) and M6 (latency)" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""

# ----------------------------------------------------------------------------
# Backup monitored folder
# ----------------------------------------------------------------------------
Write-Host "[SETUP] Backing up monitored folder ..." -ForegroundColor Yellow
$BACKUP = ".\_eval_backup2"
if (Test-Path $BACKUP) { Remove-Item $BACKUP -Recurse -Force }
Copy-Item $MONDIR $BACKUP -Recurse
Write-Host "  Backed up." -ForegroundColor Green
Write-Host ""

# ----------------------------------------------------------------------------
# M6 FIRST — measure latency with PROPER timing
#   We poll every 2 seconds for up to 60 seconds (agent batches every 5-15s)
# ----------------------------------------------------------------------------
Write-Host "[M6] Measuring detection latency (3 trials, 60s timeout each) ..." -ForegroundColor Yellow
$latencies = @()
for ($i = 1; $i -le 3; $i++) {
    $latFile = "lat_probe_$($i)_$(Get-Random).txt"
    $t0 = Get-Date
    "latency probe $i at $($t0.Ticks)" | Out-File "$MONDIR\$latFile" -Encoding utf8

    $found = $false
    $waited = 0
    while (-not $found -and $waited -lt 60) {
        Start-Sleep -Seconds 2
        $waited += 2
        $q = @{ query = @{ wildcard = @{ file_path = "*$latFile" } }; size = 1 } | ConvertTo-Json -Depth 6
        try {
            $r = Invoke-RestMethod -Uri "$OS/fim-events/_search" -Method POST -Body $q -ContentType "application/json"
            if ($r.hits.hits.Count -gt 0) { $found = $true }
        } catch {}
    }

    if ($found) {
        $latencies += $waited
        Write-Host "    Trial $i : ${waited}s" -ForegroundColor Gray
    } else {
        Write-Host "    Trial $i : not detected within 60s" -ForegroundColor Red
    }

    # short gap between trials so the agent's next batch is fresh
    Start-Sleep -Seconds 3
}

if ($latencies.Count -gt 0) {
    $avgLat = [math]::Round(($latencies | Measure-Object -Average).Average, 1)
    $maxLat = ($latencies | Measure-Object -Maximum).Maximum
    $minLat = ($latencies | Measure-Object -Minimum).Minimum
} else {
    $avgLat = "N/A"; $maxLat = "N/A"; $minLat = "N/A"
}
Write-Host "  M6 result: mean ${avgLat}s (min ${minLat}s, max ${maxLat}s, $($latencies.Count)/3 trials)" -ForegroundColor Green
Write-Host ""

# ----------------------------------------------------------------------------
# M5 — Ransomware indicator detection, with proper wait
# ----------------------------------------------------------------------------
Write-Host "[M5] Creating ransomware indicator files ..." -ForegroundColor Yellow
$ransomFiles = @{
    "evaltest_$(Get-Random).encrypted"        = "encrypted blob data"
    "HOW_TO_DECRYPT_$(Get-Random).txt"        = "PAY 1 BTC TO RECOVER YOUR FILES"
    "record_$(Get-Random).locked"             = "locked file"
}

foreach ($f in $ransomFiles.Keys) {
    $ransomFiles[$f] | Out-File "$MONDIR\$f" -Encoding utf8
    Write-Host "    Created: $f" -ForegroundColor Gray
}

Write-Host "  Waiting 30 seconds for agent batch-send to complete ..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Now check for each file individually in fim-events
$ransomCaught = 0
$ransomNotes = @()
foreach ($f in $ransomFiles.Keys) {
    $q = @{ query = @{ wildcard = @{ file_path = "*$f" } }; size = 1; sort = @(@{ timestamp = @{ order = "desc" } }) } | ConvertTo-Json -Depth 6
    try {
        $r = Invoke-RestMethod -Uri "$OS/fim-events/_search" -Method POST -Body $q -ContentType "application/json"
        if ($r.hits.hits.Count -gt 0) {
            $ev = $r.hits.hits[0]._source
            $threat = $ev.threat_score
            $sens = $ev.sensitivity
            $ransomCaught++
            $ransomNotes += "    $f -> captured (threat_score=$threat, sensitivity=$sens)"
        } else {
            $ransomNotes += "    $f -> NOT captured"
        }
    } catch {
        $ransomNotes += "    $f -> query error"
    }
}
$ransomNotes | ForEach-Object { Write-Host $_ -ForegroundColor Gray }

# Also check whether any of these triggered ransomware-style alerts
$since = (Get-Date).AddMinutes(-3).ToUniversalTime().ToString("o")
$alertQ = @{ query = @{ range = @{ timestamp = @{ gte = $since } } }; size = 50 } | ConvertTo-Json -Depth 8
$ransomAlerts = 0
try {
    $alerts = Invoke-RestMethod -Uri "$OS/fim-alerts/_search" -Method POST -Body $alertQ -ContentType "application/json"
    foreach ($h in $alerts.hits.hits) {
        $blob = ($h._source | ConvertTo-Json -Compress).ToLower()
        if ($blob -match "encrypt|ransom|decrypt|locked|\.encrypted") {
            $ransomAlerts++
        }
    }
} catch {}

Write-Host "  M5 result: $ransomCaught of 3 ransomware files captured" -ForegroundColor Green
Write-Host "  Ransomware-related alerts in last 3 min: $ransomAlerts" -ForegroundColor Green
Write-Host ""

# ----------------------------------------------------------------------------
# Cleanup
# ----------------------------------------------------------------------------
Write-Host "[CLEANUP] Restoring monitored folder ..." -ForegroundColor Yellow
Get-ChildItem $MONDIR -File | Remove-Item -Force
Copy-Item "$BACKUP\*" $MONDIR -Force
Write-Host "  Restored." -ForegroundColor Green
Write-Host ""

# ----------------------------------------------------------------------------
# Results
# ----------------------------------------------------------------------------
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  RETRY RESULTS - COPY EVERYTHING BELOW AND PASTE TO CLAUDE" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "----- SECUREFIM PRO RETRY EVALUATION (M5 + M6) -----"
Write-Host "M5 Ransomware signals captured     : $ransomCaught / 3"
Write-Host "M5 Ransomware-related alerts fired : $ransomAlerts"
Write-Host "M6 Mean detection latency          : $avgLat s"
Write-Host "M6 Latency range                   : ${minLat}s - ${maxLat}s"
Write-Host "M6 Trials succeeded                : $($latencies.Count) / 3"
Write-Host "----------------------------------------------------"
Write-Host ""
Write-Host "Done. Paste the results above back to Claude." -ForegroundColor Green
