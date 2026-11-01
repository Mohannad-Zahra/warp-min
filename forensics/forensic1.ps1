# Fixed Bulletproof Forensic Audit Script for WARP-MIN
$ErrorActionPreference = 'Continue'
$workspace = 'B:\Akuma\Warper'
$out = "$workspace\forensics\run1"
New-Item -ItemType Directory -Force $out | Out-Null
Set-Location $workspace
[System.IO.Directory]::SetCurrentDirectory($workspace)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  WARP-MIN FORENSIC KERNEL AUDIT & EVIDENCE GATHERING (STAGE 1)  " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Clean up any previous captures
Write-Host "[*] Resetting packet monitors and capture sessions..." -ForegroundColor Yellow
pktmon stop 2>$null | Out-Null
pktmon filter remove 2>$null | Out-Null
netsh wfp capture stop 2>$null | Out-Null

# 2. Enable Windows Filtering Platform drop auditing
Write-Host "[*] Enabling WFP kernel audit logging..." -ForegroundColor Yellow
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Out-Null
$t0 = Get-Date

# 3. Snapshot baseline WFP filters
Write-Host "[*] Exporting baseline WFP filters..." -ForegroundColor Yellow
netsh wfp show filters file="$out\filters_before.xml" | Out-Null
netsh wfp show state file="$out\wfpstate_before.xml" | Out-Null

# 4. Start Windows Packet Monitor (PktMon) on Roblox IP (128.116.5.33)
Write-Host "[*] Starting PktMon kernel packet trace on 128.116.5.33..." -ForegroundColor Yellow
pktmon filter add RBX -i 128.116.5.33 | Out-Null
pktmon start --capture --pkt-size 0 --comp all --file-name "$out\pktmon.etl" | Out-Null

# 5. Run WARP-MIN Diagnostics synchronously with live console output
Write-Host "[*] Executing WARP-MIN automated diagnostic suite..." -ForegroundColor Green
$exe = "$workspace\warp-min.exe"
if (-not (Test-Path $exe)) {
    Write-Host "[-] ERROR: $exe not found!" -ForegroundColor Red
} else {
    & $exe --diagnose --log-file "$out\diag.log"
}

# 6. Stop PktMon and export traces
Write-Host "[*] Stopping packet trace and exporting data..." -ForegroundColor Yellow
pktmon stop 2>$null | Out-Null
pktmon counters | Out-File "$out\pktmon_counters.txt"
pktmon format "$out\pktmon.etl" -o "$out\pktmon.txt" 2>$null | Out-Null
pktmon pcapng "$out\pktmon.etl" -o "$out\pktmon.pcapng" 2>$null | Out-Null
pktmon etl2pcap "$out\pktmon.etl" --out "$out\pktmon.pcapng" 2>$null | Out-Null
pktmon filter remove 2>$null | Out-Null

# 7. Export WFP netevents and Security event log drops
Write-Host "[*] Collecting WFP netevents and kernel drop events..." -ForegroundColor Yellow
netsh wfp show netevents file="$out\netevents.xml" 2>$null | Out-Null
netsh wfp show state file="$out\wfpstate_after.xml" 2>$null | Out-Null

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152,5157,5156,5159; StartTime=$t0} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message}} |
    Format-List | Out-File "$out\security_events.txt" -Width 400

# 8. Mark complete
'DONE' | Out-File "$out\DONE.txt" -Force
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE! All traces saved to $out" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
