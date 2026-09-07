param(
    [string]$Origin = 'http://127.0.0.1:8080',
    [Parameter(Mandatory=$true)][string]$TokenFile,
    [string]$Report = '.local/audit-capacity.json',
    [ValidateRange(1,100)][int]$WarningPercent = 70,
    [ValidateRange(1,100)][int]$CriticalPercent = 85
)
$ErrorActionPreference = 'Stop'
$uri = [Uri]$Origin
if ($uri.Scheme -ne 'https' -and !($uri.Scheme -eq 'http' -and $uri.IsLoopback)) { throw 'Use HTTPS or loopback HTTP' }
if ($uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) { throw 'Use a gateway origin' }
if ($WarningPercent -ge $CriticalPercent) { throw 'Warning must be below critical' }
$token = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $TokenFile)).Trim()
# Redirects are prohibited so credentials cannot be forwarded elsewhere.
$response = Invoke-WebRequest -UseBasicParsing -Uri "$($Origin.TrimEnd('/'))/metrics" -Headers @{Authorization="Bearer $token"} -MaximumRedirection 0 -TimeoutSec 10
$matchBytes = [regex]::Match($response.Content, '(?m)^gateway_state_bytes (\d+)\r?$')
$matchPending = [regex]::Match($response.Content, '(?m)^gateway_audit_pending (\d+)\r?$')
if (!$matchBytes.Success -or !$matchPending.Success) { throw 'Durable audit metrics missing' }
$bytes = [long]$matchBytes.Groups[1].Value
$percent = 100.0 * $bytes / 1073741824
$level = if ($percent -ge $CriticalPercent) {'critical'} elseif ($percent -ge $WarningPercent) {'warning'} else {'ok'}
$result = @{checked_at=[DateTime]::UtcNow.ToString('o'); level=$level; state_bytes=$bytes; capacity_bytes=1073741824; percent_used=[Math]::Round($percent,2); pending_events=[long]$matchPending.Groups[1].Value; warning_percent=$WarningPercent; critical_percent=$CriticalPercent}
$result | ConvertTo-Json | Set-Content -LiteralPath $Report
$result | ConvertTo-Json
if ($level -eq 'critical') { exit 2 }
if ($level -eq 'warning') { exit 1 }
