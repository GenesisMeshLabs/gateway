[CmdletBinding()]
param([Parameter(Mandatory)][string]$Configuration)
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $Configuration -Raw -Encoding UTF8 | ConvertFrom-Json
$env:PYTHONPATH = $config.code
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONUNBUFFERED = '1'
while ($true) {
    foreach ($authority in $config.authorities) {
        & $config.python $config.script --database $authority.database --key-file $authority.key --issuer $authority.issuer
        if ($LASTEXITCODE -ne 0) { throw "CRL refresh failed: $($authority.name)" }
    }
    Start-Sleep -Seconds 3600
}
