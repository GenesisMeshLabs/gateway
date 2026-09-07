param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Platform,
    [string]$Output = '.local/dist'
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$version = [regex]::Match([IO.File]::ReadAllText((Join-Path $repoRoot 'Cargo.toml')), '(?m)^version = "([^"]+)"').Groups[1].Value
$actual = & $binaryPath --version
if ($LASTEXITCODE -ne 0 -or $actual.Trim() -ne "genesis-mesh-gateway $version") { throw 'Binary version does not match Cargo.toml' }
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$outputRoot = (Resolve-Path -LiteralPath $Output).Path
$archive = Join-Path $outputRoot "genesis-mesh-gateway-$version-$Platform.zip"
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive }
$bundle = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
try {
    $files = @('README.md','docs/distribution.md','docs/operations.md','docs/services.md','docs/mesh.md','docs/federation.md','docs/platform.md','docs/improvement-plan.md','docs/adr/0001-deployment-authentication.md','deploy/secrets-store-csi.yaml','tools/check_slo.mjs','tools/check_security.mjs','tools/check_audit.ps1','docs/security-assurance-plan.md','docs/security-findings-2026-09-07.md','docs/acceptance-2026-09-07.md','ui/openapi.json','ui/services.json','deploy/compose.yml','deploy/kubernetes.yaml')
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($bundle, $binaryPath, [IO.Path]::GetFileName($binaryPath)) | Out-Null
    $operatorName = if ($binaryPath.EndsWith('.exe')) { 'genesis-mesh-operator.exe' } else { 'genesis-mesh-operator' }
    $operatorPath = Join-Path (Split-Path $binaryPath -Parent) $operatorName
    if (!(Test-Path -LiteralPath $operatorPath)) { throw 'Build genesis-mesh-operator before packaging' }
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($bundle, $operatorPath, $operatorName) | Out-Null
    foreach ($file in $files) { [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($bundle, (Join-Path $repoRoot $file), $file) | Out-Null }
    $manifest = @{version=$version; platform=$Platform; binary=[IO.Path]::GetFileName($binaryPath); binary_sha256=(Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLower(); operator_binary=$operatorName; operator_sha256=(Get-FileHash -LiteralPath $operatorPath -Algorithm SHA256).Hash.ToLower()} | ConvertTo-Json
    $writer = [IO.StreamWriter]::new($bundle.CreateEntry('manifest.json').Open())
    try { $writer.Write($manifest) } finally { $writer.Dispose() }
} finally { $bundle.Dispose() }
$digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText("$archive.sha256", "$digest  $([IO.Path]::GetFileName($archive))`n")
Write-Output $archive
