#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Payload,
    [string]$Destination = 'C:\ProgramData\GenesisMeshGateway',
    [switch]$StartServices
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Install a reviewed, offline payload. No downloads, credentials in arguments,
# state initialization, container shutdown, or existing-install overwrite.
$Payload = (Resolve-Path -LiteralPath $Payload).Path
$Destination = [IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $Destination) { throw "Destination already exists: $Destination" }
$manifest = Get-Content -LiteralPath "$Payload\services.json" -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.destination -ne $Destination) { throw 'Payload destination does not match service configuration' }
if (Get-ChildItem -LiteralPath $Payload -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
    throw 'Payload must not contain junctions or symbolic links'
}
function Resolve-Child([string]$Root, [string]$Relative) {
    $path = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes payload: $Relative"
    }
    return $path
}
foreach ($file in $manifest.files) {
    $path = Resolve-Child $Payload $file.path
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.sha256) { throw "Hash mismatch: $($file.path)" }
}
$listed = @($manifest.files | ForEach-Object { (Resolve-Child $Payload $_.path).ToLowerInvariant() })
foreach ($file in Get-ChildItem -LiteralPath $Payload -Recurse -File -Force) {
    if ($file.FullName -ne "$Payload\services.json" -and $file.FullName.ToLowerInvariant() -notin $listed) {
        throw "Unlisted payload file: $($file.Name)"
    }
}
foreach ($service in $manifest.services) {
    if ($service.id -notmatch '^GenesisMesh[A-Za-z]+$') { throw 'Invalid service ID' }
    if (Get-Service -Name $service.id -ErrorAction SilentlyContinue) { throw "Service already exists: $($service.id)" }
    foreach ($path in @($service.read) + @($service.modify)) { $null = Resolve-Child $Payload $path }
}
function Set-PrivateAcl([string]$Path, [hashtable]$Grants) {
    $directory = (Get-Item -LiteralPath $Path).PSIsContainer
    $acl = if ($directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    $all = @{'S-1-5-18'='FullControl'; 'S-1-5-32-544'='FullControl'}
    foreach ($key in $Grants.Keys) { $all[$key] = $Grants[$key] }
    foreach ($key in $all.Keys) {
        $identity = if ($key.StartsWith('S-1-')) { [Security.Principal.SecurityIdentifier]$key } else { [Security.Principal.NTAccount]$key }
        $inherit = if ($directory) { 'ContainerInherit, ObjectInherit' } else { 'None' }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, $all[$key], $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
New-Item -ItemType Directory -Path $Destination | Out-Null
Set-PrivateAcl $Destination @{'S-1-5-19'='ReadAndExecute'}
Get-ChildItem -LiteralPath $Payload -Force | Copy-Item -Destination $Destination -Recurse
foreach ($directory in @('config','state','logs')) { Set-PrivateAcl "$Destination\$directory" @{} }
# Service SIDs isolate authority keys/state even though processes use the
# unprivileged, passwordless LocalService account.
$installed = @()
try {
    foreach ($service in $manifest.services) {
        & "$Destination\services\$($service.id).exe" install
        if ($LASTEXITCODE -ne 0) { throw "Install failed: $($service.id)" }
        $installed += $service.id
        # Pending migrations must not start against an old staged snapshot at boot.
        Set-Service -Name $service.id -StartupType Manual
        & sc.exe sidtype $service.id unrestricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not enable service SID' }
    }
    $grants = @{}
    foreach ($service in $manifest.services) {
        $identity = "NT SERVICE\$($service.id)"
        foreach ($path in $service.read) {
            if (-not $grants.ContainsKey($path)) { $grants[$path] = @{} }
            $grants[$path][$identity] = 'ReadAndExecute'
        }
        foreach ($path in $service.modify) {
            if (-not $grants.ContainsKey($path)) { $grants[$path] = @{} }
            $grants[$path][$identity] = 'Modify'
        }
    }
    foreach ($path in $grants.Keys) {
        $effective = @{}
        foreach ($parent in $grants.Keys) {
            if ($path -eq $parent -or $path.StartsWith($parent.TrimEnd('/') + '/', [StringComparison]::OrdinalIgnoreCase)) {
                foreach ($identity in $grants[$parent].Keys) {
                    if (-not $effective.ContainsKey($identity) -or $grants[$parent][$identity] -eq 'Modify') {
                        $effective[$identity] = $grants[$parent][$identity]
                    }
                }
            }
        }
        Set-PrivateAcl (Resolve-Child $Destination $path) $effective
    }
    # OpenSSH checks private-key owner and permissions; this key permits only
    # forwarding to the dedicated loopback Redis port on the remote host.
    $sshKey = "$Destination\config\ssh\quota"
    Set-PrivateAcl $sshKey @{'S-1-5-19'='Read'}
    $acl = Get-Acl -LiteralPath $sshKey
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-19')
    Set-Acl -LiteralPath $sshKey -AclObject $acl
    if ($StartServices) {
        foreach ($service in $manifest.services) { Start-Service -Name $service.id }
        foreach ($service in $manifest.services) { Set-Service -Name $service.id -StartupType Automatic }
    }
    Get-CimInstance Win32_Service | Where-Object Name -in $installed | Select-Object Name, State, StartMode, StartName
} catch {
    # Do not erase state or automatically revive a stale previous deployment.
    foreach ($id in $installed) { Stop-Service -Name $id -Force -ErrorAction SilentlyContinue }
    throw
}
