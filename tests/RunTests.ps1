#requires -Version 5.1
[CmdletBinding()]
param([string]$SourceDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$script:passed = 0
function Assert-True([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL $Name" }
    $script:passed++
    Write-Output "PASS $Name"
}
function Assert-Throws([scriptblock]$Body, [string]$Pattern, [string]$Name) {
    $caught = $null
    try { & $Body | Out-Null } catch { $caught = $_.Exception.ToString() }
    Assert-True ($null -ne $caught -and $caught -match $Pattern) $Name
}

& (Join-Path $root 'tools\Build.ps1') -Check
foreach ($file in @('src\Runtime.ps1','UniVPN-Multi.ps1','tools\Build.ps1')) {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $file),[ref]$tokens,[ref]$errors)
    Assert-True ($errors.Count -eq 0) "PowerShell syntax: $file"
}
if (-not ('UniVpnMulti.BinaryPatch' -as [type])) {
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $root 'src\PatchEngine.cs')))
}
$abcHash = [UniVpnMulti.BinaryPatch]::Hash([Text.Encoding]::ASCII.GetBytes('abc'))
Assert-True ($abcHash -eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') 'SHA256 implementation'
$fixtureGuid = '{11111111-2222-3333-4444-555555555555}'
Assert-Throws { [UniVpnMulti.BinaryPatch]::PatchInstance([byte[]](0..63),0,$fixtureGuid,2) } 'Unsupported UniVPN binary/version' 'Unknown binaries are rejected before patching'
Assert-Throws { [UniVpnMulti.BinaryPatch]::PatchInstance([byte[]]@(),0,$fixtureGuid,1) } 'Instance number out of range' 'Engine rejects instance 1'
Assert-Throws { [UniVpnMulti.BinaryPatch]::PatchInstance([byte[]]@(),0,$fixtureGuid,1000) } 'Instance number out of range' 'Engine rejects out-of-range instance'

# Load function definitions from AST; never invoke the runtime entry point.
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'src\Runtime.ps1'),[ref]$tokens,[ref]$errors)
# Exercise the actual startup code through -File in a fresh shell. In Windows
# PowerShell 5.1, $PSScriptRoot may be empty during parameter default evaluation.
# Only copy initialization: no patch engine, services, adapters, or entry point.
$firstFunction = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst]},$true)
$probeDirectory = Join-Path ([IO.Path]::GetTempPath()) ('UniVPN startup ' + [guid]::NewGuid().ToString('N'))
$probeFile = Join-Path $probeDirectory 'startup.ps1'
$shellName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
try {
    $null = New-Item -ItemType Directory -Path $probeDirectory
    $startup = $ast.Extent.Text.Substring(0,$firstFunction.Extent.StartOffset)
    [IO.File]::WriteAllText($probeFile,($startup + "`nWrite-Output `$source`n"),[Text.UTF8Encoding]::new($true))
    $defaultOutput = & (Join-Path $PSHOME $shellName) -NoProfile -ExecutionPolicy Bypass -File $probeFile
    Assert-True ($LASTEXITCODE -eq 0 -and $defaultOutput -eq $probeDirectory) 'File launch defaults to script directory with spaces'
    $explicitOutput = & (Join-Path $PSHOME $shellName) -NoProfile -ExecutionPolicy Bypass -File $probeFile -SourceDirectory $root
    Assert-True ($LASTEXITCODE -eq 0 -and $explicitOutput -eq $root) 'File launch preserves explicit source directory'
} finally {
    # Remove only the known probe file and its now-empty temporary directory.
    if ([IO.File]::Exists($probeFile)) { [IO.File]::Delete($probeFile) }
    if ([IO.Directory]::Exists($probeDirectory)) { [IO.Directory]::Delete($probeDirectory) }
}
foreach ($name in @('Get-InstanceInfo','Get-NextNumber','Assert-NoRunningClients','Assert-ServiceOwner')) {
    $node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $name},$true)
    if (-not $node) { throw "Missing runtime function $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$parent = 'C:\fixture'
$stateRoot = 'C:\fixture\UniVPN\.univpn-multi'
foreach ($number in @(2,3,10,999)) {
    $info = Get-InstanceInfo $number
    Assert-True ($info.Product.Length -eq 6 -and $info.Product -eq ('UVP{0:D3}' -f $number)) "Six-byte product identity: $number"
    Assert-True ($info.RpcPort -eq 29189+$number -and $info.BackendPort -eq 19059+$number) "Separate ports: $number"
    Assert-True ($info.Directory -eq "C:\fixture\UniVPN$number") "User-facing directory: $number"
}
Assert-Throws { Get-InstanceInfo 1 } 'Supported instance numbers' 'Runtime rejects instance 1'
Assert-Throws { Get-InstanceInfo 1000 } 'Supported instance numbers' 'Runtime rejects instance 1000'

# These mocks stay in this test process. No adapter, process, or service changes.
$script:mockProcesses = @()
$script:mockTaps = @()
$script:mockDirectories = @()
$script:mockRecords = @()
$script:mockServices = @()
function Get-Process { $script:mockProcesses }
function Get-TapAdapters { $script:mockTaps }
function Get-ChildItem {
    param($LiteralPath, [switch]$Directory, $Filter, [switch]$File)
    if ($LiteralPath -eq $stateRoot) { $script:mockRecords } else { $script:mockDirectories }
}
function Test-Path { param($LiteralPath) return $LiteralPath -eq $stateRoot }
function Get-CimInstance { param($ClassName,$Filter) $script:mockServices }

foreach ($name in @('UniVPN','UniVPNCS','UniVP2','UniVP2CS','UVP003','UVP010CS')) {
    $script:mockProcesses = @([pscustomobject]@{ProcessName=$name})
    Assert-Throws { Assert-NoRunningClients } '当前已有 VPN 在运行' "Creation blocked by $name"
}
$script:mockProcesses = @([pscustomobject]@{ProcessName='UniVPNPromoteService'})
Assert-NoRunningClients
Assert-True $true 'Permanent service alone does not block creation'
$script:mockProcesses = @()
$script:mockTaps = @([pscustomobject]@{Status='Up'})
Assert-Throws { Assert-NoRunningClients } '当前已有 VPN 在运行' 'Active TAP blocks creation'
$script:mockTaps = @([pscustomobject]@{Status='Disconnected'})
Assert-NoRunningClients
Assert-True $true 'Closed clients and disconnected TAP permit creation'

Assert-True ((Get-NextNumber) -eq 2) 'Clean installation starts at 2'
$script:mockDirectories = @([pscustomobject]@{Name='UniVP2'})
Assert-True ((Get-NextNumber) -eq 3) 'Legacy directory reserves instance 2'
$script:mockDirectories = @([pscustomobject]@{Name='UniVPN3'})
$script:mockRecords = @([pscustomobject]@{Name='instance-005.json'})
$script:mockServices = @([pscustomobject]@{Name='UVP009Service'})
Assert-True ((Get-NextNumber) -eq 10) 'Numbering combines directories, failed records, and services'
$script:mockDirectories = @()
$script:mockRecords = @()
$script:mockServices = @([pscustomobject]@{Name='UniVP2Service'})
Assert-True ((Get-NextNumber) -eq 3) 'Legacy service reserves instance 2'

$info = Get-InstanceInfo 3
$expected = '"'+(Join-Path $info.Alias 'promote\UVP003PromoteService.exe')+'"'
$script:mockServices = @([pscustomobject]@{Name=$info.Service;PathName=$expected})
$null = Assert-ServiceOwner $info
Assert-True $true 'Expected instance service path is accepted'
$script:mockServices = @([pscustomobject]@{Name=$info.Service;PathName='"C:\another\service.exe"'})
Assert-Throws { Assert-ServiceOwner $info } 'Service path does not match' 'Unrelated service path is rejected'

if ($SourceDirectory) {
    $shellName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    & (Join-Path $PSHOME $shellName) -NoProfile -File (Join-Path $root 'UniVPN-Multi.ps1') -SelfTest -SourceDirectory $SourceDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Supported-original integration self-test failed.' }
} else {
    Write-Output 'SKIP supported-original integration: use -SourceDirectory for local, read-only verification.'
}
Write-Output "$script:passed assertions passed. No live clients, services, or adapters were modified."
