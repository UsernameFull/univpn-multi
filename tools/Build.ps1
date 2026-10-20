#requires -Version 5.1
[CmdletBinding()]
param([switch]$Check)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$runtime = [IO.File]::ReadAllText((Join-Path $root 'src\Runtime.ps1')).Replace("`r`n", "`n")
$engine = [IO.File]::ReadAllText((Join-Path $root 'src\PatchEngine.cs')).Replace("`r`n", "`n").TrimEnd()
$marker = '# PATCH_ENGINE'
if ([regex]::Matches($runtime, [regex]::Escape($marker)).Count -ne 1) {
    throw 'Runtime must contain exactly one patch engine marker.'
}
$embedded = "if (-not ('UniVpnMulti.BinaryPatch' -as [type])) {`nAdd-Type -TypeDefinition @'`n" + $engine + "`n'@`n}"
$content = $runtime.Replace($marker, $embedded).TrimEnd() + "`n"
$target = Join-Path $root 'UniVPN-Multi.ps1'
$encoding = [Text.UTF8Encoding]::new($true) # BOM is needed for Chinese text in Windows PowerShell 5.1.
$expected = $encoding.GetPreamble() + $encoding.GetBytes($content)
if ($Check) {
    if (-not (Test-Path -LiteralPath $target)) { throw 'Generated script is missing. Run tools/Build.ps1.' }
    $actual = [IO.File]::ReadAllBytes($target)
    if ([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($expected)) {
        throw 'Generated script differs from source. Run tools/Build.ps1 and commit the result.'
    }
    Write-Output 'PASS generated script is reproducible.'
} else {
    [IO.File]::WriteAllBytes($target, $expected)
    Write-Output "Built $target"
}
