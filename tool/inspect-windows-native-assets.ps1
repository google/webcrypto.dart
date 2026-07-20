# Copyright 2026 The webcrypto.dart authors.
# Licensed under the Apache License, Version 2.0.

param(
  [Parameter(Mandatory = $true)]
  [string]$Bundle
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -Path $Bundle -PathType Container)) {
  throw "Windows bundle does not exist: $Bundle"
}

$libraries = @(Get-ChildItem -Path $Bundle -Recurse -File -Filter webcrypto.dll)
if ($libraries.Count -ne 1) {
  throw "Expected exactly one webcrypto.dll, found $($libraries.Count)."
}
if (@(Get-ChildItem -Path $Bundle -Recurse -Force | Where-Object {
      $_.Name -match 'webcrypto_plugin'
    }).Count -ne 0) {
  throw 'Windows bundle contains a legacy webcrypto plugin artifact.'
}

$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($null -eq $dumpbin) {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path $vswhere)) {
    throw 'Cannot find dumpbin.exe or vswhere.exe.'
  }
  $installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
  $dumpbinPath = Get-ChildItem -Path (Join-Path $installation 'VC\Tools\MSVC') -Recurse -File -Filter dumpbin.exe |
    Where-Object { $_.FullName -match '\\bin\\Hostx64\\x64\\dumpbin\.exe$' } |
    Select-Object -First 1
  if ($null -eq $dumpbinPath) {
    throw 'Visual Studio is installed but x64 dumpbin.exe was not found.'
  }
  $dumpbin = $dumpbinPath.FullName
} else {
  $dumpbin = $dumpbin.Source
}

$headers = & $dumpbin /headers $libraries[0].FullName | Out-String
if ($LASTEXITCODE -ne 0) {
  throw 'dumpbin /headers failed.'
}
if ($headers -notmatch '8664 machine \(x64\)') {
  throw 'webcrypto.dll is not an x64 PE image.'
}

$exports = & $dumpbin /exports $libraries[0].FullName | Out-String
if ($LASTEXITCODE -ne 0) {
  throw 'dumpbin /exports failed.'
}
if ($exports -notmatch '(?m)\swebcrypto_lookup_symbol\s*$') {
  throw 'webcrypto_lookup_symbol is not exported by webcrypto.dll.'
}

Write-Host "Windows Native Asset inspection: PASS ($($libraries[0].FullName))"
