# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Tests install.ps1 on Windows against fake releases served on localhost
# (made by fakerel.sh under <root>/ok, <root>/tamper and <root>/nosum):
# good installs (as `irm | iex` does, under Windows PowerShell 5.1 as a
# file, a pinned version, a second install over the first), then cases
# that must be refused with nothing installed: a tampered archive, an
# archive missing from SHA256SUMS, NOQTIS_COSIGN=1 without cosign, a
# non-https base URL. Run from the source root:
#   pwsh -File packaging/insttest.ps1 <root> <work dir>
# with an http server for <root> on 127.0.0.1, port $env:NQPORT (8471).
param([Parameter(Mandatory)] [string]$Root, [Parameter(Mandatory)] [string]$Work)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$port = $env:NQPORT
if (-not $port) { $port = '8471' }
$url = "http://127.0.0.1:$port"
$ver = (Select-String -Path CMakeLists.txt -Pattern '^project\(noqtis VERSION ([0-9.]+)').Matches[0].Groups[1].Value
$script = (Resolve-Path install.ps1).Path
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$fail = 0

# runs install.ps1 in a new process with these environment variables;
# returns @(exit code, output)
function Run-Install([hashtable]$envs, [string]$shell, [switch]$Iex) {
  $saved = @{}
  foreach ($k in @('NOQTIS_BASE', 'NOQTIS_PREFIX', 'NOQTIS_VERSION', 'NOQTIS_COSIGN')) {
    $saved[$k] = [Environment]::GetEnvironmentVariable($k)
    [Environment]::SetEnvironmentVariable($k, $null)
  }
  foreach ($k in $envs.Keys) { [Environment]::SetEnvironmentVariable($k, $envs[$k]) }
  # the child's error output is data here, not an error of this script
  $ErrorActionPreference = 'Continue'
  try {
    if ($Iex) {
      # what `irm <url>/install.ps1 | iex` runs
      $cmd = "Invoke-RestMethod '$($envs['NOQTIS_BASE'])/latest/download/install.ps1' | Invoke-Expression"
      $out = & $shell -NoProfile -NonInteractive -Command $cmd 2>&1 | Out-String
    } else {
      $out = & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script 2>&1 | Out-String
    }
    return @($LASTEXITCODE, $out)
  } finally {
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
  }
}

function Pass([string]$name, [hashtable]$envs, [string]$shell = 'pwsh', [switch]$Iex) {
  $r = Run-Install $envs $shell -Iex:$Iex
  $exe = Join-Path $envs['NOQTIS_PREFIX'] 'bin\noqtis.exe'
  $v = ''
  if (Test-Path -LiteralPath $exe) { $v = (& $exe version | Out-String).Trim() }
  if ($r[0] -eq 0 -and $v -eq "noqtis $ver") {
    Write-Host "ok   $name"
  } else {
    Write-Host "FAIL $name (should have installed; exit $($r[0]), version '$v')"
    Write-Host $r[1]
    $script:fail = 1
  }
  return $r[1]
}

function Refuse([string]$name, [hashtable]$envs, [string]$text) {
  $r = Run-Install $envs 'pwsh'
  $exe = Join-Path $envs['NOQTIS_PREFIX'] 'bin\noqtis.exe'
  if ($r[0] -eq 0) {
    Write-Host "FAIL $name (should have been refused)"; Write-Host $r[1]; $script:fail = 1
  } elseif (Test-Path -LiteralPath $exe) {
    Write-Host "FAIL $name (refused, but left $exe)"; Write-Host $r[1]; $script:fail = 1
  } elseif ($r[1] -notmatch [regex]::Escape($text)) {
    Write-Host "FAIL $name (refused without saying '$text')"; Write-Host $r[1]; $script:fail = 1
  } else {
    Write-Host "ok   $name (refused: $text)"
  }
}

if (Get-Command cosign -ErrorAction SilentlyContinue) {
  throw 'insttest.ps1 expects a machine without cosign'
}

$p1 = Join-Path $Work 'p1'
$out = Pass 'iex' @{ NOQTIS_BASE = "$url/ok"; NOQTIS_PREFIX = $p1 } -Iex
if ($out -notmatch 'cosign not found') {
  Write-Host 'FAIL iex (no word that cosign was skipped)'; $fail = 1
}
$null = Pass 'again' @{ NOQTIS_BASE = "$url/ok"; NOQTIS_PREFIX = $p1 }
# a second install merges into the first: nothing nested
if (-not (Test-Path (Join-Path $p1 'lib\cmake\noqtis\noqtisConfig.cmake')) -or
    (Test-Path (Join-Path $p1 'lib\cmake\cmake')) -or
    (Test-Path (Join-Path $p1 'lib\lib'))) {
  Write-Host 'FAIL again (the second install did not merge)'; $fail = 1
}
$null = Pass 'ps51' @{ NOQTIS_BASE = "$url/ok"; NOQTIS_PREFIX = (Join-Path $Work 'p2');
  NOQTIS_VERSION = "v$ver" } 'powershell'
Refuse 'tamper' @{ NOQTIS_BASE = "$url/tamper"; NOQTIS_PREFIX = (Join-Path $Work 'p3');
  NOQTIS_COSIGN = '0' } 'SHA-256 mismatch'
Refuse 'tamperpin' @{ NOQTIS_BASE = "$url/tamper"; NOQTIS_PREFIX = (Join-Path $Work 'p4');
  NOQTIS_VERSION = $ver } 'SHA-256 mismatch'
Refuse 'nosum' @{ NOQTIS_BASE = "$url/nosum"; NOQTIS_PREFIX = (Join-Path $Work 'p5') } 'lists no'
Refuse 'needcosign' @{ NOQTIS_BASE = "$url/ok"; NOQTIS_PREFIX = (Join-Path $Work 'p6');
  NOQTIS_COSIGN = '1' } 'cosign is not installed'
Refuse 'plainhttp' @{ NOQTIS_BASE = 'http://example.com/releases';
  NOQTIS_PREFIX = (Join-Path $Work 'p7') } 'must be an https URL'
Refuse 'userinfo' @{ NOQTIS_BASE = "http://localhost:@127.0.0.2:$port/ok";
  NOQTIS_PREFIX = (Join-Path $Work 'p9') } 'must be an https URL'
Refuse 'noversion' @{ NOQTIS_BASE = "$url/ok"; NOQTIS_PREFIX = (Join-Path $Work 'p8');
  NOQTIS_VERSION = '9.9.9' } 'cannot download SHA256SUMS'

if ($fail -eq 0) { Write-Host 'install.ps1: every case passed' }
exit $fail
