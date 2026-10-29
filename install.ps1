# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Installs the noqtis command, library, header and manual pages from a
# GitHub release of rootcoder007/noqtis, on Windows (x64 or ARM64).
#
#   irm https://github.com/rootcoder007/noqtis/releases/latest/download/install.ps1 | iex
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# What it does, in order, stopping at the first failure:
#   1. picks the archive for this CPU (windows-x86_64 or windows-arm64);
#   2. downloads the release's SHA256SUMS and, when cosign is installed,
#      checks its Sigstore signature: signed by this repository's release
#      workflow for that very tag (without cosign it says so and goes on);
#   3. downloads the archive and checks its SHA-256 against SHA256SUMS;
#   4. checks every path in the archive stays inside its top directory;
#   5. copies bin\, include\, lib\ and share\ into the prefix.
# Nothing from the archive runs before step 3 passes, and nothing is
# installed if any step fails. It never asks for administrator rights.
#
# Environment:
#   NOQTIS_PREFIX   where to install (default: $HOME\.local)
#   NOQTIS_VERSION  a release such as 0.1.1 (default: the latest release)
#   NOQTIS_COSIGN   auto (default): check with cosign when it is installed;
#                   1: require cosign; 0: skip the Sigstore check
#   NOQTIS_BASE     the releases URL (default:
#                   https://github.com/rootcoder007/noqtis/releases); only
#                   https, or http to localhost for testing
#
# Errors are thrown, never `exit`, so that `irm ... | iex` does not close
# the PowerShell window it runs in; run as a file, an error exits non-zero.

function Install-Noqtis {
  $ErrorActionPreference = 'Stop'
  Set-StrictMode -Version 3
  $repo = 'rootcoder007/noqtis'
  $issuer = 'https://token.actions.githubusercontent.com'
  $script:nqCopied = $false

  function Say([string]$m) { [Console]::Error.WriteLine("noqtis install: $m") }
  function Fail([string]$m) {
    if ($script:nqCopied) { $tail = 'the install into the prefix may be incomplete' }
    else { $tail = 'nothing was installed' }
    throw "noqtis install: error: $m; $tail"
  }
  function Get-File([string]$url, [string]$dest) {
    try {
      $old = $ProgressPreference
      $ProgressPreference = 'SilentlyContinue'
      # no redirects for plain http (localhost tests); GitHub's https
      # downloads redirect to their CDN
      if ($url -like 'http://*') {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest -MaximumRedirection 0
      } else {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dest
      }
    } catch {
      return $false
    } finally {
      $ProgressPreference = $old
    }
    return $true
  }

  # Windows PowerShell 5.1 may default to TLS 1.0
  try {
    [Net.ServicePointManager]::SecurityProtocol =
      [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  } catch { }

  $prefix = $env:NOQTIS_PREFIX
  if (-not $prefix) { $prefix = Join-Path $HOME '.local' }
  $ver = $env:NOQTIS_VERSION
  if ($ver) { $ver = $ver.TrimStart('v') }
  if ($ver -and $ver -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$') {
    Fail "not a release version: $ver"
  }
  $sigmode = $env:NOQTIS_COSIGN
  if (-not $sigmode) { $sigmode = 'auto' }
  if ($sigmode -notin @('auto', '0', '1')) { Fail 'NOQTIS_COSIGN must be auto, 0 or 1' }
  $verify = $env:NOQTIS_VERIFY
  if (-not $verify) { $verify = '1' }
  if ($verify -notin @('0', '1')) { Fail 'NOQTIS_VERIFY must be 0 or 1' }
  # the release signing key (SECURITY.md)
  $signer = 'noqtis ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIITExiNM+YezpSqyif5ZOhFb+abk4iy7CadyZnUMLRMj'
  $sshkey = $env:NOQTIS_SSHKEY
  if (-not $sshkey) { $sshkey = $signer }
  if ($sshkey -ne $signer) { Say 'the release key is NOQTIS_SSHKEY, not the one in SECURITY.md' }
  $base = $env:NOQTIS_BASE
  if (-not $base) { $base = "https://github.com/$repo/releases" }
  $base = $base.TrimEnd('/')
  if ($base -notmatch '^https://' -and
      $base -notmatch '^http://(127\.0\.0\.1|localhost)(:[0-9]{1,5})?(/[^@]*)?$') {
    Fail "NOQTIS_BASE must be an https URL (or http to localhost): $base"
  }

  # 1. the archive for this machine
  $arch = $null
  try {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  } catch { }
  if (-not $arch) {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
  }
  switch -Regex ($arch) {
    '^(X64|AMD64)$' { $target = 'windows-x86_64'; break }
    '^(Arm64|ARM64)$' { $target = 'windows-arm64'; break }
    default { Fail "no release archive for the $arch CPU; build from source" }
  }

  if ($ver) { $url = "$base/download/v$ver" } else { $url = "$base/latest/download" }

  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("noqtis-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    # 2. the sums, and their signature
    $sums = Join-Path $tmp 'SHA256SUMS'
    Say "fetching $url/SHA256SUMS"
    if (-not (Get-File "$url/SHA256SUMS" $sums)) { Fail 'cannot download SHA256SUMS' }
    $table = @{}
    foreach ($line in Get-Content -LiteralPath $sums) {
      if ($line -match '^([0-9A-Fa-f]{64}) [ *]?(\S+)$') {
        if ($table.ContainsKey($Matches[2])) { Fail "SHA256SUMS lists $($Matches[2]) twice" }
        $table[$Matches[2]] = $Matches[1].ToLowerInvariant()
      }
    }
    $pat = '^noqtis-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?-' + [regex]::Escape($target) + '\.zip$'
    if ($ver) {
      $name = "noqtis-$ver-$target.zip"
      if (-not $table.ContainsKey($name)) { Fail "SHA256SUMS of v$ver lists no $name" }
    } else {
      $names = @($table.Keys | Where-Object { $_ -match $pat })
      if ($names.Count -eq 0) { Fail "the latest release lists no archive for $target" }
      if ($names.Count -gt 1) { Fail "SHA256SUMS lists more than one archive for $target" }
      $name = $names[0]
      $ver = $name.Substring(7, $name.Length - 7 - $target.Length - 5)
    }
    $want = $table[$name]

    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if ($sigmode -eq '0') {
      Say 'NOQTIS_COSIGN=0: the Sigstore signature of SHA256SUMS is NOT checked'
    } elseif ($cosign) {
      Say 'checking the Sigstore signature of SHA256SUMS with cosign'
      $bundle = Join-Path $tmp 'SHA256SUMS.sigstore.json'
      if (-not (Get-File "$url/SHA256SUMS.sigstore.json" $bundle)) {
        Fail 'cosign is installed but SHA256SUMS.sigstore.json cannot be downloaded'
      }
      $id = "https://github.com/$repo/.github/workflows/release.yml@refs/tags/v$ver"
      & $cosign.Source verify-blob --bundle $bundle --certificate-identity $id `
        --certificate-oidc-issuer $issuer $sums
      if ($LASTEXITCODE -ne 0) { Fail 'the Sigstore signature of SHA256SUMS does not verify' }
      Say "Sigstore signature: good (release workflow of $repo, tag v$ver)"
      $cosok = $true
    } elseif ($sigmode -eq '1') {
      Fail 'NOQTIS_COSIGN=1 but cosign is not installed'
    } else {
      Say 'cosign not found: the Sigstore signature of SHA256SUMS is NOT checked'
    }
    # the SSH signature: who published the sums (Windows 10 and later
    # carry OpenSSH's ssh-keygen)
    $sshkg = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if ($verify -eq '0') {
      Say 'NOQTIS_VERIFY=0: who signed this release is NOT checked'
    } elseif ($sshkg) {
      $sig = Join-Path $tmp 'SHA256SUMS.sig'
      if (-not (Get-File "$url/SHA256SUMS.sig" $sig)) { Fail 'SHA256SUMS.sig cannot be downloaded' }
      $allowed = Join-Path $tmp 'signers'
      [IO.File]::WriteAllText($allowed, "$sshkey`n")
      # the sums as stdin, byte for byte (a PowerShell pipe would re-encode)
      $pr = Start-Process -FilePath $sshkg.Source -NoNewWindow -Wait -PassThru `
        -ArgumentList @('-Y', 'verify', '-f', "`"$allowed`"", '-I', 'noqtis', '-n', 'file', '-s', "`"$sig`"") `
        -RedirectStandardInput $sums -RedirectStandardOutput (Join-Path $tmp 'ssh.out') `
        -RedirectStandardError (Join-Path $tmp 'ssh.err')
      if ($pr.ExitCode -ne 0) {
        Get-Content (Join-Path $tmp 'ssh.err') | ForEach-Object { Say $_ }
        Fail 'the SSH signature of SHA256SUMS does not verify'
      }
      Say 'SSH signature: good (the noqtis release key)'
    } elseif ($cosok) {
      Say 'ssh-keygen not found: the SSH signature is not checked (Sigstore was)'
    } else {
      Fail 'ssh-keygen (OpenSSH) is not installed, so who signed this release cannot be checked; install it (or cosign), or set NOQTIS_VERIFY=0 to go on without'
    }

    # 3. the archive, checked before anything else touches it
    $zip = Join-Path $tmp $name
    Say "fetching $url/$name"
    if (-not (Get-File "$url/$name" $zip)) { Fail "cannot download $name" }
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
    if ($got -ne $want) {
      Say "SHA256SUMS says $want"
      Say "the download is $got"
      Fail "SHA-256 mismatch for $name"
    }
    Say "SHA-256 of $name matches SHA256SUMS"

    # 4. every entry inside noqtis-<version>-<target>/, no absolute or ..
    $top = "noqtis-$ver-$target"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $z = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
      foreach ($e in $z.Entries) {
        $p = $e.FullName.Replace('\', '/')
        if (-not ($p -eq "$top/" -or $p.StartsWith("$top/"))) {
          Fail "$name has entries outside $top/"
        }
        if ($p -match '(^|/)\.\.(/|$)' -or $p -match '^[A-Za-z]:') {
          Fail "$name has an unsafe path: $p"
        }
      }
    } finally {
      $z.Dispose()
    }
    $x = Join-Path $tmp 'x'
    Expand-Archive -LiteralPath $zip -DestinationPath $x
    $src = Join-Path $x $top
    if (-not (Test-Path -LiteralPath (Join-Path $src 'bin\noqtis.exe'))) {
      Fail "$name has no bin\noqtis.exe"
    }

    # 5. into the prefix: the library, header and pages first, the command last
    try {
      New-Item -ItemType Directory -Force -Path $prefix | Out-Null
      $probe = Join-Path $prefix ('.noqtis-' + [guid]::NewGuid().ToString('N'))
      [IO.File]::WriteAllText($probe, '')
      Remove-Item -LiteralPath $probe
    } catch {
      Fail "cannot write to $prefix; choose another with NOQTIS_PREFIX"
    }
    $script:nqCopied = $true
    foreach ($d in @('include', 'lib', 'share', 'bin')) {
      $from = Join-Path $src $d
      if (Test-Path -LiteralPath $from) {
        # file by file, so that a folder already in the prefix is merged
        # into, never nested inside
        $root = (Get-Item -LiteralPath $from).FullName.TrimEnd('\', '/')
        foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -File) {
          $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
          $dest = Join-Path (Join-Path $prefix $d) $rel
          New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
          Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
        }
      }
    }
    Say "installed noqtis $ver ($target) into $prefix"
    $exe = Join-Path $prefix 'bin\noqtis.exe'
    if ($target -eq 'windows-arm64' -and $arch -notmatch '^(Arm64|ARM64)$') {
      Say 'ARM64 build on a non-ARM64 machine: not run'
    } else {
      & $exe version
      if ($LASTEXITCODE -ne 0) { Fail 'the installed noqtis does not run' }
    }
    $bin = Join-Path $prefix 'bin'
    $path = @($env:PATH -split ';' | ForEach-Object { $_.TrimEnd('\') })
    if ($path -notcontains $bin.TrimEnd('\')) {
      Say "add $bin to PATH, for example (for your user, new windows):"
      Say "  [Environment]::SetEnvironmentVariable('PATH', `"$bin;`" + [Environment]::GetEnvironmentVariable('PATH', 'User'), 'User')"
    }
  } finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Install-Noqtis
