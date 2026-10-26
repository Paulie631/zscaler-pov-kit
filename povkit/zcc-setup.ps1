# Zscaler POV Kit: set up a Windows pilot device (Client Connector, then the POV's own tests).
#
# In PowerShell opened with "Run as administrator":
#   & ([scriptblock]::Create((irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zcc-setup.ps1))) -Cloud zscalertwo -Domain acme.com -User jane
#
# The POV console's Get ready to test > Set up a pilot device gives this line filled in, or a script file with the POV's
# probe pack inside. What it does:
#   1. downloads the kit's pinned Client Connector installer (or uses -Msi FILE from your tenant's Platform Releases
#      page) and installs it only if its SHA-256 matches (pinned copy) and it's validly signed by Zscaler, Inc.;
#   2. installs it silently with this tenant's cloud, user domain and user name (CLOUDNAME, USERDOMAIN, UNAME), so
#      nobody picks the cloud by hand;
#   3. installs the POV probe (the kit's small pilot-device part: tests and traffic, no keys) and, with a probe pack,
#      keeps the pack on the device, waits until traffic goes through Zscaler and runs the POV's tests. Results go to
#      the Desktop for the SE.
# It changes nothing in any Zscaler tenant.
param(
  [string]$Cloud = "",
  [string]$Domain = "",
  [string]$User = "",
  [string]$Msi = "",
  [int]$Wait = 20,
  [switch]$Replace,
  [string]$PackB64 = $env:ZPOV_PACK_B64,
  [string]$PackGz = $env:ZPOV_PACK_GZ,
  [string]$Pov = $(if ($env:ZPOV_POV) { $env:ZPOV_POV } else { "pov" })
)
$ErrorActionPreference = "Stop"
$Repo = if ($env:ZPOV_KIT_REPO) { $env:ZPOV_KIT_REPO } else { "Paulie631/zscaler-pov-kit" }
function Say($m) { Write-Host "  $m" }
function Fail($m) { Write-Host ""; Write-Host "  $m" -ForegroundColor Red; Write-Host ""; throw $m }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ""; Say "Zscaler POV Kit - pilot device setup (Windows)"; Say "=============================================="
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "Open PowerShell with 'Run as administrator' and run this again (installing needs it)." }
if ($Cloud -notmatch '^[a-z0-9]+$') { Fail "Give the Zscaler cloud (-Cloud zscalertwo): the POV console shows it." }
if ($Domain -notmatch '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { Fail "Give the pilot users' domain (-Domain acme.com)." }
if ($User -and $User -notmatch '^[A-Za-z0-9._+-]+$') { Fail "-User is the part before the @ (jane, not jane@acme.com)." }
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("zpov-zcc-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $Tmp | Out-Null

try {
  # 0. never take over a device that already has Client Connector (a work laptop's corporate one, say)
  $have = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match '^Zscaler' }
  $skip = $have -and -not $Replace
  if ($skip) {   # already installed: leave it as it is (the probe checks it's in the POV's tenant before testing)
    Say "Client Connector is already installed: leaving it as it is (-Replace reinstalls it for this tenant)."
  }
  if (-not $skip) {
    # 1. the installer
    if (-not $Msi) {
      try { $pins = Invoke-RestMethod "https://github.com/$Repo/releases/latest/download/zcc_installers.json" }
      catch { Fail "Couldn't reach GitHub. Ask IT to allow github.com downloads, or give -Msi FILE." }
      $w = $pins.windows
      if (-not $w) { Fail "The kit has no Windows installer pinned. Download the .msi from your Zscaler console (Platform Releases) and give -Msi FILE." }
      Say "Downloading Client Connector $($w.version)..."
      $Msi = Join-Path $Tmp $w.file
      Invoke-WebRequest "https://github.com/$Repo/releases/download/$($pins.release_tag)/$($w.file)" -OutFile $Msi -UseBasicParsing
      if ((Get-FileHash $Msi -Algorithm SHA256).Hash.ToLower() -ne $w.sha256.ToLower()) {
        Fail "The installer doesn't match the kit's pinned SHA-256, so it wasn't installed."
      }
      Say "Matches the kit's pinned SHA-256"
    }
    if (-not (Test-Path $Msi)) { Fail "No installer at $Msi." }
    $sig = Get-AuthenticodeSignature $Msi
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch 'CN="?Zscaler, Inc\.') {
      Fail "The installer isn't validly signed by Zscaler, Inc. ($($sig.Status)), so it wasn't installed."
    }
    Say "Signed by Zscaler, Inc."

    # 2. install with this tenant's settings
    $args_ = @("/i", "`"$Msi`"", "/quiet", "/norestart", "CLOUDNAME=$Cloud", "USERDOMAIN=$Domain")
    if ($User) { $args_ += "UNAME=$User" }
    Say "Installing Client Connector (cloud $Cloud, domain $Domain$(if ($User) { ", user $User" }))..."
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList $args_
    if ($p.ExitCode -notin 0, 3010) { Fail "The installer failed (msiexec exit code $($p.ExitCode))." }
    Say "Client Connector installed. Sign in as $(if ($User) { "$User@$Domain" } else { 'a pilot user' }) when it opens."
  }

  # 3. the POV probe and the POV's tests
  Say "Installing the POV probe (tests and traffic only: no keys, nothing in the tenant)..."
  $home_ = if ($env:ZPOV_PROBE_HOME) { $env:ZPOV_PROBE_HOME } else { Join-Path $env:USERPROFILE ".zscaler-pov-probe" }
  New-Item -ItemType Directory -Force -Path $home_ | Out-Null
  $packf = $null
  if ($PackGz) {   # the POV's tests, as the console's command carries them: gzip, then base64
    $packf = Join-Path $home_ "pack-download-$Pov.json"
    $in = New-Object IO.MemoryStream(,[Convert]::FromBase64String($PackGz))
    $gz = New-Object IO.Compression.GzipStream($in, [IO.Compression.CompressionMode]::Decompress)
    $fs = [IO.File]::Create($packf); $gz.CopyTo($fs); $fs.Close(); $gz.Close()
  } elseif ($PackB64) {
    $packf = Join-Path $home_ "pack-download-$Pov.json"
    [IO.File]::WriteAllBytes($packf, [Convert]::FromBase64String($PackB64))
  }
  if ($packf) { $env:ZPOV_PACK_FILE = $packf }
  & ([scriptblock]::Create((Invoke-RestMethod "https://github.com/$Repo/releases/latest/download/install-probe.ps1")))
  $probe = Join-Path $home_ "app\pov-probe.cmd"
  $who = if ($User) { "$User@$Domain" } else { "the pilot user" }
  if ($packf) {
    $out = Join-Path ([Environment]::GetFolderPath("Desktop")) "pov-probe-results-$Pov-$(if ($User) { $User } else { 'device' }).json"
    Say ""
    Say "NEXT: sign in to Client Connector as $who (the window that just opened)."
    Say "The POV's tests then run by themselves (waiting up to $Wait minutes for you to sign in)..."
    & $probe test --wait $Wait --out $out
    if ($LASTEXITCODE -eq 0) {
      Say ""; Say "Results: $out"
      Say "Last step: in the POV console, Set up a pilot device > 3. Import the results, and pick that file."
      Say "(On a customer's device: send the file to the SE.)"
    } else {
      Say ""; Say "The tests didn't run. Once Client Connector is signed in (Internet Security: On), run them again:"
      Say "  & `"$probe`" test --wait $Wait"
    }
  } else {
    Say ""; Say "NEXT: sign in to Client Connector as $who."
    Say "Then run the POV's tests: in the POV console, Set up a pilot device > 2. Run the tests > copy the command,"
    Say "and paste it here."
  }
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
Write-Host ""; Say "Done."
