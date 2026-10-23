# Zscaler POV probe: one-line installer for a Windows pilot device (PowerShell).
#
#   irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install-probe.ps1 | iex
#
# The probe is the small part of the POV kit that runs on pilot devices: the POV's tests and the ZIA traffic
# generator. It has no console, no API keys and no tenant access; it only browses and writes a results file for the
# SE. This gets the latest release, checks the probe's SHA-256 against the release's latest.json, installs uv (the
# free tool it runs on) if needed, and puts the probe in %USERPROFILE%\.zscaler-pov-probe\app. To install a probe
# pack with it, set $env:ZPOV_PACK_FILE first.
$ErrorActionPreference = "Stop"
$Repo = if ($env:ZPOV_KIT_REPO) { $env:ZPOV_KIT_REPO } else { "Paulie631/zscaler-pov-kit" }
$Base = "https://github.com/$Repo/releases/latest/download"
$Dest = if ($env:ZPOV_PROBE_HOME) { $env:ZPOV_PROBE_HOME } else { Join-Path $env:USERPROFILE ".zscaler-pov-probe" }
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("zpov-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $Tmp | Out-Null
function Say($m) { Write-Host "  $m" }
function Fail($m) { Write-Host ""; Write-Host "  $m" -ForegroundColor Red; Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue; throw $m }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
  Say "Zscaler POV probe - installer"
  try { $info = Invoke-RestMethod "$Base/latest.json" } catch { Fail "Couldn't reach GitHub. Ask IT to allow github.com downloads." }
  if (-not ($info.version -and $info.probe_zip_url -and $info.probe_sha256.Length -eq 64)) { Fail "The release information wasn't in the expected format." }
  if (-not $info.probe_zip_url.StartsWith("https://github.com/")) { Fail "Unexpected download address: $($info.probe_zip_url)" }
  Say "Downloading the probe $($info.version)..."
  $zip = Join-Path $Tmp "probe.zip"
  Invoke-WebRequest $info.probe_zip_url -OutFile $zip -UseBasicParsing
  if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $info.probe_sha256.ToLower()) { Fail "The download doesn't match the release's SHA-256, so nothing was installed." }
  Say "Download verified against the release's SHA-256"
  Expand-Archive $zip -DestinationPath $Tmp -Force
  if (-not (Test-Path (Join-Path $Tmp "zscaler-pov-probe\pov_probe.py"))) { Fail "The release zip didn't contain the probe." }

  $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
  if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Say "Installing uv (the free tool the probe runs on)..."
    try { Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression } catch { }
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
  }
  if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { Fail "Couldn't install uv. Ask IT to allow astral.sh and github.com." }

  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  $app = Join-Path $Dest "app"
  Remove-Item -Recurse -Force "$app.old" -ErrorAction SilentlyContinue
  if (Test-Path $app) { Move-Item $app "$app.old" }
  Move-Item (Join-Path $Tmp "zscaler-pov-probe") $app
  $env:UV_SYSTEM_CERTS = "1"; $env:PYTHONUTF8 = "1"
  Say "Preparing Python and two small libraries (the first time takes a minute)..."
  $probe = Join-Path $app "pov-probe.cmd"
  & $probe version | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "The probe didn't start. The message above says why." }
  if ($env:ZPOV_PACK_FILE) { & $probe pack install $env:ZPOV_PACK_FILE }
  Say "Installed: $probe  (test | pack | traffic | cleanup)"
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
