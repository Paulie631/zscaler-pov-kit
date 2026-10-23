# Zscaler POV Kit: one-line installer for Windows (PowerShell).
#
#   irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.ps1 | iex
#
# Why a one-liner: Windows SmartScreen warns about scripts a browser downloaded, because the kit isn't code-signed.
# Content fetched by PowerShell isn't marked as downloaded, so nothing prompts. It does what the double-click
# installer does: gets the latest release, checks its SHA-256 against the release's latest.json, installs uv if
# needed, then runs the kit's own installer and opens the console. Nothing changes in any Zscaler tenant.
$ErrorActionPreference = "Stop"
$Repo = if ($env:ZPOV_KIT_REPO) { $env:ZPOV_KIT_REPO } else { "Paulie631/zscaler-pov-kit" }
$Base = "https://github.com/$Repo/releases/latest/download"
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("zpov-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $Tmp | Out-Null
function Say($m) { Write-Host "  $m" }
function Fail($m) { Write-Host ""; Write-Host "  $m" -ForegroundColor Red; Write-Host ""; Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue; throw $m }

try {
  Write-Host ""
  Say "Zscaler POV Kit - installer"
  Say "==========================="
  try { $info = Invoke-RestMethod "$Base/latest.json" } catch { Fail "Couldn't reach GitHub. Ask IT to allow github.com downloads." }
  if (-not ($info.version -and $info.zip_url -and $info.sha256.Length -eq 64)) { Fail "The release information wasn't in the expected format." }
  if (-not $info.zip_url.StartsWith("https://github.com/")) { Fail "Unexpected download address: $($info.zip_url)" }

  Say "Downloading version $($info.version)..."
  $zip = Join-Path $Tmp "kit.zip"
  Invoke-WebRequest $info.zip_url -OutFile $zip -UseBasicParsing
  if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $info.sha256.ToLower()) {
    Fail "The download doesn't match the release's SHA-256, so nothing was installed."
  }
  Say "Download verified against the release's SHA-256"
  Expand-Archive $zip -DestinationPath $Tmp -Force
  $kit = Join-Path $Tmp "zscaler-pov-kit"
  if (-not (Test-Path (Join-Path $kit "pov_kit.py"))) { Fail "The release zip didn't contain the kit." }

  $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
  if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Say "Installing uv (the free tool the kit runs on)..."
    try { Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression } catch { }
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
  }
  if (-not (Get-Command uv -ErrorAction SilentlyContinue) -and (Get-Command winget -ErrorAction SilentlyContinue)) {
    winget install --id=astral-sh.uv -e --accept-source-agreements --accept-package-agreements
    $env:Path = "$env:LOCALAPPDATA\Microsoft\WinGet\Links;$env:Path"
  }
  if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Fail "Couldn't install uv. Ask IT to allow astral.sh and github.com, or see https://docs.astral.sh/uv/getting-started/installation/"
  }

  $env:UV_SYSTEM_CERTS = "1"; $env:PYTHONUTF8 = "1"
  Say "Preparing Python 3.12 and the kit's libraries (the first time takes a minute or two)..."
  uv run --quiet --python 3.12 --script (Join-Path $kit "pov_kit.py") install
  if ($LASTEXITCODE -ne 0) { Fail "Install failed. The message above says why." }
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

Write-Host ""
Say "Opening the console. Keep this window open while you use it; close it to stop the console."
Say "Next time, open 'Zscaler POV Console' from your desktop or Start menu."
& "$env:USERPROFILE\.zscaler-pov-kit\app\pov-kit.cmd" gui
