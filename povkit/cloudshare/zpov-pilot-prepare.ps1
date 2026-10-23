# Zscaler POV Kit: prepare a Windows 11 pilot device for a CloudShare blueprint. Run once, in PowerShell opened with
# "Run as administrator", when building the blueprint:
#
#   irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zpov-pilot-prepare.ps1 | iex
#
# It installs the POV kit (for its probe) and saves the kit's pinned Client Connector installer, checked by SHA-256
# and Zscaler's signature, to C:\ZPOV. It does NOT install Client Connector: its cloud, domain and user are per POV,
# so each POV runs the console's one-line command (Next steps > Set up a pilot device) with -Msi C:\ZPOV\<file>.
$ErrorActionPreference = "Stop"
$Repo = if ($env:ZPOV_KIT_REPO) { $env:ZPOV_KIT_REPO } else { "Paulie631/zscaler-pov-kit" }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path C:\ZPOV | Out-Null
$pins = Invoke-RestMethod "https://github.com/$Repo/releases/latest/download/zcc_installers.json"
$w = $pins.windows
$f = Join-Path C:\ZPOV $w.file
Invoke-WebRequest "https://github.com/$Repo/releases/download/$($pins.release_tag)/$($w.file)" -OutFile $f -UseBasicParsing
if ((Get-FileHash $f -Algorithm SHA256).Hash.ToLower() -ne $w.sha256.ToLower()) { Remove-Item $f; throw "Installer SHA-256 doesn't match; removed." }
$sig = Get-AuthenticodeSignature $f
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch 'CN="?Zscaler, Inc\.') { Remove-Item $f; throw "Installer isn't signed by Zscaler, Inc.; removed." }
Write-Host "  Client Connector $($w.version) saved to $f (checked)."
$env:ZPOV_NO_GUI = "1"
& ([scriptblock]::Create((Invoke-RestMethod "https://github.com/$Repo/releases/latest/download/install.ps1")))
Write-Host ""
Write-Host "  Ready. Save the machine (or the CloudShare blueprint) now. Per POV: run the console's one-line command"
Write-Host "  (Next steps > Set up a pilot device) and add:  -Msi $f"
