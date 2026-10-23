#!/bin/bash
# Zscaler POV Kit: set up a macOS pilot device (Client Connector, then the POV's own tests).
#
#   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zcc-setup.sh | bash -s -- \
#     --cloud zscalertwo --domain acme.com --user jane
#
# The POV console's Next steps > Set up a pilot device gives this line filled in, or a script file with the POV's
# probe pack inside. What it does:
#   1. gets the Client Connector .pkg (the kit's pinned copy, or --pkg FILE from your tenant's Platform Releases page)
#      and installs it only if its SHA-256 matches (pinned copy) and Apple's check says it's signed by Zscaler;
#   2. opens a settings profile (cloud, user domain, user name) for you to approve in System Settings, so Client
#      Connector signs in to this tenant without anyone choosing the cloud by hand;
#   3. installs Client Connector, then the POV kit (for its probe), and, with a probe pack, waits until traffic goes
#      through Zscaler and runs the POV's tests. Results go to your Desktop for the SE.
# It changes nothing in any Zscaler tenant. It asks for your Mac password once (sudo), to install.
set -euo pipefail

REPO="${ZPOV_KIT_REPO:-Paulie631/zscaler-pov-kit}"
CLOUD="" DOMAIN="" ZUSER="" PKG="" PACK_B64="${ZPOV_PACK_B64:-}" POV="${ZPOV_POV:-pov}" WAIT=20
while [ $# -gt 0 ]; do
  case "$1" in
    --cloud) CLOUD="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --user) ZUSER="$2"; shift 2 ;;
    --pkg) PKG="$2"; shift 2 ;;
    --wait) WAIT="$2"; shift 2 ;;
    *) echo "Unknown option $1"; exit 2 ;;
  esac
done
say() { printf '  %s\n' "$*"; }
fail() { printf '\n  %s\n\n' "$*" >&2; exit 1; }
[ "$(uname)" = Darwin ] || fail "This is the macOS setup. On Windows, use zcc-setup.ps1."
[[ "$CLOUD" =~ ^[a-z0-9]+$ ]] || fail "Give the Zscaler cloud (--cloud zscalertwo): the POV console shows it."
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || fail "Give the pilot users' domain (--domain acme.com)."
[ -z "$ZUSER" ] || [[ "$ZUSER" =~ ^[A-Za-z0-9._+-]+$ ]] || fail "--user is the part before the @ (jane, not jane@acme.com)."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo; say "Zscaler POV Kit - pilot device setup (macOS)"; say "============================================"

# 1. the installer
if [ -z "$PKG" ]; then
  curl -fsSL "https://github.com/$REPO/releases/latest/download/zcc_installers.json" -o "$TMP/pins.json" \
    || fail "Couldn't reach GitHub. Ask IT to allow github.com downloads, or give --pkg FILE."
  pin() { plutil -extract "macos.$1" raw -o - "$TMP/pins.json" 2>/dev/null || true; }
  FILE="$(pin file)"; SHA="$(pin sha256)"
  if [ -z "${FILE:-}" ]; then
    fail "The kit doesn't have a macOS installer yet. Download the .pkg from your Zscaler console (Infrastructure >
  Common Resources > Deployment > Platform Releases > macOS, or search the menu for Platform Releases), then run
  this again with --pkg ~/Downloads/<the file>.pkg"
  fi
  say "Downloading Client Connector ($FILE)..."
  curl -fsSL "https://github.com/$REPO/releases/download/zcc-installer/$FILE" -o "$TMP/zcc.pkg" || fail "The download failed."
  GOT="$(shasum -a 256 "$TMP/zcc.pkg" | cut -d' ' -f1)"
  [ "$GOT" = "$SHA" ] || fail "The installer doesn't match the kit's pinned SHA-256, so it wasn't installed."
  say "Matches the kit's pinned SHA-256"
  PKG="$TMP/zcc.pkg"
fi
[ -f "$PKG" ] || fail "No installer at $PKG."
case "$PKG" in *.pkg) ;; *) fail "Give the .pkg file (from Platform Releases > macOS)." ;; esac
SIG="$(pkgutil --check-signature "$PKG" 2>&1 || true)"
echo "$SIG" | grep -q "Developer ID Installer: Zscaler" || fail "The installer isn't signed by Zscaler, so it wasn't installed."
spctl -a -t install "$PKG" >/dev/null 2>&1 || fail "macOS doesn't accept the installer's signature, so it wasn't installed."
say "Signed by Zscaler, and accepted by macOS"

# 2. the settings profile (what an MDM would push: com.zscaler.installparams)
PROFILE="$HOME/Downloads/Zscaler POV settings ($DOMAIN).mobileconfig"
U1=$(uuidgen); U2=$(uuidgen)
cat > "$PROFILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.zscaler.pov.installparams</string>
  <key>PayloadUUID</key><string>$U1</string>
  <key>PayloadDisplayName</key><string>Zscaler POV: Client Connector settings</string>
  <key>PayloadDescription</key><string>Signs Client Connector in to the $CLOUD cloud for $DOMAIN. Remove it after the POV.</string>
  <key>PayloadScope</key><string>System</string>
  <key>PayloadContent</key><array><dict>
    <key>PayloadType</key><string>com.apple.ManagedClient.preferences</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>com.zscaler.pov.installparams.prefs</string>
    <key>PayloadUUID</key><string>$U2</string>
    <key>PayloadDisplayName</key><string>Client Connector install parameters</string>
    <key>PayloadContent</key><dict>
      <key>com.zscaler.installparams</key><dict><key>Forced</key><array><dict><key>mcx_preference_settings</key><dict>
        <key>installation-parameters</key><dict>
          <key>cloudName</key><string>$CLOUD</string>
          <key>userDomain</key><string>$DOMAIN</string>
          <key>userName</key><string>$ZUSER</string>
          <key>strictEnforcement</key><string>0</string>
        </dict>
      </dict></dict></array></dict>
    </dict>
  </dict></array>
</dict></plist>
EOF
MANAGED="/Library/Managed Preferences/com.zscaler.installparams.plist"
if [ ! -f "$MANAGED" ]; then
  open "$PROFILE" </dev/null || true
  say ""
  say "Approve the settings profile: System Settings > General > Device Management (or Privacy & Security >"
  say "Profiles) > 'Zscaler POV: Client Connector settings' > Install. Waiting up to 5 minutes..."
  for _ in $(seq 1 60); do [ -f "$MANAGED" ] && break; sleep 5; done
  [ -f "$MANAGED" ] || fail "The settings profile isn't installed yet. Approve it (it's in your Downloads folder too), then run this again."
fi
say "Settings profile: cloud $CLOUD, domain $DOMAIN${ZUSER:+, user $ZUSER}"

# 3. install Client Connector, then the kit and the POV's tests
say "Installing Client Connector (your Mac password, once)..."
sudo installer -pkg "$PKG" -target / </dev/null >/dev/null || fail "The installer failed."
say "Client Connector installed. Sign in as ${ZUSER:-a pilot user}${ZUSER:+@$DOMAIN} when it opens."
open -a "Zscaler" 2>/dev/null || true

say "Installing the POV kit for its probe (no keys, nothing in the tenant)..."
curl -fsSL "https://github.com/$REPO/releases/latest/download/install.sh" | ZPOV_NO_GUI=1 bash >/dev/null \
  || fail "The POV kit didn't install; Client Connector is installed. Run the kit's one-line installer by hand."
KIT="$HOME/.zscaler-pov-kit/app/pov-kit"
if [ -n "$PACK_B64" ]; then
  PACKF="$HOME/.zscaler-pov-kit/probe-pack-$POV.json"
  printf '%s' "$PACK_B64" | base64 -D > "$PACKF"
  OUT="$HOME/Desktop/pov-probe-$POV-${ZUSER:-device}.json"
  say "Once you're signed in, the POV's tests run (waiting up to $WAIT minutes for Zscaler)..."
  "$KIT" probe --pack "$PACKF" --wait "$WAIT" --out "$OUT" </dev/null || true
  say "Results: $OUT. Send them to the SE."
else
  say "Next: once signed in, run the POV's tests with the probe pack the SE sends:"
  say "  $KIT probe --pack <the pack file> --wait $WAIT"
fi
echo; say "Done. After the POV: remove the settings profile (System Settings > Device Management)."
