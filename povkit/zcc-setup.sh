#!/bin/bash
# Zscaler POV Kit: set up a macOS pilot device (Client Connector, then the POV's own tests).
#
#   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zcc-setup.sh | bash -s -- \
#     --cloud zscalertwo --domain acme.com --user jane
#
# The POV console's Next steps > Set up a pilot device gives this line filled in, or a script file with the POV's
# probe pack inside. What it does:
#   1. gets the Client Connector installer (the kit's pinned copy of Zscaler's installer app, or --pkg FILE from your
#      tenant's Platform Releases page: the .pkg, or the installer .app, zipped or not) and installs it only if its
#      SHA-256 matches (pinned copy) and it's signed by Zscaler (Developer ID, team PCBCQZJ7S7);
#   2. points Client Connector at this tenant (cloud and user domain): the installer app takes them directly; with a
#      .pkg, a settings profile opens for you to approve in System Settings;
#   3. installs Client Connector, then the POV probe (the kit's small pilot-device part: tests and traffic, no keys),
#      and, with a probe pack, keeps the pack on the device, waits until traffic goes through Zscaler and runs the
#      POV's tests. Results go to your Desktop for the SE.
# It changes nothing in any Zscaler tenant. It asks for your Mac password once (sudo), to install.
set -euo pipefail

REPO="${ZPOV_KIT_REPO:-Paulie631/zscaler-pov-kit}"
CLOUD="" DOMAIN="" ZUSER="" PKG="" APP="" PACK_B64="${ZPOV_PACK_B64:-}" POV="${ZPOV_POV:-pov}" WAIT=20 REPLACE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cloud) CLOUD="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --user) ZUSER="$2"; shift 2 ;;
    --pkg) PKG="$2"; shift 2 ;;
    --wait) WAIT="$2"; shift 2 ;;
    --replace) REPLACE=1; shift ;;
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

# 0. never take over a device that already has Client Connector (a work laptop's corporate one, say)
MANAGED="/Library/Managed Preferences/com.zscaler.installparams.plist"
mine() { [ "$(plutil -extract installation-parameters.cloudName raw "$MANAGED" 2>/dev/null)" = "$CLOUD" ] &&
         [ "$(plutil -extract installation-parameters.userDomain raw "$MANAGED" 2>/dev/null)" = "$DOMAIN" ]; }
if [ -z "$REPLACE" ]; then
  if [ -f "$MANAGED" ] && ! mine; then
    fail "This Mac already has Zscaler settings from another organization (an MDM profile: your company's, most
  likely). Installing here would fight them or take over the corporate Client Connector, so nothing was changed.
  Use a spare Mac or a macOS virtual machine for the pilot device."
  fi
  if [ -d "/Applications/Zscaler/Zscaler.app" ] && ! mine; then
    fail "Client Connector is already installed on this Mac (your company's, perhaps). This setup would reinstall it
  for the POV's tenant and sign it out of its current one, so nothing was changed. Use a spare Mac or a macOS
  virtual machine, or run again with --replace if this Mac is meant only for the POV."
  fi
fi
# 1. the installer
if [ -z "$PKG" ]; then
  curl -fsSL "https://github.com/$REPO/releases/latest/download/zcc_installers.json" -o "$TMP/pins.json" \
    || fail "Couldn't reach GitHub. Ask IT to allow github.com downloads, or give --pkg FILE."
  pin() { plutil -extract "macos.$1" raw -o - "$TMP/pins.json" 2>/dev/null || true; }
  FILE="$(pin file)"; SHA="$(pin sha256)"
  if [ -z "${FILE:-}" ]; then
    fail "The kit doesn't have a macOS installer yet. Download it from your Zscaler console (Infrastructure >
  Common Resources > Deployment > Platform Releases > macOS, or search the menu for Platform Releases), then run
  this again with --pkg ~/Downloads/<the file>"
  fi
  say "Downloading Client Connector ($FILE)..."
  curl -fsSL "https://github.com/$REPO/releases/download/zcc-installer/$FILE" -o "$TMP/$FILE" \
    || fail "Couldn't download the kit's macOS installer ($FILE). Download the installer from your Zscaler console
  (Platform Releases > macOS), then run this again with --pkg ~/Downloads/<the file>"
  GOT="$(shasum -a 256 "$TMP/$FILE" | cut -d' ' -f1)"
  [ "$GOT" = "$SHA" ] || fail "The installer doesn't match the kit's pinned SHA-256, so it wasn't installed."
  say "Matches the kit's pinned SHA-256"
  PKG="$TMP/$FILE"
fi
[ -e "$PKG" ] || fail "No installer at $PKG."
case "$PKG" in
  *.zip) mkdir -p "$TMP/app"; unzip -q "$PKG" -d "$TMP/app" || fail "Couldn't unzip $PKG."
         APP="$(find "$TMP/app" -maxdepth 2 -name '*.app' -type d | head -1)"
         [ -n "$APP" ] || fail "There's no installer app in $PKG."
         # a zip made without Unix permissions (a browser or Windows zipped it) loses the execute bit; the code
         # signature doesn't cover permissions, so restoring it leaves the signature intact
         chmod -R u+rwX "$APP"; chmod +x "$APP"/Contents/MacOS/* "$APP"/Contents/Resources/installbuilder 2>/dev/null || true ;;
  *.app|*.app/) APP="${PKG%/}" ;;
  *.pkg) ;;
  *) fail "Give the installer from Platform Releases > macOS: the .pkg, or the installer .app (zipped is fine)." ;;
esac
if [ -n "$APP" ]; then
  codesign --verify --deep --strict "$APP" 2>/dev/null || fail "The installer's signature doesn't check out, so it wasn't installed."
  codesign -dv "$APP" 2>&1 | grep -q "TeamIdentifier=PCBCQZJ7S7" \
    || fail "The installer isn't signed by Zscaler (Developer ID team PCBCQZJ7S7), so it wasn't installed."
  say "Signed by Zscaler (Developer ID, team PCBCQZJ7S7)"
else
  SIG="$(pkgutil --check-signature "$PKG" 2>&1 || true)"
  echo "$SIG" | grep -q "Developer ID Installer: Zscaler" || fail "The installer isn't signed by Zscaler, so it wasn't installed."
  spctl -a -t install "$PKG" >/dev/null 2>&1 || fail "macOS doesn't accept the installer's signature, so it wasn't installed."
  say "Signed by Zscaler, and accepted by macOS"
fi

# 2. the settings profile (what an MDM would push: com.zscaler.installparams); the installer app takes them directly
if [ -z "$APP" ]; then
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
if ! mine; then
  open "$PROFILE" </dev/null || true
  say ""
  say "Approve the settings profile: System Settings > General > Device Management (or Privacy & Security >"
  say "Profiles) > 'Zscaler POV: Client Connector settings' > Install. Waiting up to 5 minutes..."
  for _ in $(seq 1 60); do [ -f "$MANAGED" ] && break; sleep 5; done
  [ -f "$MANAGED" ] || fail "The settings profile isn't installed yet. Approve it (it's in your Downloads folder too), then run this again."
fi
say "Settings profile: cloud $CLOUD, domain $DOMAIN${ZUSER:+, user $ZUSER}"
fi

# 3. install Client Connector, then the kit and the POV's tests
say "Installing Client Connector (your Mac password, once)..."
if [ -n "$APP" ]; then
  sudo sh "$APP/Contents/MacOS/installbuilder.sh" --mode unattended --unattendedmodeui none \
    --cloudName "$CLOUD" --userDomain "$DOMAIN" </dev/null >/dev/null || fail "The installer failed."
else
  sudo installer -pkg "$PKG" -target / </dev/null >/dev/null || fail "The installer failed."
fi
say "Client Connector installed. Sign in as ${ZUSER:-a pilot user}${ZUSER:+@$DOMAIN} when it opens."
open -a "Zscaler" 2>/dev/null || true

say "Installing the POV probe (tests and traffic only: no keys, nothing in the tenant)..."
PHOME="${ZPOV_PROBE_HOME:-$HOME/.zscaler-pov-probe}"
mkdir -p "$PHOME"
PACKF=""
if [ -n "$PACK_B64" ]; then
  PACKF="$PHOME/pack-download-$POV.json"
  printf '%s' "$PACK_B64" | base64 -D > "$PACKF"
fi
curl -fsSL "https://github.com/$REPO/releases/latest/download/install-probe.sh" | bash -s -- ${PACKF:+"$PACKF"} \
  || fail "The POV probe didn't install; Client Connector is installed. Run the probe's one-line installer by hand."
PROBE="$PHOME/app/pov-probe"
if [ -n "$PACKF" ]; then
  OUT="$HOME/Desktop/pov-probe-$POV-${ZUSER:-device}.json"
  say "Once you're signed in, the POV's tests run (waiting up to $WAIT minutes for Zscaler)..."
  "$PROBE" test --wait "$WAIT" --out "$OUT" </dev/null || true
  say "Results: $OUT. Send them to the SE."
else
  say "Next: once signed in, install the probe pack the SE sends and run the POV's tests:"
  say "  $PROBE pack install <the pack file>"
  say "  $PROBE test --wait $WAIT"
fi
echo
if [ -n "$APP" ]; then say "Done. After the POV: uninstall Client Connector (Zscaler > Uninstall, or the SE's teardown notes)."
else say "Done. After the POV: remove the settings profile (System Settings > Device Management)."; fi
