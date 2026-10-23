#!/bin/bash
# Zscaler POV probe: one-line installer for a pilot device (macOS and Linux).
#
#   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install-probe.sh | bash
#
# The probe is the small part of the POV kit that runs on pilot devices: the POV's tests and the ZIA traffic
# generator. It has no console, no API keys and no tenant access; it only browses and writes a results file for the
# SE. This gets the latest release, checks the probe's SHA-256 against the release's latest.json, installs uv (the
# free tool it runs on) if needed, and puts the probe in ~/.zscaler-pov-probe/app. Optional: a probe pack file to
# install with it:  ... | bash -s -- /path/to/pov-probe-pack.json
set -euo pipefail

REPO="${ZPOV_KIT_REPO:-Paulie631/zscaler-pov-kit}"
BASE="https://github.com/$REPO/releases/latest/download"
DEST="${ZPOV_PROBE_HOME:-$HOME/.zscaler-pov-probe}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say() { printf '  %s\n' "$*"; }
fail() { printf '\n  %s\n\n' "$*" >&2; exit 1; }
field() { sed -n "s/^ *\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$TMP/latest.json" | head -1; }

say "Zscaler POV probe - installer"
curl -fsSL "$BASE/latest.json" -o "$TMP/latest.json" \
  || fail "Couldn't reach GitHub. Ask IT to allow github.com downloads."
VERSION="$(field version)"; ZIP_URL="$(field probe_zip_url)"; SHA="$(field probe_sha256)"
[ -n "$VERSION" ] && [ -n "$ZIP_URL" ] && [ ${#SHA} -eq 64 ] || fail "The release information wasn't in the expected format."
case "$ZIP_URL" in https://github.com/*) ;; *) fail "Unexpected download address: $ZIP_URL" ;; esac
say "Downloading the probe $VERSION..."
curl -fsSL "$ZIP_URL" -o "$TMP/probe.zip" || fail "The download failed."
if command -v shasum >/dev/null; then GOT="$(shasum -a 256 "$TMP/probe.zip" | cut -d' ' -f1)"
else GOT="$(sha256sum "$TMP/probe.zip" | cut -d' ' -f1)"; fi
[ "$GOT" = "$SHA" ] || fail "The download doesn't match the release's SHA-256, so nothing was installed."
say "Download verified against the release's SHA-256"
unzip -q "$TMP/probe.zip" -d "$TMP"
[ -f "$TMP/zscaler-pov-probe/pov_probe.py" ] || fail "The release zip didn't contain the probe."

find_uv() {
  UV="$(command -v uv || true)"
  for c in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; do
    [ -z "$UV" ] && [ -x "$c" ] && UV="$c"
  done
  return 0
}
find_uv
if [ -z "$UV" ]; then
  say "Installing uv (the free tool the probe runs on)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null || true
  find_uv
fi
[ -n "$UV" ] || fail "Couldn't install uv. Ask IT to allow astral.sh and github.com."

mkdir -p "$DEST"
rm -rf "$DEST/app.old"; [ -d "$DEST/app" ] && mv "$DEST/app" "$DEST/app.old"
mv "$TMP/zscaler-pov-probe" "$DEST/app"
chmod +x "$DEST/app/pov-probe"
mkdir -p "$HOME/.local/bin" && ln -sf "$DEST/app/pov-probe" "$HOME/.local/bin/pov-probe" 2>/dev/null || true
export UV_SYSTEM_CERTS=1
say "Preparing Python and two small libraries (the first time takes a minute)..."
"$DEST/app/pov-probe" version >/dev/null || fail "The probe didn't start. The message above says why."
if [ -n "${1:-}" ]; then "$DEST/app/pov-probe" pack install "$1"; fi
say "Installed: $DEST/app/pov-probe  (test | pack | traffic | cleanup)"
