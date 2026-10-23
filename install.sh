#!/bin/bash
# Zscaler POV Kit: one-line installer for macOS (and Linux).
#
#   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.sh | bash
#
# Why a one-liner: macOS Gatekeeper blocks scripts a browser downloaded ("Apple could not verify..."), because the
# kit isn't signed with an Apple Developer ID. Files fetched by curl aren't marked as downloaded, so nothing prompts.
# It does what the double-click installer does: gets the latest release, checks its SHA-256 against the release's
# latest.json, installs uv if needed, then runs the kit's own installer and opens the console.
# Nothing changes in any Zscaler tenant. Read it first if you like: it's in the repository as install.sh.
set -euo pipefail

REPO="${ZPOV_KIT_REPO:-Paulie631/zscaler-pov-kit}"
BASE="https://github.com/$REPO/releases/latest/download"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say() { printf '  %s\n' "$*"; }
fail() { printf '\n  %s\n\n' "$*" >&2; exit 1; }
field() { sed -n "s/^ *\"$1\": *\"\\([^\"]*\\)\".*/\\1/p" "$TMP/latest.json" | head -1; }

echo
say "Zscaler POV Kit - installer"
say "==========================="
curl -fsSL "$BASE/latest.json" -o "$TMP/latest.json" \
  || fail "Couldn't reach GitHub. If your laptop's web policy blocks it, ask IT to allow github.com downloads."
VERSION="$(field version)"; ZIP_URL="$(field zip_url)"; SHA="$(field sha256)"
[ -n "$VERSION" ] && [ -n "$ZIP_URL" ] && [ ${#SHA} -eq 64 ] || fail "The release information wasn't in the expected format."
case "$ZIP_URL" in https://github.com/*) ;; *) fail "Unexpected download address: $ZIP_URL" ;; esac

say "Downloading version $VERSION..."
curl -fsSL "$ZIP_URL" -o "$TMP/kit.zip" || fail "The download failed."
if command -v shasum >/dev/null; then GOT="$(shasum -a 256 "$TMP/kit.zip" | cut -d' ' -f1)"
else GOT="$(sha256sum "$TMP/kit.zip" | cut -d' ' -f1)"; fi
[ "$GOT" = "$SHA" ] || fail "The download doesn't match the release's SHA-256, so nothing was installed."
say "Download verified against the release's SHA-256"
unzip -q "$TMP/kit.zip" -d "$TMP"
KIT="$TMP/zscaler-pov-kit"
[ -f "$KIT/pov_kit.py" ] || fail "The release zip didn't contain the kit."

find_uv() {
  UV="$(command -v uv || true)"
  for c in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; do
    [ -z "$UV" ] && [ -x "$c" ] && UV="$c"
  done
  return 0
}
find_uv
if [ -z "$UV" ]; then
  say "Installing uv (the free tool the kit runs on)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null || true
  find_uv
fi
if [ -z "$UV" ] && command -v brew >/dev/null; then brew install uv && find_uv; fi
[ -n "$UV" ] || fail "Couldn't install uv. Ask IT to allow astral.sh and github.com, or see https://docs.astral.sh/uv/getting-started/installation/"

export UV_SYSTEM_CERTS=1
say "Preparing Python 3.12 and the kit's libraries (the first time takes a minute or two)..."
"$UV" run --quiet --python 3.12 --script "$KIT/pov_kit.py" install || fail "Install failed. The message above says why."

echo
say "Opening the console. Keep this window open while you use it; close it (or press Ctrl+C) to stop the console."
say "Next time, open 'Zscaler POV Console' from your Desktop."
rm -rf "$TMP"; trap - EXIT
[ -n "${ZPOV_NO_GUI:-}" ] && exit 0
exec "$HOME/.zscaler-pov-kit/app/pov-kit" gui </dev/null
