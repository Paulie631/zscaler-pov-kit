#!/bin/bash
# Zscaler POV Kit - double-click installer for macOS.
cd "$(dirname "$0")" || exit 1
if [ ! -f pov_kit.py ]; then
  echo; echo "  The rest of the kit isn't next to this installer. Double-click the zip to unzip it,"
  echo "  then run 'Install Zscaler POV Kit.command' from the unzipped zscaler-pov-kit folder."; echo
  read -r -p "  Press Return to close. "; exit 1
fi
clear
cat <<'TXT'

  Zscaler POV Kit - installer
  ===========================
  This will:
    - install uv (the free tool the kit runs on) if it isn't installed yet
    - copy the kit to ~/.zscaler-pov-kit/app
    - add a "Zscaler POV Console" app to your Desktop
    - let you run "pov-kit" from any terminal
  Nothing changes in any Zscaler tenant: the kit only writes what a customer approves.

TXT
read -r -p "  Press Return to install, or close this window to cancel. "

find_uv() {
  UV="$(command -v uv || true)"
  for c in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; do
    [ -z "$UV" ] && [ -x "$c" ] && UV="$c"
  done
}
fail() { echo; echo "  $1"; echo; read -r -p "  Press Return to close. "; exit 1; }

find_uv
if [ -z "$UV" ]; then
  echo; echo "  Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  find_uv
fi
if [ -z "$UV" ] && command -v brew >/dev/null; then
  echo "  The uv installer didn't work here. Trying Homebrew..."
  brew install uv
  find_uv
fi
[ -z "$UV" ] && fail "Couldn't install uv. Your laptop's security policy may be blocking the download. Ask IT to allow astral.sh and github.com, or see https://docs.astral.sh/uv/getting-started/installation/ - then double-click this installer again."

export UV_SYSTEM_CERTS=1 UV_NATIVE_TLS=1
echo; echo "  Preparing Python 3.12 and the kit's libraries (the first time takes a minute or two)..."
"$UV" run --quiet --python 3.12 --script ./pov_kit.py install || fail "Install failed. The message above says why."
echo; echo "  Opening the console. Keep this window open while you use it; close it to stop the console."
exec "$HOME/.zscaler-pov-kit/app/pov-kit" gui
