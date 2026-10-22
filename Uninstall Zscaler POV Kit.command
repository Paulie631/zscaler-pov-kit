#!/bin/bash
# Zscaler POV Kit - uninstall (macOS). Keeps your POVs, secrets and every tenant object.
DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/pov-kit" uninstall
read -r -p "  Press Return to close. "
