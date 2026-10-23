# /// script
# requires-python = ">=3.10,<3.15"
# dependencies = ["zscaler-sdk-python>=1.11", "requests>=2.31", "keyring>=24", "truststore>=0.9", "cryptography>=42", "pypdf>=4"]
# ///
"""Zscaler POV Kit: set up, prove and hand over a proof of value in a customer's tenant.

Run it with the launcher (./pov-kit or .\\pov-kit.cmd), which uses uv to fetch the dependencies above.
See README.md for the commands and docs/DESIGN.md for the safety model.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from povkit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
