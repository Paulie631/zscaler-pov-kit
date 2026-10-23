# /// script
# requires-python = ">=3.10,<3.15"
# dependencies = ["requests>=2.31", "truststore>=0.9"]
# ///
"""Zscaler POV probe: the POV's tests and the ZIA traffic generator, for pilot devices. No API keys, no console,
nothing in any tenant changes. Run it with the launcher (./pov-probe or pov-probe.cmd), which uses uv.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:   # trust the OS certificate store (Zscaler's root CA, which Client Connector installs)
    import truststore
    truststore.inject_into_ssl()
except Exception:   # noqa: BLE001
    pass

from povkit.device import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
