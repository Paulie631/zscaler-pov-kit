"""AI Endpoint Security (Endpoint AI): DRAFT criteria and pilot-device tests, no tenant objects.

Zscaler describes it (blog, 8 Oct 2026) as AI asset inventory, runtime monitoring of AI agents, and inline policy on
the device, through the Zscaler agent. There's no API for it in the Zscaler SDK (1.11.3) yet, so the kit neither reads
nor writes it: the probe plants harmless, clearly named test files on a pilot device (probe.py: ai_*), and a person
records what the admin console shows. Replace the draft criteria with Zscaler's internal POV plan when it's shared.
"""
from __future__ import annotations

from .base import NotReady


class EAI(NotReady):
    name, title, phase = "eai", "AI Endpoint Security (draft)", "v3"
    later_note = ("no API for it yet: proved on pilot devices with the probe's harmless test files, and by what the "
                  "admin console shows (attestations)")

    def role_scopes(self, pov=None):
        return {"discovery": [], "apply": []}
