"""AI security products with no API in the Zscaler SDK yet: DRAFT criteria, proved by what a person shows.

AI Asset Management / AI-SPM (discovery of shadow AI, models, MCP servers and agents; posture and governance) and AI
Red Teaming (automated attack scans of the customer's own AI apps) were announced in 2026 (press release 27 Jan 2026;
"AI security at a glance"). Neither has a module in zscaler-sdk-python 1.11.3, so the kit neither reads nor writes
them: each criterion is attested (a note and a screenshot, `pov-kit attest`). AI-SPM's inventory gets GenAI traffic
from the traffic generator so there is something to find. Replace the draft criteria with Zscaler's internal POV plan
when it's shared, and with API proofs when the SDK has them.
"""
from __future__ import annotations

from .base import NotReady


class AISPM(NotReady):
    name, title, phase = "aispm", "AI Asset Management / AI-SPM (draft)", "v3"
    later_note = "no API for it yet: proved by what the admin console shows (attestations)"

    def role_scopes(self, pov=None):
        return {"discovery": [], "apply": []}


class AIRedTeam(NotReady):
    name, title, phase = "airt", "AI Red Teaming (draft)", "v3"
    later_note = "no API for it yet: proved by the scan's report (attestations)"

    def role_scopes(self, pov=None):
        return {"discovery": [], "apply": []}
