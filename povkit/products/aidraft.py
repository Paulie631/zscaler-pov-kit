"""Products that prove their criteria by what a person shows: AI Asset Management / AI-SPM, Data Security Posture
Management (DSPM) and AI Red Teaming. DRAFT criteria.

AI-SPM and DSPM were announced in 2026 (press release 27 Jan 2026; "AI security at a glance"); neither, nor AI Red
Teaming, has a module in zscaler-sdk-python 1.11.3, so the kit neither reads nor writes them: each criterion is
attested (a note and a screenshot, `pov-kit attest`). The kit does organize what they need:

- AI-SPM and DSPM scan the customer's cloud accounts. The customer's cloud admin connects a TEST account with
  Zscaler's own onboarding template (it creates a role Zscaler assumes), then deploys the POV seed stack
  (seed_aws.py: synthetic sensitive data, a training-data bucket, an over-permissioned AI agent and, optionally, an
  unauthenticated MCP server) so the scans have something real to find. Both are steps for people, agreed at kickoff.
- AI-SPM's inventory of shadow AI comes from the traffic generator's GenAI traffic (ZIA).

Replace the draft criteria with Zscaler's internal POV plans when they're shared, and with API proofs when the SDK has
them.
"""
from __future__ import annotations

from ..core.changelist import item
from .readonly import ReadOnlyProduct

CLOUD = ("aispm", "dspm")   # the products that scan cloud accounts: the first one in the POV carries the shared steps
CONNECT_WHY = ("The customer's cloud admin connects a TEST AWS account (or Azure subscription, or GCP project) in the "
               "Zscaler console's cloud account onboarding for AI-SPM / DSPM. Zscaler's own template creates a role "
               "Zscaler assumes: it reads the account's configuration and, for classification, the data in it. Use "
               "a test account, and have their security team review the role first (docs/SEED-STACK.md).")
SEED_WHY = ("After the account is connected: Get ready to test › Seed stack (or `pov-kit seed template`). CloudFormation "
            "with synthetic sensitive data, a training-data bucket, an over-permissioned AI agent and, optionally, an "
            "unauthenticated MCP server, so the scans have something to find. Scans take hours to a day.")


class Draft(ReadOnlyProduct):
    """No API: nothing to read, nothing to make. Its steps for people, and its criteria, attested."""
    def role_scopes(self, pov=None):
        return {"discovery": [], "apply": []}

    def discover(self, t, pov):
        return {"readable": True, "draft": True}, []

    def plan(self, pov, snap):
        out = super().plan(pov, snap)[0]
        mine = [c["id"] for c in self.criteria()]
        if self.name in CLOUD and next((n for n in CLOUD if n in pov.products), None) == self.name:
            cloud = [c["id"] for n in CLOUD if n in pov.products for c in _product(n).criteria()
                     if c["id"] not in ("AS-INV-01", "AS-GOV-01")]
            out[:0] = [item(self.name, "customer_action", "cloud.ca.connect", "A test cloud account is connected to "
                            "Zscaler for AI-SPM / DSPM", action="customer_action", criteria=cloud, why=CONNECT_WHY),
                       item(self.name, "customer_action", "cloud.ca.seed", "The POV seed stack runs in that account",
                            action="customer_action", criteria=cloud, why=SEED_WHY)]
        return [i for i in out if set(i["criteria"]) & set(mine) or i["key"].startswith("cloud.")], []



def _product(n):
    from . import get
    return get(n)


class AISPM(Draft):
    name, title, phase = "aispm", "AI Asset Management / AI-SPM (draft)", "v3"


class DSPM(Draft):
    name, title, phase = "dspm", "Data Security Posture Management (DSPM, draft)", "v3"


class AIRedTeam(Draft):
    name, title, phase = "airt", "AI Red Teaming (draft)", "v3"
    STEPS = [("target", "The customer names an AI app to scan, and who approves the scan", ["RT-SCN-01"],
              "Their chatbot's test or staging endpoint, or a test AI app; red teaming sends attacks to it, so their "
              "app owner agrees first.")]
