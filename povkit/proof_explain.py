"""Why a proof failed, in plain words, and what to do about it.

A product's API proof (or the AI Guard test runner) reports what it found in one line: "'ZPOV: Block gambling' is
disabled; ZIA puts www.bet365.com in SPORTS, not in the rule's categories". explain() splits that into its problems
and, for each, says why it happens and how to fix it. Some fixes the console can do from the same place ('action'):
fixdrift (Status > Fix drift, only the POV's own objects), finish (Setup > Finish setup), policy (AI Guard > Policy),
runner (AI Guard > Test runner), pilot (Setup > Pilot users), changes (Setup > Change list).
"""
from __future__ import annotations

import re

RULES = [
    # ---- configuration that drifted (Fix drift puts it back)
    (r"'(?P<n>[^']+)' isn't in (ZIA|ZPA|AI Guard)|isn't in (ZIA|ZPA)|policy is gone|access rule isn't in ZPA",
     "A POV object behind this criterion isn't in the tenant: Apply didn't finish, or someone deleted it in the console.",
     ["Status > Fix drift recreates the POV's missing objects (it never touches the customer's).",
      "If Apply stopped part-way, open Setup > Apply and run it again: it carries on where it stopped."], "fixdrift"),
    (r"is disabled",
     "Someone disabled a POV rule in the console, so it doesn't act on the pilot group's traffic.",
     ["Status > Fix drift enables it again.", "Ask the customer's admin not to change the POV's rules during the POV "
      "(they're named with the POV's prefix)."], "fixdrift"),
    (r"no longer applies only to the pilot group|not scoped as approved",
     "Someone changed who a POV rule applies to. It must apply to the pilot group only, as the customer approved.",
     ["Status > Fix drift puts the scope back.", "If the customer wants more people in the POV, add them to the pilot "
      "group instead (Setup > Pilot users)."], "fixdrift"),
    # ---- ZIA's categorization of a test site
    (r"ZIA puts (?P<u>\S+) in (?P<c>.+?), not in the rule's categories",
     "ZIA classifies this test site differently in this tenant (a custom category, or Zscaler re-categorized it), so "
     "the rule's category doesn't cover it and the device test can't show the block.",
     ["Check the site in the console: search the menu for URL Lookup.",
      "Ask Claude (Use cases) for a use case that blocks this exact site for the pilot group, or pick a test site in "
      "the rule's category.",
      "If the customer is happy that the category is right, record an attestation on this criterion instead."], None),
    (r"URL lookup didn't run",
     "The kit couldn't ask ZIA how it classifies the test sites (the API client may lack URL lookup access).",
     ["Give the API client view access to ZIA's URL categories (role spec), then Check again."], None),
    # ---- ZPA
    (r"(?P<k>\d+) of (?P<m>\d+) POV connectors connected",
     "ZPA reaches the POV's app only through its App Connectors, and fewer than two are connected.",
     ["Deploy them: Setup > Finish setup > Deploy the POV's App Connectors (AWS, Azure or CloudShare).",
      "Connectors take 10 to 15 minutes to enroll and need outbound TCP 443.",
      "Already deployed? On the connector machine, check the zpa-connector service is running."], "finish"),
    (r"broad customer rules: (?!none)",
     "A customer access rule already lets everyone reach the app's domains, so the POV can't show that only the pilot "
     "group gets in.",
     ["Use the kit's test app (or a domain only the POV uses) in Setup > Pilot users.",
      "Or the customer narrows their rule; otherwise attest what the POV shows instead."], "pilot"),
    # ---- devices and users
    (r"(?P<k>\d+) of (?P<m>\d+) pilot devices registered|name the pilot users",
     "The kit can't find a pilot device registered in Client Connector for the pilot users yet.",
     ["Set up a pilot device: Setup > Finish setup > Set up a pilot device, and sign in as a pilot user.",
      "Signed in but not counted? Check the user signs in with the address the kit knows (Pilot users)."], "finish"),
    (r"(?P<k>\d+) of 2 POV profiles",
     "The POV's Client Connector profiles aren't in the portal yet (the API sometimes refuses to create them).",
     ["Build them by hand with the exact names: Setup > Finish setup > Build the POV's Client Connector profiles.",
      "Then Status > Fix drift adopts them."], "finish"),
    (r"(?P<k>\d+) of (?P<m>\d+) pilot devices report ZDX scores",
     "ZDX scores come from pilot devices running Client Connector with ZDX. Some (or all) haven't reported yet.",
     ["Check the pilot devices are set up and signed in (Finish setup).",
      "ZDX must be on in the app profile they use; scores appear within an hour of first use.",
      "A device that's off or asleep stops reporting."], "finish"),
    (r"SaaS scan configuration|findings appear after the first scan",
     "No scan has run on the connected SaaS tenant yet.",
     ["Connect a SaaS tenant if there isn't one (Finish setup or the steps for people).",
      "The first scan can take hours on a large tenant: check again later."], "finish"),
    # ---- AI Guard
    (r"handled by policy '(?P<p>[^']+)', not the POV's",
     "A customer AI Guard rule runs before the POV's and catches the POV's app, so the POV's policy never sees the "
     "test prompts.",
     ["In AI Guard (search the console for Policy Rules), move the POV's rule above the customer's broad rule, or the "
      "customer excludes the POV app from theirs.", "Then run the tests again."], "runner"),
    (r"not as expected: (?P<t>.+)",
     "Some test prompts didn't trigger the detectors they should. Usually that detector isn't on in the POV's "
     "policy, or the test needs a stricter setting.",
     ["AI Guard > Test runner: click the failing rows to see what fired and what was expected.",
      "AI Guard > Policy: Block attacks + data leakage (or Custom) turns on the detectors these tests need.",
      "Run the criterion's tests again."], "runner"),
    (r"no POV detection key",
     "The POV's AI Guard key isn't in this computer's keychain (its secret is shown only once, when it's created).",
     ["Delete the key 'POV detection key' in AI Guard, then Status > Fix drift makes a new one and keeps it."],
     "fixdrift"),
    (r"(\d+) of (\d+) tests run",
     "Not every test for this criterion has run (the run was stopped, or only some were picked).",
     ["AI Guard > Test runner: run This POV's criteria (or this criterion's group) to the end."], "runner"),
    # ---- the kit itself
    (r"no change list yet",
     "There's no change list for this POV yet, so there's nothing of the POV's to check.",
     ["Setup > Change list, have the customer approve it, then Apply."], "changes"),
    (r"couldn't run|unreadable|HTTP \d{3}",
     "The check couldn't read the tenant (a permission the API client doesn't have, or the API was unavailable).",
     ["Check the API client has the access the role spec lists for this product.",
      "Try again: Check again on Success criteria."], None),
]


def explain(detail, status="fail"):
    """-> [{problem, why, fix: [...], action}] for a failing or incomplete proof's detail."""
    if status not in ("fail", "incomplete") or not detail:
        return []
    out, seen = [], set()
    for part in [p.strip() for p in re.split(r";\s+|\.\s+(?=[A-Z])", str(detail)) if p.strip()]:
        for pat, why, fix, action in RULES:
            if re.search(pat, part, re.I):
                if why not in seen:
                    seen.add(why)
                    out.append({"problem": part, "why": why, "fix": fix, "action": action})
                break
    if not out:
        out.append({"problem": str(detail), "why": "The check found the setup isn't complete yet." if status ==
                    "incomplete" else "The check found the tenant doesn't match what this criterion needs.",
                    "fix": ["Open the criterion's evidence below for what was found.",
                            "Status > Check now shows drift on the POV's objects; Setup > Finish setup lists what's "
                            "left for people."], "action": None})
    return out
