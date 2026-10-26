"""Why a proof failed, in plain words, and what to do about it.

A product's API proof (or the AI Guard test runner) reports what it found in one line: "'ZPOV: Block gambling' is
disabled; ZIA puts www.bet365.com in SPORTS, not in the rule's categories". explain() splits that into its problems
and, for each, says why it happens and how to fix it. Some fixes the console can do from the same place ('action'):
fixdrift (Status > Fix drift, only the POV's own objects), finish (Setup > Get ready to test), policy (AI Guard > Policy),
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
      "If the customer is happy that the category is right, show it live and mark the criterion Demonstrated instead."], None),
    (r"URL lookup didn't run",
     "The kit couldn't ask ZIA how it classifies the test sites (the API client may lack URL lookup access).",
     ["Give the API client view access to ZIA's URL categories (role spec), then Check again."], None),
    # ---- ZPA
    (r"(?P<k>\d+) of (?P<m>\d+) POV connectors connected",
     "ZPA reaches the POV's app only through its App Connectors, and fewer than two are connected.",
     ["Deploy them: Setup > Get ready to test > Deploy the POV's App Connectors (AWS, Azure or CloudShare).",
      "Connectors take 10 to 15 minutes to enroll and need outbound TCP 443.",
      "Already deployed? On the connector machine, check the zpa-connector service is running."], "finish"),
    (r"broad customer rules: (?!none)",
     "A customer access rule already lets everyone reach the app's domains, so the POV can't show that only the pilot "
     "group gets in.",
     ["Use the kit's test app (or a domain only the POV uses) in Setup > Pilot users.",
      "Or the customer narrows their rule; otherwise show what the POV does live and mark it Demonstrated."], "pilot"),
    # ---- devices and users
    (r"(?P<k>\d+) of (?P<m>\d+) pilot devices registered|name the pilot users",
     "The kit can't find a pilot device registered in Client Connector for the pilot users yet.",
     ["Set up a pilot device: Setup > Get ready to test > Set up a pilot device, and sign in as a pilot user.",
      "Signed in but not counted? Check the user signs in with the address the kit knows (Pilot users)."], "finish"),
    (r"(?P<k>\d+) of 2 POV profiles",
     "The POV's Client Connector profiles aren't in the portal yet (the API sometimes refuses to create them).",
     ["Build them by hand with the exact names: Setup > Get ready to test > Build the POV's Client Connector profiles.",
      "Then Status > Fix drift adopts them."], "finish"),
    (r"(?P<k>\d+) of (?P<m>\d+) pilot devices report ZDX scores",
     "ZDX scores come from pilot devices running Client Connector with ZDX. Some (or all) haven't reported yet.",
     ["Check the pilot devices are set up and signed in (Get ready to test).",
      "ZDX must be on in the app profile they use; scores appear within an hour of first use.",
      "A device that's off or asleep stops reporting."], "finish"),
    (r"SaaS scan configuration|findings appear after the first scan",
     "No scan has run on the connected SaaS tenant yet.",
     ["Connect a SaaS tenant if there isn't one (Get ready to test or the steps for people).",
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


def explain_ai_guard(rows, enabled=None):
    """AI Guard test results that didn't go as expected, one explanation per test: what fired, and whether the
    missed detector is even on in the POV's policy (if it is, AI Guard judged this example differently)."""
    out = []
    for r in rows or []:
        if r.get("pass") is not False:
            continue
        want, got = list(r.get("expect") or []), list(r.get("detected") or [])
        missed = [d for d in want if d not in got]
        found = (f"{r.get('test')}: expected {', '.join(missed) or 'nothing harmful'}; AI Guard found "
                 f"{', '.join(got) or 'nothing'} ({r.get('action') or 'no action'})")
        if not want:
            out.append({"problem": found, "why": "A test of normal use was flagged: the POV's policy is stricter than "
                        "this prompt needs (or the detector over-matched).", "fix": [
                        "AI Guard > Test runner: open the row to see which detector fired and why.",
                        "If it's a fair catch, tell the customer; if not, loosen that detector in AI Guard > Policy "
                        "(Custom) and run the test again."], "action": "runner"})
            continue
        off = [d for d in missed if enabled is not None and d not in enabled]
        if off:
            out.append({"problem": found, "why": f"The {', '.join(off)} detector isn't on in the POV's AI Guard "
                        "policy, so it can't fire.", "fix": [
                        "AI Guard > Policy: Block attacks + data leakage, or Custom with that detector on.",
                        "Run the criterion's tests again (AI Guard > Test runner)."], "action": "policy"})
        else:
            out.append({"problem": found, "why": f"The {', '.join(missed)} detector is on in the POV's policy, but AI "
                        "Guard didn't judge this example as that. Its detectors weigh each prompt, so a borderline "
                        "test can fall either side.", "fix": [
                        "AI Guard > Test runner: open the row to see AI Guard's full verdict, and run it again.",
                        "If it keeps passing through, replace it with a clearer example (Draft more tests with "
                        "Claude), or show it live and mark it Demonstrated.",
                        "Worth a note for the AI Guard team if a clear-cut example is missed."], "action": "runner"})
    return out


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
                            "Status > Check now shows drift on the POV's objects; Setup > Get ready to test lists what's "
                            "left for people."], "action": None})
    return out


# ---------------------------------------------------------------- device (probe) tests that didn't go as expected
PROBE = {
    ("IS-FW-01", "IS-DNS-01"): (
        "Firewall and DNS rules only see traffic that Client Connector sends to Zscaler with Z-Tunnel 2.0. This device "
        "sent the port or DNS test straight out: it's on Z-Tunnel 1.0 (web only), or not on the POV's app profile.",
        ["On the device: Client Connector > More shows the app profile: it should be the POV's ('pilot devices' on "
         "Windows, 'pilot Macs' on macOS) and Tunnel version Z-Tunnel 2.0.",
         "A Mac pilot and a POV made before kit 0.9.55: make the change list again (it now adds the macOS profile), "
         "sign it off, and Apply.",
         "Then in Client Connector: More > Update Policy, and run the tests again."], "finish"),
    ("IS-CBI-01",): (
        "Isolation needs Cloud Browser Isolation in the tenant, and only applies to browsers: the test page wasn't "
        "isolated for this device.",
        ["Open the test site in a browser on the device, signed in as the pilot user: it should open in isolation.",
         "No isolation there either: check the tenant has Cloud Browser Isolation and the POV rule's isolation "
         "profile (Policy > URL & Cloud App Control).",
         "If it works in a browser, show it live and mark the criterion Demonstrated."], "runner_none"),
    ("IS-DLP-01", "AI-GEN-02"): (
        "The test post with fake card numbers went through: DLP didn't act on it for this device.",
        ["Check the POV's DLP rule is enabled for the pilot group, with the engine '5 or more Credit Card Numbers'.",
         "DLP only sees decrypted traffic: the HTTPS inspection test (IS-SSL-01) should pass on this device.",
         "Rules take a few minutes after activation: run the tests again. Still through? Show a DLP block live "
         "(paste card numbers into a web form) and mark it Demonstrated."], "fixdrift"),
    ("IS-URL-02",): (
        "No caution page: the site's category isn't in the POV's caution rule, or this device already clicked "
        "through the caution page (ZIA remembers that for a while).",
        ["Check the site's category (the console's URL Lookup) is in the caution rule.",
         "Run the tests again later, or open the site in a browser on the device to see the caution page."], None),
    ("AI-GEN-01",): (
        "The GenAI app the test expects to be blocked was allowed: it isn't in the POV's block rule. Apply leaves out "
        "apps the tenant can't put in a Cloud App Control rule.",
        ["Check the POV's 'Block risky GenAI' rule (Policy > URL & Cloud App Control > AI & ML) for the app.",
         "Review the device tests (Set up a pilot device > More) and test an app the rule lists."], None),
}


def explain_probe(results):
    """Device tests that didn't go as expected, each with why and what to do."""
    out = []
    for r in results or []:
        if r.get("pass"):
            continue
        cid, got, want = r.get("criterion"), str(r.get("outcome")), r.get("expect")
        sp = r.get("spec") or {}
        what = f"{sp.get('url') or sp.get('host') or sp.get('name') or sp.get('type')}: expected {want}, got {got}"
        rule = next((v for k, v in PROBE.items() if cid in k), None)
        if got.startswith("error:"):
            out.append({"problem": what, "why": "The device couldn't complete the test (a network or TLS error), so "
                        "there's no result to judge.", "fix": [
                        "Check the device is online and signed in to Client Connector as the pilot user.",
                        "Run the tests again; if it repeats, open the site in a browser on the device."], "action": None})
        elif rule:
            why, fix, action = rule
            out.append({"problem": what, "why": why, "fix": fix, "action": None if action == "runner_none" else action})
        else:
            out.append({"problem": what, "why": "The device saw something other than what this criterion expects.",
                        "fix": ["Status > Check now: is the POV's rule for this criterion in place and enabled?",
                                "Run the tests again after a few minutes (changes take a moment after activation)."],
                        "action": "fixdrift"})
    return out
