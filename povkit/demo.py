"""What a device test is and how to show it: shared by the console's Device tests tab and the pilot device's own
test runner (`pov-probe ui`). Nothing here reads a POV or a tenant, so the probe package carries it.
"""
from __future__ import annotations

import hashlib
import json


def _h(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:10]


def spec_id(cid, sp):
    """A test's ID (the same as the console's): its criterion and its spec."""
    return _h([cid, {k: v for k, v in sp.items() if k not in ("id", "by", "at")}])


def describe_spec(sp):
    """A probe test in plain words."""
    t, e = sp.get("type"), sp.get("expect")
    word = {"block": "blocked", "allow": "allowed", "caution": "a caution page", "isolate": "isolated",
            "open": "open", "resolved": "resolves", "Zscaler": "inspected by Zscaler",
            "not-Zscaler": "not inspected"}.get(e, e or "")
    return {"http": f"Open {sp.get('url')} → expect {word}",
            "eicar": "Download the EICAR antivirus test file → expect blocked",
            "dlp_post": "Post 6 fake card numbers → expect blocked",
            "tls_issuer": f"HTTPS to {sp.get('host')} → expect {word}",
            "tcp": f"Connect to {sp.get('host')} on TCP {sp.get('port')} → expect {word}",
            "dns": f"Look up {sp.get('name')} (DNS) → expect {word}",
            "zcc_running": "Client Connector is running",
            "via_zscaler": "Traffic goes through Zscaler (ip.zscaler.com)",
            "ai_artifacts": "Plant AI test items for the AI asset inventory",
            "ai_risky_skill": "Plant an inert risky AI skill → expect removed or locked",
            "ai_local_prompt": "Send a prompt to a local AI app"}.get(t, t)


# where to see a test's events (the console's own menus; no deep links, which change by tenant and release)
LOGS = "Zscaler console: Analytics > Web Insights > Logs, filtered to the pilot user and the last 15 minutes"

STORIES = [
    {"id": "follows-user", "title": "Policy follows the user", "criteria": ["IS-TEN-01", "IS-ZCC-01"],
     "for": "Everyone",
     "say": "This laptop is a pilot user’s. Only the pilot group gets the POV’s rules; nobody else in the company sees a "
            "change.",
     "point": "The POV’s block page on www.example.com, and Client Connector running with Zscaler confirmed.",
     "after": "Same policy on any network: office, home, hotel."},
    {"id": "gambling", "title": "A user tries a gambling site", "criteria": ["IS-URL-01"], "for": "Security",
     "say": "Watch what happens when someone opens a site in a category the company doesn’t allow.",
     "point": "The block page: the category, the policy and the user are named.",
     "after": "Find the same event in Web Insights: who, what, when, which rule."},
    {"id": "coach", "title": "Coaching instead of blocking", "criteria": ["IS-URL-02"], "for": "Security, CISO",
     "say": "Not everything should be blocked. Some categories get a reminder and a choice.",
     "point": "The caution page, then Continue.",
     "after": "Users learn the policy; you keep the record of who went ahead."},
    {"id": "inspect", "title": "Malware hidden in HTTPS", "criteria": ["IS-SSL-01", "IS-SSL-02", "IS-THR-01"],
     "for": "Security engineers",
     "say": "Most attacks arrive encrypted. Here is a malware test file over HTTPS.",
     "point": "The certificate issuer on wikipedia.org (Zscaler: inspected) and chase.com (not: banking is bypassed), "
              "then the EICAR download blocked.",
     "after": "Inspection where it protects, bypass where privacy matters."},
    {"id": "phish", "title": "A phishing link", "criteria": ["IS-THR-02"], "for": "Security",
     "say": "A user clicks a phishing link from an email.",
     "point": "The known phishing and malware pages never load.",
     "after": "Threat intelligence updated continuously, applied inline."},
    {"id": "dlp", "title": "Card numbers leave the company", "criteria": ["IS-DLP-01"], "for": "Security, CISO",
     "say": "Someone uploads a list of card numbers to a website.",
     "point": "The DLP block, even though the upload is over HTTPS.",
     "after": "The DLP event names the rule, the user and the data type."},
    {"id": "genai", "title": "Safe use of GenAI", "criteria": ["AI-GEN-01", "AI-GEN-02"], "for": "CISO",
     "say": "Your people use AI. Approved apps stay open; risky ones and leaking data don’t.",
     "point": "ChatGPT opens; poe.com is blocked; card numbers sent to an AI app are blocked.",
     "after": "Pair this with AI Guard for the company’s own AI apps."},
    {"id": "files", "title": "Risky downloads and file sharing", "criteria": ["IS-FTC-01", "IS-CAC-01"],
     "for": "Security",
     "say": "An executable from the web, and an unsanctioned file-sharing app.",
     "point": "The .exe download stopped; the file-sharing app handled by Cloud App Control.",
     "after": "Control by file type and by app, not just by site."},
    {"id": "isolate", "title": "A risky site, opened safely", "criteria": ["IS-CBI-01"], "for": "Security",
     "say": "Some sites are useful but risky. They can run in the cloud instead of on the laptop.",
     "point": "The site opening in browser isolation (in a browser on this computer).",
     "after": "Nothing from the site reaches the device."},
    {"id": "network", "title": "Not just the web", "criteria": ["IS-FW-01", "IS-DNS-01"], "for": "IT, networking",
     "say": "Every port and every DNS lookup goes through the same policy, not only web traffic.",
     "point": "TCP 2222 blocked by the cloud firewall; a DNS lookup for a blocked category refused.",
     "after": "One policy for all traffic, with Z-Tunnel 2.0."},
]


def open_url(sp):
    """A page to open in a browser for the same test, where there is one."""
    if sp.get("type") == "http":
        return sp.get("url")
    if sp.get("type") == "tls_issuer":
        return f"https://{sp.get('host')}/"
    if sp.get("type") == "dlp_post":
        return "https://dlptest.com/http-post/"
    if sp.get("type") == "eicar":
        return "https://secure.eicar.org/eicar.com.txt"
    if sp.get("type") == "via_zscaler":
        return "https://ip.zscaler.com/"
    return None


SAMPLE_CARDS = "\n".join(f"Card number: {c}  Exp: 12/29  CVV: 123" for c in (
    "4111 1111 1111 1111", "5555-5555-5555-4444", "378282246310005", "4012888888881881",
    "6011 1111 1111 1117", "5105-1051-0510-5100"))


def show(sp):
    """What the user sees for a test, for showing it to the room: {open, terminal, look, copy}"""
    t, e = sp.get("type"), sp.get("expect")
    out = {"open": open_url(sp), "terminal": None, "copy": None}
    if t == "http":
        out["look"] = {"block": "Zscaler’s block page: it names the category, the rule and the user.",
                       "caution": "Zscaler’s caution page. Click Continue: the user can still go ahead, and it’s "
                                  "logged.",
                       "isolate": "The site opens in Browser Isolation: it runs in Zscaler’s cloud, not on this "
                                  "computer.",
                       "allow": "The page opens normally: approved sites aren’t in the way."}.get(e, "The page.")
    elif t == "tls_issuer":
        out["look"] = ("Click the padlock › certificate: issued by Zscaler, so the traffic is inspected."
                       if e == "Zscaler" else
                       "Click the padlock › certificate: issued by the site’s own authority, so it isn’t inspected "
                       "(privacy bypass).")
    elif t == "eicar":
        out["look"] = "The EICAR test file over HTTPS: Zscaler stops it with its virus page."
    elif t == "dlp_post":
        out["look"] = "Paste the test card numbers (copied for you) into the form and submit: Zscaler’s DLP block."
        out["copy"] = SAMPLE_CARDS
    elif t == "tcp":
        out["terminal"] = f"nc -vz -w 5 {sp.get('host')} {sp.get('port')}"
        out["look"] = ("In Terminal: the connection times out or is refused (cloud firewall)." if e == "block" else
                       "In Terminal: the connection succeeds (allowed port).")
    elif t == "dns":
        out["terminal"] = f"dig @{sp.get('server')} {sp.get('name')} +short"
        out["look"] = ("In Terminal: no address comes back (DNS control)." if e == "block" else
                       "In Terminal: the name resolves.")
    elif t == "zcc_running":
        out["look"] = "The Client Connector icon in the menu bar: open it, Internet Security is ON."
    elif t == "via_zscaler":
        out["look"] = "ip.zscaler.com says this computer is going through Zscaler, and which data centre."
    else:
        out["look"] = describe_spec(sp)
    return out
