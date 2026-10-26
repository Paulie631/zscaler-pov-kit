# Zscaler POV Kit: SE Deployment Guide

*For Zscaler SEs and partner SEs. Versioned with the kit: the copy attached to each GitHub release (Word and
Markdown) is stamped with the kit version it describes. The source is `docs/DEPLOYMENT-GUIDE.md` in the repo, and it
changes together with the behavior it describes.*

## Overview

By the end of this guide you have run a proof of value in a customer's tenant: their pilot users protected by the
POV's own policy, every agreed success criterion proved with evidence in a report, and the tenant handed back exactly
as you found it (or the configuration handed over as Terraform). Plan about an hour on your laptop before your first
POV, a 60-minute kickoff with the customer's admin, then a few minutes before each customer session.

| Piece | Runs on | What it does |
| --- | --- | --- |
| Zscaler POV Kit (`pov-kit`) | Your laptop | Reads the tenant, writes the change list, applies what the customer approved, proves the criteria, hands over |
| The POV console | Your browser (this computer only) | Quick start and the step-by-step wizard, plus status, use cases, evidence and handover |
| Pilot devices | The customer's laptops, a spare laptop, or a virtual machine | Client Connector signed in as a pilot user; the POV probe (tests and traffic only, no keys) proves blocks, inspection and access from there |
| App Connectors (ZPA POVs) | The customer's AWS or Azure, or a CloudShare lab | Two connectors from the kit's template, plus the kit's test app when the customer hasn't named one |
| The customer's tenant | Zscaler cloud | Holds the POV's objects: each one is named with the POV prefix (`ZPOV`) and removed or handed over at the end |

**Golden rules**

- **Read before you write.** Discovery is read-only, and nothing is written until the customer approves the exact
  change list. If the tenant changes after approval, apply refuses: make the change list again and ask again.
- **The kit only touches what it created.** Every object carries the prefix and sits in the POV's ledger, and most
  also carry a `zpov:<pov-id>` stamp in their description. The customer's own objects are never edited, reordered or deleted; changes to them are customer
  steps, listed for them to make.
- **Pilot users only.** Every rule applies to the pilot group (or a SAML attribute), never to everyone.
- **Never activate someone else's work.** If ZIA has pending changes, the kit stops until the customer's admin
  activates or discards them.
- **Keep secrets out of chat, email and tickets.** API secrets, the provisioning key and test-user passwords live in
  your keychain; the console shows one only when you ask for it by name.
- **Leave cleanly.** Every POV has an end date. Hand it over (teardown or Terraform) before it, and keep backups on so
  a lost laptop can't strand objects in a customer's tenant.

## Prerequisites

**Your laptop**

- [ ] A Mac or Windows laptop where you can run the installer.
- [ ] Downloads from `github.com` and `astral.sh` allowed (the installer gets uv from there; updates come from GitHub).
- [ ] A folder synced off the laptop for encrypted backups (OneDrive, Google Drive or iCloud Drive), and a password
  manager for the backup passphrase.

**Your lab tenant (required before your first customer POV)**

- [ ] A Zscaler tenant of your own. The self-test runs there, never in a customer's tenant. Zscaler SEs use their
  SE lab tenant; partners use their partner demo tenant.
- [ ] A OneAPI client in it with the scopes from the kit's role spec. If Claude Desktop already has a Zscaler MCP
  server for that tenant, the kit can use its client.
- [ ] A pilot device for the lab: a spare laptop or a virtual machine without another organization's Client
  Connector (on a Mac, UTM runs a macOS virtual machine for free).

**Optional**

- [ ] For AI use cases and the executive summary: an AI Guard app in **PROXY** mode in your own AI Guard tenant, with
  an Anthropic provider key behind it. If you set up the AI Guard SE Demo Kit's Anthropic app, the kit uses it.
  Without an AI Guard tenant (partners, say): your own Anthropic API key from the Anthropic Console instead; requests
  then go directly to Anthropic, not scanned by AI Guard. Without either, everything else works and use cases are
  written by hand.
- [ ] For ZPA without the customer's cloud account: access to CloudShare (see [CLOUDSHARE.md](CLOUDSHARE.md)).

**From the customer, before the kickoff**

- [ ] The products in scope and the success criteria you agreed (from the kit's catalog).
- [ ] An admin who can create a OneAPI client from the kit's role spec, at or before the kickoff.
- [ ] One or more pilot devices.
- [ ] Optional, and can come later: who the pilot users are (a group, or named people; until then the POV starts with
  a test account), the POV app for ZPA (until then, the kit's test app), and where the App Connectors run (their AWS
  or Azure, or your CloudShare lab).
- [ ] CASB: a SaaS tenant they've connected for SaaS security (an OAuth grant only they can make). It's one of the
  Steps for people; until it's done, the SaaS criteria can't be proved.

## Part 1: Install the kit (5 minutes)

1. Paste one line (no security prompts, because the terminal fetches the files rather than a browser):
   - **Mac (Terminal):** `curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.sh | bash`
   - **Windows (PowerShell):** `irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.ps1 | iex`

   It downloads the latest release, checks its SHA-256, installs uv if needed, copies the kit to
   `~/.zscaler-pov-kit/app`, adds a **Zscaler POV Console** shortcut and the `pov-kit` command, and opens the console.

   Or download `zscaler-pov-kit-<version>.zip` from the latest release, unzip it, and double-click **Install Zscaler
   POV Kit** (`.command` on Mac, `.cmd` on Windows):
   - **Mac: "Apple could not verify… Not Opened".** The installer isn't signed with an Apple Developer ID, so macOS
     blocks it once. Click **Done** (not Move to Trash), then **System Settings → Privacy & Security → Open Anyway**,
     and double-click it again.
   - **Windows: "Windows protected your PC".** Click **More info → Run anyway**.
2. Optional: open `zscaler-pov-kit-<version>.plugin` from the release in the Claude desktop app, so Claude can run the
   kit for you.

The **Updates** button at the top of the console tells you when a new version is out (see *Updating* below).

## Part 2: Prove the kit in your lab tenant (30 minutes, before your first POV)

1. **Setup → Start a POV.** Customer: "Lab". Tick the products you sell. Under **More options**, tick **This is my own
   lab tenant**. For the API client, choose **The one Claude Desktop uses** if it's offered, or enter your lab
   client. Click **Quick start**.
2. **Your safety net (once, for every POV):** **Status → Safety net → Encrypted ledger backup**. Choose your synced
   folder and a passphrase of 12+ characters, and save the passphrase in your password manager
   (`pov-kit backup setup FOLDER`). Then **Turn on reminders** in the same panel: a daily notification when a POV is
   ending, overdue, or not backed up (`pov-kit remind install`). The panel appears once a POV exists.
3. **Logs → Lab tools → Run the self-test**. It reads every product, then creates, reads back and deletes one harmless
   object in ZIA, ZPA and AI Guard. All green means the kit's API access works from your laptop and network.
4. Walk a whole POV once: review the change list, approve it, apply, set up your lab pilot device (Part 4), run the
   probe, build the report, then **Handover → Remove the POV**. The tenant should be exactly as before.

## Part 3: Before the POV

1. Agree the success criteria with the customer. Once the POV exists, **Success criteria → The customer's success
   criteria** takes their list: paste it, upload their document (Word, PDF, Excel or CSV), or pick from the catalog.
   **Map them** matches each one to the catalog (with Claude once the customer's agreement is
   recorded in Use cases; otherwise by keywords), and you can change any mapping. **Build the POV from these** chooses
   the catalog criteria and, for the rest, has Claude write the configuration and tests as use cases. Everything
   joins the change list for the customer to approve, and the report shows each of their criteria in their own words
   next to its proof. (By hand: `pov-kit set criteria IS-URL-01,IS-SSL-01,...`; until criteria are chosen, the POV
   uses every criterion for its products.)
2. **Setup → Start a POV**: the customer's name and the products, then **Step by step** (the end date, prefix and two
   API clients are under **More options**). On **Connect**, **Copy the role spec** and send it to the customer's
   admin. They create the client at kickoff, or give you a temporary admin login to create it yourself. The optional
   read-only client in the spec is for Claude Desktop's read-only access (Part 5).
3. Send the **Customer Overview** (attached to each release) to their security team: what the kit does and never does
   in their tenant, and how approval works.

## Part 4: The kickoff (about 60 minutes, with the customer's admin)

### 1. Quick start

On **Connect**, enter the vanity domain and the client ID and secret the admin created (the secret goes straight to
your keychain; with ZPA, also the customer ID from **Administration → API → Legacy API → Private Access API → Copy
ID**), then click **Quick start from here**. If you didn't start the POV beforehand (in your lab, say), **Setup →
Start a POV** takes the customer, the products and the API client on one page: click **Quick start** there. Two API
clients (view-only first, write access after approval) use the step-by-step path instead.

The kit signs in, then fills in the rest from the tenant, read-only:

- **Pilot users:** if nobody's named, one test account the kit creates (in ZIA, or in ZIdentity when that's where the
  tenant keeps its users; the kit detects it). Name the customer's group or people any time (step 3).
- **The Zscaler cloud** (for setting up pilot devices).
- **ZPA:** the kit's test app when no app is named.

It runs the preflight checks and opens the change list. If anything needs fixing first, the change list says so, and
**Preflight** lists it under **Needs you**.
Products that can't go ahead yet (for example no ZDX role on the API client, or no ZPA group or customer ID) are
**added later**: the rest of the POV goes ahead, and once they're fixed, running the checks again and approving the new change
list adds them.

### 2. Review and approve the change list

Walk the admin through every object, who it affects and where it sits, and the steps only they make. **Open the
customer page** gives them the same list in their browser, printable with a signature line. Then **Approval**: record
who approved it, or let them approve on their own: the change-list page has an approval form that saves a file they
send you, and **Import their approval file** checks it's for this exact list.

### 3. Who tests (any time, in Pilot users)

**Setup → Pilot users** asks one question, "Who will test?":

- **A group they already have:** pick it from the list the kit reads from ZIA (or type its name). Rules apply to its
  members.
- **People we name:** the kit makes a POV group, `ZPOV - pilot users`, in ZIdentity and adds them (it's only made after
  approval, and removed at teardown; existing users are only added to it). Type a name or email; the step shows who
  isn't in ZIdentity. ZIdentity sends the group to ZIA only once it has the **Internet & SaaS** entitlement, which its
  API can't grant: where the tenant entitles chosen groups (common with Okta), the customer grants it. Apply checks the
  entitlement, stops at once if it's missing, and otherwise waits up to three minutes for ZIA to have the group; click
  **Apply** again after granting it and it carries on. With nobody named yet, the group starts with a test user.
- **Test accounts:** 1 to 10 accounts the kit creates (`zpov-pilot-1@<domain>`…), with passwords in your keychain
  (**Next steps → Test users → Show password**). If the tenant keeps its users in ZIdentity, they're made there, on
  `<vanity>.zslogin.net`, and you set their passwords in **Administration → Authentication → Directory → Users** (a
  domain your IdP owns, such as Okta's, can't take a ZIdentity password).

A line at the bottom says exactly who the POV's rules will apply to. **More options** has the identity provider (its
sign-in and MFA sites stay out of SSL inspection), your own list of sign-in sites not to decrypt (it replaces the
IdP's list), and rule placement. The ZPA and CASB
details are on the same page. Any change here means a new change list for the customer to approve.

### 4. Apply

Live progress, then a status check. Client Connector profiles are created for the pilot group; if the tenant has no
profile to copy or its API refuses them, the console prints the exact spec to build by hand (Windows, plus macOS for
Mac pilot devices), and **Status → Fix drift** adopts them by name.

### 5. Finish setup

After Apply, the setup stops at **Finish setup**: the steps for people that follow Apply, in order (entitle the POV's
group, set test users' passwords, Client Connector profiles if the API refused them, App Connectors, ZPA in Client
Connector, pilot devices), with **Set up a pilot device** on the same page. It works like Preflight (see **Steps the
API can't do** below), and the POV is ready to test once they're done.

### 6. Next steps

- **Steps for people:** every step, done or not, with instructions (see below).
- **Set up a pilot device** (see below).
- **ZPA App Connectors:** the AWS or Azure template (with the test app inside when no app is named), the provisioning
  key, and **CloudShare commands**.
- The probe pack, the AI Guard policy switch, and test-user passwords.

### Setting up a pilot device

**Next steps → Set up a pilot device** installs Client Connector already pointed at the customer's tenant, then the
**POV probe**. The probe is the kit's small pilot-device part: the POV's tests and the traffic generator, with no
console, no API keys and no tenant access, so it's an easy install for the customer's security team to approve
([PROBE.md](PROBE.md) is its one-page description). Pick the pilot user and macOS or Windows, then either:

- **Copy the one-line command** and paste it on the device: in Terminal on a Mac, or in PowerShell opened with
  **Run as administrator** on Windows; or
- **Download the setup script** for the customer's IT to read or push with their own tools. It has the POV's probe
  pack inside, so once the user signs in and traffic goes through Zscaler, the POV's tests run by themselves and the
  results land on the Desktop for you to import.

The cloud (**Detect** reads it from the tenant, or type it, such as `zscalertwo`), the user's domain and the user name
are filled in: `CLOUDNAME`, `USERDOMAIN` and `UNAME` on Windows; on macOS, the installer app's `--cloudName` and
`--userDomain` (unattended install, no profile to approve). Given a `.pkg` instead (`--pkg FILE`), the macOS setup
opens a settings profile with the same values (`com.zscaler.installparams`, what an MDM would push) for the user to
approve once in System Settings → General → Device Management. On both, the installer is the kit's pinned copy
(Windows MSI 4.10.0.477, macOS installer app 4.10.0.36), checked by SHA-256 and Zscaler's signature (on macOS:
Developer ID team PCBCQZJ7S7). To use the customer's own version, download it from **Infrastructure → Common
Resources → Deployment → Platform Releases** and add `--pkg FILE` (macOS: the `.pkg`, or the installer `.app`,
zipped or not) or `-Msi FILE` (Windows). A file you give is checked for Zscaler's signature.

**The probe pack keeps the devices in step with the criteria.** It holds the tests for the criteria the customer
chose (catalog criteria and use cases), each test's version, and what the traffic generator should send for them.
The setup script installs it on the device (`pov-probe pack install FILE` does it by hand), and every results file
says which pack and which test versions it ran. So when the criteria or a use case change:

- **Success criteria** lists the criteria whose tests changed since the last run, and the ones no device has run
  yet;
- a criterion whose tests changed counts as still to prove until a device runs the new pack. Results from another
  POV are refused.

Send the new pack (**Download probe pack**), install it on the devices, and run `pov-probe test` again.

The setup stops, and changes nothing, on a device that already has Client Connector or another organization's
Zscaler settings: never use your own work laptop as a pilot device. To set up a dedicated pilot device again (a lab
VM, say), add `--replace` (macOS) or `-Replace` (Windows). After the POV, uninstall Client Connector from the
pilot Mac (and remove the settings profile, if a `.pkg` was used).

### Traffic for the dashboards (ZIA)

The probe proves each criterion once; the **traffic generator** keeps the customer's ZIA dashboards, Insights and
Shadow IT busy with the POV's policy at work, the way the SE demo kit does. It browses web categories, SaaS and GenAI
apps, fetches the EICAR and Google Safe Browsing test pages, posts fake card numbers (published test ranges), uploads
and downloads file types, makes DNS lookups and tries the POV's blocked ports. No keys; nothing in the tenant changes.
Each round first asks ip.zscaler.com and sends nothing unless traffic goes through Zscaler.

The probe pack shapes it: only the kinds of traffic the chosen criteria call for (no DLP posts without a DLP
criterion, say), plus each use case's own sites and blocked ports. On a pilot device with the POV probe (the device
setup installs it):

```
pov-probe traffic check                  # in the POV's tenant, as a pilot user? (the tenant-check page is blocked)
pov-probe traffic run                    # one round now, shaped by the probe pack (--types, --count N to override)
pov-probe traffic schedule --every 30    # a round every 30 minutes while signed in; --remove stops it
```

With no spare device: **Next steps → ZIA traffic generator → AWS generator template** writes a CloudFormation template
for the pilot user chosen in **Set up a pilot device**: a Windows Server instance in its own VPC, no inbound ports, an
SSM role (connect with Fleet Manager remote desktop), the kit's pinned Client Connector for the POV's cloud and user,
and a scheduled round every 30 minutes; a weekday start and nightly stop keeps the cost down. Upload it in
CloudFormation (**Create stack → Upload a template file**), sign in to Client Connector once over remote desktop, and
read **POV traffic log** on its desktop. Delete the stack at the end of the POV (CLI: `pov-kit traffic aws`). On
CloudShare, **CloudShare Windows pilot script** on the same card sets up the blueprint's Windows pilot the same way
(the probe pack, a check, and a round every 30 minutes). The AWS template
carries the POV's probe pack, so download it again after the criteria change.

### Steps the API can't do

Some steps need a person in the Zscaler console: creating the API client, giving it a ZDX role, granting an
entitlement, Malware Protection (tenant-wide, so the kit only reads it), connecting a SaaS tenant (an OAuth consent),
deploying App Connectors, building Client Connector profiles by hand when the API refuses, and deleting the API
clients at the end. **Next steps → Steps for people** lists the ones this POV needs, in order, each with:

- who does it and when, the console path (where it's been checked in a live console) and the term to type in the
  console's **Search menu** (it finds any page if a menu has moved);
- numbered steps, the exact names to use, and what done looks like;
- **Check now**, where the API can see the result (read-only): the API client signs in, ZDX and ZPA are readable,
  pilot users are entitled, Malware Protection blocks viruses, devices are registered, connectors are up, a SaaS
  tenant is connected, profiles are adopted. A passing check ticks the step; **Check them all** runs every one;
- **Mark done** with a name, for the rest.

**The setup stops where they're needed**, like the SE demo kit's preflight:

- **Preflight** lists the steps for people needed before the change list (ZDX role, ZPA customer ID, Malware
  Protection, a SaaS tenant), under the read-only checks. **Finish setup** lists the ones after Apply.
- **Continue** waits until each step is done: its check passes (Preflight checks the ones the API can see as it runs),
  or someone marks it done. **Continue anyway**, with a name (and why), lets the setup go on. Those steps stay on the
  list and keep holding up their criteria, and the record shows who decided.
- **With the admin, now** (on a call) or **Admin does them later**: the second gives **Copy these steps for the
  admin**, with only what this point of the setup waits on. Come back when they're done and **Check them all**; the
  POV picks up where it stopped.
- Every step, and every preflight check that isn't passing, has **How to verify**: what it checks, why it matters,
  how to verify by hand, the fix, and how to re-test.

**Copy the steps for the customer's admin** gives the same list as Markdown to paste into an email or the shared POV
doc (no secrets in it). From the command line: `pov-kit steps` (`--check`, `--done KEY --by NAME`, `--sheet`).

### AI Guard and Endpoint AI

**AI Guard** proves eight criteria automatically, by scanning test prompts and model replies through AI Guard's
Detection API with the POV's own app key (**AI Guard → Test runner**, whose results are those criteria's proof). The tests are the SE demo kit's library (synthetic data
only): prompt injection (AI-AIG-01), secrets, PII and personal data (02), evasion with gibberish and invisible text
(03), source code (04), responsible-AI topics such as toxicity, financial or legal advice, competitors and brand risk
(05), model replies that leak data, are toxic, carry malicious links or refuse (06), topic and language tagging (07),
and everyday prompts that must not be flagged (08). Industry packs are optional criteria for the customer's sector:
financial services (AI-AIG-P1), healthcare (P2) and legal (P3); add them with `pov-kit set criteria ...,AI-AIG-P2`.
The competitor named in the responsible-AI tests is `aiguard.competitor` (`pov-kit set aiguard.competitor "Name"`).
Results show which tests behaved as expected, and the AI Guard policy switch (Monitor, Block attacks, + data leakage)
shows detection turning into blocking.

The **AI Guard tab** brings the SE demo kit's tools to the POV, always on the POV's own app, keys and policy. It has
four parts: **Test runner**, **Guided demos**, **Policy** and **Setup**.

- **Test runner** (laid out like the demo kit's): the test library on the left, Run and Live prompt beside it, then
  the POV's criteria, dashboard coverage and the results as they land.
  - **This POV's criteria** comes first in the library: a group per AI Guard criterion of the POV (the catalog's,
    the customer's imported prompts, and use cases with AI Guard prompts), each test labelled with its criterion.
    **▸ This POV's criteria** selects them all. The demo kit's library (presets, industry packs, groups) follows.
  - **Detection API** or **LLM proxy** per run; in proxy mode, **Detector tags** also scans the prompt and the reply,
    so the detectors show. **Rounds**, and the **users** the tests run as (rotated): the POV's pilot or test users by
    default, or names carrying the POV's ID, so AI Guard Insights shows just the POV's scans.
  - **Stop** ends the run after the test in flight. What ran stays in the results and counts.
  - **Results count as evidence:** a criterion's results become its proof in Success criteria (no separate API
    proofs needed). Detection API results count, and proxy results with Detector tags. A criterion whose tests didn't
    all run stays incomplete, unless one already failed.
  - **Draft more tests with Claude**, under any criterion: Claude writes up to six test prompts with the detectors
    they should trigger (synthetic data only), for you to Accept or Discard. Accepted tests join that criterion's
    group and its proof. For the customer's own criteria, the customer's agreement (Use cases) is needed first.
  - Results: counters, a progress bar, Flag missed detectors (turn it off for a customer demo), CSV, One-page report.
- **Policy:** Monitor, Block attacks, Block attacks + data leakage, Block everything risky, or **Custom** (Block or
  Detect per detector, for prompts and replies separately).
- **The customer's own prompts:** import a CSV (a `prompt` column; optional `direction`, `name`, `expect`). It becomes
  a pack and a success criterion (AI-AIG-C1…) proved through the Detection API. It stays in the POV folder.
- **Proxy mode** (AI Guard → Setup): real prompts to models through AI Guard, for **Anthropic, OpenAI or both**.
  The kit reads which providers and keys the customer's AI Guard already has (**Read the tenant again** refreshes
  it). For each provider: **reuse one of their keys**, **use your own key** (it goes to your keychain; the change list
  adds it to their AI Guard as a POV object, and teardown removes it), or **off**, plus the model. Each provider in
  use gets its own POV proxy key and rule. Save, run the checks again and get the new change list approved; then the
  runner's **LLM proxy** mode rotates across the models you tick, and the live prompt's **Send to the model** works.
- **Guided demos:** the demo kit's storylines (AI Guard in 8 steps, Data protection, Blocking step by step,
  Healthcare, Financial services, Legal) with a Say/Show talk track, presenter notes (so what, a discovery question,
  objections), OWASP Top 10 for LLM tags, real incidents, and a Monitor/Block switch per step that changes the POV
  policy as you open the step. **Recap** lists what each step caught, ready to paste into the follow-up email.

**AI Endpoint Security (Endpoint AI)** is a *draft* product in the kit: Zscaler announced it in October 2026, and it
has no API in the Zscaler SDK yet, so the kit creates nothing for it. Tick it on Start a POV to add five draft
criteria (EP-AIE-01 to 05: shadow AI inventoried, a malicious skill file blocked, dangerous agent commands stopped,
PII in a prompt to a local model flagged, agent activity visible per user and device). The probe proves the device
side with harmless, clearly named test files: a local model file, an MCP server definition and an agent skill
(`zpov-test-…`), an inert "risky" skill (`zpov-risky-…`, removed by the probe), and a prompt with synthetic PII to a
local Ollama model if one is installed. A person records what the admin console shows. Afterwards, on the device:
`pov-probe cleanup`. Replace the draft criteria with Zscaler's internal POV plan for the product when you have
it.

### More Zscaler products in a POV

Some criteria are **opt-in**: they count only when chosen (Success criteria › Pick from the catalog, or when the
customer's own list maps to them), so a POV without them is unchanged.

| Product | Criteria | What the kit does |
|---|---|---|
| Cloud Sandbox (ZIA) | IS-SBX-01 | A POV sandbox rule for the pilot group; the device test downloads a never-seen PDF and expects quarantine. |
| Workflow Automation | IS-DLP-02 | Reads the pilot users' DLP incidents (last 7 days). Read-only. |
| ZPA Privileged Remote Access | PA-PRA-01 | A PRA segment (RDP or SSH to one server), a pilot-only access rule, a portal and a console. Set the server, the portal's domain and a ZPA certificate that covers it (Setup › ZPA › Privileged Remote Access); after Apply the customer adds the portal's CNAME to DNS. The device test opens the portal. |
| ZPA App Protection | PA-APP-03 | Makes the POV app segment an inspected one, with an App Protection profile (OWASP and ThreatLabZ controls, blocking) and an inspection rule for the pilot group. An HTTPS app needs a ZPA certificate for its domain. The device test sends a cross-site scripting request and expects it stopped (a 403). Choose it before Apply: an app segment made earlier isn't inspected. |
| GenAI in browser isolation (AI Access Security) | AI-GEN-03 | A Cloud App Control rule opens Perplexity (an assistant neither approved nor blocked) in browser isolation for the pilot group. Needs an isolation profile. The device test expects isolation; the rule has a demo switch. |
| AI Asset Management / AI-SPM (draft) | AS-INV-01, AS-MOD-01, AS-RSK-01, AS-GOV-01 | No API yet: a person shows and records the inventory, the cloud AI assets, a risk finding and a governance report. With ZIA in the POV, the traffic generator sends GenAI traffic so the inventory has something to show. |
| DSPM (draft) | DS-FND-01, DS-RSK-01, DS-ACC-01 | No API yet: a person shows and records sensitive data found and classified, a risky exposure flagged, and who can reach the data. |
| AI Red Teaming (draft) | RT-SCN-01, RT-FND-01, RT-GRD-01, RT-CON-01 | No API yet: the scan's report is the evidence. RT-GRD-01 re-runs the successful attacks with AI Guard in front. |
| External Attack Surface (EASM) | EA-FND-01, EA-LKA-01 | Read-only: findings by severity and lookalike domains for the customer's EASM organization. |
| Business Insights | BI-RPT-01 | Read-only: the reports available. |
| Microsegmentation | MS-AGT-01, MS-POL-01 | Read-only: agents installed and connected, and policy rules. The customer installs the agents. Needs the ZPA customer ID. |
| Cloud & Branch Connector | CC-GRP-01, CC-FWD-01 | Read-only: connector groups and their VMs, and forwarding rules. The customer deploys the connector from a provisioning template. |

**AI-SPM and DSPM need the customer's cloud account.** Agree at kickoff: the customer's cloud admin connects a *test*
AWS account with Zscaler's own onboarding template, then deploys the kit's **seed stack** (Next steps › Seed stack, or
`pov-kit seed template`): synthetic sensitive data, a deliberately weak bucket, AI training data with personal data in
it, an over-permissioned AI agent on Bedrock and, optionally, an unauthenticated MCP server, so the scans find
something. Both are on the steps for people, and removing them is on the end-of-POV steps. Step by step:
[SEED-STACK.md](SEED-STACK.md).

The read-only and draft products (AI-SPM, AI Red Teaming) are chosen on Start a POV like the others; draft criteria are replaced by Zscaler's internal POV plans, and by API proofs when the SDK has them. They put the customer's steps on the list of
steps for people, create nothing, and have nothing to tear down. Their API client needs view access to each one.
PRA and App Protection bodies follow the SDK's documentation and are confirmed in the lab test plan, like the rest
of ZPA.

### A POV lab on CloudShare

No cloud account for the connectors? [CLOUDSHARE.md](CLOUDSHARE.md) builds a CloudShare blueprint once (two App
Connectors, the test app, a Windows pilot) with no customer values in it; each POV starts a copy and enrolls it with
the commands from **Next steps → ZPA App Connectors → CloudShare commands**.

### The step-by-step path

**Step by step** on Start a POV opens the same work as eight steps (Start a POV, Connect, Pilot users, Preflight,
Change list, Approval, Apply, Next steps), for two-client POVs or when you want to set everything before the first change list.
Any step can be revisited after Quick start.

## Part 5: During the POV

- **Before every customer session:** **Status → Check now**. It says whether the tenant still matches the approval,
  what drifted (and **Fix drift** repairs only the POV's own objects), the end date and the last backup.
- **Dashboards:** keep the traffic generator running on a pilot device (`pov-probe traffic schedule`) or the AWS
  generator, so ZIA, Insights and Shadow IT have the pilot group's traffic to show.
- **Evidence:** run the probe on each pilot device (the setup script runs it for you), and import the results
  (**Success criteria → Import probe results**). The kit checks what the API can see on its own (read-only): after
  Apply, after Finish setup's checks, with every Status check, and when Success criteria opens if the last check is
  over three hours old (**Check again** runs it now). It covers the ZIA rules behind each criterion and its test
  sites' categories, connectors, ZDX scores, devices and SaaS scans; AI Guard's criteria come from the test runner.
  A criterion that doesn't pass says **why**, with the steps to fix it and, where the console can do it, a button
  (Fix drift, Finish setup, the test runner). Record what
  people see as attestations (a screenshot can be attached with `pov-kit attest <criterion> --note ... --file`).
- **New use cases:** check the library first (no AI call). Otherwise, in the **Use cases** tab, give the kit a way to
  Claude (your AI Guard proxy key, found automatically if the AI Guard demo kit is on your laptop; or, without an AI
  Guard tenant, your own Anthropic API key, sent directly and not scanned), record the customer's
  agreement once (names are replaced before anything leaves your laptop, unless they agree to share them), describe
  the use case, refine it in words, and **Add to the change list**. The customer approves the new change list before
  Apply builds it. **Save to library** keeps what worked.
- **Products added later:** once the fix is in (for example, the ZDX role), **Preflight → Run checks again**, then
  review and approve the new change list.
- **Ask Claude about the tenant:** with the customer's agreement, **Next steps → Ask Claude about this tenant → Add to
  Claude Desktop**. It is read-only: Claude can answer "why was Jane blocked?" but can't change anything.
- **Let Claude make changes:** with a second agreement from the customer, the same card adds a **changes connector**
  that the kit runs (`pov-kit mcp actions`). Claude Desktop can then:
  - **propose a change** ("marketing can use ChatGPT but not upload files"): the kit checks every value against the
    tenant, names and scopes each object to the pilot group, and adds it to the change list. The customer approves
    the new change list and you click **Apply** in the console; Claude can't apply;
  - switch the POV's AI Guard policy, run the AI Guard tests (results count as evidence) and the API proofs, check
    status and **Fix drift** on the POV's own objects, and check the steps for people.

  It never uses Zscaler's write tools and never writes to the tenant directly, so every change is approved, recorded
  and removed at the end like the rest of the POV. Each action shows in Logs as done by Claude Desktop. Removing the
  read-only entry removes the changes connector too.

## Part 6: Closing

1. **Success criteria → Draft the summary**, then **Build the report**, and give the customer the report (print it to
   PDF from the browser).
2. Agree the exit with the customer, before the end date:
   - **Keep it:** **Handover → Export to Terraform**. The configuration is adopted in place with import blocks, and
     the kit never touches it again.
   - **Remove it:** **Handover → Remove the POV**. ZPA: delete the connector stack in AWS or Azure (or the CloudShare
     environment) and the enrolled connectors first; teardown keeps the connector group until they're gone.
3. Either way, the kit removes the POV's secrets, discovery data, raw API recordings and Claude Desktop entry from
   your laptop (a recording is first kept as a test fixture with customer names replaced).
   Remind the customer to delete the POV's API clients (the last of the Steps for people).
4. **Delete the POV** when you no longer need its record: **Setup → Start a POV → Delete…** next to it (or
   `pov-kit delete <pov-id>`). The kit first checks, read-only, that nothing the POV created is still in the tenant;
   if something is, it says what and stops. Then you type the POV's ID to confirm, and its folder, keychain secrets,
   Claude Desktop entry and backup are deleted from your laptop. The customer's tenant isn't touched.

## Updating, rolling back and recovering

**Update:** when a new version is out, the **Updates** button turns into **Update to x.y.z**. Click it, then **Install
update**: it verifies the download, installs it and restarts the console; the page reloads itself. Terminal:
`pov-kit update`.

**Roll back one version:** **Roll back** in the same dialog, or `pov-kit update --rollback`.

**New laptop, or a lost one:** install the kit, point it at the same synced folder (`pov-kit backup setup FOLDER`),
then `pov-kit backup restore <pov-id>` with your passphrase (or give the `.zpovbak` file's path), and connect again. Without a backup, `pov-kit recover <pov-id> --customer "<name>" --products ...`, connect, then
`pov-kit recover <pov-id>` finds the POV's objects in the tenant (read-only) and `--write` records them so teardown can
remove them.

## Troubleshooting

Start with the **Logs** tab: every API call and change is there, and **Download diagnostics** makes a zip without
secrets or the customer's object names for the kit owner. **Report a problem** (next to it) opens the kit's GitHub
issue form: attach the zip, and never paste a secret, a customer's name or anything from their tenant there (the
repository is public).

| Symptom | Fix |
| --- | --- |
| Connect: "rejected the API client's sign-in (401)" | Wrong client ID or secret, wrong vanity domain, or the secret was rotated. Re-enter them in Connect |
| ZPA added later: ZPA customer ID | Copy it from **Administration → API → Legacy API → Private Access API → Copy ID** into Connect (`pov-kit set customer_id`) |
| ZPA added later: no SCIM group | ZPA needs the pilot users as a group from the customer's IdP (SCIM) or a SAML attribute: set it in Pilot users (ZPA) |
| ZDX: "Pilot users for ZDX: none known yet" | Deep traces need pilot devices: name the pilot users, or apply the test accounts, then run the checks again |
| ZDX added later: ZDX readable (403) | The API client has no ZDX role: **Administration → API → OneAPI → API Clients**, edit the client and add one (view only is enough), or take ZDX out of the POV |
| Preflight: pilot users not in ZIA | With SAML or SCIM, users appear after provisioning or their first sign-in: have each one sign in to Client Connector once |
| Preflight: ZIdentity entitlements | ZIdentity's API can't grant them: the customer assigns the missing service to the pilot group (Steps for people) |
| Preflight: pilot group doesn't exist | Pick an existing group from the list, or choose **People we name** |
| Apply stops: "don't have the Internet & SaaS entitlement" | The customer gives the POV's pilot group that entitlement, then click **Apply** again: it carries on and creates nothing twice. In a lab, **Test accounts** avoid it |
| Apply stops: "keeps its users in ZIdentity" | Make the change list again (the test users now go in ZIdentity, on `<vanity>.zslogin.net`), get it approved, apply, then set their passwords in ZIdentity |
| No option to set a user's password in ZIdentity | The user is on a domain your IdP (Okta, Entra…) owns, which signs them in. Use a user on `<vanity>.zslogin.net` |
| Pilot device setup: "already has Client Connector" | It's protecting another organization's Client Connector (a work laptop). Use a spare device or a virtual machine; on a dedicated pilot device, add `--replace` / `-Replace` |
| Self-test: "isn't marked as a lab POV" | Start a POV for your lab tenant with **More options → This is my own lab tenant** ticked |
| Delete: "still in the customer's tenant" | Remove the POV first (**Handover → Remove the POV**) or export it to Terraform, then delete |
| Apply: "ZIA has changes waiting to be activated" | Another admin's changes are pending. The customer activates or discards them; the kit never does |
| Apply: "the tenant changed since the customer approved" | Something the plan depends on changed. Make the change list again and get it approved again |
| Client Connector refused the profiles, or no profile to copy | Build them from the printed spec with exactly those names, then **Status → Fix drift** adopts them |
| ZPA connectors don't appear | Check the machines reach the internet on TCP 443 and have the POV's provisioning key; they enroll within about 15 minutes |
| Use cases: "AI Guard blocked the request" | Your AI Guard demo policy is enforcing. Switch it to Monitor, or rephrase |
| Status: "POV end date" FAIL | The end date passed with objects in the tenant: hand the POV over now, or agree a new date (`pov-kit set ends`) |
| Update: "couldn't reach GitHub" | Your web policy blocks GitHub downloads: download the zip from the releases page and run its installer |
| A console path in a step doesn't match | Zscaler renames menus between versions: use the console's **Search menu**, and tell the kit owner the path you see |
