# Changelog

## 0.9.26

- **Every error or blocker says how to resolve it, step by step.** A failed or warning check (Preflight, Status,
  teardown, Steps for people), a failed job and a console error now come with a **How to fix** panel: who does it,
  the console path or search term, numbered steps and what fixed looks like. Before, most showed one line.
  - A 403 from any product becomes "give the API client a <product> role", with the exact steps, for ZIA, ZPA, ZDX,
    Client Connector, ZIdentity, AI Guard, SaaS security and Insights (Steps for people's checks now name the
    product that refused, not only ZDX).
  - Sign-in (401), a missing client, the keychain, network, TLS inspection, rate limits (429) and Zscaler-side
    errors each have their own fix, as do the ZPA customer ID (missing or wrong), pending ZIA activation, pilot
    users and groups, entitlements, names already taken, drift, App Connectors, Client Connector profiles, SaaS
    tenants, AI Guard proxy mode, Malware Protection, pilot devices, ZDX apps, teardown leftovers and the end date.
  - The fixes are in `povkit/fixes.json`, one place to correct the wording or a click path. The CLI prints them
    too, and the sheet for the customer's admin includes the fix for any step whose last check failed.
- Fixed: a failed check in Steps for people showed `&gt;` instead of `>` (the message was escaped twice).

## 0.9.25

- **The POV probe: a separate small download for pilot devices.** It holds only the POV's tests and the traffic
  generator: no console, no API keys, no tenant access, two small libraries. It installs with one line
  (`install-probe.sh` / `install-probe.ps1`, SHA-256-checked), and gives a `pov-probe` command (`test`, `pack`,
  `traffic`, `cleanup`). The pilot device setup, the CloudShare pilot and the AWS traffic generator now install it
  instead of the whole kit. The kit's own `pov-kit probe` and `pov-kit traffic` still work.
- **Probe packs follow the success criteria.**
  - A pack holds the chosen criteria's tests (use cases included), each test's version, and a traffic profile: only
    the traffic those criteria call for, plus the use cases' own sites and blocked ports.
  - Results say which POV and which test versions they ran. Results from another POV are refused.
  - A criterion whose tests changed counts as still to prove until a device runs the new pack. **Success criteria**
    lists what's out of date and what no device has run yet.

## 0.9.24

- **Claude without an AI Guard tenant.** SEs and partners with no AI Guard proxy key can save their own Anthropic API
  key (Use cases tab, or `pov-kit ai connect --direct`). Use cases, criteria mapping and the report summary then go
  directly to Anthropic, with the same customer agreement and name replacement but no AI Guard scanning. An AI Guard
  proxy key, when there is one, is still used first. The customer's agreement now records the route, so switching
  routes asks for it again.

## 0.9.23

- **The SE demo kit's ZIA traffic generator**, for the customer's dashboards: `pov-kit traffic check | run | schedule`
  on a pilot device (web categories, SaaS, GenAI, EICAR and phishing test pages, fake card numbers, file types, DNS,
  the POV's blocked ports), matched to the POV policy (the tenant check is the POV's own blocked page). Each round
  sends nothing unless ip.zscaler.com confirms traffic goes through Zscaler.
- **An AWS generator** (Next steps → ZIA traffic generator, or `pov-kit traffic aws`): a CloudFormation template for a
  Windows instance with the kit's pinned Client Connector for the POV's cloud and pilot user, no inbound ports, and a
  round every 30 minutes.

## 0.9.22

- **Guided demos in the AI Guard tab**, from the SE demo kit: six storylines with a Say/Show talk track, presenter
  notes, OWASP Top 10 for LLM tags, real incidents, a Monitor/Block switch per step (the POV policy changes as the step
  opens, with a countdown while it applies), real model replies in proxy mode, and a recap for the follow-up email.

## 0.9.21

- **An AI Guard tab, like the SE demo kit**, on the POV's own app, keys and policy:
  - policy profiles: Monitor, Block attacks, + data leakage, **Block everything risky**, and **Custom** (per detector,
    prompts and replies separately);
  - the demo kit's **test runner** (72 tests, presets, industry packs, users and rounds, detectors fired and missed,
    hide-missed for demos), a **live prompt** box, and a **one-page report**;
  - **the customer's own prompts** from CSV, as a pack and a success criterion (AI-AIG-C1…);
  - **proxy mode** with the customer's model key or the SE's own (kept out of the change list; removed at teardown).
- Keyword mapping of imported criteria is smarter (word stems; AI criteria only for AI wording).

## 0.9.20

- **The customer's success criteria in, the POV out.** Success criteria → **The customer's success criteria**: paste
  their list, upload their document (Word, PDF, Excel or CSV) or pick from the catalog. **Map them** matches each one
  to the catalog (Claude through AI Guard, with the customer's agreement; otherwise keywords), editable row by row.
  **Build the POV from these** chooses those catalog criteria and has Claude write the configuration and tests for
  the rest as use cases (accepted when the kit can build them, or kept as steps to attest). It all joins one change
  list for the customer to approve, and the report quotes each of their criteria next to its proof.

## 0.9.19

- **AI Guard: the SE demo kit's full test library as success criteria.** Eight criteria, each proved automatically
  through AI Guard's Detection API: prompt injection, secrets/PII/personal data, evasion (gibberish, invisible text),
  source code, responsible AI (toxicity, financial and legal advice, competitors, brand risk), model replies (leaked
  data, toxicity, malicious links, refusals), topic and language tagging, and no false positives on everyday prompts.
  Industry packs for financial services, healthcare and legal are optional criteria (`pov-kit set criteria`).
- **AI Endpoint Security (draft).** A new product to tick on Start a POV, with five draft criteria from Zscaler's
  public description, to be replaced by the internal POV plan. No API yet, so nothing is created in the tenant; the
  probe plants harmless, clearly named test files on a pilot device (a local model file, an MCP definition, agent
  skills, a PII prompt to a local Ollama model) and a person records what the console shows. `pov-kit probe
  --cleanup` removes the test files.

## 0.9.18

- **SE Deployment Guide and Quick Start rewritten** for Zscaler and partner SEs, leading with Quick start, and checked
  against the kit: current option names, "Needs you" and "added later", optional prerequisites (pilot group, ZPA app,
  cloud account), pilot devices on Mac and virtual machines, CloudShare, verified console paths, and new
  troubleshooting rows.
- **Mark a lab POV in the console:** Start a POV → More options → **This is my own lab tenant** (the self-test needs
  it; before, only `pov-kit new --lab` could).
- **Quick start from here** on Connect carries on a POV started earlier (to send the customer the role spec before
  the kickoff), instead of starting a second one.
- The hand-built Client Connector spec covers Mac pilot devices (a macOS app profile with the same settings).
- An independent check of the guides against the code fixed 17 more points, among them: the safety net is set up
  once a POV exists; success criteria are recorded with `pov-kit set criteria`; the CloudShare pilot uses the setup
  script (with the probe pack) and the environment is deleted before teardown; macOS needs `--pkg` until a macOS
  installer is pinned; the self-test writes only in ZIA, ZPA and AI Guard.
- **ZDX no longer holds a POV back for want of named pilot users:** it uses the POV's test accounts too, and without
  any pilot users it warns (deep traces wait for pilot devices anyway).
- A downloaded setup script takes extra options (`--pkg FILE`, `-Msi FILE`, `--replace`), as the one-line command does.

## 0.9.17

- **A POV lab on CloudShare** ([docs/CLOUDSHARE.md](docs/CLOUDSHARE.md)): scripts to build a blueprint once with two
  ZPA App Connectors (Zscaler's EL9 package source, its signing key checked against the fingerprint in Zscaler's
  guide, left unenrolled), the test app, and a Windows pilot with the kit and the checked Client Connector installer.
  No customer values in the blueprint: each POV enrolls its copy with **Next steps → ZPA App Connectors → CloudShare
  commands**, filled in with the POV's provisioning key.

## 0.9.16

- Preflight says the right place for a ZIdentity POV group's test users (ZIdentity, not ZIA). Seen live.

## 0.9.15

- **Quick start.** Start a POV asks for the customer, the products and the API client (or the one Claude Desktop uses).
  The kit fills in the rest from the tenant (read-only), runs preflight and opens the change list. The step-by-step
  wizard stays for changing anything.
- **Products that aren't ready are added later instead of blocking.** A product whose checks fail (no ZDX role, no
  SaaS tenant, a ZPA app that overlaps the customer's) sits out the change list as "added later", with its fix; the
  rest of the POV goes ahead. Products that build on it wait too (Client Connector and CASB on ZIA).
- **Pilot users start themselves.** A POV group in ZIdentity with nobody named starts with a test user on ZIdentity's
  own domain; Quick start defaults to one test account (in ZIA, or ZIdentity when that's where the tenant keeps users,
  detected and re-planned automatically).
- **ZPA brings its own test app.** With no app named, the AWS and Azure connector templates also start a small private
  web page (`pov-app.zpov.internal`, port 80, reachable only from the connectors) and the kit makes it the POV app.
- **Simpler screens.** Pilot users asks one question ("Who will test?") with a one-line summary of who the rules apply
  to; extra options are folded away. Preflight groups what needs you, what's added later, and what's worth a look, with
  passed checks folded away.
- Console paths seen live: API clients (Administration → API → OneAPI → API Clients) and the ZPA customer ID
  (Administration → API → Legacy API → Private Access API → Copy ID).

## 0.9.14

- **The pilot-device setup never takes over a work laptop.** If Client Connector is already installed, or (macOS) an
  MDM already sets Zscaler's install settings, it stops and changes nothing, rather than reinstalling Client Connector
  for the POV's tenant and signing it out of the company's. `--replace` / `-Replace` is for a device meant only for
  the POV.

## 0.9.13

- **Cloud detection fix** (seen live): a PAC file's bypass lines mention `*.zscaler.net` whatever the cloud, so a
  zscalertwo tenant was detected as `zscaler`. Only the PAC URL (`pac.<cloud>.net`) and the gateway
  (`gateway.<cloud>.net`) count now; otherwise the console asks for the cloud.

## 0.9.12

- **Detect the cloud** also reads ZIA's PAC files (they name the cloud's gateway) when ZIdentity's entitlements
  don't say, and looks further down ZIdentity's user list for an entitled user. Both read-only.

## 0.9.11

- **Set up a pilot device from the console.** Next steps → **Set up a pilot device** gives, for a pilot user on macOS
  or Windows, a one-line command or a setup script for the customer's IT. It installs Client Connector with this
  tenant's cloud, the user's domain and name filled in (Windows: CLOUDNAME, USERDOMAIN, UNAME; macOS: a settings
  profile the user approves once), then the kit's probe. The script carries the POV's probe pack and runs the tests
  once traffic goes through Zscaler.
- **Client Connector from the kit**, like the SE demo kit: a pinned copy on the kit's `zcc-installer` pre-release,
  installed only if its SHA-256 matches and it's signed by Zscaler. The customer's own version works too.
- **Detect the cloud** from ZIdentity's Internet & SaaS entitlement (read-only), or type it (`pov-kit set zcc.cloud`).
- `pov-kit probe --wait N` waits up to N minutes for traffic to go through Zscaler before testing.
- The pilot-devices check counts the POV's own test users, not only named pilot users.

## 0.9.10

From running the new checks against the lab tenant:
- **The ZPA customer ID check** says plainly when no customer ID is set, or when ZPA doesn't know the one entered,
  instead of showing ZPA's raw "not found" answer. Its steps give ZPA's Public API page.
- **"Build the Client Connector profiles by hand"** only appears after Apply, when it's actually needed.

## 0.9.9

- **Detailed instructions for every step the API can't do.** Next steps → **Steps for people** lists them in order
  (before the POV, during it, at the end), each with who and when, the console path or the term to type in the
  console's Search menu, numbered steps, the exact names to use, and what done looks like.
- **Checks where the API can see the result**, all read-only: the API client signs in, ZDX and ZPA are readable,
  pilot users have the Internet & SaaS entitlement, Malware Protection blocks viruses, pilot devices are registered,
  App Connectors are up, a SaaS tenant is connected, Client Connector profiles are adopted. A pass ticks the step; the
  rest are marked done with a name.
- **A sheet for the customer's admin**: the same steps as Markdown to paste into an email (no secrets).
- `pov-kit steps` (`--check`, `--done KEY --by NAME`, `--sheet`).
- Console paths seen in a live console are recorded; the others give a menu search term.

## 0.9.8

- **ZIA's success criteria get an automated proof.** For each criterion, the POV rules behind it are checked in the
  tenant (present, enabled, applying only to the pilot group), and ZIA's own URL lookup confirms each test site falls
  in the rule's categories. Insights adds tenant-wide context (blocked transactions in the 7 days to yesterday:
  Insights can't filter to one user or rule and lags a day). The probe pack stays the proof that pilot traffic was
  handled; attestations are still accepted where neither applies.
- **Firewall use cases.** Claude can propose a cloud firewall rule (ports, optional destinations, block or allow):
  the kit builds its own network service and a rule scoped to the pilot group, like every other use case.
- **ZPA preflight** says to set the ZPA customer ID when ZPA answers "not found" without one (seen live).

## 0.9.7

Follow-ups from the live lab test:
- **Status is much faster.** One status check signs in once and reads each list once: discovery and the drift
  check share a read cache, and ZIA drift uses those lists instead of fetching every POV object one by one.
- **A recording survives the handover.** Before the POV's customer data is removed, its API recording is exported
  as a replay fixture with customer names replaced (`~/.zscaler-pov-kit/fixtures/`), so a live run can become a test.
- **The Updates dialog shows release notes formatted** (bold, code, bullets) instead of raw Markdown.
- **Client Connector's build-by-hand spec** says "a new profile" when the tenant has no default to copy, instead of
  naming a default that doesn't exist.

## 0.9.6

From the live lab test:
- **Obfuscated user names no longer block teardown.** An API role with "User Names: Obfuscated" makes ZIA scramble
  the name of a user fetched on its own, so the kit took its own test users for renamed ones and would have left them
  in the tenant. It now reads their names from ZIA's user list, which shows them as they are, matched by ID.
- Apply says "Already there" for objects an earlier run made, instead of "Created" again.

## 0.9.5

From the live lab test (ZIA, Client Connector and AI Guard, with test users made in ZIA):
- **Apply no longer stops when there's no default Client Connector profile to copy.** Preflight warned, but apply
  then failed with "the forwarding profile the change list copies is gone", so AI Guard was never reached. It now
  prints the spec to build the profiles by hand (Fix drift adopts them) and carries on.
- ZIA's own test users no longer get the customer action "has the Internet & SaaS entitlement in ZIdentity".

## 0.9.4

From the live lab test, and mirroring the SE demo kit:
- **Test users made by the kit**, a third choice in the Pilot users step, made the way the demo kit makes its
  traffic-generator user: a group, a department and 1 to 10 users (`zpov-pilot-1@<your domain>`…) straight in ZIA,
  with generated passwords in the keychain, so there's nothing to entitle or wait for. When ZIA refuses because the
  tenant keeps its users in ZIdentity ("UNMODIFIABLE … OneIdentityUserLogin"), apply says so and the next change list
  makes them in ZIdentity on `<vanity>.zslogin.net`, where ZIdentity can give them a password even when the company
  domain signs in through Okta. SAML tenants go to ZIdentity straight away; directory tenants are told to use their
  own group. This replaces the old "N test users" field, which refused any tenant with ZIdentity in front.
- **Entitlement first, as the demo kit learned.** 0.9.3 said a ZIdentity group reaches ZIA at a member's first
  sign-in; the demo kit's experience is that ZIdentity sends entitled users and groups within about a minute. Apply
  now checks the members' Internet & SaaS entitlement and stops at once with the fix if it's missing, otherwise waits
  up to three minutes (as the demo kit does). The "signs in once" customer action is gone.
- **Teardown empties the pilot group before deleting it.** Live ZIdentity refuses to delete a group with members
  ("Resource in use"); teardown now takes the remaining members out first (the users themselves are untouched), and
  a ZIdentity error no longer stops the rest of teardown.

## 0.9.3

From the live lab test:
- **A ZIdentity pilot group reaches ZIA at a member's first sign-in**, not when it's entitled: a live tenant showed ZIA
  holds none of its ZIdentity groups until one of their users signs in. The change list now has the customer action
  "One pilot user signs in once", and apply, preflight, status and the guide say so; apply looks for the group for
  15 seconds, not a minute, then stops and carries on next time.

## 0.9.2

- **One-line install, no security prompts.** `curl -fsSL …/releases/latest/download/install.sh | bash` on a Mac, or
  `irm …/install.ps1 | iex` in PowerShell, downloads the latest release, checks its SHA-256, installs uv if needed,
  installs the kit and opens the console. macOS Gatekeeper ("Apple could not verify…") and Windows SmartScreen only
  block files a browser downloaded, so this avoids both without code signing. The double-click installers stay, and
  the guides now say what to do when Gatekeeper or SmartScreen stops them.

## 0.9.1

From an independent review of 0.9.0's tenant writes, and the follow-ups:
- **The pilot group outlives every rule that uses it.** Teardown keeps the POV's ZIdentity group while any ZIA rule
  still applies to it (a POV rule the customer renamed and so kept, or one of theirs) or another product's POV object
  is left, and says which; deleting it then would leave a rule pointing at a group that no longer exists.
- **Fix drift after the group is deleted in ZIdentity** recreates it and re-scopes the POV's rules to the new group,
  instead of re-pointing them at the deleted one.
- **Nothing stranded by a settings change.** Teardown and status cover every product that still has objects in the
  ledger, and the pilot group choice can't change while the POV's ZIdentity group is in the tenant.
- **No delete while a job runs**, and one job at a time per POV. POV IDs are checked before they're used as folders.
- ZIdentity lists use its documented filters and paging (`name[like]`, `limit`, `offset`).
- **Terraform handover keeps everything in place as the customer's**, including objects Terraform can't import and
  the POV's ZIdentity group (its README says what to do with it), so the POV can be deleted afterwards.
- **Report a problem**: a link next to Download diagnostics opens the kit's GitHub issue form.
- Builds use the Node 24 GitHub actions and Ubuntu 24.04.

## 0.9.0

From the live lab test:
- **The kit can make the pilot group.** Pilot users step → **Create one for the POV in ZIdentity**: `ZPOV - pilot
  users`, with the users you name added to it (existing users are only added, never changed) and, in lab tenants,
  the users who don't exist yet created. It's in the change list like everything else, so it's written only after
  approval, scoped by the ledger, and deleted at teardown. ZIdentity's API can't grant entitlements, so granting
  Internet & SaaS (and Private Access) to the group is a customer action; Apply waits for ZIdentity to provision the
  group to ZIA, uses ZIA's copy for every POV rule (linked in the ledger, never changed or deleted by the kit), and if
  the entitlement isn't granted yet it stops and carries on next time without creating anything twice.
- **Pick instead of type.** The Pilot users step lists ZIA's groups and ZIdentity's users from the tenant (read-only),
  adds users by name or email, and shows who isn't in ZIdentity.
- **Delete a POV, after verifying.** Setup → Start a POV → **Delete…**, or `pov-kit delete`. It looks up every object
  the ledger still lists in the tenant (read-only) and refuses while any is there (or can't be checked); then it needs
  the POV's ID typed back, and removes the POV's folder, keychain secrets, Claude Desktop entry and backup from the
  laptop. The tenant is never touched.
- **Clearer ZDX 403.** Preflight says the API client has no ZDX role and where to add one (or to take ZDX out).

## 0.8.1

From the first checks against a live tenant:
- **Use your Zscaler MCP client.** Connect can take the OneAPI client of the Zscaler MCP server in Claude Desktop
  ("Use the client from Claude Desktop", or `pov-kit connect --from-claude-desktop`): the secret goes straight to the
  keychain, never shown or logged.
- **DLP engine names stay readable for Claude.** A live tenant flags Zscaler's own engine templates ("5 or more Credit
  Card Numbers", "GDPR - High Volume"...) as custom, so names-only use cases hid them all. Only the customer's own
  engines are hidden now. The test tenant returns engines the way the live one does.

## 0.8.0

Released like the AI Guard SE Demo Kit:
- **Double-click installers** for Mac and Windows (and uninstallers): uv if needed, the kit in
  `~/.zscaler-pov-kit/app`, a **Zscaler POV Console** desktop shortcut (an app on the Mac; desktop and Start menu on
  Windows) and the `pov-kit` command. `pov-kit install` / `uninstall` do the same from a terminal.
- **Updates button** in the console: checks the latest release (cached for 12 hours), shows its notes, installs it
  after checking its SHA-256, restarts the console, and rolls back one version. A git checkout is told to `git pull`.
  `pov-kit update` (`--check`, `--rollback`) does the same.
- **Releases publish themselves** when VERSION changes on main: the zip, an email-safe zip, the plugin, SHA256SUMS,
  latest.json, and three guides as Markdown and Word: the **SE deployment guide** (restructured like the demo kit's:
  overview, golden rules, prerequisites, parts with times, troubleshooting), a **customer overview** for the
  customer's security team, and a one-page **quick start**.

The console now matches the demo kit:
- Header: the **Updates** pill, the POV's state and end date, the **AI Guard policy switch** (once the POV's policy
  exists), a **Zscaler console** link, and a **light / dark / auto** theme toggle.
- The demo kit's layout, step titles and check list style (✓, !, ✗ with a "Fix:" line), and its **Logs** tab: filter
  by kind or text, pause, clear the view, click an entry for its details.

## 0.7.0

- **Claude Desktop's read-only access to the POV tenant** (`pov-kit mcp consent|install|remove|config|status|serve`,
  and a card in the console's Next steps). It uses Zscaler's MCP server (zscaler-mcp 0.15.4, pinned), started by the
  kit from the keychain with writes off, every write and start tool disabled, secret-returning reads disabled, and
  only the POV's products. The Claude Desktop entry holds no secret; handover removes it. Checked against the real
  server: 186 to 194 read tools offered, none that write. An optional view-only client (`connect --mcp`) is in the
  role spec.
- **A Claude plugin** that drives the kit (`tools/build_plugin.py`), with approval, apply and teardown always left to
  the SE and the customer.
- **ZPA customer ID** (`set customer_id`, or the Connect step): ZPA over OneAPI needs it; preflight warns without it.
- `--pov` works after the command too (`pov-kit mcp serve --pov ID`).

## 0.6.1

Fixes from an independent review of 0.6.0's safety-critical code:
- **Client Connector could edit the customer's default profile.** Its save is create-or-update, and the copied
  forwarding-profile actions (and nested app-profile settings) kept their IDs. Every body is now stripped of copied
  IDs, and the kit refuses to send one that still carries any. This was also true of 0.5's forwarding profile.
- **Client Connector profile names are now per POV** (they carry the POV ID's last part), apply never creates over a
  profile with the same name, and a new profile's ID is taken only from what appeared after the save.
- **recover** records an object without a description only when something certain ties it to the POV; prefix-only
  finds are listed, never recorded. It never reuses a key another active entry holds.
- **Teardown with --yes keeps adopted objects**; delete them with `--include-adopted`.
- **selftest** runs only on a POV marked as a lab POV (`new --lab`), does ZIA first, rechecks its pending state just
  before writing, and activates only after its own create and delete succeeded.
- **Names only** also covers accented names (no ASCII escaping before masking), upper- and lower-case variants, the
  customer's own DLP engines and isolation profile, and no longer sends the POV ID in request metadata.
- **Backups** run after each product during apply and even when apply or teardown fails; a restore refuses to
  replace a local ledger that has objects the backup lacks.
- **Recordings**: name-like fields are always replaced in exports (even in capitals), the POV ID is replaced,
  errors are redacted, and recordings are deleted at handover.

## 0.6.0

Nothing left behind:
- **`pov-kit recover`** finds a POV's objects in the tenant, read-only, by prefix and stamp, and rebuilds the
  ledger (`--write`), so teardown works even when the laptop that ran the POV is gone. Another POV's objects are
  left alone; objects found by name only are recorded as adopted.
- **Encrypted backups** of each POV's ledger, approval and change list to a synced folder, after every change
  (`pov-kit backup setup|now|restore`; scrypt and Fernet, passphrase in the keychain).
- **End dates and reminders.** Every POV has an end date; status warns in the last week and fails after it with
  objects still in the tenant. `pov-kit remind install` adds a daily desktop notification (Windows, Mac, Linux).

AI use cases:
- **Names only by default.** The customer's names, emails and domains are placeholders before anything leaves the
  laptop; replies are swapped back before validation. `ai.share full` needs its own agreement.
- Claude answers through a **tool with a fixed schema** (structured output); plain-text JSON is the fallback.
- **Refine** a proposal in words; the earlier version is kept in its history.
- A **use-case library**: save what worked (customer names taken out), reuse it in the next POV with no AI call;
  a shared folder works for a team.

Evidence and approval:
- **Executive summary** drafted by Claude from the results only (names removed), opening the report
  (`pov-kit report --summary`, or the Success criteria tab).
- **The customer approves on the change-list page**: its form saves an approval file bound to the change list's
  hash; `pov-kit approve --file` (or the Approval step) checks the hash before recording it.

Lab run and setup:
- **`pov-kit selftest --lab`**: read, create, read back and delete one harmless object per product.
- **API recording** (`pov-kit record on|export`) and replay tests that hold the fake tenant to real responses.
- **Client Connector app profile automated** (ported from the demo kit's setup_zcc), with plainer forwarding-profile
  copies on a bare 400 and a read-back check. Build-by-hand-and-adopt stays the fallback. Client Connector IDs are
  sent as integers.
- **Azure template** for the ZPA App Connectors (`pov-kit zpa template --cloud azure`), from Zscaler's Azure modules:
  the Marketplace image and plan, no public IPs, deny-all inbound.

## 0.5.0

- **Use cases across the product suite.** Besides ZIA rules, Claude can now propose, and the kit build after a fresh
  approval: a ZPA app (its own segment and allow or deny access rule for the pilot users, through the POV's
  connectors; refused if a domain is already a customer segment), an AI Guard app with its own key, rule and blocking
  policy (the customer's AI Guard apps and the POV's main policy stay as they are), ZDX deep traces on the pilot devices
  for a monitored app, and a report-only CASB DLP rule. Client Connector stays directions only.
- Discovery adds what the checks need: customer ZPA segment domains, the AI Guard detectors that can block, ZDX's
  monitored apps, and every DLP engine for CASB.
- Use-case tests can include AI Guard test prompts, run by `pov-kit test --api` with the use case's own key.
- Use cases' AI Guard keys go to the keychain and are deleted at teardown and handover.

## 0.4.0

- **Use cases from a prompt** (console: Use cases tab; CLI: `pov-kit usecase ask|list|show|accept|directions|discard`).
  Claude proposes changes, directions and a test; the kit validates every change against the tenant (allowed kinds
  and fields only, tenant categories, engines and file types, pilot-group scope, kit naming) and turns anything it
  won't build into directions with the reason. Accepted use cases join the change list, so the customer approves
  again before Apply. Each use case gets its own success criterion and probe tests.
- Claude is reached only through an AI Guard proxy (the demo kit's Anthropic app key, or `pov-kit ai connect`), so
  every request and reply is scanned by AI Guard. A blocked request says so.
- Nothing goes to Claude until the customer's agreement to share the discovery snapshot is recorded
  (`pov-kit ai consent --by`, or the Use cases tab). Model: `claude-sonnet-5-5` by default (`set ai.model`).

## 0.3.0

- **Browser console** (`pov-kit gui`) with the demo kit's look and its setup wizard pattern: start a POV, connect,
  pilot users, preflight, change list, approval, apply, next steps. Tabs for status and Fix drift, success criteria
  (API proofs, probe import, attestations, report), handover (Terraform or teardown) and logs (diagnostics zip).
  Same safety as the kit's console: 127.0.0.1 only, Host header checked, a per-run token on every call, and pages
  with customer data need the token too.
- **One API client by default.** Two-client mode stays a setting (`client_mode separate`).
- **Identity step** in discovery, across products: how pilot users sign in; each pilot user exists in ZIA and is in
  the pilot group; ZIdentity entitlements (Internet & SaaS, Private Access) read and checked automatically; the IdP's
  sign-in and MFA sites kept out of SSL inspection by an approved bypass rule placed above the inspect rule.
- ZPA can scope the access rule by a SAML attribute instead of a SCIM group (`zpa.scope saml`).
- Hosted DB test users (`identity.test_users`, up to 10) for tenants where ZIA keeps its own users; refused where
  ZIdentity or an IdP owns them. Passwords are made at apply, kept in the keychain, never in the change list;
  `pov-kit users --show`. The role spec asks for user management only when test users are chosen.
- ZIA discovery searches users, groups and departments by the POV prefix instead of listing every user.
- Settings are validated in one place for the CLI and the console.

## 0.2.0

Every product module, with the full lifecycle. Still for lab tenants until TESTPLAN.md is worked through.

- ZIA: firewall and DNS control rules, file type control, browser isolation (left out when the tenant has no
  isolation profile), a tenant-check custom URL category and a network service, all from the demo kit's template.
  The module is now one table of object kinds. Five new criteria (IS-TEN-01, IS-CBI-01, IS-FTC-01, IS-FW-01, IS-DNS-01)
  and probe tests for TCP ports and DNS.
- ZPA: App Connector group, provisioning key (secret to the keychain), server and segment groups, the POV app segment
  and an access rule for the pilot SCIM group, placed first. Discovery refuses an app the customer already publishes and
  warns about broad allow rules. `pov-kit zpa template` writes a CloudFormation template for two connectors.
- AI Guard: the demo kit's detection policy, a POV app, a Detection API key and an app-only rule. `pov-kit aiguard
  policy monitor|attacks|data` changes only the POV policy.
- ZDX: a deep trace on each pilot device; CASB/SSPM: a report-only CASB DLP rule on a connected SaaS tenant.
- Automated API proofs (`pov-kit test --api`) for ZPA, AI Guard, ZDX, CASB and Client Connector.
- Probe packs: `pov-kit probe-pack` fills in the POV's own values for the pilot devices.
- Terraform names checked against the provider docs: URL filtering rules, file type control rules, rule labels and
  firewall filtering rules confirmed; the rest are marked "check" in the export.
- Fixed: the POV's own CASB rule changed the plan after apply. A test now holds every product to that.
- Checks are labelled with their product.

## 0.1.0

First scaffold, for lab tenants.

- Safety core: ownership ledger (ID + prefix + description stamp), change list bound by SHA-256 with recorded approval,
  read-only and ledger-only guarded clients, activation guard, checks with exit codes 0/2/1.
- ZIA module: read-only discovery (activation status, sign-in mode, ZIdentity, pilot group, categories, DLP engines,
  Cloud App Control actions, name collisions, lookalikes), plan, apply (label first, rules at the top in template
  order, pilot group only), drift and Fix drift, teardown, Terraform export with import blocks.
- Client Connector module: Z-Tunnel 2.0 forwarding profile copied from the default; bare 400 falls back to build by hand
  and adopt by exact name. App profile by hand and adopt for now.
- Success-criteria catalog across ZIA, Client Connector, ZPA, AI Guard, ZDX and CASB/SSPM (12 criteria for v1).
- Probe for pilot devices (no keys), probe import, attestations, evidence report, customer change-list page.
- Diagnostics zip without secrets or customer object names; self-updater with SHA-256 check and rollback.
- Launchers from the AI Guard SE Demo Kit. Offline tests against a fake tenant.
