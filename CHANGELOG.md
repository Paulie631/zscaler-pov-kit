# Changelog

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
