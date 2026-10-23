# Zscaler POV Kit

Stand up a proof of value in a **customer's** tenant, prove each success criterion with evidence, and leave the tenant
as you found it, or hand the configuration over as Terraform.

Built on the patterns of the [AI Guard SE Demo Kit](https://github.com/Paulie631/aiguard-se-kit), with a customer-tenant
safety model on top. Design: [docs/DESIGN.md](docs/DESIGN.md). Status: **0.9.14**: every product module, the identity step,
the browser console and AI use cases are built and tested offline against a fake tenant. Run it in a lab tenant first ([TESTPLAN.md](TESTPLAN.md)); not yet for customer
tenants.

## Install

Mac (Terminal):
```
curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.sh | bash
```
Windows (PowerShell):
```
irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.ps1 | iex
```
No Gatekeeper or SmartScreen prompts: the terminal fetches the release and checks its SHA-256. Or download
`zscaler-pov-kit-<version>.zip` from the [latest release](https://github.com/Paulie631/zscaler-pov-kit/releases/latest),
unzip it, and double-click **Install Zscaler POV Kit** (`.command` on Mac, `.cmd` on Windows). It installs uv if
needed, copies the kit to `~/.zscaler-pov-kit/app`, adds a **Zscaler POV Console** shortcut and the `pov-kit` command,
and opens the console. The **Updates** button in the console installs new releases (verified against their SHA-256)
and rolls back. Details: [INSTALL.md](INSTALL.md). Each release also carries the SE deployment guide, a customer
overview for the customer's security team, and a one-page quick start, as Word and Markdown.

## What it will and won't do in a customer tenant

- **One API client by default.** Nothing is written before the customer approves the change list, and the code
  keeps discovery read-only. Two-client mode (view-only first, write after approval) is a setting for security
  teams that want it.
- **Discovery is read-only.** A view-only API client, and a guard in the code that refuses any write before it is sent.
- **Only an approved change list is applied.** `plan` writes the list (`plan.html` for the customer). `apply` refuses
  if the plan made from the tenant today differs from the one approved, by SHA-256.
- **It only touches what it created.** Each object's ID goes in the POV's ledger, its name carries the prefix (`ZPOV:`),
  and its description carries `zpov:<pov-id>`. Update and delete need all three. Lookalikes are left alone.
- **It never edits the customer's objects.** Changes to them (malware policy, ZIdentity entitlements, installing
  Client Connector) are *customer actions* in the change list: the kit checks them, a person makes them.
- **Rules apply to the customer's pilot group only**, placed at the top (or bottom) of each rule type, as the change
  list says. The identity step checks the pilot users exist and are entitled in every product, and keeps the
  customer's IdP and MFA sites out of SSL inspection so the POV can't break sign-in.
- **It never activates someone else's work.** If ZIA has pending changes, apply and teardown stop (CASB DLP rules
  are ZIA policy, so they follow the same rule).
- **It leaves cleanly.** `handover teardown` deletes the ledger objects; `handover terraform` exports them with
  `import` blocks so the customer adopts them in place. Both delete the POV's secrets and discovery data.

## Quickstart (lab tenant)

```
./pov-kit gui                                      # .\pov-kit.cmd gui on Windows
```

The console opens in your browser (this computer only). Its **Setup** tab walks through eight steps, like the demo
kit's wizard:

1. **Start a POV**: customer, products, prefix, end date, and one API client (recommended) or two.
2. **Connect**: copy the role spec for the customer's admin, then enter the vanity domain, client ID and secret
   (straight to the keychain).
3. **Pilot users**: the pilot group (or Hosted DB test users), their emails, the IdP, and per-product details such as
   the ZPA app and whether ZPA scopes by SCIM group or SAML attribute.
4. **Preflight**: read-only checks of every product and of the pilot users across products.
5. **Change list**: everything the kit will create, who it affects, and what only the customer does.
6. **Approval**: who approved this exact change list, recorded here or by the customer on the change-list page
   (it has an approval form that saves a file you import).
7. **Apply**: live progress, then a status check.
8. **Next steps**: customer actions, the probe pack, the ZPA connector template (AWS or Azure) and key, the AI Guard
   profile, test users' sign-ins.

**Status** compares the tenant with what was approved (and fixes drift on POV objects only) and holds the safety net
(end date, encrypted backups, reminders), **Success criteria** runs the API proofs, imports probe results, records
attestations, drafts the executive summary and builds the report, **Handover** exports to Terraform or tears down,
and **Logs** holds the activity log, the diagnostics zip and the lab tools (self-test, API recording).

Everything is also on the command line:

```
./pov-kit new "Acme Corp" --products zia,zcc
./pov-kit set vanity_domain acme
./pov-kit set pilot_group "POV Pilot"
./pov-kit set pilot_emails jane@acme.com,raj@acme.com
./pov-kit role-spec
./pov-kit connect                                  # one client; --discovery / --apply for two
./pov-kit preflight
./pov-kit plan                                     # show the customer plan.html
./pov-kit approve --by "Jane Doe, CISO"           # or --file approval-....json from the customer
./pov-kit apply
./pov-kit status                                   # --fix repairs drift on POV objects only
```

Product extras: `./pov-kit set zpa.domains hr.acme.internal` (the POV app) and `./pov-kit zpa template [--cloud
azure]` (its App Connectors on AWS or Azure); `./pov-kit aiguard policy attacks` (what the POV's AI Guard policy blocks); `./pov-kit set
pilot_emails jane@acme.com,raj@acme.com` (for ZDX and device checks).

`./pov-kit probe-pack` writes this POV's probe tests. On a pilot device with Client Connector signed in:
`./pov-kit probe --pack pov-probe-pack-<id>.json` (no keys), then send the results file to the SE:

```
./pov-kit import-probe pov-probe-ab12cd34.json
./pov-kit test --api                               # automated API proofs
./pov-kit attest IS-URL-01 --note "Blocks seen in Web Insights for the pilot user"
./pov-kit test
./pov-kit report --summary                         # report.html, opened by Claude's executive summary
./pov-kit handover teardown                        # or: handover terraform
```

`./pov-kit diagnostics` writes a zip for the kit owner: no secrets, no customer object names.

## The safety net: nothing left behind

- **End date.** Every POV has one (30 days unless `--ends` or `set ends`). Status warns in the last week and fails
  once it has passed with POV objects still in the tenant.
- **Reminders.** `./pov-kit remind install` adds a daily scheduled task (Task Scheduler, a LaunchAgent or cron) that
  reads only the POV folders on this laptop and shows a notification when a POV is ending, overdue or not backed up.
- **Encrypted backups.** `./pov-kit backup setup ~/OneDrive/pov-backups` asks for a passphrase (keep it in your
  password manager) and, after every apply, Fix drift, teardown and handover, writes each POV's ledger, approval and
  change list there, encrypted. On a new laptop: `./pov-kit backup restore <pov-id>`, then `connect`.
- **Recover without a backup.** `./pov-kit recover <pov-id> --customer "Acme Corp" --products zia,zpa` makes an empty
  POV with the same ID; after `connect`, `./pov-kit recover <pov-id>` sweeps the tenant read-only for objects with the
  prefix and that POV's stamp, and `--write` records them so teardown can remove them. Objects without a description
  are recorded (as adopted) only when something certain ties them to the POV: a Client Connector profile with the
  POV's own name, a provisioning key for its stamped connector group, an AI Guard rule pointing at its stamped policy.
  Prefix-only finds are listed for a person to check, never recorded; another POV's objects are never touched.
  Teardown deletes adopted objects only with `--include-adopted` (or a yes in the console); `--yes` alone keeps them.

## Before a customer: the lab tools

- `./pov-kit selftest --lab` on a POV for your own lab tenant (start it with `./pov-kit new "Lab" --lab`): reads every product, then creates, reads back and deletes one
  harmless object per product (a ZIA label, a disabled ZPA segment group, an AI Guard app).
- `./pov-kit record on` saves every API call and response, redacted, in the POV folder; `./pov-kit record export
  lab-1` turns them into `tests/fixtures/lab-1.jsonl` (field names, types and Zscaler's own values only). The offline
  tests then check the fake tenant against the real API and run discovery on the recording.

## Use cases from a prompt

In the console's **Use cases** tab (or `pov-kit usecase ask "..."`), describe what the customer wants to see, for
example "marketing can use ChatGPT but can't upload files to it". Claude, reached through your AI Guard proxy, reads
the tenant snapshot and proposes:

- **changes the kit can build**, in any product of the POV:

  | Product | What a use case can add |
  |---|---|
  | ZIA | URL filtering (categories or a list of sites), SSL inspection, Cloud App Control, file type control, DLP and DNS control rules |
  | ZPA | another private app: its own application segment (in the POV's segment and server groups, through the POV's connectors) and its own allow or deny access rule |
  | AI Guard | its own app, Detection API key, rule and policy, with every detector on and the named ones blocking |
  | ZDX | a deep trace on each pilot device, for an app ZDX already monitors |
  | CASB | a report-only CASB DLP rule over the connected SaaS tenant |
  | Client Connector | directions only: profile changes reach devices, and its API sometimes refuses new profiles |

  The kit checks every value against that product's discovery (categories, engines, file types, detectors, ZDX apps,
  and that a ZPA domain isn't already a customer segment), scopes each object to the pilot users and names it; Claude
  can't widen scope or touch the customer's objects. **Add to the change list** puts them in the plan, so the customer
  approves again before Apply builds them; teardown and the handover remove them with the rest.
- **directions for a person**, for everything else (Client Connector, tenant-wide settings, products outside the POV)
  and for any change that failed the kit's checks, with the reason.
- **a test**: a success criterion (UC-01, UC-02...) with probe tests, AI Guard test prompts (scanned through the
  Detection API with the use case's own key by `pov-kit test --api`), or an attestation, proved in the report like the
  catalog's.

**What Claude sees.** By default the customer's names, emails and domains are replaced by placeholders on your laptop
before anything is sent (`ai.share names_only`); Claude sees the policy's shape, and its reply is swapped back before
the kit checks it. `pov-kit set ai.share full` sends the snapshot as discovery read it, and needs its own agreement.

**Refine, then reuse.** Refine a proposal in words ("make it Caution, not Block"); the earlier version is kept.
**Save to library** keeps a use case that worked, with the customer's names taken out, for the next POV: using it
checks it against the new tenant and makes no AI call. Point the library at a shared folder for the team with
`pov-kit usecase library --folder PATH`. Claude answers through a fixed tool format, so its replies arrive as
structured data rather than text to parse.

Before the first use, record the customer's agreement: Claude reads the discovery snapshot (names replaced, unless
you choose otherwise), which travels through your AI Guard tenant to Anthropic. The proxy key is your AI Guard demo kit's Anthropic app key if it's on this
computer, or one you save with `pov-kit ai connect`; your Anthropic key stays in your own AI Guard tenant.

## Ask Claude about the tenant (read-only)

During the POV, Claude Desktop can read the customer's tenant through Zscaler's own MCP server ("why was Jane
blocked?", "what did the pilot group use today?", "why is this device's ZDX score down?"):

```
./pov-kit mcp consent --by "Jane Doe, CISO"        # the customer agrees: these requests don't go through AI Guard
./pov-kit mcp install                              # adds zscaler-pov-<id> to Claude Desktop; quit and reopen it
./pov-kit mcp remove                               # handover removes it anyway
```

The entry holds no secret: it runs `pov-kit --pov <id> mcp serve`, which takes the credentials from the keychain and
starts `zscaler-mcp` (pinned) with writes off whatever the environment says, every create, update, delete, activate
and start tool disabled, the reads that return secrets disabled (a device's one-time password, PRA and VPN
credentials), and only the POV's products. It uses the most read-only client the POV has: a view-only client from
`pov-kit connect --mcp` (in the role spec as optional), else the discovery client, else the main one. Writes to the
tenant still go only through the approved change list. `pov-kit mcp config` prints the entry for other MCP clients.

## Let Claude drive the kit

`python tools/build_plugin.py` builds `dist/zscaler-pov-kit.plugin` (a skill plus a copy of the kit). Installed in the
Claude desktop app, it lets you say "run preflight for Acme", "what's left for the customer?", "build the report".
Claude never approves, applies or tears down without you saying so, and never asks for a secret in chat.

## Products and criteria

Choose products with `pov-kit new "<customer>" --products zia,zcc,zpa,aiguard,zdx,casb` (or `pov-kit set products`).
Every module has the full lifecycle: read-only discovery, a plan in the change list, apply, drift, teardown.

| Module | What the POV creates (pilot group only) | Criteria | Automated API proofs |
| --- | --- | --- | --- |
| ZIA | Rule label, tenant-check URL category, network service; URL filtering, isolation, SSL inspection, Cloud App Control, file type control, DLP, firewall and DNS rules | 15 | none yet (attest log checks) |
| Client Connector | Z-Tunnel 2.0 forwarding profile (copy of the default); Windows app profile, built by hand and adopted | 2 | profiles present, pilot devices registered |
| ZPA | App Connector group, provisioning key, server and segment groups, the POV app segment, an access rule for the pilot SCIM group; AWS template for 2 connectors | 3 | connectors connected, rule scoped, no broad allow rules |
| AI Guard | The demo kit's detection policy (starts in Monitor), a POV app, a Detection API key, a rule for that app | 2 | Detection API scans of the kit's attack and data-leak prompts |
| ZDX | A 15-minute deep trace on each pilot device | 1 | pilot devices report ZDX scores |
| CASB/SSPM | A report-only CASB DLP rule on a SaaS tenant the customer connected | 1 | SaaS scan configured for that tenant |

Criteria live in `povkit/catalog/<product>.json` (24 in all). `pov-kit test --api` runs the automated proofs; where a
product has none, an attestation stands in and the report says so.

## For maintainers

**Releasing:** bump `VERSION` in `povkit/__init__.py` (and the plugin's `plugin.json`), add a `## <version>` section to
CHANGELOG.md, and push to main. The release workflow runs the tests, then publishes `zscaler-pov-kit-<v>.zip`, an
email-safe zip, the plugin, SHA256SUMS.txt, latest.json (what the Updates button reads) and the three guides as Markdown
and Word. `python tools/package.py` and `python tools/build_guide.py` build the same files locally into `dist/`.


- Offline tests: `uv run --with pytest --with requests --with keyring pytest -q` (a fake tenant records every call, so
  the tests prove what the kit never touches). CI runs them on Windows, macOS and Linux.
- A new product: a module in `povkit/products/` implementing `Product` (base.py) and a catalog file. It gets a guarded
  client from the core and never talks to the tenant directly.
- Console paths live in `povkit/console_paths.json`, each with a last-verified date. Fix a moved menu there once.
- Releases follow the kit: bump `VERSION` in `povkit/__init__.py`, add a `## <version>` section to CHANGELOG.md,
  update `docs/DEPLOYMENT-GUIDE.md` in the same branch. The release workflow and self-updater use `latest.json` with a
  SHA-256, as the kit does (release workflow: to do).
