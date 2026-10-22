# Zscaler POV Kit

Stand up a proof of value in a **customer's** tenant, prove each success criterion with evidence, and leave the tenant
as you found it, or hand the configuration over as Terraform.

Built on the patterns of the [AI Guard SE Demo Kit](https://github.com/Paulie631/aiguard-se-kit), with a customer-tenant
safety model on top. Design: [docs/DESIGN.md](docs/DESIGN.md). Status: **0.4.0**: every product module, the identity step,
the browser console and AI use cases are built and tested offline against a fake tenant. Run it in a lab tenant first ([TESTPLAN.md](TESTPLAN.md)); not yet for customer
tenants.

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

1. **Start a POV**: customer, products, prefix, and one API client (recommended) or two.
2. **Connect**: copy the role spec for the customer's admin, then enter the vanity domain, client ID and secret
   (straight to the keychain).
3. **Pilot users**: the pilot group (or Hosted DB test users), their emails, the IdP, and per-product details such as
   the ZPA app and whether ZPA scopes by SCIM group or SAML attribute.
4. **Preflight**: read-only checks of every product and of the pilot users across products.
5. **Change list**: everything the kit will create, who it affects, and what only the customer does.
6. **Approval**: who approved this exact change list.
7. **Apply**: live progress, then a status check.
8. **Next steps**: customer actions, the probe pack, the ZPA connector template and key, the AI Guard profile, test
   users' sign-ins.

**Status** compares the tenant with what was approved (and fixes drift on POV objects only), **Success criteria**
runs the API proofs, imports probe results, records attestations and builds the report, **Handover** exports to
Terraform or tears down, and **Logs** holds the activity log and the diagnostics zip.

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
./pov-kit approve --by "Jane Doe, CISO"
./pov-kit apply
./pov-kit status                                   # --fix repairs drift on POV objects only
```

Product extras: `./pov-kit set zpa.domains hr.acme.internal` (the POV app) and `./pov-kit zpa template` (its App
Connectors on AWS); `./pov-kit aiguard policy attacks` (what the POV's AI Guard policy blocks); `./pov-kit set
pilot_emails jane@acme.com,raj@acme.com` (for ZDX and device checks).

`./pov-kit probe-pack` writes this POV's probe tests. On a pilot device with Client Connector signed in:
`./pov-kit probe --pack pov-probe-pack-<id>.json` (no keys), then send the results file to the SE:

```
./pov-kit import-probe pov-probe-ab12cd34.json
./pov-kit test --api                               # automated API proofs
./pov-kit attest IS-URL-01 --note "Blocks seen in Web Insights for the pilot user"
./pov-kit test
./pov-kit report                                   # report.html, print to PDF
./pov-kit handover teardown                        # or: handover terraform
```

`./pov-kit diagnostics` writes a zip for the kit owner: no secrets, no customer object names.

## Use cases from a prompt

In the console's **Use cases** tab (or `pov-kit usecase ask "..."`), describe what the customer wants to see, for
example "marketing can use ChatGPT but can't upload files to it". Claude, reached through your AI Guard proxy, reads
the tenant snapshot and proposes:

- **changes the kit can build**: ZIA URL filtering (categories or a list of sites), SSL inspection, Cloud App Control,
  file type control, DLP and DNS control rules. The kit checks every value against the tenant, scopes each rule to the
  pilot group and names it; Claude can't widen scope or touch the customer's objects. **Add to the change list** puts
  them in the plan, so the customer approves again before Apply builds them.
- **directions for a person**, for everything else (other products, tenant-wide settings) and for any change that
  failed the kit's checks, with the reason.
- **a test**: a success criterion (UC-01, UC-02...) with probe tests or an attestation, proved in the report like the
  catalog's.

Before the first use, record the customer's agreement: Claude reads the full discovery snapshot, which travels through
your AI Guard tenant to Anthropic. The proxy key is your AI Guard demo kit's Anthropic app key if it's on this
computer, or one you save with `pov-kit ai connect`; your Anthropic key stays in your own AI Guard tenant.

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

- Offline tests: `uv run --with pytest --with requests --with keyring pytest -q` (a fake tenant records every call, so
  the tests prove what the kit never touches). CI runs them on Windows, macOS and Linux.
- A new product: a module in `povkit/products/` implementing `Product` (base.py) and a catalog file. It gets a guarded
  client from the core and never talks to the tenant directly.
- Console paths live in `povkit/console_paths.json`, each with a last-verified date. Fix a moved menu there once.
- Releases follow the kit: bump `VERSION` in `povkit/__init__.py`, add a `## <version>` section to CHANGELOG.md,
  update `docs/DEPLOYMENT-GUIDE.md` in the same branch. The release workflow and self-updater use `latest.json` with a
  SHA-256, as the kit does (release workflow: to do).
