# Zscaler POV Kit

Stand up a proof of value in a **customer's** tenant, prove each success criterion with evidence, and leave the tenant
as you found it, or hand the configuration over as Terraform.

Built on the patterns of the [AI Guard SE Demo Kit](https://github.com/Paulie631/aiguard-se-kit), with a customer-tenant
safety model on top. Design: [docs/DESIGN.md](docs/DESIGN.md). Status: **0.2.0**: every product module is built and
tested offline against a fake tenant. Run it in a lab tenant first ([TESTPLAN.md](TESTPLAN.md)); not yet for customer
tenants.

## What it will and won't do in a customer tenant

- **Discovery is read-only.** A view-only API client, and a guard in the code that refuses any write before it is sent.
- **Only an approved change list is applied.** `plan` writes the list (`plan.html` for the customer). `apply` refuses
  if the plan made from the tenant today differs from the one approved, by SHA-256.
- **It only touches what it created.** Each object's ID goes in the POV's ledger, its name carries the prefix (`ZPOV:`),
  and its description carries `zpov:<pov-id>`. Update and delete need all three. Lookalikes are left alone.
- **It never edits the customer's objects.** Changes to them (malware policy, ZIdentity entitlements, installing
  Client Connector) are *customer actions* in the change list: the kit checks them, a person makes them.
- **Rules apply to the customer's pilot group only**, placed at the top (or bottom) of each rule type, as the change
  list says.
- **It never activates someone else's work.** If ZIA has pending changes, apply and teardown stop (CASB DLP rules
  are ZIA policy, so they follow the same rule).
- **It leaves cleanly.** `handover teardown` deletes the ledger objects; `handover terraform` exports them with
  `import` blocks so the customer adopts them in place. Both delete the POV's secrets and discovery data.

## Quickstart (lab tenant)

```
./pov-kit new "Acme Corp" --products zia,zcc       # .\pov-kit.cmd on Windows
./pov-kit set vanity_domain acme                   # the acme in acme.zslogin.net
./pov-kit set pilot_group "POV Pilot"              # an existing group of pilot users
./pov-kit role-spec                                # the two API clients to create
./pov-kit connect --discovery                      # client ID, then the secret (to the keychain)
./pov-kit preflight
./pov-kit plan                                     # show the customer plan.html
./pov-kit approve --by "Jane Doe, CISO"
./pov-kit connect --apply
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
