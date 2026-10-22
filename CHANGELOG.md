# Changelog

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
