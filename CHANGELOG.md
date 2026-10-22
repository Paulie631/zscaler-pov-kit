# Changelog

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
