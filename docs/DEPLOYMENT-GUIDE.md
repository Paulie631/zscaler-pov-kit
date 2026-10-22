# Zscaler POV Kit: SE deployment guide

Version 0.7.0. This guide ships with the kit and changes in the same branch as the behavior it describes.

Run `pov-kit gui` and follow the console's Setup tab; every step below has a matching wizard step. The commands are
the same steps on the command line.

## Once, on your laptop

- `pov-kit backup setup <a folder synced off the laptop>` (OneDrive, Google Drive, iCloud), with a passphrase you keep
  in your password manager. Every POV is then backed up, encrypted, after every change.
- `pov-kit remind install`: a daily notification when a POV is ending, overdue, or not backed up.
- In your own lab tenant: `pov-kit new "Lab" --lab`, connect it, then `pov-kit selftest --lab`.
- Optional: install the plugin (`python tools/build_plugin.py`, then open `dist/zscaler-pov-kit.plugin`) so Claude can
  run the kit for you.

## Before the POV

1. Agree the success criteria with the customer from the catalog (`povkit/catalog/`); record them with
   `pov-kit set criteria IS-URL-01,IS-SSL-01,...`.
2. Ask the customer for a pilot group of real users from their own directory, and one or more pilot devices.
3. Start the POV with the products in scope and its end date: `pov-kit new "<customer>" --products
   zia,zcc,zpa,aiguard,zdx,casb --ends YYYY-MM-DD`, then
   `set vanity_domain`, `set pilot_group` and `set pilot_emails`.
   - ZPA: `set zpa.domains` and `set zpa.tcp_ports` for the POV app, and `set zpa.group` if its SCIM group has
     another name.
   - CASB: the customer connects a SaaS tenant (an OAuth grant) before the kickoff; `set casb.tenant` picks one.
4. Send the role spec (console: Connect, Copy the role spec; or `pov-kit role-spec`) to the customer's admin. By
   default they create **one** client at kickoff; in two-client mode, a view-only client now and the apply client
   after approval. Or they give you a temporary admin login to create it yourself.
5. Agree the pilot users: a group from their directory and the members' emails. If ZIA keeps its own users and there
   is no group yet, the POV can create up to 10 Hosted DB test users instead. For ZPA, check whether the IdP sends
   SCIM groups; if not, agree a SAML attribute and value that marks pilot users.

## Kickoff session (with the customer's admin)

1. Connect, then Preflight. Fix every FAIL before going on: missing ZIdentity entitlements, pilot users outside the
   group, an unrecognised IdP (choose it in Pilot users so its sign-in sites stay out of SSL inspection).
2. `pov-kit plan`. Walk the admin through `plan.html`: every object, who it affects, where it sits, and the customer
   actions only they make.
3. When they agree: `pov-kit approve --by "<name, title>"`. Or send them `plan.html`: its approval form saves a file
   they send back, and `pov-kit approve --file <file>` checks it's for this exact change list. Any later change to
   the plan needs a fresh approval.
4. Apply. (Two-client mode: the admin creates the apply client first, entered at the Approval step.)
5. Apply creates both Client Connector profiles. If Client Connector refuses them even in their plainest form (a
   bare 400), build them from the printed spec, then `pov-kit status --fix` adopts them.
6. ZPA: `pov-kit zpa template --show-key` (add `--cloud azure` for Azure); the customer deploys it in their account
   (AWS: the App Connector AMI from the Marketplace; Azure: accept the image terms once). Connectors show up within
   about 15 minutes.
7. AI Guard: the policy starts in Monitor. `pov-kit aiguard policy attacks` (or `data`) when the customer wants to see
   blocking.
8. Work through the customer actions with the admin, then `pov-kit status`.

## During the POV

- **New use cases.** When the customer asks "can you show...?", check the library first (no AI call), then type it
  in the console's Use cases tab. Before the first one, record their agreement to share the discovery snapshot with
  Claude through your AI Guard tenant: with names replaced (the default), or in full if they prefer. Refine a
  proposal in words until it's right, and save what worked to the library. Review
  the proposal with them; **Add to the change list**, then make the change list again, get it approved and Apply.
  Directions go to whoever owns that setting. Use cases work in every product of the POV: a ZPA app needs the POV's
  App Connectors running, a ZDX trace needs pilot devices reporting, a CASB rule needs a connected SaaS tenant.

- **Ask Claude about the tenant.** If the customer agrees, `pov-kit mcp consent --by "<name, title>"` and `pov-kit mcp
  install`, then reopen Claude Desktop. It can read, never write. Ask the customer for the optional view-only client
  in the role spec (`pov-kit connect --mcp`) so it doesn't use the main client.

- `pov-kit probe-pack`, then on each pilot device, signed in to Client Connector as a pilot user:
  `pov-kit probe --pack <file>`. Import each results file with `pov-kit import-probe`.
- `pov-kit test --api` runs the automated API proofs (connectors, AI Guard scans, ZDX scores, SaaS scans).
- Record what people see in the console with `pov-kit attest <criterion> --note "..." [--file screenshot.png]`.
- Run `pov-kit status` before every customer session; `--fix` repairs only the POV's own objects.

## Closing

1. `pov-kit report --summary` (Claude drafts the executive summary from the results) and give the customer
   `report.html` (or its PDF).
2. Agree the exit with the customer: `pov-kit handover teardown`, or `pov-kit handover terraform` to keep the
   configuration. Both remove the POV's secrets and discovery data from your laptop.
3. ZPA: delete the connector stack in AWS and the enrolled connectors in the ZPA console first; teardown keeps the
   connector group until they're gone.
4. Remind the customer to delete the POV's two API clients in the console.
