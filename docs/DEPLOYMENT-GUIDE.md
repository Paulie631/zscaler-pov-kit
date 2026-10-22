# Zscaler POV Kit: SE deployment guide

Version 0.2.0. This guide ships with the kit and changes in the same branch as the behavior it describes.

## Before the POV

1. Agree the success criteria with the customer from the catalog (`povkit/catalog/`); record them with
   `pov-kit set criteria IS-URL-01,IS-SSL-01,...`.
2. Ask the customer for a pilot group of real users from their own directory, and one or more pilot devices.
3. Start the POV with the products in scope: `pov-kit new "<customer>" --products zia,zcc,zpa,aiguard,zdx,casb`, then
   `set vanity_domain`, `set pilot_group` and `set pilot_emails`.
   - ZPA: `set zpa.domains` and `set zpa.tcp_ports` for the POV app, and `set zpa.group` if its SCIM group has
     another name.
   - CASB: the customer connects a SaaS tenant (an OAuth grant) before the kickoff; `set casb.tenant` picks one.
4. Send `pov-kit role-spec` to the customer's admin. They create the **discovery** client now and the **apply** client
   after approval, or give you a temporary admin login to create them yourself.

## Kickoff session (with the customer's admin)

1. `pov-kit connect --discovery`, then `pov-kit preflight`. Fix every FAIL before going on.
2. `pov-kit plan`. Walk the admin through `plan.html`: every object, who it affects, where it sits, and the customer
   actions only they make.
3. When they agree: `pov-kit approve --by "<name, title>"`. Any later change to the plan needs a fresh approval.
4. The admin creates the apply client; `pov-kit connect --apply`; `pov-kit apply`.
5. If Client Connector refused the forwarding profile (a bare 400), build both profiles from the printed spec, then
   `pov-kit status --fix` adopts them.
6. ZPA: `pov-kit zpa template --show-key`; the customer deploys the stack in their AWS account (the App Connector
   AMI from the Marketplace, a subnet that reaches the app and Zscaler). Connectors show up within about 15 minutes.
7. AI Guard: the policy starts in Monitor. `pov-kit aiguard policy attacks` (or `data`) when the customer wants to see
   blocking.
8. Work through the customer actions with the admin, then `pov-kit status`.

## During the POV

- `pov-kit probe-pack`, then on each pilot device, signed in to Client Connector as a pilot user:
  `pov-kit probe --pack <file>`. Import each results file with `pov-kit import-probe`.
- `pov-kit test --api` runs the automated API proofs (connectors, AI Guard scans, ZDX scores, SaaS scans).
- Record what people see in the console with `pov-kit attest <criterion> --note "..." [--file screenshot.png]`.
- Run `pov-kit status` before every customer session; `--fix` repairs only the POV's own objects.

## Closing

1. `pov-kit report` and give the customer `report.html` (or its PDF).
2. Agree the exit with the customer: `pov-kit handover teardown`, or `pov-kit handover terraform` to keep the
   configuration. Both remove the POV's secrets and discovery data from your laptop.
3. ZPA: delete the connector stack in AWS and the enrolled connectors in the ZPA console first; teardown keeps the
   connector group until they're gone.
4. Remind the customer to delete the POV's two API clients in the console.
