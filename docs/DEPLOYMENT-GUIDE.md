# Zscaler POV Kit: SE deployment guide

Version 0.1.0. This guide ships with the kit and changes in the same branch as the behavior it describes.

## Before the POV

1. Agree the success criteria with the customer from the catalog (`povkit/catalog/`); record them with
   `pov-kit set criteria IS-URL-01,IS-SSL-01,...`.
2. Ask the customer for a pilot group of real users from their own directory, and one or more pilot devices.
3. Start the POV: `pov-kit new "<customer>" --products zia,zcc`, then `set vanity_domain` and `set pilot_group`.
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
6. Work through the customer actions with the admin, then `pov-kit status`.

## During the POV

- On each pilot device, with Client Connector signed in as a pilot user: `pov-kit probe`. Import each results file
  with `pov-kit import-probe`.
- Record what people see in the console with `pov-kit attest <criterion> --note "..." [--file screenshot.png]`.
- Run `pov-kit status` before every customer session; `--fix` repairs only the POV's own objects.

## Closing

1. `pov-kit report` and give the customer `report.html` (or its PDF).
2. Agree the exit with the customer: `pov-kit handover teardown`, or `pov-kit handover terraform` to keep the
   configuration. Both remove the POV's secrets and discovery data from your laptop.
3. Remind the customer to delete the POV's two API clients in the console.
