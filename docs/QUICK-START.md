# Zscaler POV Kit: Quick Start

*One page for SEs. The full steps are in the SE Deployment Guide.*

## Install (5 minutes)

1. Download `zscaler-pov-kit-<version>.zip` from the latest release on GitHub. Unzip it (Windows: right-click → Extract
   All).
2. Double-click **Install Zscaler POV Kit** (`.command` on Mac, `.cmd` on Windows). Press Return or a key to start.
3. From then on, open **Zscaler POV Console** from your desktop. Keep its terminal window open while you work.

## Once

- **Status → Safety net:** turn on encrypted backups (a synced folder and a passphrase in your password manager) and
  daily reminders.
- Run the self-test in your own lab tenant: Setup → start a POV marked as lab → **Logs → Lab tools → Run the
  self-test**.

## Your first POV in 10 steps

1. **Setup → Start a POV:** customer, products, end date.
2. **Connect:** copy the role spec to the customer's admin; enter the client ID and secret they create.
3. **Pilot users:** the pilot group, members' emails, their identity provider, product details.
4. **Preflight:** fix every FAIL (each one says how).
5. **Change list:** walk the admin through it, or send them the change-list page.
6. **Approval:** record who approved it, or import the approval file they saved from the page.
7. **Apply:** watch it run, then check the status.
8. **Next steps:** customer actions, the probe pack for pilot devices, the ZPA connector template.
9. **Success criteria:** import probe results, run the API proofs, record attestations, draft the summary, build the
   report.
10. **Handover:** export to Terraform, or remove the POV, before its end date.

## Every customer session

- **Status → Check now.** Fix drift repairs only the POV's own objects.
- New "can you show…?" ideas go in **Use cases**: library first, then Claude. They need a fresh approval before Apply.

## Never

- Approve, apply or tear down without the customer's say-so.
- Paste a secret into chat, email or a ticket.
- Run the self-test in a customer's tenant.

## Help

- **Updates** button: install the newest version, or roll back one.
- **Logs → Download diagnostics:** a zip without secrets or customer names, for the kit owner.
- The SE Deployment Guide has a troubleshooting table.
