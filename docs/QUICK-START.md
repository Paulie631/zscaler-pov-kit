# Zscaler POV Kit: Quick Start

*One page for Zscaler and partner SEs. The full steps are in the SE Deployment Guide.*

## Install (5 minutes)

1. Paste one line:
   - **Mac (Terminal):** `curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.sh | bash`
   - **Windows (PowerShell):** `irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.ps1 | iex`
2. Or download the zip from the latest release, unzip it and double-click **Install Zscaler POV Kit**. Mac says "Not
   Opened"? **Done**, then System Settings → Privacy & Security → **Open Anyway**. Windows: **More info → Run anyway**.
3. From then on, open **Zscaler POV Console** from your desktop. Keep its terminal window open while you work.

## Once

- Prove the kit in your own lab tenant: **Setup → Start a POV**, tick **More options → This is my own lab tenant**,
  **Quick start**, then **Logs → Lab tools → Run the self-test**.
- Then **Status → Safety net:** turn on encrypted backups (a synced folder and a passphrase in your password manager)
  and daily reminders. (The panel appears once a POV exists.)

## Your first POV

1. **Before the kickoff:** Setup → Start a POV: customer and products, then **Step by step** → Connect → **Copy the
   role spec** for the customer's admin.
2. **At the kickoff, on Connect:** the API client they created (with ZPA, the customer ID: Administration → API →
   Legacy API → Private Access API → Copy ID), then **Quick start from here**. The kit fills in the rest from the tenant,
   read-only, runs preflight and opens the change list. Fix anything under **Needs you**; products not ready yet are
   **added later** without holding up the rest.
3. **Change list → Approval:** walk the admin through it, or send them the customer page and import their approval.
4. **Apply:** watch it run, then check the status.
5. **Who tests** (Pilot users, any time): a group they have, people you name, or test accounts. A change means a new
   approval.
6. **Next steps:** Steps for people (with instructions and checks), **Set up a pilot device** (one line per device;
   never your own work laptop), the ZPA connector template or CloudShare commands.
7. **Success criteria:** import probe results, run the API proofs, record attestations, draft the summary, build the
   report.
8. **Handover:** export to Terraform, or remove the POV, before its end date. Later, **Delete…** on Start a POV
   forgets it on your laptop, once it has checked nothing is left in the tenant.

## Every customer session

- **Status → Check now.** Fix drift repairs only the POV's own objects.
- New "can you show…?" ideas go in **Use cases**: library first, then Claude. They need a fresh approval before Apply.

## Never

- Approve, apply or tear down without the customer's say-so.
- Paste a secret into chat, email or a ticket.
- Run the self-test in a customer's tenant.

## Help

- **Updates** button: install the newest version, or roll back one.
- **Logs → Download diagnostics:** a zip without secrets or customer names. **Report a problem** opens a GitHub issue
  form: attach the zip, and never paste secrets or customer names (the repository is public).
- The SE Deployment Guide has a troubleshooting table.
