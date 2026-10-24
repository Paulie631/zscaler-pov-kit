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

## Rehearse first (recommended)

Before your first customer POV, run one end to end in your own lab tenant: Start a POV → **More options** → tick
**This is my own lab tenant**. The **POV checklist** under the tabs then becomes a rehearsal: it adds the checks that
are easiest to get wrong in the field (self-test, backups, the Claude Desktop connectors, a pilot device, the traffic
generator, teardown). Mark each step **Worked** or **Problem…** with a note, and send the **rehearsal report** to the
kit's owner.

## Your first POV

The **POV checklist** under the tabs shows what's done and what's next; **Go ›** takes you there.

The console opens in **Simple view**: the main path only. **Advanced view** (top right) adds the rest: prefix and
client options, CloudShare and AWS traffic generators, AI Guard test users and rounds, Claude-drafted tests, and
letting Claude Desktop make changes.

1. **Before the kickoff:** Setup → Start a POV: customer and products, then **Step by step** → Connect → **Copy the
   role spec** for the customer's admin.
2. **At the kickoff, on Connect:** the API client they created (with ZPA, the customer ID: Administration → API →
   Legacy API → Private Access API → Copy ID), then **Quick start from here**. The kit fills in the rest from the tenant,
   read-only, runs preflight and opens the change list. Fix anything under **Needs you**; products not ready yet are
   **added later** without holding up the rest.
3. **Change list → Sign-off:** review it, walk the admin through it, and sign it off yourself. If the account needs the
   customer's formal approval, choose **Ask the customer to approve instead** on Sign-off.
4. **Apply:** watch it run, then check the status. **Finish setup** then walks the steps for people that follow Apply
   (entitlement, connectors, pilot devices), with the admin or sent to them; the POV is ready to test once they're
   done. Preflight does the same for the steps before the change list.
5. **Who tests** (Pilot users, any time): a group they have, people you name, or test accounts. A change means a new
   approval.
6. **Next steps:** every step for people (with instructions and checks), **Set up a pilot device** (one line per device;
   never your own work laptop), the ZPA connector template or CloudShare commands.
7. **Success criteria:** configuration is checked automatically; import probe results; anything you showed live, mark
   **Demonstrated**. Then build the report.
8. **Handover:** **Executive summary** (customer and internal versions, as Word and PowerPoint), then export to
   Terraform, or remove the POV, before its end date. Later, **Delete…** on Start a POV
   forgets it on your laptop, once it has checked nothing is left in the tenant.

## Live demos

- **AI Guard tab › Guided demos** and **Device tests tab › Guided demos**: short stories with what to say and a Run
  button. Device tests run on the computer running the console, which must be a pilot device signed in as the pilot
  user.
- **Device tests › Guided demos › Show it**: the user's view. Step by step, each test's page opens in the pilot
  device's default browser (Safari or Chrome, not an in-app browser) for the room, then the test runs and is recorded.
  Put the console and the browser side by side. Firewall and DNS steps give a Terminal command to copy instead.
  The Test runner has the same for any tests you pick: **Show them, step by step**.
- **Device tests › Policy**: switch a POV rule (web categories, SSL inspection, DLP, GenAI apps) between Block,
  Caution, Isolate or Allow in front of the customer, then **Check again** to show the page change. Each Show it step
  has the switches for its test. Only the POV's own rules change; results aren't recorded while anything is switched.
  **Put everything back as planned** when you're done (Status reminds you).
- **Device tests › Run on › Link a device**: run the tests on another computer with Client Connector and watch the
  results land here. Turn linking on (same network, or same network + anywhere through a Cloudflare quick tunnel,
  which needs `cloudflared` on the console's computer), run the command shown on the device, then pick it under
  **Run on**. Test runs, guided demos and Show it then use that device (pages open in its browser). Runs started on
  the device itself appear under Linked devices.
- **Device tests › Tenant logs**: when a device can't be linked, ZIA streams the pilot users' web logs to the console
  (Cloud NSS, a minute or two behind) and each line is matched to the device tests. Choose **To this console** (needs
  the Cloudflare tunnel) or **To the customer's SIEM** (Splunk HEC), make the change list again, get it approved and
  Apply. A run the logs saw in full can be counted as evidence. After a console restart, **Update the feed address**.
- **Device tests › Demo helpers**: ZPA, ZDX and CASB talk tracks, and **Warm up the dashboards** the day before.

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
