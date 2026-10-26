# Zscaler POV Kit: Quick Start

*One page for Zscaler and partner SEs. The full steps are in the SE Deployment Guide.*

## Install (5 minutes)

1. Paste one line:
   - **Mac (Terminal):** `curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.sh | bash`
   - **Windows (PowerShell):** `irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.ps1 | iex`
2. Or download the zip from the latest release, unzip it and double-click **Install Zscaler POV Kit**. Mac says "Not
   Opened"? **Done**, then System Settings → Privacy & Security → **Open Anyway**. Windows: **More info → Run anyway**.
3. From then on, open **Zscaler POV Console** from your desktop: it runs in the background and opens in your browser.
   **Quit** at the top of the console stops it.

## Once

- Prove the kit in your own lab tenant: **Setup → Connect**, tick **More options → This is my own lab tenant**,
  **Quick start**, then **Logs → Lab tools → Run the self-test**.
- Then **Status → Safety net:** turn on encrypted backups (a synced folder and a passphrase in your password manager)
  and daily reminders. (The panel appears once a POV exists.)

## Rehearse first (recommended)

Before your first customer POV, run one end to end in your own lab tenant: Connect → **More options** → tick
**This is my own lab tenant**. The **POV checklist** under the tabs then becomes a rehearsal: it adds the checks that
are easiest to get wrong in the field (self-test, backups, the Claude Desktop connectors, a pilot device, the traffic
generator, teardown). Mark each step **Worked** or **Problem…** with a note, and send the **rehearsal report** to the
kit's owner.

## Your first POV

The **POV checklist** under the tabs shows what's done and what's next; **Go ›** takes you there.

The console opens in **Simple view**: the main path only. **Advanced view** (top right) adds the rest: prefix and
client options, CloudShare and AWS traffic generators, AI Guard test users and rounds, Claude-drafted tests, and
letting Claude Desktop make changes.

Setup has four steps: **Connect → Pilot users → Review & apply → Get ready to test**.

1. **Before the kickoff (Connect):** customer and products. Leave the API client fields empty and click **Quick start**:
   the kit creates the POV and shows the **role spec** to send to the customer's admin.
2. **At the kickoff (Connect):** the API client they created (with ZPA, the customer ID: Administration → API →
   Legacy API → Private Access API → Copy ID), then **Quick start**. The kit signs in, reads the tenant (read-only),
   fills in the defaults and lands on Review & apply.
3. **Pilot users** (any time): who tests — a group they have, people you name, or test accounts. A change means a new
   change list.
4. **Review & apply:** problems are listed with their fixes (**Fixed it: check again**), then the steps for people
   needed before the change list, then the change list itself. Options a criterion needs (the ZPA app, PRA, the SaaS
   tenant, the identity provider, rule placement) show here only when they're needed. Walk the admin through it, type
   your name and **Apply**. Products not ready yet are **added later** without holding up the rest.
5. **Get ready to test:** the steps for people that follow Apply (entitlement, connectors, pilot devices), with the
   admin or sent to them, **Set up a pilot device** (one line per device; never your own work laptop), the probe pack,
   the ZPA connector template or CloudShare commands, and the rest. The POV is ready to test once the steps are done.
6. **Success criteria:** configuration is checked automatically; import probe results; anything you showed live, mark
   **Demonstrated**. Then build the report.
7. **Handover:** **Executive summary** (customer and internal versions, as Word and PowerPoint), then export to
   Terraform, or remove the POV, before its end date. Later, **Delete…** on Connect
   forgets it on your laptop, once it has checked nothing is left in the tenant.

**The SE applies directly** (the default): **Review & apply** shows what the kit will make (pilot users only) and
the **Changes made** so far; type your name and Apply. Your sign-off is recorded as it applies, and every object is in
the ledger, so teardown removes exactly them. Use cases (**Accept and make it in the tenant**), AI Guard proxy setup
(**Save**) and demo switches go straight in too. A customer that must approve changes first: **Switch to customer
approval** on Review & apply, and the change-list page, Sign-off and Apply come back as their own steps.

## Live demos

- **Device tests › Test runner**: one list of the POV's criteria, each test's result landing on its own row as it runs
  (✓ as expected, ✕ not, ! error), with failures opened in place. Before Run, a readiness check confirms Client
  Connector is running, traffic goes through Zscaler, the device is the pilot user in the POV's tenant and the policy is as
  planned; Run waits until it passes. The run bar stays in view, with a filter for what wasn't as expected.
  Each test has its own **Run** button, and the POV rule that decides it sits on its row: switch it (Block, Caution,
  Allow, Isolate, Inspect, Hold for the verdict…) and press Run again to show the change. Switching never re-runs by
  itself, and results while the policy is switched don't count as evidence until it's put back.
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
- **On the pilot itself: POV device tests** (`pov-probe ui`): the Device tests runner without the console: the POV's
  tests, guided demos and Show it, in Presenter or Plain mode. The AWS template and the CloudShare script put it on
  the pilot's desktop and open it at sign-in. Results are saved to a file, and sent to your console when linked.
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
