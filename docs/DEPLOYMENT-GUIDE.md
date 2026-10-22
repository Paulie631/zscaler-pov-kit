# Zscaler POV Kit: SE Deployment Guide

*Versioned with the kit: the copy attached to each GitHub release (Word and Markdown) is stamped with the kit version
it describes. The source is `docs/DEPLOYMENT-GUIDE.md` in the repo; it changes in the same branch as the behavior it
describes.*

## Overview

By the end of this guide you have run a proof of value in a customer's tenant: their pilot users protected by the
POV's own policy, every agreed success criterion proved with evidence in a report, and the tenant handed back exactly
as you found it (or the configuration handed over as Terraform). Plan about an hour on your laptop before your first
POV, a 60-to-90-minute kickoff with the customer's admin, then a few minutes before each customer session.

| Piece | Runs on | What it does |
| --- | --- | --- |
| Zscaler POV Kit (`pov-kit`) | Your laptop | Reads the tenant, writes the change list, applies what the customer approved, proves the criteria, hands over |
| The POV console | Your browser (this computer only) | The same steps as a wizard, plus status, use cases, evidence and handover |
| Pilot devices | The customer's laptops | Client Connector as pilot users; the kit's probe proves blocks, inspection and access from there |
| App Connectors (ZPA POVs) | The customer's AWS or Azure | Two connectors from the kit's template, for the POV app only |
| The customer's tenant | Zscaler cloud | Holds the POV's objects: every one is named with the POV prefix (`ZPOV`) and removed or handed over at the end |

**Golden rules**

- **Read before you write.** Discovery is read-only, and nothing is written until the customer approves the exact
  change list. If the tenant changes after approval, apply refuses: make the change list again and ask again.
- **The kit only touches what it created.** Every object carries the prefix and the `zpov:<pov-id>` stamp and sits in
  the POV's ledger. The customer's own objects are never edited, reordered or deleted; changes to them are customer
  actions in the change list.
- **Pilot users only.** Every rule applies to the pilot group (or SAML attribute), never to everyone.
- **Never activate someone else's work.** If ZIA has pending changes, the kit stops until the customer's admin
  activates or discards them.
- **Keep secrets out of chat, email and tickets.** API secrets, the provisioning key and test-user passwords live in
  your keychain; the console shows one only when you ask for it by name.
- **Leave cleanly.** Every POV has an end date. Hand it over (teardown or Terraform) before it, and keep backups on so
  a lost laptop can't strand objects in a customer's tenant.

## Prerequisites

Tick every box before your first POV.

**Your laptop**

- [ ] A Mac or Windows laptop where you can run the installer (see INSTALL.md for first-run security prompts).
- [ ] Downloads from `github.com` and `astral.sh` allowed (the installer gets uv from there; updates come from GitHub).
- [ ] A folder synced off the laptop for encrypted backups (OneDrive, Google Drive or iCloud Drive), and a password
  manager for the backup passphrase.

**Your lab tenant**

- [ ] A Zscaler tenant of your own, set up like a customer's (a few rules of its own, a pilot group, Client Connector
  on one Windows device). The self-test runs there, never in a customer's tenant.
- [ ] A OneAPI client in it with the scopes from the kit's role spec.

**For AI use cases and the executive summary (optional)**

- [ ] An AI Guard app in **PROXY** mode in your own AI Guard tenant, with an Anthropic provider key behind it. If you
  set up the AI Guard SE Demo Kit's Anthropic app, the POV kit uses it automatically.

**From the customer, before the kickoff**

- [ ] The products in scope and the success criteria you agreed (from the kit's catalog).
- [ ] A pilot group of real users from their directory, its members' emails, and one or more pilot devices.
- [ ] An admin who can create a OneAPI client from the kit's role spec, at or before the kickoff.
- [ ] ZPA: the POV app (its domains or IPs and ports), the tenant's ZPA customer ID, and an AWS account or Azure
  subscription for two App Connectors.
- [ ] CASB: a SaaS tenant they've connected for SaaS security (an OAuth grant only they can make).

## Part 1: Install the kit (5 minutes)

1. Download `zscaler-pov-kit-<version>.zip` from the latest release, unzip it, and double-click **Install Zscaler POV
   Kit** (`.command` on Mac, `.cmd` on Windows). It installs uv if needed, copies the kit to `~/.zscaler-pov-kit/app`,
   adds a **Zscaler POV Console** shortcut and the `pov-kit` command, and opens the console.
2. Optional: open `zscaler-pov-kit-<version>.plugin` from the release in the Claude desktop app, so Claude can run the
   kit for you.

The **Updates** button at the top of the console tells you when a new version is out; one click installs it after
checking its SHA-256, and **Roll back** goes back one version.

## Part 2: Your safety net (5 minutes, once)

1. Console: **Status → Safety net → Encrypted ledger backup**. Choose your synced folder and a passphrase of 12+
   characters, and save the passphrase in your password manager. (`pov-kit backup setup FOLDER`)
2. **Turn on reminders** in the same panel: a daily notification when a POV is ending, overdue, or not backed up.
   (`pov-kit remind install`)

## Part 3: Prove the kit in your lab tenant (20 minutes, before your first POV)

1. In the console's Setup tab, start a POV named "Lab" with the products you sell, and mark it as a lab POV
   (`pov-kit new "Lab" --products zia,zcc,zpa --lab`).
2. Connect it with your lab client. Fill in the pilot users and run Preflight.
3. **Logs → Lab tools → Run the self-test**. It reads every product, then creates, reads back and deletes one harmless
   object per product. All green means the kit's API access works from your laptop and network.
4. Walk the whole wizard once: change list, approval, apply, status, a probe run on your lab device, the report,
   then **Handover → Remove it**. The tenant should be exactly as before.

## Part 4: Before the POV

1. Agree the success criteria with the customer from the catalog; record them in the console (Success criteria) or
   with `pov-kit set criteria IS-URL-01,IS-SSL-01,...`.
2. Start the POV in the console: customer, products, prefix and **end date**. One API client is the default; choose
   two clients (view-only first, write access after approval) if their security team asks.
3. **Connect → Copy the role spec** and send it to the customer's admin. They create the client at kickoff, or give you
   a temporary admin login to create it yourself. The optional read-only client in the spec is for Claude Desktop's
   read-only access (Part 6).
4. Send the **Customer Overview** (attached to each release) to their security team: what the kit does and never does
   in their tenant, and how approval works.

## Part 5: The kickoff (60 to 90 minutes, with the customer's admin)

1. **Connect**: the vanity domain, the client ID and secret (straight to your keychain) and, with ZPA, the customer ID.
2. **Pilot users**: the pilot group, its members, their identity provider (so its sign-in and MFA sites stay out of
   SSL inspection), and per-product details: the ZPA app, SCIM group or SAML attribute, the CASB tenant.
   - **Use one of the customer's groups:** pick it from the list the kit reads from ZIA (or type its name).
   - **Create one for the POV in ZIdentity:** the kit makes `ZPOV - pilot users` and puts the users in it, once the
     change list is approved, and removes it at teardown. Existing users are only added to the group. In a lab tenant,
     tick **Also create the users who don't exist** and the kit creates them too (you set their passwords in
     ZIdentity). ZIdentity's API can't grant entitlements, so the customer gives the group Internet & SaaS (and
     Private Access with ZPA); Apply waits for ZIdentity to provision the group to ZIA, and if it stops to wait, click
     **Apply** again once the entitlement is granted.
   - Add users by typing a name or email: the list comes from ZIdentity, and the step shows who isn't there.
3. **Preflight**: read-only checks of every product and of the pilot users across products. Fix every FAIL before
   going on; each one says how.
4. **Change list**: walk the admin through every object, who it affects and where it sits, and the customer actions
   only they make. **Open the change-list page** gives them the same list in their browser.
5. **Approval**: record who approved it, or let the customer approve on their own: the change-list page has an
   approval form that saves a file they send you, and **Import their approval file** checks it's for this exact list.
6. **Apply**: live progress, then a status check. Client Connector profiles are created for the pilot group; if the
   tenant's Client Connector API refuses them, the console prints the exact spec to build by hand, and **Fix drift**
   adopts them.
7. **Next steps**: customer actions, the probe pack, the ZPA connector template (AWS or Azure) and its key, the AI Guard
   policy switch.

## Part 6: During the POV

- **Before every customer session:** Status → **Check now**. It says whether the tenant still matches the approval,
  what drifted (and **Fix drift** repairs only the POV's own objects), the end date and the last backup.
- **Evidence:** download the probe pack and run it on each pilot device signed in as a pilot user; import the results.
  **Run API proofs** covers connectors, AI Guard scans, ZDX scores and SaaS scans. Record what people see as
  attestations, with a screenshot if you like.
- **New use cases:** check the library first (no AI call). Otherwise, in the **Use cases** tab, record the customer's
  agreement once (names are replaced before anything leaves your laptop, unless they agree to share them), describe
  the use case, refine it in words, and **Add to the change list**. The customer approves the new change list before
  Apply builds it. Save what worked to the library.
- **Ask Claude about the tenant:** with the customer's agreement, **Next steps → Ask Claude about this tenant → Add to
  Claude Desktop**. It is read-only: Claude can answer "why was Jane blocked?" but can't change anything.

## Part 7: Closing

1. **Success criteria → Draft the summary**, then **Build the report**, and give the customer the report (print it to
   PDF from the browser).
2. Agree the exit with the customer, before the end date:
   - **Keep it:** Handover → **Export to Terraform**. The configuration is adopted in place with import blocks, and the
     kit never touches it again.
   - **Remove it:** Handover → **Remove the POV**. ZPA: delete the connector stack in AWS or Azure and the enrolled
     connectors first; teardown keeps the connector group until they're gone.
3. Either way, the kit removes the POV's secrets, discovery data, recordings and Claude Desktop entry from your laptop.
   Remind the customer to delete the POV's API clients.
4. **Delete the POV** when you no longer need its record: Setup → Start a POV → **Delete…** next to it (or
   `pov-kit delete <pov-id>`). The kit first checks, read-only, that nothing the POV created is still in the tenant;
   if something is, it says what and stops. Then you type the POV's ID to confirm, and its folder, keychain secrets,
   Claude Desktop entry and backup are deleted from your laptop. The customer's tenant isn't touched.

## Updating, rolling back and recovering

**Update:** when a new version is out, the **Updates** button turns into **Update to x.y.z**. Click it, then **Install
update**: it verifies the download, installs it and restarts the console. Terminal: `pov-kit update`.

**Roll back one version:** **Roll back** in the same dialog, or `pov-kit update --rollback`.

**New laptop, or a lost one:** install the kit, then `pov-kit backup restore <pov-id>` with your passphrase, and
connect again. Without a backup, `pov-kit recover <pov-id> --customer "<name>" --products ...`, connect, then
`pov-kit recover <pov-id>` finds the POV's objects in the tenant (read-only) and `--write` records them so teardown can
remove them.

## Troubleshooting

Start with the **Logs** tab: every API call and change is there, and **Download diagnostics** makes a zip without
secrets or the customer's object names for the kit owner. **Report a problem** (next to it) opens the kit's GitHub
issue form: attach the zip, and never paste a secret, a customer's name or anything from their tenant there (the
repository is public).

| Symptom | Fix |
| --- | --- |
| Connect: "rejected the API client's sign-in (401)" | Wrong client ID or secret, wrong vanity domain, or the secret was rotated. Re-enter them in Connect |
| Preflight: ZPA calls fail | Set the ZPA customer ID in Connect (`pov-kit set customer_id`) |
| Preflight: pilot users not in ZIA | With SAML or SCIM, users appear after provisioning or their first sign-in: have each one sign in to Client Connector once |
| Preflight: ZIdentity entitlements FAIL | ZIdentity's API can't grant them: the customer assigns the missing service to the pilot group in ZIdentity |
| Preflight: pilot group doesn't exist | Pick an existing group from the list, or choose **Create one for the POV in ZIdentity** |
| Preflight: ZDX readable FAIL (403) | The API client has no ZDX role: in ZIdentity → API Clients, add one (view only is enough), or take ZDX out of the POV |
| Apply stops: "ZIA doesn't have it yet" | Give the POV's ZIdentity group its entitlements, wait a minute, click **Apply** again: it carries on and creates nothing twice |
| Delete: "still in the customer's tenant" | Remove the POV first (Handover → Remove the POV) or export it to Terraform, then delete |
| Apply: "ZIA has changes waiting to be activated" | Another admin's changes are pending. The customer activates or discards them; the kit never does |
| Apply: "the tenant changed since the customer approved" | Something the plan depends on changed. Make the change list again and get it approved again |
| Client Connector refused the profiles (bare 400) | Build both from the printed spec with exactly those names, then Status → **Fix drift** adopts them |
| ZPA connectors don't appear | Check the subnet reaches the internet on TCP 443 and the template's provisioning key; they enroll within about 15 minutes |
| Use cases: "AI Guard blocked the request" | Your AI Guard demo policy is enforcing. Switch it to Monitor, or rephrase |
| Status: "POV end date" FAIL | The end date passed with objects in the tenant: hand the POV over now, or agree a new date (`pov-kit set ends`) |
| Update: "couldn't reach GitHub" | Your web policy blocks GitHub downloads: download the zip from the releases page and run its installer |
| A console path in a step doesn't match | Zscaler renames menus between versions: tell the kit owner the path you see |
