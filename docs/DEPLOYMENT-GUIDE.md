# Zscaler POV Kit: SE Deployment Guide

*For Zscaler SEs and partner SEs. Versioned with the kit: the copy attached to each GitHub release (Word and
Markdown) is stamped with the kit version it describes. The source is `docs/DEPLOYMENT-GUIDE.md` in the repo, and it
changes together with the behavior it describes.*

## Overview

By the end of this guide you have run a proof of value in a customer's tenant: their pilot users protected by the
POV's own policy, every agreed success criterion proved with evidence in a report, and the tenant handed back exactly
as you found it (or the configuration handed over as Terraform). Plan about an hour on your laptop before your first
POV, a 60-minute kickoff with the customer's admin, then a few minutes before each customer session.

| Piece | Runs on | What it does |
| --- | --- | --- |
| Zscaler POV Kit (`pov-kit`) | Your laptop | Reads the tenant, writes the change list, applies what the customer approved, proves the criteria, hands over |
| The POV console | Your browser (this computer only) | Quick start and the step-by-step wizard, plus status, use cases, evidence and handover |
| Pilot devices | The customer's laptops, a spare laptop, or a virtual machine | Client Connector signed in as a pilot user; the kit's probe proves blocks, inspection and access from there |
| App Connectors (ZPA POVs) | The customer's AWS or Azure, or a CloudShare lab | Two connectors from the kit's template, plus the kit's test app when the customer hasn't named one |
| The customer's tenant | Zscaler cloud | Holds the POV's objects: each one is named with the POV prefix (`ZPOV`) and removed or handed over at the end |

**Golden rules**

- **Read before you write.** Discovery is read-only, and nothing is written until the customer approves the exact
  change list. If the tenant changes after approval, apply refuses: make the change list again and ask again.
- **The kit only touches what it created.** Every object carries the prefix and the `zpov:<pov-id>` stamp and sits in
  the POV's ledger. The customer's own objects are never edited, reordered or deleted; changes to them are customer
  steps, listed for them to make.
- **Pilot users only.** Every rule applies to the pilot group (or a SAML attribute), never to everyone.
- **Never activate someone else's work.** If ZIA has pending changes, the kit stops until the customer's admin
  activates or discards them.
- **Keep secrets out of chat, email and tickets.** API secrets, the provisioning key and test-user passwords live in
  your keychain; the console shows one only when you ask for it by name.
- **Leave cleanly.** Every POV has an end date. Hand it over (teardown or Terraform) before it, and keep backups on so
  a lost laptop can't strand objects in a customer's tenant.

## Prerequisites

**Your laptop**

- [ ] A Mac or Windows laptop where you can run the installer.
- [ ] Downloads from `github.com` and `astral.sh` allowed (the installer gets uv from there; updates come from GitHub).
- [ ] A folder synced off the laptop for encrypted backups (OneDrive, Google Drive or iCloud Drive), and a password
  manager for the backup passphrase.

**Your lab tenant (required before your first customer POV)**

- [ ] A Zscaler tenant of your own. The self-test runs there, never in a customer's tenant. Zscaler SEs use their
  SE lab tenant; partners use their partner demo tenant.
- [ ] A OneAPI client in it with the scopes from the kit's role spec. If Claude Desktop already has a Zscaler MCP
  server for that tenant, the kit can use its client.
- [ ] A pilot device for the lab: a spare laptop or a virtual machine without another organization's Client
  Connector (on a Mac, UTM runs a macOS virtual machine for free).

**Optional**

- [ ] For AI use cases and the executive summary: an AI Guard app in **PROXY** mode in your own AI Guard tenant, with
  an Anthropic provider key behind it. If you set up the AI Guard SE Demo Kit's Anthropic app, the kit uses it.
- [ ] For ZPA without the customer's cloud account: access to CloudShare (see [CLOUDSHARE.md](CLOUDSHARE.md)).

**From the customer, before the kickoff**

- [ ] The products in scope and the success criteria you agreed (from the kit's catalog).
- [ ] An admin who can create a OneAPI client from the kit's role spec, at or before the kickoff.
- [ ] One or more pilot devices.
- [ ] Optional, and can come later: who the pilot users are (a group, or named people; until then the POV starts with
  a test account), the POV app for ZPA (until then, the kit's test app), and where the App Connectors run (their AWS
  or Azure, or your CloudShare lab).
- [ ] CASB: a SaaS tenant they've connected for SaaS security (an OAuth grant only they can make). Until then, CASB is
  added later.

## Part 1: Install the kit (5 minutes)

1. Paste one line (no security prompts, because the terminal fetches the files rather than a browser):
   - **Mac (Terminal):** `curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.sh | bash`
   - **Windows (PowerShell):** `irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install.ps1 | iex`

   It downloads the latest release, checks its SHA-256, installs uv if needed, copies the kit to
   `~/.zscaler-pov-kit/app`, adds a **Zscaler POV Console** shortcut and the `pov-kit` command, and opens the console.

   Or download `zscaler-pov-kit-<version>.zip` from the latest release, unzip it, and double-click **Install Zscaler
   POV Kit** (`.command` on Mac, `.cmd` on Windows):
   - **Mac: "Apple could not verify… Not Opened".** The installer isn't signed with an Apple Developer ID, so macOS
     blocks it once. Click **Done** (not Move to Trash), then **System Settings → Privacy & Security → Open Anyway**,
     and double-click it again.
   - **Windows: "Windows protected your PC".** Click **More info → Run anyway**.
2. Optional: open `zscaler-pov-kit-<version>.plugin` from the release in the Claude desktop app, so Claude can run the
   kit for you.

The **Updates** button at the top of the console tells you when a new version is out (see *Updating* below).

## Part 2: Your safety net (5 minutes, once)

1. Console: **Status → Safety net → Encrypted ledger backup**. Choose your synced folder and a passphrase of 12+
   characters, and save the passphrase in your password manager. (`pov-kit backup setup FOLDER`)
2. **Turn on reminders** in the same panel: a daily notification when a POV is ending, overdue, or not backed up.
   (`pov-kit remind install`)

## Part 3: Prove the kit in your lab tenant (30 minutes, before your first POV)

1. **Setup → Start a POV.** Customer: "Lab". Tick the products you sell. Under **More options**, tick **This is my own
   lab tenant**. For the API client, choose **The one Claude Desktop uses** if it's offered, or enter your lab
   client. Click **Quick start**.
2. **Logs → Lab tools → Run the self-test**. It reads every product, then creates, reads back and deletes one harmless
   object per product. All green means the kit's API access works from your laptop and network.
3. Walk a whole POV once: review the change list, approve it, apply, set up your lab pilot device (Part 5), run the
   probe, build the report, then **Handover → Remove the POV**. The tenant should be exactly as before.

## Part 4: Before the POV

1. Agree the success criteria with the customer from the catalog; record them in **Success criteria** (or
   `pov-kit set criteria IS-URL-01,IS-SSL-01,...`).
2. **Setup → Start a POV**: the customer's name and the products, then **Step by step** (the end date, prefix and two
   API clients are under **More options**). On **Connect**, **Copy the role spec** and send it to the customer's
   admin. They create the client at kickoff, or give you a temporary admin login to create it yourself. The optional
   read-only client in the spec is for Claude Desktop's read-only access (Part 6).
3. Send the **Customer Overview** (attached to each release) to their security team: what the kit does and never does
   in their tenant, and how approval works.

## Part 5: The kickoff (about 60 minutes, with the customer's admin)

### 1. Quick start

On **Connect**, enter the vanity domain and the client ID and secret the admin created (the secret goes straight to
your keychain; with ZPA, also the customer ID from **Administration → API → Legacy API → Private Access API → Copy
ID**), then click **Quick start from here**. If you didn't start the POV beforehand (in your lab, say), **Setup →
Start a POV** takes the customer, the products and the API client on one page: click **Quick start** there. Two API
clients (view-only first, write access after approval) use the step-by-step path instead.

The kit signs in, then fills in the rest from the tenant, read-only:

- **Pilot users:** if nobody's named, one test account the kit creates (in ZIA, or in ZIdentity when that's where the
  tenant keeps its users; the kit detects it). Name the customer's group or people any time (step 3).
- **The Zscaler cloud** (for setting up pilot devices).
- **ZPA:** the kit's test app when no app is named.

It runs the preflight checks and opens the change list. Anything that needs fixing first shows under **Needs you**.
Products that aren't ready yet (no ZDX role on the API client, no SaaS tenant connected, no ZPA group) are **added
later**: the rest of the POV goes ahead, and once they're fixed, running the checks again and approving the new change
list adds them.

### 2. Review and approve the change list

Walk the admin through every object, who it affects and where it sits, and the steps only they make. **Open the
customer page** gives them the same list in their browser, printable with a signature line. Then **Approval**: record
who approved it, or let them approve on their own: the change-list page has an approval form that saves a file they
send you, and **Import their approval file** checks it's for this exact list.

### 3. Who tests (any time, in Pilot users)

**Setup → Pilot users** asks one question, "Who will test?":

- **A group they already have:** pick it from the list the kit reads from ZIA (or type its name). Rules apply to its
  members.
- **People we name:** the kit makes a POV group, `ZPOV - pilot users`, in ZIdentity and adds them (it's only made after
  approval, and removed at teardown; existing users are only added to it). Type a name or email; the step shows who
  isn't in ZIdentity. ZIdentity sends the group to ZIA only once it has the **Internet & SaaS** entitlement, which its
  API can't grant: where the tenant entitles chosen groups (common with Okta), the customer grants it. Apply checks the
  entitlement, stops at once if it's missing, and otherwise waits up to three minutes for ZIA to have the group; click
  **Apply** again after granting it and it carries on. With nobody named yet, the group starts with a test user.
- **Test accounts:** 1 to 10 accounts the kit creates (`zpov-pilot-1@<domain>`…), with passwords in your keychain
  (**Next steps → Test users → Show password**). If the tenant keeps its users in ZIdentity, they're made there, on
  `<vanity>.zslogin.net`, and you set their passwords in **Administration → Authentication → Directory → Users** (a
  domain your IdP owns, such as Okta's, can't take a ZIdentity password).

A line at the bottom says exactly who the POV's rules will apply to. **More options** has the identity provider (its
sign-in and MFA sites stay out of SSL inspection), extra sites not to decrypt, and rule placement. The ZPA and CASB
details are on the same page. Any change here means a new change list for the customer to approve.

### 4. Apply

Live progress, then a status check. Client Connector profiles are created for the pilot group; if the tenant has no
profile to copy or its API refuses them, the console prints the exact spec to build by hand (Windows, plus macOS for
Mac pilot devices), and **Status → Fix drift** adopts them by name.

### 5. Next steps

- **Steps for people:** everything the API can't do, in order, with instructions (see below).
- **Set up a pilot device** (see below).
- **ZPA App Connectors:** the AWS or Azure template (with the test app inside when no app is named), the provisioning
  key, and **CloudShare commands**.
- The probe pack, the AI Guard policy switch, and test-user passwords.

### Setting up a pilot device

**Next steps → Set up a pilot device** installs Client Connector already pointed at the customer's tenant, then the
kit's probe. Pick the pilot user and macOS or Windows, then either:

- **Copy the one-line command** and paste it on the device: in Terminal on a Mac, or in PowerShell opened with
  **Run as administrator** on Windows; or
- **Download the setup script** for the customer's IT to read or push with their own tools. It has the POV's probe
  pack inside, so once the user signs in and traffic goes through Zscaler, the POV's tests run by themselves and the
  results land on the Desktop for you to import.

The cloud (**Detect** reads it from the tenant, or type it, such as `zscalertwo`), the user's domain and the user name
are filled in: `CLOUDNAME`, `USERDOMAIN` and `UNAME` on Windows; on macOS, a settings profile with the same values
(`com.zscaler.installparams`, what an MDM would push) that the user approves once in System Settings → General →
Device Management. The installer is the kit's pinned copy, and the device checks its SHA-256 and that it's signed by
Zscaler before installing. To use the customer's own version, download it from **Infrastructure → Common Resources →
Deployment → Platform Releases** and give it to the setup (`--pkg FILE` on macOS, `-Msi FILE` on Windows).

The setup stops, and changes nothing, on a device that already has Client Connector or another organization's
Zscaler settings: never use your own work laptop as a pilot device. Remove the settings profile from a Mac after the
POV.

### Steps the API can't do

Some steps need a person in the Zscaler console: creating the API client, giving it a ZDX role, granting an
entitlement, Malware Protection (tenant-wide, so the kit only reads it), connecting a SaaS tenant (an OAuth consent),
deploying App Connectors, building Client Connector profiles by hand when the API refuses, and deleting the API
clients at the end. **Next steps → Steps for people** lists the ones this POV needs, in order, each with:

- who does it and when, the console path (where it's been checked in a live console) and the term to type in the
  console's **Search menu** (it finds any page if a menu has moved);
- numbered steps, the exact names to use, and what done looks like;
- **Check now**, where the API can see the result (read-only): the API client signs in, ZDX and ZPA are readable,
  pilot users are entitled, Malware Protection blocks viruses, devices are registered, connectors are up, a SaaS
  tenant is connected, profiles are adopted. A passing check ticks the step; **Check them all** runs every one;
- **Mark done** with a name, for the rest.

**Copy the steps for the customer's admin** gives the same list as Markdown to paste into an email or the shared POV
doc (no secrets in it). From the command line: `pov-kit steps` (`--check`, `--done KEY --by NAME`, `--sheet`).

### A POV lab on CloudShare

No cloud account for the connectors? [CLOUDSHARE.md](CLOUDSHARE.md) builds a CloudShare blueprint once (two App
Connectors, the test app, a Windows pilot) with no customer values in it; each POV starts a copy and enrolls it with
the commands from **Next steps → ZPA App Connectors → CloudShare commands**.

### The step-by-step path

**Step by step** on Start a POV opens the same work as eight steps (Connect, Pilot users, Preflight, Change list,
Approval, Apply, Next steps), for two-client POVs or when you want to set everything before the first change list.
Any step can be revisited after Quick start.

## Part 6: During the POV

- **Before every customer session:** **Status → Check now**. It says whether the tenant still matches the approval,
  what drifted (and **Fix drift** repairs only the POV's own objects), the end date and the last backup.
- **Evidence:** run the probe on each pilot device (the setup script runs it for you), and import the results
  (**Success criteria → Import probe results**). **Run API proofs** checks what the API can see: the ZIA rules behind
  each criterion and its test sites' categories, connectors, AI Guard scans, ZDX scores and SaaS scans. Record what
  people see as attestations, with a screenshot if you like.
- **New use cases:** check the library first (no AI call). Otherwise, in the **Use cases** tab, record the customer's
  agreement once (names are replaced before anything leaves your laptop, unless they agree to share them), describe
  the use case, refine it in words, and **Add to the change list**. The customer approves the new change list before
  Apply builds it. **Save to library** keeps what worked.
- **Products added later:** once the fix is in (for example, the ZDX role), **Preflight → Run checks again**, then
  review and approve the new change list.
- **Ask Claude about the tenant:** with the customer's agreement, **Next steps → Ask Claude about this tenant → Add to
  Claude Desktop**. It is read-only: Claude can answer "why was Jane blocked?" but can't change anything.

## Part 7: Closing

1. **Success criteria → Draft the summary**, then **Build the report**, and give the customer the report (print it to
   PDF from the browser).
2. Agree the exit with the customer, before the end date:
   - **Keep it:** **Handover → Export to Terraform**. The configuration is adopted in place with import blocks, and
     the kit never touches it again.
   - **Remove it:** **Handover → Remove the POV**. ZPA: delete the connector stack in AWS or Azure (or the CloudShare
     environment) and the enrolled connectors first; teardown keeps the connector group until they're gone.
3. Either way, the kit removes the POV's secrets, discovery data, recordings and Claude Desktop entry from your laptop.
   Remind the customer to delete the POV's API clients (the last of the Steps for people).
4. **Delete the POV** when you no longer need its record: **Setup → Start a POV → Delete…** next to it (or
   `pov-kit delete <pov-id>`). The kit first checks, read-only, that nothing the POV created is still in the tenant;
   if something is, it says what and stops. Then you type the POV's ID to confirm, and its folder, keychain secrets,
   Claude Desktop entry and backup are deleted from your laptop. The customer's tenant isn't touched.

## Updating, rolling back and recovering

**Update:** when a new version is out, the **Updates** button turns into **Update to x.y.z**. Click it, then **Install
update**: it verifies the download, installs it and restarts the console (reload the page afterwards). Terminal:
`pov-kit update`.

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
| ZPA added later: ZPA customer ID | Copy it from **Administration → API → Legacy API → Private Access API → Copy ID** into Connect (`pov-kit set customer_id`) |
| ZPA added later: no SCIM group | ZPA needs the pilot users as a group from the customer's IdP (SCIM) or a SAML attribute: set it in Pilot users (ZPA) |
| ZDX added later: ZDX readable (403) | The API client has no ZDX role: **Administration → API → OneAPI → API Clients**, edit the client and add one (view only is enough), or take ZDX out of the POV |
| Preflight: pilot users not in ZIA | With SAML or SCIM, users appear after provisioning or their first sign-in: have each one sign in to Client Connector once |
| Preflight: ZIdentity entitlements | ZIdentity's API can't grant them: the customer assigns the missing service to the pilot group (Steps for people) |
| Preflight: pilot group doesn't exist | Pick an existing group from the list, or choose **People we name** |
| Apply stops: "don't have the Internet & SaaS entitlement" | The customer gives the POV's pilot group that entitlement, then click **Apply** again: it carries on and creates nothing twice. In a lab, **Test accounts** avoid it |
| Apply stops: "keeps its users in ZIdentity" | Make the change list again (the test users now go in ZIdentity, on `<vanity>.zslogin.net`), get it approved, apply, then set their passwords in ZIdentity |
| No option to set a user's password in ZIdentity | The user is on a domain your IdP (Okta, Entra…) owns, which signs them in. Use a user on `<vanity>.zslogin.net` |
| Pilot device setup: "already has Client Connector" | It's protecting another organization's Client Connector (a work laptop). Use a spare device or a virtual machine |
| Self-test: "isn't marked as a lab POV" | Start a POV for your lab tenant with **More options → This is my own lab tenant** ticked |
| Delete: "still in the customer's tenant" | Remove the POV first (**Handover → Remove the POV**) or export it to Terraform, then delete |
| Apply: "ZIA has changes waiting to be activated" | Another admin's changes are pending. The customer activates or discards them; the kit never does |
| Apply: "the tenant changed since the customer approved" | Something the plan depends on changed. Make the change list again and get it approved again |
| Client Connector refused the profiles, or no profile to copy | Build them from the printed spec with exactly those names, then **Status → Fix drift** adopts them |
| ZPA connectors don't appear | Check the machines reach the internet on TCP 443 and have the POV's provisioning key; they enroll within about 15 minutes |
| Use cases: "AI Guard blocked the request" | Your AI Guard demo policy is enforcing. Switch it to Monitor, or rephrase |
| Status: "POV end date" FAIL | The end date passed with objects in the tenant: hand the POV over now, or agree a new date (`pov-kit set ends`) |
| Update: "couldn't reach GitHub" | Your web policy blocks GitHub downloads: download the zip from the releases page and run its installer |
| A console path in a step doesn't match | Zscaler renames menus between versions: use the console's **Search menu**, and tell the kit owner the path you see |
