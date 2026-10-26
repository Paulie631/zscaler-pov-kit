# Changelog

## 0.9.97
- **Pilot users › Test accounts is easier to read.** The accounts show as a table (Account · Password · Status) with the full address, plain-text status and real buttons (Show, Generate/New, Type…). Fewer hints; the summary banner stays.
- **The domain fills itself in from the tenant.** The kit reads the domains ZIA has for the organisation (orgInformation), ranked by how many users have each, and falls back to the users' email domains. One domain: it's filled in, marked *from tenant*, still editable. Several: a dropdown with the most used picked, plus Other…. ZIdentity accounts show their zslogin.net domain, read-only.

## 0.9.96
- **Test account names nobody in the tenant has.** When you pick Test accounts, the kit looks in the tenant (read-only): if `zpov-pilot-1`… already belongs to another POV or SE, this POV's accounts get its own code, `zpov-b10c-pilot-1`…, and the step says why. Preflight checks again. Works for ZIA (Hosted DB) and ZIdentity accounts. A name you type is always kept (and flagged if it's taken), and once the accounts exist their name doesn't change until teardown.
- The test accounts' domain shows as found in the tenant.

## 0.9.95
- **The Apply step shows what's stopping it, with the fix, right there.** Instead of "The checks found problems… See Preflight", it lists each problem with what was found, the fix, the console steps where there are any, and a button to the setup step that fixes it (Open Pilot users, Open Connect, Use prefix ZPOV2…). **Fixed it: check again** reads the tenant again in place. The list of objects to make folds away until the problems are fixed. The customer-approval change list shows the same.
- Fixes written as Terminal commands (`pov-kit set …`) now say where that setting is in Setup, with the command kept as a small aside; the test accounts' missing email domain says to type it in Pilot users › Test accounts.

## 0.9.94
- **No more loop at Finish setup.** After Apply, the checklist pointed at Finish setup, and Finish setup wouldn't open Next steps until every step for people was done, including "pilot devices run Client Connector", which can't happen until you set up a pilot device. Now **Next steps** is always open: steps still to do stay on the checklist (and the tests that need them wait), and moving on is recorded, so the checklist moves on too. Preflight works the same way for steps for people; real check failures still stop it.
- **After Apply, Setup goes straight to Finish setup**, instead of reading the whole tenant again to show "nothing new to make".
- **"Run the tests on a pilot device" on the checklist opens Device tests** (it opened Finish setup again).
- **Fewer full tenant reads.** The setup steps reuse a reading from the last 10 minutes when nothing was applied and no setting changed since, and say which reading they used, with **Read the tenant again**. From Quick start to applied, the tenant is now read twice (Quick start, and Apply itself, which always reads fresh before writing) instead of four times.

## 0.9.93
- **Use cases: from directions to changes in one click.** When Claude can only write directions because a product the use case needs isn't in the POV (ZPA for an internal app, say), or a product wasn't readable in the last tenant reading, the card says so and offers one button: **Add ZPA to this POV, read the tenant and ask Claude again**. It adds the product, reads the tenant (read-only), and asks Claude again, so the card comes back with changes the kit can build. Then **Accept and make it in the tenant** applies them as before, with the POV's own sign-off rule (the SE's, or the customer's). If the product still can't be read, the card says why (a missing ZPA customer ID, say) and nothing changes.
- **Only what the API can't do is left for a person** (Client Connector profiles, tenant-wide settings, the customer's own objects), under "Left for a person", and each group can be ticked off when it's done.
- Use cases made before this release show the button too.

## 0.9.92
- **No Terminal window.** The desktop app (Mac) and shortcut (Windows) now start the console in the background and open it in the browser when it's ready; nothing else appears on screen. Its output goes to `~/.zscaler-pov-kit/console.log`, and if it doesn't start, a dialog says so and offers the log.
- **Quit** is a button at the top of the console (click it twice). Opening the app again while the console runs brings that console back up rather than starting a second one.
- For troubleshooting, the old way is still there: `pov-kit gui` in Terminal, or the app's `Contents/Resources/console.command`.

## 0.9.91
- **Updates work on laptops whose Zscaler Client Connector inspects TLS.** Client Connector re-signs github.com with the Zscaler root, which the computer trusts but Python's own certificate list doesn't, so the update check failed with CERTIFICATE_VERIFY_FAILED. Update checks and downloads now trust the computer's roots too (the macOS System keychain, or Windows' certificate stores) alongside Python's list; nothing is turned off, and the release is still checked against its SHA-256. If the root isn't on the computer, the message says what to do.

## 0.9.90
- **Name the test accounts.** Setup › Pilot users › Test accounts has a name field (default `<prefix>-pilot`), so when another POV or SE already has `zpov-pilot-1` in the tenant you can use, say, `paul-pov` and get `paul-pov-1`, `paul-pov-2`… Preflight now checks the names are free, in ZIA and in ZIdentity, and says which are taken. Once the accounts exist, the name stays until teardown.
- **See the accounts before Apply.** The step lists every account it will create with its full sign-in address (the domain comes from Preflight, or type it), and whether it exists yet.
- **Choose each password.** Per account: **Generate now**, **Type one…** (checked against ZIA's rules) or **Show**. A password set before Apply is the one Apply gives the account; after Apply, a new one is set in ZIA straight away. Passwords stay in your keychain and are never in the change list. Accounts made in ZIdentity get their passwords there (its API can't set them).

## 0.9.89
- **The tenant check (IS-TEN-01, www.example.com) can be switched too: Block or Caution.** It was left out because every test run checks it first to confirm the device is the POV's. That check now accepts either Zscaler page (the block page, or the caution page while it's switched), so switching it no longer stops the tests. Allow isn't offered: an ordinary page can't prove the device is in the POV's tenant. A linked device is told which page to expect.

## 0.9.88
- **Run each device test on its own.** Every test in Device tests › Test runner has its own **Run** button (Run again once it has a result); the whole list still runs from the run bar. A test run alone counts as evidence when its criterion has just that one test.
- **Change the policy right on the test.** The POV rule that decides a test sits on its row with its actions (the planned one marked •): switch it and the row says what the test now expects ("now expects caution"); then press Run. Switching never re-runs by itself. While a rule is switched, results don't count as evidence; **Put back as planned** restores everything.
- **More rules can be switched:** the firewall rule for the POV ports (Block / Allow), DNS Control (the category rule and DNS over HTTPS: Block / Allow), file type control for executables (Block / Caution / Allow), Cloud Sandbox's first-time action (Hold for the verdict / Allow and scan), and the ZPA access rule for the POV app (Allow / Block). Each switches only the POV's own rule, for the pilot group.

## 0.9.87
- **Device tests › Test runner is one list.** Each criterion is a single line (title first, the ID small beside it, ◆ for a differentiator), and each test's result lands on its own row as it runs: ✓ as expected, ✕ not as expected, ! error. Failures open in place with what came back, **Show it**, and details, policy and Check again. Criteria fold away; anything not as expected opens by itself. A criterion recorded as evidence says so.
- **A readiness check before Run.** Before anything runs, the console checks the device: Client Connector running, traffic going through Zscaler (with the data centre), the pilot user in the POV's tenant, and the policy as planned. Run waits until those pass, and each failed check says how to fix it. A linked device shows whether it's online (it checks the tenant itself). **Check again** re-runs it.
- **The run bar stays in view** while the list scrolls: Run, Stop, progress and "18 of 22 as expected · 3 not · 1 error", with a filter for **Not as expected** and **Not run**. The tabs no longer slip under the header on narrow windows.
- Fixed: with tenant recording on, products read at the same time could write into the recording together and garble a line (seen on Windows). Writes now take turns.

## 0.9.86
- **Competitive land mines, rebuilt from public research.** Nine differentiators, now with cited SE notes for eight competitors: Palo Alto Prisma Access, Netskope, Cisco Secure Access, Cloudflare One, Microsoft Entra (Global Secure Access), Fortinet FortiSASE, Check Point Harmony SASE and Cato Networks. For each, the notes say where the competitor stands (gap: use it; parity: skip it; strong: avoid it; unverified: test, don't claim), what their own public docs say, and link the sources (researched 2026-10-25, each claim re-checked against its page). Each differentiator also says what Zscaler needs for the test to pass. Independent results (CyberRatings 2025 SSE) are listed with their source.
- New differentiators: apps outside the browser get the same protection, encrypted DNS can't route around policy, large files are still inspected, and slow apps traced hop by hop. New opt-in criteria: **IS-DLP-03** (a 60 MB upload with card numbers at the end is blocked) and **DX-PATH-01** (a slow app traced hop by hop to the cause, demonstrated).
- **DNS over HTTPS is now blocked with a DNS Control rule** (protocol DNS over HTTPS) and tested with a real DNS-over-HTTPS query; 0.9.84's URL-category rule wouldn't have matched. **IS-SSL-03** names what it needs: ZIA Advanced Firewall and Auto Proxy Forwarding for Non-Defined Ports.
- Customer-facing text (the vendor sheet, the report) still never names a competitor.

## 0.9.85
- **AI Guard policy in the Test runner.** A Policy panel beside the run box (and the Policy tab) sets each detector to **Block, Monitor or Off**, for prompts and replies, read live from the POV policy in AI Guard; presets are there too. Open a result to change the detectors it triggered straight away, then **Run this test again** (it doesn't re-run by itself). Only the POV policy changes; a preset turns every detector back on.
- Detectors have their own names: "PII (cards, IDs, contact details)", "PII deep scan" and "Personal data" were all "Sensitive data (PII)" (the name AI Guard's dashboard files them under, still used for dashboard coverage).
- **Reading the tenant is faster.** Products are read at the same time, each with its own signed-in client (their APIs are separate), so a read takes as long as the slowest product rather than all of them added up. The log shows how long each product took. Asking Claude about a use case reuses the tenant reading from the last 15 minutes when nothing was applied since (tick "Read the tenant again" for a fresh one).

## 0.9.84
- **Competitive land mines** (Success criteria › Competitive land mines): five vendor-neutral differentiators, each proved by tests: inspects all of it (TLS on a non-standard port, new IS-SSL-03; DNS over HTTPS controlled, new IS-DNS-02 with a POV block rule), one agent and the same policy on any network (new IS-ZCC-03, run the tests off network), private apps stay invisible (new PA-APP-04: another port on the app's server is closed to pilot users, and the segment opens only the planned ports), unknown files held for the sandbox verdict, and AI security proven live. **Add the bake-off pack** proposes them for this POV; **Vendor sheet for the customer** is a printable "ask every vendor to show this" scoresheet. Criteria carry a **Differentiator** badge in Success criteria and Device tests; the report adds a neutral "Where Zscaler stood apart" section.
- SE-only notes per competitor (Palo Alto Prisma Access, Netskope, Cisco Secure Access, Cloudflare One): questions to probe in their POVs, drafts marked "not verified: check with competitive intelligence". They stay in the console: never in the report, the vendor sheet, exports or anything sent to Claude. IS-SSL-03 says to confirm the setting in your lab first.
- **AI Guard Save is faster and says what it's doing.** Saving the proxy setup re-reads only AI Guard (the other products are planned from the last reading, which it says), reads each list once instead of twice, and logs each step: the reads, the sign-off, "Creating ZPOV: POV proxy key…", the key's secret going to the keychain. The log stays under "What it did" afterwards.

## 0.9.83
- **See what the kit is doing.** Preflight, Apply and the change list now show each step live while they read the tenant: each product as it's read, every read-only API call it makes (for example "ZPA application segment: list segments"), what each product's checks found, and how many objects each product will make, ending with "Nothing has changed in the tenant". When it finishes, the log folds away under "What the kit read and checked", one click to open.
- Setup's side note says when the tenant changes in the SE-applies flow ("until you click Apply in step 5"); it named the customer-approval steps before.

## 0.9.82
- **Seed stack for AI-SPM and DSPM** (Next steps › Seed stack, or `pov-kit seed template [--mcp] [--public-decoy]`): CloudFormation for the customer's test AWS account with synthetic sensitive data (customers, payroll, patients, cards; CSV, JSON, PDF and Word), a deliberately weak bucket, a DynamoDB table, AI training data with personal data in it, an over-permissioned AI agent on Bedrock and, optionally, an MCP server with no authentication and a public decoy file. Everything is named zpov-… and tagged; deleting the stack empties and removes it all. Step-by-step deployment: docs/SEED-STACK.md.
- **DSPM (draft)**: a new product with three attested criteria (sensitive data found and classified, risky exposure flagged, access to sensitive data mapped).
- AI-SPM and DSPM put their cloud steps on the steps for people: connect a test account with Zscaler's own onboarding template, then deploy the seed stack, with the criteria they hold up; removing both is an end-of-POV step. AI Red Teaming adds "name the AI app to scan, and who approves it".

## 0.9.81
- **GenAI in browser isolation** (opt-in criterion AI-GEN-03, part of AI Access Security): a POV Cloud App Control rule opens an assistant that's neither approved nor blocked (Perplexity) in Cloud Browser Isolation for the pilot group, so users read answers but can't paste, upload or download. The device test expects isolation, and the rule's demo switch offers Block, Caution, Isolate and Allow. Tenants without an isolation profile: the rule is left out, with a note.
- **AI Asset Management / AI-SPM (draft)**: a new product with four criteria, each shown and recorded by a person (no API in the Zscaler SDK yet): shadow AI inventoried (the traffic generator sends GenAI traffic so there's something to find), AI assets in a connected cloud account found, risky AI exposures flagged with a fix, and governance reported against NIST AI RMF, the EU AI Act or ISO 42001.
- **AI Red Teaming (draft)**: a new product with four criteria, proved by the scan's report: a scan runs against the customer's AI app, findings are rated with fixes, AI Guard stops what the red team found, and scans repeat on a schedule.
- The API sign-in check and its manual step work for POVs whose first product is read-only or draft.

## 0.9.80
- **ZPA Privileged Remote Access** (opt-in criterion PA-PRA-01): a PRA segment for one server (RDP or SSH), a pilot-only access rule, a PRA portal and a console. New ZPA settings: PRA server, protocol, port, portal domain and certificate (a ZPA certificate that covers the portal's domain is found by itself). The device test opens the portal.
- **ZPA App Protection** (opt-in criterion PA-APP-03): the POV app segment becomes an inspected one, with an App Protection profile (OWASP and ThreatLabZ controls, blocking) and an inspection rule for the pilot group. The device test sends a cross-site scripting request and expects it stopped; a test can now count an HTTP status (ZPA's 403) as a block.
- **New products, read-only:** External Attack Surface (EA-FND-01 findings by severity, EA-LKA-01 lookalike domains), Business Insights (BI-RPT-01), Microsegmentation (MS-AGT-01 agents connected, MS-POL-01 policy rules) and Cloud & Branch Connector (CC-GRP-01 connector running, CC-FWD-01 forwarding rules). The kit reads them and proves their criteria from what the tenant has; the customer's steps (add domains, install agents, deploy the connector) go on the list of steps for people. Nothing is created or torn down.
- Cloud Sandbox (IS-SBX-01) and Workflow Automation (IS-DLP-02) are opt-in too, so POVs that don't choose them are unchanged.
- Deployment guide: "More Zscaler products in a POV".

## 0.9.79
- **Cloud Sandbox** (new criterion IS-SBX-01, "Never-seen files are held for Cloud Sandbox analysis"): a POV sandbox rule for the pilot group (first-time action Quarantine for PDF, Office, executables and ZIP; blocks malicious verdicts; AI Instant Verdict on). The device test downloads a PDF made fresh for each run, so its hash is new, and expects Zscaler's quarantine page; the result shows the file's MD5 to look up the sandbox report. Tenants without Advanced Cloud Sandbox: preflight says so and the rule is left out. New guided demo: "A file no one has seen before".
- **Workflow Automation** (new criterion IS-DLP-02, "DLP incidents reach Workflow Automation"): an API check, read-only, for DLP incidents of the pilot users in the last 7 days; new demo helper to walk the incident in the Zscaler console. It needs the Workflow Automation subscription and view access for the API client.
- The read-only guard accepts the incident search (a POST that only reads).

## 0.9.78
- Opened results: **Show it in the browser** sits with Check again, and "open it in the browser when it changes" (on by default) opens the page as soon as a switch changes the result, so the room sees the new block, caution or allowed page. The page details now follow the latest run (they showed the first run's page). Earlier runs are no longer listed.

## 0.9.77
- Device tests › Test runner: **open a result** (Details, policy and Check again). It shows the POV rule that decides the test, with its switches (Block, Caution, Isolate, Allow), who it applies to and the planned action; switch it and the test re-runs every 15 seconds for up to 2 minutes until the result changes ("Changed: caution → block"). **Check again** and **Check until it changes** work without a switch too.
- Also in an opened result: Zscaler's category for the site (the tenant's URL lookup, read-only), the block page's status and text, time taken, the Zscaler data centre and public IP (ip.zscaler.com), the certificate's issuer, expiry and TLS version, where to find the event in the Zscaler console (user, URL, time, and the run tag to search, with Copy), the tenant's log line when the log feed is on, and earlier recorded runs of the test.
- Every probe result now carries its run tag and time.

## 0.9.76
- AI Guard: after Save applies the proxy setup, the tab refreshes, so LLM proxy and the model choice (Anthropic, OpenAI) are available in the Test runner straight away (before, they stayed greyed out until the tab was reopened). The model choice names a provider that isn't the default one (DeepSeek, say).

## 0.9.75
- **The SE applies directly** (POVs with SE sign-off, the default). Setup's Change list, Sign-off and Apply steps become one **Apply** step: what the kit will make now (pilot users only), the **Changes made** so far (what, why, who it affects, when), and Apply with your name recorded as the sign-off. The checklist shows "Apply to the tenant" instead of making and signing off a change list, and Status shows what's waiting to apply instead of who approved.
- Use cases: **Accept and make it in the tenant ›** accepts and applies in one go; Make it in the tenant applies straight away when nothing else is waiting (and still shows anything else that would go in with it first).
- The change list still works underneath: the kit only creates what it planned, only changes or deletes what its ledger holds, and teardown removes exactly that. **Switch to customer approval** on the Apply step brings back the change-list page and the customer's sign-off.

## 0.9.74
- AI Guard proxy mode: the provider's own keys are listed first ("Default OpenAI Provider" before "DeepSeek (OpenAI-compatible)"); compatible providers come after.

## 0.9.73
- AI Guard proxy mode: a tenant with more than one provider of a type (a real OpenAI provider and an OpenAI-compatible DeepSeek one) now offers every key of that type, labelled with its provider, OpenAI's first, and the provider follows the key you pick. Before, the kit took the first provider of the type it found, so the OpenAI menu could show only the DeepSeek key.

## 0.9.72
- AI Guard › Setup › Proxy mode: **Save applies it** on POVs with SE sign-off. The console makes the change list, signs it off in the SE's name (noted "when saving AI Guard proxy setup"), and applies only AI Guard's part: the provider keys, proxy keys and rules. Nothing outside AI Guard changes; other waiting items stay for the next Apply. POVs that need the customer's approval save the setting and say so.

## 0.9.71
- Apply no longer stops when the log feed can't be made yet (the Cloudflare tunnel is off): the rest of the change list goes in, with a warning, and the feed is added by the next apply once the tunnel is on. Before, an approved log feed blocked every apply, including Make it in the tenant.
- Client Connector: a tenant whose Windows default app profile has no forwarding profile (or that has none) now copies the macOS default's forwarding profile, or one named Default, so the POV's forwarding profile and the macOS pilot profile are made instead of being left to build by hand. The check now lists which defaults it found.
- Status no longer reports the POV's own URL categories (tenant check, sign-in sites) as "renamed": it read the wrong name field for categories.

## 0.9.70
- Use cases: **Make it in the tenant ›** on an accepted use case. The console checks the tenant, makes the change list and shows exactly what it would create for that use case (pilot users only), plus anything else waiting in the change list (apply makes the whole approved list). On an SE sign-off POV, tick "I reviewed these changes", type your name, and **Sign off and apply**: the sign-off is recorded against that exact change list (it refuses if the tenant changed since you looked), then the changes are applied and activated and the success criteria checked. A POV that needs the customer's approval says so and changes nothing.

## 0.9.69
- **POV device tests** (`pov-probe ui`): the pilot device's own test runner, in the probe package. The console's Device tests tab cut down to running tests: the POV's tests with results and what they mean, Guided demos with Show it (pages open in this computer's browser) and Check again, in **Presenter** (talk track) or **Plain** mode. No tenant settings, no keys; a page on this computer only, with a one-time token. Full runs are saved to the Desktop and, with a link code (pasted on the page or `pov-probe link`), sent to the SE's console.
- The AWS pilot template and the CloudShare Windows script put **POV device tests** on the desktop and open it at sign-in.
- The test descriptions, guided demos and Show it text now live in one module shared by the console and the device (same test IDs on both).

## 0.9.68
- Device tests › **Tenant logs**: the console sees the device tests in ZIA's own logs, live, for when a device can't be linked. A Cloud NSS web-log feed (one change-list item, filtered to the pilot users: the POV's test users' department, or the named pilot users) streams to this console through the Cloudflare tunnel, or to the customer's SIEM (Splunk HEC). Each line is matched to the POV's device tests (the probe tags every test URL with its run), the view shows what Zscaler just saw with action, reason, category and the matching test, and a run the logs saw in full can be counted as evidence ("tenant logs"). Firewall, DNS and certificate tests aren't in web logs.
- The feed's address and key are filled in at apply and never written into the change list, so the approval stands when the tunnel's address changes; **Update the feed address** points the POV's own feed at the new one. Teardown removes it. Discovery checks Cloud NSS is there and reads the tenant's own JSON web-log format.

## 0.9.67
- Device tests › **Run on**: run the device tests on another computer with Client Connector and see the results in the console as they land. **Link a device** turns on a device listener (same network, or also from anywhere through a Cloudflare quick tunnel when `cloudflared` is installed) and shows a one-line command for macOS and Windows. The device runs `pov-probe link`, connects out to the console and waits: the Test runner, Guided demos, Show it (pages open in the device's browser) and Check again all work on the chosen device. Runs started on the device itself (`pov-probe test`) are sent to the console when linked, and count as evidence like an imported file.
- The listener is separate from the console and serves only device requests carrying the POV's link token; it comes back on after a restart (the tunnel's address changes, so a device elsewhere relinks).

## 0.9.66
- Success criteria: an API check made before a criterion's test changed no longer stands. Each API proof records which test sites it checked; when the criterion's tests change (reddit.com became facebook.com for IS-URL-02), the old result shows as needing a re-check and the automatic check runs again.

## 0.9.65
- Setup no longer opens on Preflight every time the page loads. Preflight's results were kept only in the open page, so after a reload or an update the step looked undone; a POV with a change list (or applied objects) now counts it as done, and Setup opens on the first step really left.

## 0.9.64
- AI Guard › Test runner: when LLM proxy is greyed out, a line says why (proxy mode isn't set up for this POV) and links to AI Guard › Setup.

## 0.9.63
- Policy switches: a switched rule's tests now expect what the switch does (Caution social switched to Block: facebook.com expects the block page and shows as expected, marked "Demo switch"). The Point at line follows too. Each switch is tied to the tests it decides, so switching Block anonymizers no longer shows up under the gambling tests.

## 0.9.62
- Policy switches: the sign-in bypass (the customer's IdP and MFA sites) is never offered, so a switch can't lock users out; GenAI rules whose tenant names the action DENY show as Block, and put back correctly.

## 0.9.61
- Device tests › **Policy**: demo switches for the POV's own ZIA rules: web categories (Block, Caution, Isolate where the rule isolates, Allow), SSL inspection (Inspect, Don't inspect), DLP (Block, Allow and log) and GenAI apps (Block, Caution, Allow, as the tenant offers). Each switch changes only that rule's action, through the ledger guard, then activates. The tenant-check rule is never offered.
- Show it steps carry the switches for their test, with **Check again** to reopen the page and rerun the test after a switch.
- While anything is switched: a banner with **Put back as planned**, a Status warning, and test results aren't recorded as evidence.

## 0.9.60
- Device tests › Test runner: **Show them, step by step** walks through the chosen POV tests the same way as a guided demo's Show it: each page opens in this computer's default browser with what to point at, the test runs alongside, and at the end all of them are recorded together and listed in Results.

## 0.9.59
- Device tests › Guided demos › **Show it**: shows the end user's experience. Step by step, each test's page opens in this computer's default browser (the block, caution, isolation or DLP page the user would see), with what to point at; the test runs alongside, and at the end the demo's tests are recorded together for the scorecard. Firewall and DNS steps give a Terminal command to copy; the DLP step copies test card numbers to paste.
- Test runner results: "Show it in this computer's browser" opens the page in the default browser instead of the browser the console is in.

## 0.9.58
- Device tests: ZIA's caution page ("cautioned for category") is read as a caution, and its Browser Isolation page as isolation, even though both pages carry the block template's text.
- Device tests: when ZIA answers the HTTPS request on port 443 in plain HTTP (blocked at connection), the probe reads that answer directly and records a block.

## 0.9.57

- **Device test results say what Zscaler's page said:** each web test's detail carries the page title and its reason
  line ("Website blocked …", "Caution …"), so a surprise outcome explains itself.
- **The caution page is recognised more widely** (a "Continue" button, "acknowledge"), and a block page that mentions
  continuing no longer reads as caution.
- **HTTPS refused before TLS** (`WRONG_VERSION_NUMBER`: ZIA blocking at connection time, as for phishing pages) is
  checked over plain HTTP, where Zscaler's block page shows.

## 0.9.56

- **Device tests tab** (POVs with Internet Access, Client Connector, ZPA, ZDX or CASB): the AI Guard test runner's
  counterpart, for live demos on a pilot device running the console.
  - **Test runner:** the POV's device tests by criterion; run all or some, results stream in as cards (expected vs
    got, the detail), **Open in a browser** repeats a test for the room, Stop ends after the test in flight. A
    criterion counts as evidence once all of its tests ran. The probe's tenant check comes first, as always.
  - **Guided demos:** ten short stories (policy follows the user, a gambling site, coaching, malware in HTTPS,
    phishing, card numbers leaving, safe GenAI, risky downloads, isolation, not just the web), each with what to say
    first, what to point at and what to say after, and a **Run it** button.
  - **Demo helpers:** for ZPA, ZDX and CASB, what to say, the steps to show in the console and each criterion's
    state; and **Warm up the dashboards**: rounds of the POV's test traffic from this computer, so Insights isn't
    empty.

## 0.9.55

From the first real pilot-device run (12 of 21 passed), fixes for the 9 that didn't:

- **Mac pilot devices get their own Client Connector profile** (`… pilot Macs …`): the pilot group, the Zscaler
  certificate and the POV's Z-Tunnel 2.0 forwarding profile, like the Windows one. Without it a Mac stayed on the
  tenant's default profile (web traffic only), so the firewall and DNS tests (IS-FW-01, IS-DNS-01) never reached
  Zscaler. Existing POVs: make the change list again, sign it off, and Apply.
- **A blocked HTTPS site that isn't decrypted counts as blocked:** ZIA answers with a Zscaler-issued certificate, which
  the probe took for an error (IS-THR-02).
- **Test sites that match the rules:** the caution test opens facebook.com (ZIA files reddit.com under discussion
  forums, not social networking); the GenAI block test opens poe.com (the tenant can't put DeepSeek in a Cloud App
  Control rule, so Apply leaves it out).
- **The probe looks like a browser** (headers browsers send), which caution and isolation pages respond to; the DLP
  test posts ten fake card numbers as plain text to dlptest.com.
- **Failed device tests explain themselves** on Success criteria: why (Z-Tunnel 1.0, no isolation, DLP not acting,
  the site's category, an app not in the rule, a network error) and what to do.

## 0.9.54

- **Set up a pilot device, simplified to one command.** It installs Client Connector and the probe only if they're
  missing (an existing Client Connector is left as it is), then runs the POV's tests once the pilot user signs in.
  The long command isn't shown any more: one copy button, with *Show the command*, the setup script and *Review and
  add tests* under **More**.
- **Run the tests on this computer:** when the computer running the console is the pilot device, one button runs
  the tests and imports the results. No Terminal.
- **Before any test traffic, the probe checks the device is in the POV's tenant as a pilot user** (the POV's own
  test page must be blocked). On another tenant (a work laptop's corporate Client Connector, say) it stops and says
  so.

## 0.9.53

- *Download probe pack* says what the file is (tests for the probe to read, not a program) and how to use it, and
  points to the one-command way on Set up a pilot device.

## 0.9.52

- **Review the POV's device tests before they go out** (Set up a pilot device > Review and add tests): every test the
  commands carry, criterion by criterion, in plain words ("Open www.bet365.com → expect blocked"), with where it came
  from. Leave a test out (and put it back), or **add your own**: a web page (blocked, allowed, caution, isolated),
  HTTPS inspection on or off for a site, a port (blocked or open), or a DNS name (blocked or resolves). Added tests
  count toward their criterion's evidence, or go in *Extra checks*. The commands and the setup script carry the
  reviewed pack, and results from before a change show as out of date.

## 0.9.51

- The *Run the tests* command refreshes the probe on the device first, so a device set up with an older kit runs
  the POV's current tests too.

## 0.9.50

- **Pilot-device testing, made plain.** *Set up a pilot device* is three numbered steps:
  1. **Install:** the install command now carries the POV's tests, so they run by themselves once the pilot user
     signs in to Client Connector (no separate probe pack to send or install).
  2. **Run the tests:** one command for a device that's already set up, or after the POV's criteria change.
  3. **Import the results:** pick the results file from the device's Desktop, right on the same card.
- The device scripts and `pov-probe` end with what to do next, in words: sign in as whom, where the results file is,
  and how to run the tests again if they didn't.

## 0.9.49

- **Set a test user's password from the console** (Set up a pilot device > Show password > Set new password):
  type one, or leave it empty for a random one. The kit sets it in ZIA (on the POV's own test user only), activates,
  and keeps it in the keychain. ZIdentity users still get theirs in ZIdentity: its API can't set passwords.

## 0.9.48

- **Set up a pilot device** shows the test user's password right there (**Show password**), instead of only on
  Next steps, which stays locked until Finish setup is done. A ZIdentity test user says where to set one.

## 0.9.47

- **Fixed: macOS setup could wrongly say the installer isn't signed by Zscaler.** The team-ID check piped
  `codesign` into `grep -q`, which under `pipefail` fails when grep stops reading early; it now reads the signature
  details first.

## 0.9.46

- **Fixed: the macOS installer failed with 'Permission denied'.** The pinned zip carries no Unix permissions, so
  the installer's programs weren't executable after unzipping; the setup now restores them (the signature still
  checks out: it doesn't cover permissions).

## 0.9.45

- A console page left open across a restart (after an update, say) reloads itself instead of saying "bad token".

## 0.9.44

- **macOS pilot devices: Client Connector 4.10.0.36 is pinned** (Zscaler's installer app, SHA-256 and Developer ID
  team PCBCQZJ7S7 checked on the device). It installs unattended with the tenant's cloud and user domain, so there's
  no settings profile to approve any more. `--pkg FILE` still takes the customer's own `.pkg`, or the installer `.app`
  (zipped or not).
- **`pov-probe trust-ca`** adds the Zscaler root CA to a pilot device's trusted roots, for devices where Client
  Connector didn't (the kit's copy is checked against its pinned fingerprint). `traffic check` suggests it when HTTPS
  inspection fails on an untrusted certificate.

## 0.9.43

- **Fixed: Stop was greyed out during a run** after the AI Guard tab redrew (switching tabs, or the page reloading).
  The tab now reattaches to the run still going: Stop works, and results keep coming in.
- A model whose account behind the AI Guard proxy is out of credit (the provider answers 'insufficient balance') is
  named plainly, and the rest of the run uses the other model(s) instead of failing every test it's given.

## 0.9.42

- **POV checklist** under the tabs: what's done, what's next, and **Go ›** to get there (connect, pilot users, change
  list, sign-off, Apply, Finish setup, pilot device, AI Guard tests, success criteria, executive summary, handover).
- **Rehearsal in a lab tenant:** tick *This is my own lab tenant* (Start a POV → More options). The checklist adds the
  field checks (self-test, backups, both Claude Desktop connectors, traffic generator), each step can be marked
  **Worked** or **Problem…** with a note, and **Download rehearsal report** collects them (no customer data).
- **The test library, checked against a live AI Guard tenant:** prompts that didn't trigger their detectors were
  reworded (or replaced), so the shipped tests trigger as written. The encoded-blob evasion test now expects prompt
  injection (that's how AI Guard flags it). The malicious-URL reply test is out of AI-AIG-06's automated proof: no
  safe test URL is on Zscaler's live threat feed, so show it live with one the AI Guard team gives you.
- Calibration skips tests meant to provoke something else (the refusal trigger), and redoes a test whenever the test
  itself changes in a new kit version.

## 0.9.41

- **Every AI Guard test triggers what it's meant to show.** Before a run, the kit scans each test once through the
  POV's Detection API (no model involved). A test that misses is reworded by Claude (up to 3 tries) or swapped for
  another test that expects the same detectors and does trigger them. The customer's own prompts are never changed.
  Results are remembered per POV and redone when the policy changes; the test library shows each test's state, and
  **Check the picked tests again** re-runs it. The internal readout lists what was reworded or swapped.

## 0.9.40

- Executive summary: the AI Guard "risky prompts caught" figure now counts each harmful test once (its latest
  result per model), and only where the detectors are known; it used to count every past run, including proxy runs
  without detector tags and classification tests.

## 0.9.39

- **Executive summary, two versions, as Word and PowerPoint** (Handover tab). Claude drafts a *customer* version
  for their executives (what was proved, in business terms, the AI Guard numbers, what's open, and a recommended next
  step) and an *internal* one for Zscaler's deal review (verdict, win themes, risks, gaps, competitive notes, asks),
  from the results, the use cases, the AI Guard counts and your notes, with the customer's names removed. The kit fills
  in the customer's name on your computer. The customer version also opens the evidence report.
- **Simple view by default.** Advanced view (top right) shows the rest: start options, CloudShare and AWS traffic
  generators, AI Guard test users, rounds and detector tags, Claude-drafted tests, and Claude making changes.
- **The SE signs off the change list by default.** Customer approval is now a choice per POV (Sign-off step:
  *Ask the customer to approve instead*); Apply still refuses anything but the signed-off list.
- **Demonstrated replaces attestations:** showed it live? One click marks the criterion proved, in your name.
- The kit now uses python-docx and python-pptx (fetched automatically on the next start).

## 0.9.38

- **Fixed: LLM proxy runs used only one model.** With both Anthropic and OpenAI ticked, the console sent no model
  list until a box was clicked, so every test went through the first proxy key. The run now rotates through every
  ticked model (and every model with a POV proxy key when none is named); with none ticked it says so.

## 0.9.37

- An AI Guard criterion that doesn't pass explains each test that missed: what AI Guard found, and whether the
  missed detector is on in the POV's policy (if not: turn it on; if it is: AI Guard judged that example differently,
  so re-run it, swap in a clearer example, or attest it).

## 0.9.36

- **The API proofs run on their own** (read-only): after Apply, after Finish setup's checks, with every Status check,
  and when Success criteria opens if the last check is over three hours old. **Check again** runs them now; the
  button is gone for AI Guard-only POVs, whose criteria the test runner proves.
- **A criterion that doesn't pass says why:** what was found, why it happens, how to fix it, and a button where the
  console can do the fix (Fix drift, Finish setup, Pilot users, the change list, the AI Guard test runner). The
  first reason also shows under the criterion's result.

## 0.9.35

- Fixed: **Ask Claude** (and criteria mapping, the report summary and drafted AI Guard tests) failed with "tool_choice:
  type "tool" and "any" are not supported for this model" on models that don't take a forced tool call. The kit now
  asks again with the tool offered rather than forced, and remembers that for the model.

## 0.9.34

- **Proxy mode for Anthropic and OpenAI, side by side, from what the tenant has** (AI Guard → Setup), like the SE
  demo kit. A card per provider shows whether the customer's AI Guard has that provider and which keys it holds.
  Choose per provider: reuse one of their keys, use your own, or off, and the model. **Read the tenant again**
  refreshes it. Each provider in use gets its own POV proxy key and rule.
- The test runner's LLM proxy mode rotates across the providers you tick, and each result shows which one answered.
- POVs set up with one provider before this keep their settings and their approved change list.

## 0.9.33

- **Claude Desktop can make changes, through the change list.** A second Claude Desktop connector, run by the kit,
  with its own customer agreement (Next steps → Ask Claude about this tenant → Let Claude make changes):
  - **Propose a change:** the kit checks it against the tenant, scopes it to the pilot group and adds it to the change
    list. The customer approves and you Apply in the console; Claude can't apply.
  - **Act on what's already approved:** switch the POV's AI Guard policy, run AI Guard tests (they count as
    evidence) and API proofs, check status, Fix drift on the POV's own objects, and check the steps for people.
  - It never uses Zscaler's write tools. Each action is logged as Claude Desktop's.
- Fixed: **Ask Claude** on the Use cases tab failed with "NameError: cannot access free variable 'ai'" (since
  0.9.24). Drafting the report summary had the same problem.
- Fixed: messages showed `&#39;` and similar where names had apostrophes.

## 0.9.32

- **The AI Guard tab, rebuilt like the SE demo kit's test runner,** with four parts: Test runner, Guided demos, Policy,
  Setup.
  - The test library on the left, with **This POV's criteria** first: a group per AI Guard criterion (catalog,
    customer prompts, use cases), each test labelled with its criterion, and a preset that selects them all.
  - **Detection API / LLM proxy** (with Detector tags), rounds, users, a progress bar and counters; results land as
    they run, with dashboard coverage, CSV and the one-page report.
  - **Stop** ends a run after the test in flight; what ran stays and counts.
  - **Results count as evidence:** criterion-labelled results update Success criteria straight away (partial runs stay
    incomplete).
  - **Draft more tests with Claude** for any criterion; accepted drafts join its group and its proof.
  - Tests run as the POV's pilot or test users (or names with the POV's ID), so Insights shows just the POV.

## 0.9.31

- **Details and how to fix, for status checks too.** Every check that isn't passing (after Apply, on Status, in
  Preflight) has a **Details and how to fix** panel: what it checks, why it matters, how to verify by hand, numbered
  fix steps, and how to re-test. It's open by default when a check fails. New: the ledger backup, Claude Desktop
  access, the approval, the end date, pilot users' sign-in, rule scope, missing or disabled POV objects, ZDX, AI
  Guard's key, connectors and customer actions.
- **Fix it from the panel:** turn on encrypted backups (folder and passphrase) or back up now, Fix drift, open the
  change list, or open Ask Claude about this tenant.
- Status fixes now name the console's buttons instead of command-line commands.
- An AI Guard-only POV no longer shows pilot-user checks ("How pilot users sign in: ZIA: unknown"): it has no pilot
  users.

## 0.9.30

- **The setup stops for the steps for people, like the SE demo kit.**
  - **Preflight** now lists the steps needed before the change list (ZDX role, ZPA customer ID, Malware Protection,
    a SaaS tenant) under its checks. A new **Finish setup** step after Apply walks the rest in order (entitlement,
    passwords, Client Connector profiles, App Connectors, ZPA in Client Connector, pilot devices), with Set up a
    pilot device on the same page.
  - **Continue** waits until each step is checked or marked done. **Continue anyway** records who decided and why;
    those steps stay on the list and keep holding up their criteria.
  - **With the admin, now** or **Admin does them later** (per POV). The second sends just this stage's steps to the
    admin; **Check them all** picks up when they're done.
  - **How to verify** on every step and on every preflight check that isn't passing: what it checks, why it
    matters, how to verify by hand, the fix, and how to re-test.

## 0.9.29

- **Steps for people, where they're needed.**
  - **Start a POV** previews the steps the chosen products will need from a person, to agree at kickoff.
  - **Connect** shows how to create the API client (and find the ZPA customer ID) right there, with Check now.
  - **Pilot users** shows the entitlement and password steps.
  - The header shows **N steps for people** on every tab; clicking it opens the list.
- **What each step holds up.** Each open step lists the success criteria that can't pass until it's done. On
  **Success criteria**, a criterion that isn't passing says "waiting on" the step, with a link to it.
- **Values to paste.** Each step shows the exact values to use (API client name, group to entitle, connector group,
  provisioning key name, pilot users, cloud...) with a Copy button. They're in the sheet for the customer's admin
  too, with what each step holds up.

## 0.9.28

- **CloudShare for the traffic generator in the console:** Next steps → ZIA traffic generator → **CloudShare Windows
  pilot script**. One PowerShell file with the POV's probe pack inside: it installs the probe if needed, checks the
  device is in the POV's tenant and schedules a round every 30 minutes.

## 0.9.27

- **Deleting a POV that still has objects in the tenant** no longer stops at a dead end. The Delete dialog lists
  them and offers **Remove them from the tenant** (the same teardown as Handover → Remove the POV, confirmed by typing
  DELETE). Once they're gone it shows the delete confirmation.

## 0.9.26

- **Two POVs in one tenant no longer collide.** A new POV takes the prefix ZPOV2 (ZPOV3...) when another POV on this
  laptop already has objects under ZPOV, so a second POV in a lab tenant gets names of its own.
- **When names are taken,** Apply now says whose they are (another POV on this laptop, or objects it doesn't know)
  and offers **Use prefix ZPOV2 for this POV**. That renames the planned objects; the new change list is then
  approved again. The prefix can change only while the POV has nothing in the tenant (`pov-kit set prefix NAME`).

## 0.9.25

- **The POV probe: a separate small download for pilot devices.** It holds only the POV's tests and the traffic
  generator: no console, no API keys, no tenant access, two small libraries. It installs with one line
  (`install-probe.sh` / `install-probe.ps1`, SHA-256-checked), and gives a `pov-probe` command (`test`, `pack`,
  `traffic`, `cleanup`). The pilot device setup, the CloudShare pilot and the AWS traffic generator now install it
  instead of the whole kit. The kit's own `pov-kit probe` and `pov-kit traffic` still work.
- **Probe packs follow the success criteria.**
  - A pack holds the chosen criteria's tests (use cases included), each test's version, and a traffic profile: only
    the traffic those criteria call for, plus the use cases' own sites and blocked ports.
  - Results say which POV and which test versions they ran. Results from another POV are refused.
  - A criterion whose tests changed counts as still to prove until a device runs the new pack. **Success criteria**
    lists what's out of date and what no device has run yet.

## 0.9.24

- **Claude without an AI Guard tenant.** SEs and partners with no AI Guard proxy key can save their own Anthropic API
  key (Use cases tab, or `pov-kit ai connect --direct`). Use cases, criteria mapping and the report summary then go
  directly to Anthropic, with the same customer agreement and name replacement but no AI Guard scanning. An AI Guard
  proxy key, when there is one, is still used first. The customer's agreement now records the route, so switching
  routes asks for it again.

## 0.9.23

- **The SE demo kit's ZIA traffic generator**, for the customer's dashboards: `pov-kit traffic check | run | schedule`
  on a pilot device (web categories, SaaS, GenAI, EICAR and phishing test pages, fake card numbers, file types, DNS,
  the POV's blocked ports), matched to the POV policy (the tenant check is the POV's own blocked page). Each round
  sends nothing unless ip.zscaler.com confirms traffic goes through Zscaler.
- **An AWS generator** (Next steps → ZIA traffic generator, or `pov-kit traffic aws`): a CloudFormation template for a
  Windows instance with the kit's pinned Client Connector for the POV's cloud and pilot user, no inbound ports, and a
  round every 30 minutes.

## 0.9.22

- **Guided demos in the AI Guard tab**, from the SE demo kit: six storylines with a Say/Show talk track, presenter
  notes, OWASP Top 10 for LLM tags, real incidents, a Monitor/Block switch per step (the POV policy changes as the step
  opens, with a countdown while it applies), real model replies in proxy mode, and a recap for the follow-up email.

## 0.9.21

- **An AI Guard tab, like the SE demo kit**, on the POV's own app, keys and policy:
  - policy profiles: Monitor, Block attacks, + data leakage, **Block everything risky**, and **Custom** (per detector,
    prompts and replies separately);
  - the demo kit's **test runner** (72 tests, presets, industry packs, users and rounds, detectors fired and missed,
    hide-missed for demos), a **live prompt** box, and a **one-page report**;
  - **the customer's own prompts** from CSV, as a pack and a success criterion (AI-AIG-C1…);
  - **proxy mode** with the customer's model key or the SE's own (kept out of the change list; removed at teardown).
- Keyword mapping of imported criteria is smarter (word stems; AI criteria only for AI wording).

## 0.9.20

- **The customer's success criteria in, the POV out.** Success criteria → **The customer's success criteria**: paste
  their list, upload their document (Word, PDF, Excel or CSV) or pick from the catalog. **Map them** matches each one
  to the catalog (Claude through AI Guard, with the customer's agreement; otherwise keywords), editable row by row.
  **Build the POV from these** chooses those catalog criteria and has Claude write the configuration and tests for
  the rest as use cases (accepted when the kit can build them, or kept as steps to attest). It all joins one change
  list for the customer to approve, and the report quotes each of their criteria next to its proof.

## 0.9.19

- **AI Guard: the SE demo kit's full test library as success criteria.** Eight criteria, each proved automatically
  through AI Guard's Detection API: prompt injection, secrets/PII/personal data, evasion (gibberish, invisible text),
  source code, responsible AI (toxicity, financial and legal advice, competitors, brand risk), model replies (leaked
  data, toxicity, malicious links, refusals), topic and language tagging, and no false positives on everyday prompts.
  Industry packs for financial services, healthcare and legal are optional criteria (`pov-kit set criteria`).
- **AI Endpoint Security (draft).** A new product to tick on Start a POV, with five draft criteria from Zscaler's
  public description, to be replaced by the internal POV plan. No API yet, so nothing is created in the tenant; the
  probe plants harmless, clearly named test files on a pilot device (a local model file, an MCP definition, agent
  skills, a PII prompt to a local Ollama model) and a person records what the console shows. `pov-kit probe
  --cleanup` removes the test files.

## 0.9.18

- **SE Deployment Guide and Quick Start rewritten** for Zscaler and partner SEs, leading with Quick start, and checked
  against the kit: current option names, "Needs you" and "added later", optional prerequisites (pilot group, ZPA app,
  cloud account), pilot devices on Mac and virtual machines, CloudShare, verified console paths, and new
  troubleshooting rows.
- **Mark a lab POV in the console:** Start a POV → More options → **This is my own lab tenant** (the self-test needs
  it; before, only `pov-kit new --lab` could).
- **Quick start from here** on Connect carries on a POV started earlier (to send the customer the role spec before
  the kickoff), instead of starting a second one.
- The hand-built Client Connector spec covers Mac pilot devices (a macOS app profile with the same settings).
- An independent check of the guides against the code fixed 17 more points, among them: the safety net is set up
  once a POV exists; success criteria are recorded with `pov-kit set criteria`; the CloudShare pilot uses the setup
  script (with the probe pack) and the environment is deleted before teardown; macOS needs `--pkg` until a macOS
  installer is pinned; the self-test writes only in ZIA, ZPA and AI Guard.
- **ZDX no longer holds a POV back for want of named pilot users:** it uses the POV's test accounts too, and without
  any pilot users it warns (deep traces wait for pilot devices anyway).
- A downloaded setup script takes extra options (`--pkg FILE`, `-Msi FILE`, `--replace`), as the one-line command does.

## 0.9.17

- **A POV lab on CloudShare** ([docs/CLOUDSHARE.md](docs/CLOUDSHARE.md)): scripts to build a blueprint once with two
  ZPA App Connectors (Zscaler's EL9 package source, its signing key checked against the fingerprint in Zscaler's
  guide, left unenrolled), the test app, and a Windows pilot with the kit and the checked Client Connector installer.
  No customer values in the blueprint: each POV enrolls its copy with **Next steps → ZPA App Connectors → CloudShare
  commands**, filled in with the POV's provisioning key.

## 0.9.16

- Preflight says the right place for a ZIdentity POV group's test users (ZIdentity, not ZIA). Seen live.

## 0.9.15

- **Quick start.** Start a POV asks for the customer, the products and the API client (or the one Claude Desktop uses).
  The kit fills in the rest from the tenant (read-only), runs preflight and opens the change list. The step-by-step
  wizard stays for changing anything.
- **Products that aren't ready are added later instead of blocking.** A product whose checks fail (no ZDX role, no
  SaaS tenant, a ZPA app that overlaps the customer's) sits out the change list as "added later", with its fix; the
  rest of the POV goes ahead. Products that build on it wait too (Client Connector and CASB on ZIA).
- **Pilot users start themselves.** A POV group in ZIdentity with nobody named starts with a test user on ZIdentity's
  own domain; Quick start defaults to one test account (in ZIA, or ZIdentity when that's where the tenant keeps users,
  detected and re-planned automatically).
- **ZPA brings its own test app.** With no app named, the AWS and Azure connector templates also start a small private
  web page (`pov-app.zpov.internal`, port 80, reachable only from the connectors) and the kit makes it the POV app.
- **Simpler screens.** Pilot users asks one question ("Who will test?") with a one-line summary of who the rules apply
  to; extra options are folded away. Preflight groups what needs you, what's added later, and what's worth a look, with
  passed checks folded away.
- Console paths seen live: API clients (Administration → API → OneAPI → API Clients) and the ZPA customer ID
  (Administration → API → Legacy API → Private Access API → Copy ID).

## 0.9.14

- **The pilot-device setup never takes over a work laptop.** If Client Connector is already installed, or (macOS) an
  MDM already sets Zscaler's install settings, it stops and changes nothing, rather than reinstalling Client Connector
  for the POV's tenant and signing it out of the company's. `--replace` / `-Replace` is for a device meant only for
  the POV.

## 0.9.13

- **Cloud detection fix** (seen live): a PAC file's bypass lines mention `*.zscaler.net` whatever the cloud, so a
  zscalertwo tenant was detected as `zscaler`. Only the PAC URL (`pac.<cloud>.net`) and the gateway
  (`gateway.<cloud>.net`) count now; otherwise the console asks for the cloud.

## 0.9.12

- **Detect the cloud** also reads ZIA's PAC files (they name the cloud's gateway) when ZIdentity's entitlements
  don't say, and looks further down ZIdentity's user list for an entitled user. Both read-only.

## 0.9.11

- **Set up a pilot device from the console.** Next steps → **Set up a pilot device** gives, for a pilot user on macOS
  or Windows, a one-line command or a setup script for the customer's IT. It installs Client Connector with this
  tenant's cloud, the user's domain and name filled in (Windows: CLOUDNAME, USERDOMAIN, UNAME; macOS: a settings
  profile the user approves once), then the kit's probe. The script carries the POV's probe pack and runs the tests
  once traffic goes through Zscaler.
- **Client Connector from the kit**, like the SE demo kit: a pinned copy on the kit's `zcc-installer` pre-release,
  installed only if its SHA-256 matches and it's signed by Zscaler. The customer's own version works too.
- **Detect the cloud** from ZIdentity's Internet & SaaS entitlement (read-only), or type it (`pov-kit set zcc.cloud`).
- `pov-kit probe --wait N` waits up to N minutes for traffic to go through Zscaler before testing.
- The pilot-devices check counts the POV's own test users, not only named pilot users.

## 0.9.10

From running the new checks against the lab tenant:
- **The ZPA customer ID check** says plainly when no customer ID is set, or when ZPA doesn't know the one entered,
  instead of showing ZPA's raw "not found" answer. Its steps give ZPA's Public API page.
- **"Build the Client Connector profiles by hand"** only appears after Apply, when it's actually needed.

## 0.9.9

- **Detailed instructions for every step the API can't do.** Next steps → **Steps for people** lists them in order
  (before the POV, during it, at the end), each with who and when, the console path or the term to type in the
  console's Search menu, numbered steps, the exact names to use, and what done looks like.
- **Checks where the API can see the result**, all read-only: the API client signs in, ZDX and ZPA are readable,
  pilot users have the Internet & SaaS entitlement, Malware Protection blocks viruses, pilot devices are registered,
  App Connectors are up, a SaaS tenant is connected, Client Connector profiles are adopted. A pass ticks the step; the
  rest are marked done with a name.
- **A sheet for the customer's admin**: the same steps as Markdown to paste into an email (no secrets).
- `pov-kit steps` (`--check`, `--done KEY --by NAME`, `--sheet`).
- Console paths seen in a live console are recorded; the others give a menu search term.

## 0.9.8

- **ZIA's success criteria get an automated proof.** For each criterion, the POV rules behind it are checked in the
  tenant (present, enabled, applying only to the pilot group), and ZIA's own URL lookup confirms each test site falls
  in the rule's categories. Insights adds tenant-wide context (blocked transactions in the 7 days to yesterday:
  Insights can't filter to one user or rule and lags a day). The probe pack stays the proof that pilot traffic was
  handled; attestations are still accepted where neither applies.
- **Firewall use cases.** Claude can propose a cloud firewall rule (ports, optional destinations, block or allow):
  the kit builds its own network service and a rule scoped to the pilot group, like every other use case.
- **ZPA preflight** says to set the ZPA customer ID when ZPA answers "not found" without one (seen live).

## 0.9.7

Follow-ups from the live lab test:
- **Status is much faster.** One status check signs in once and reads each list once: discovery and the drift
  check share a read cache, and ZIA drift uses those lists instead of fetching every POV object one by one.
- **A recording survives the handover.** Before the POV's customer data is removed, its API recording is exported
  as a replay fixture with customer names replaced (`~/.zscaler-pov-kit/fixtures/`), so a live run can become a test.
- **The Updates dialog shows release notes formatted** (bold, code, bullets) instead of raw Markdown.
- **Client Connector's build-by-hand spec** says "a new profile" when the tenant has no default to copy, instead of
  naming a default that doesn't exist.

## 0.9.6

From the live lab test:
- **Obfuscated user names no longer block teardown.** An API role with "User Names: Obfuscated" makes ZIA scramble
  the name of a user fetched on its own, so the kit took its own test users for renamed ones and would have left them
  in the tenant. It now reads their names from ZIA's user list, which shows them as they are, matched by ID.
- Apply says "Already there" for objects an earlier run made, instead of "Created" again.

## 0.9.5

From the live lab test (ZIA, Client Connector and AI Guard, with test users made in ZIA):
- **Apply no longer stops when there's no default Client Connector profile to copy.** Preflight warned, but apply
  then failed with "the forwarding profile the change list copies is gone", so AI Guard was never reached. It now
  prints the spec to build the profiles by hand (Fix drift adopts them) and carries on.
- ZIA's own test users no longer get the customer action "has the Internet & SaaS entitlement in ZIdentity".

## 0.9.4

From the live lab test, and mirroring the SE demo kit:
- **Test users made by the kit**, a third choice in the Pilot users step, made the way the demo kit makes its
  traffic-generator user: a group, a department and 1 to 10 users (`zpov-pilot-1@<your domain>`…) straight in ZIA,
  with generated passwords in the keychain, so there's nothing to entitle or wait for. When ZIA refuses because the
  tenant keeps its users in ZIdentity ("UNMODIFIABLE … OneIdentityUserLogin"), apply says so and the next change list
  makes them in ZIdentity on `<vanity>.zslogin.net`, where ZIdentity can give them a password even when the company
  domain signs in through Okta. SAML tenants go to ZIdentity straight away; directory tenants are told to use their
  own group. This replaces the old "N test users" field, which refused any tenant with ZIdentity in front.
- **Entitlement first, as the demo kit learned.** 0.9.3 said a ZIdentity group reaches ZIA at a member's first
  sign-in; the demo kit's experience is that ZIdentity sends entitled users and groups within about a minute. Apply
  now checks the members' Internet & SaaS entitlement and stops at once with the fix if it's missing, otherwise waits
  up to three minutes (as the demo kit does). The "signs in once" customer action is gone.
- **Teardown empties the pilot group before deleting it.** Live ZIdentity refuses to delete a group with members
  ("Resource in use"); teardown now takes the remaining members out first (the users themselves are untouched), and
  a ZIdentity error no longer stops the rest of teardown.

## 0.9.3

From the live lab test:
- **A ZIdentity pilot group reaches ZIA at a member's first sign-in**, not when it's entitled: a live tenant showed ZIA
  holds none of its ZIdentity groups until one of their users signs in. The change list now has the customer action
  "One pilot user signs in once", and apply, preflight, status and the guide say so; apply looks for the group for
  15 seconds, not a minute, then stops and carries on next time.

## 0.9.2

- **One-line install, no security prompts.** `curl -fsSL …/releases/latest/download/install.sh | bash` on a Mac, or
  `irm …/install.ps1 | iex` in PowerShell, downloads the latest release, checks its SHA-256, installs uv if needed,
  installs the kit and opens the console. macOS Gatekeeper ("Apple could not verify…") and Windows SmartScreen only
  block files a browser downloaded, so this avoids both without code signing. The double-click installers stay, and
  the guides now say what to do when Gatekeeper or SmartScreen stops them.

## 0.9.1

From an independent review of 0.9.0's tenant writes, and the follow-ups:
- **The pilot group outlives every rule that uses it.** Teardown keeps the POV's ZIdentity group while any ZIA rule
  still applies to it (a POV rule the customer renamed and so kept, or one of theirs) or another product's POV object
  is left, and says which; deleting it then would leave a rule pointing at a group that no longer exists.
- **Fix drift after the group is deleted in ZIdentity** recreates it and re-scopes the POV's rules to the new group,
  instead of re-pointing them at the deleted one.
- **Nothing stranded by a settings change.** Teardown and status cover every product that still has objects in the
  ledger, and the pilot group choice can't change while the POV's ZIdentity group is in the tenant.
- **No delete while a job runs**, and one job at a time per POV. POV IDs are checked before they're used as folders.
- ZIdentity lists use its documented filters and paging (`name[like]`, `limit`, `offset`).
- **Terraform handover keeps everything in place as the customer's**, including objects Terraform can't import and
  the POV's ZIdentity group (its README says what to do with it), so the POV can be deleted afterwards.
- **Report a problem**: a link next to Download diagnostics opens the kit's GitHub issue form.
- Builds use the Node 24 GitHub actions and Ubuntu 24.04.

## 0.9.0

From the live lab test:
- **The kit can make the pilot group.** Pilot users step → **Create one for the POV in ZIdentity**: `ZPOV - pilot
  users`, with the users you name added to it (existing users are only added, never changed) and, in lab tenants,
  the users who don't exist yet created. It's in the change list like everything else, so it's written only after
  approval, scoped by the ledger, and deleted at teardown. ZIdentity's API can't grant entitlements, so granting
  Internet & SaaS (and Private Access) to the group is a customer action; Apply waits for ZIdentity to provision the
  group to ZIA, uses ZIA's copy for every POV rule (linked in the ledger, never changed or deleted by the kit), and if
  the entitlement isn't granted yet it stops and carries on next time without creating anything twice.
- **Pick instead of type.** The Pilot users step lists ZIA's groups and ZIdentity's users from the tenant (read-only),
  adds users by name or email, and shows who isn't in ZIdentity.
- **Delete a POV, after verifying.** Setup → Start a POV → **Delete…**, or `pov-kit delete`. It looks up every object
  the ledger still lists in the tenant (read-only) and refuses while any is there (or can't be checked); then it needs
  the POV's ID typed back, and removes the POV's folder, keychain secrets, Claude Desktop entry and backup from the
  laptop. The tenant is never touched.
- **Clearer ZDX 403.** Preflight says the API client has no ZDX role and where to add one (or to take ZDX out).

## 0.8.1

From the first checks against a live tenant:
- **Use your Zscaler MCP client.** Connect can take the OneAPI client of the Zscaler MCP server in Claude Desktop
  ("Use the client from Claude Desktop", or `pov-kit connect --from-claude-desktop`): the secret goes straight to the
  keychain, never shown or logged.
- **DLP engine names stay readable for Claude.** A live tenant flags Zscaler's own engine templates ("5 or more Credit
  Card Numbers", "GDPR - High Volume"...) as custom, so names-only use cases hid them all. Only the customer's own
  engines are hidden now. The test tenant returns engines the way the live one does.

## 0.8.0

Released like the AI Guard SE Demo Kit:
- **Double-click installers** for Mac and Windows (and uninstallers): uv if needed, the kit in
  `~/.zscaler-pov-kit/app`, a **Zscaler POV Console** desktop shortcut (an app on the Mac; desktop and Start menu on
  Windows) and the `pov-kit` command. `pov-kit install` / `uninstall` do the same from a terminal.
- **Updates button** in the console: checks the latest release (cached for 12 hours), shows its notes, installs it
  after checking its SHA-256, restarts the console, and rolls back one version. A git checkout is told to `git pull`.
  `pov-kit update` (`--check`, `--rollback`) does the same.
- **Releases publish themselves** when VERSION changes on main: the zip, an email-safe zip, the plugin, SHA256SUMS,
  latest.json, and three guides as Markdown and Word: the **SE deployment guide** (restructured like the demo kit's:
  overview, golden rules, prerequisites, parts with times, troubleshooting), a **customer overview** for the
  customer's security team, and a one-page **quick start**.

The console now matches the demo kit:
- Header: the **Updates** pill, the POV's state and end date, the **AI Guard policy switch** (once the POV's policy
  exists), a **Zscaler console** link, and a **light / dark / auto** theme toggle.
- The demo kit's layout, step titles and check list style (✓, !, ✗ with a "Fix:" line), and its **Logs** tab: filter
  by kind or text, pause, clear the view, click an entry for its details.

## 0.7.0

- **Claude Desktop's read-only access to the POV tenant** (`pov-kit mcp consent|install|remove|config|status|serve`,
  and a card in the console's Next steps). It uses Zscaler's MCP server (zscaler-mcp 0.15.4, pinned), started by the
  kit from the keychain with writes off, every write and start tool disabled, secret-returning reads disabled, and
  only the POV's products. The Claude Desktop entry holds no secret; handover removes it. Checked against the real
  server: 186 to 194 read tools offered, none that write. An optional view-only client (`connect --mcp`) is in the
  role spec.
- **A Claude plugin** that drives the kit (`tools/build_plugin.py`), with approval, apply and teardown always left to
  the SE and the customer.
- **ZPA customer ID** (`set customer_id`, or the Connect step): ZPA over OneAPI needs it; preflight warns without it.
- `--pov` works after the command too (`pov-kit mcp serve --pov ID`).

## 0.6.1

Fixes from an independent review of 0.6.0's safety-critical code:
- **Client Connector could edit the customer's default profile.** Its save is create-or-update, and the copied
  forwarding-profile actions (and nested app-profile settings) kept their IDs. Every body is now stripped of copied
  IDs, and the kit refuses to send one that still carries any. This was also true of 0.5's forwarding profile.
- **Client Connector profile names are now per POV** (they carry the POV ID's last part), apply never creates over a
  profile with the same name, and a new profile's ID is taken only from what appeared after the save.
- **recover** records an object without a description only when something certain ties it to the POV; prefix-only
  finds are listed, never recorded. It never reuses a key another active entry holds.
- **Teardown with --yes keeps adopted objects**; delete them with `--include-adopted`.
- **selftest** runs only on a POV marked as a lab POV (`new --lab`), does ZIA first, rechecks its pending state just
  before writing, and activates only after its own create and delete succeeded.
- **Names only** also covers accented names (no ASCII escaping before masking), upper- and lower-case variants, the
  customer's own DLP engines and isolation profile, and no longer sends the POV ID in request metadata.
- **Backups** run after each product during apply and even when apply or teardown fails; a restore refuses to
  replace a local ledger that has objects the backup lacks.
- **Recordings**: name-like fields are always replaced in exports (even in capitals), the POV ID is replaced,
  errors are redacted, and recordings are deleted at handover.

## 0.6.0

Nothing left behind:
- **`pov-kit recover`** finds a POV's objects in the tenant, read-only, by prefix and stamp, and rebuilds the
  ledger (`--write`), so teardown works even when the laptop that ran the POV is gone. Another POV's objects are
  left alone; objects found by name only are recorded as adopted.
- **Encrypted backups** of each POV's ledger, approval and change list to a synced folder, after every change
  (`pov-kit backup setup|now|restore`; scrypt and Fernet, passphrase in the keychain).
- **End dates and reminders.** Every POV has an end date; status warns in the last week and fails after it with
  objects still in the tenant. `pov-kit remind install` adds a daily desktop notification (Windows, Mac, Linux).

AI use cases:
- **Names only by default.** The customer's names, emails and domains are placeholders before anything leaves the
  laptop; replies are swapped back before validation. `ai.share full` needs its own agreement.
- Claude answers through a **tool with a fixed schema** (structured output); plain-text JSON is the fallback.
- **Refine** a proposal in words; the earlier version is kept in its history.
- A **use-case library**: save what worked (customer names taken out), reuse it in the next POV with no AI call;
  a shared folder works for a team.

Evidence and approval:
- **Executive summary** drafted by Claude from the results only (names removed), opening the report
  (`pov-kit report --summary`, or the Success criteria tab).
- **The customer approves on the change-list page**: its form saves an approval file bound to the change list's
  hash; `pov-kit approve --file` (or the Approval step) checks the hash before recording it.

Lab run and setup:
- **`pov-kit selftest --lab`**: read, create, read back and delete one harmless object per product.
- **API recording** (`pov-kit record on|export`) and replay tests that hold the fake tenant to real responses.
- **Client Connector app profile automated** (ported from the demo kit's setup_zcc), with plainer forwarding-profile
  copies on a bare 400 and a read-back check. Build-by-hand-and-adopt stays the fallback. Client Connector IDs are
  sent as integers.
- **Azure template** for the ZPA App Connectors (`pov-kit zpa template --cloud azure`), from Zscaler's Azure modules:
  the Marketplace image and plan, no public IPs, deny-all inbound.

## 0.5.0

- **Use cases across the product suite.** Besides ZIA rules, Claude can now propose, and the kit build after a fresh
  approval: a ZPA app (its own segment and allow or deny access rule for the pilot users, through the POV's
  connectors; refused if a domain is already a customer segment), an AI Guard app with its own key, rule and blocking
  policy (the customer's AI Guard apps and the POV's main policy stay as they are), ZDX deep traces on the pilot devices
  for a monitored app, and a report-only CASB DLP rule. Client Connector stays directions only.
- Discovery adds what the checks need: customer ZPA segment domains, the AI Guard detectors that can block, ZDX's
  monitored apps, and every DLP engine for CASB.
- Use-case tests can include AI Guard test prompts, run by `pov-kit test --api` with the use case's own key.
- Use cases' AI Guard keys go to the keychain and are deleted at teardown and handover.

## 0.4.0

- **Use cases from a prompt** (console: Use cases tab; CLI: `pov-kit usecase ask|list|show|accept|directions|discard`).
  Claude proposes changes, directions and a test; the kit validates every change against the tenant (allowed kinds
  and fields only, tenant categories, engines and file types, pilot-group scope, kit naming) and turns anything it
  won't build into directions with the reason. Accepted use cases join the change list, so the customer approves
  again before Apply. Each use case gets its own success criterion and probe tests.
- Claude is reached only through an AI Guard proxy (the demo kit's Anthropic app key, or `pov-kit ai connect`), so
  every request and reply is scanned by AI Guard. A blocked request says so.
- Nothing goes to Claude until the customer's agreement to share the discovery snapshot is recorded
  (`pov-kit ai consent --by`, or the Use cases tab). Model: `claude-sonnet-5-5` by default (`set ai.model`).

## 0.3.0

- **Browser console** (`pov-kit gui`) with the demo kit's look and its setup wizard pattern: start a POV, connect,
  pilot users, preflight, change list, approval, apply, next steps. Tabs for status and Fix drift, success criteria
  (API proofs, probe import, attestations, report), handover (Terraform or teardown) and logs (diagnostics zip).
  Same safety as the kit's console: 127.0.0.1 only, Host header checked, a per-run token on every call, and pages
  with customer data need the token too.
- **One API client by default.** Two-client mode stays a setting (`client_mode separate`).
- **Identity step** in discovery, across products: how pilot users sign in; each pilot user exists in ZIA and is in
  the pilot group; ZIdentity entitlements (Internet & SaaS, Private Access) read and checked automatically; the IdP's
  sign-in and MFA sites kept out of SSL inspection by an approved bypass rule placed above the inspect rule.
- ZPA can scope the access rule by a SAML attribute instead of a SCIM group (`zpa.scope saml`).
- Hosted DB test users (`identity.test_users`, up to 10) for tenants where ZIA keeps its own users; refused where
  ZIdentity or an IdP owns them. Passwords are made at apply, kept in the keychain, never in the change list;
  `pov-kit users --show`. The role spec asks for user management only when test users are chosen.
- ZIA discovery searches users, groups and departments by the POV prefix instead of listing every user.
- Settings are validated in one place for the CLI and the console.

## 0.2.0

Every product module, with the full lifecycle. Still for lab tenants until TESTPLAN.md is worked through.

- ZIA: firewall and DNS control rules, file type control, browser isolation (left out when the tenant has no
  isolation profile), a tenant-check custom URL category and a network service, all from the demo kit's template.
  The module is now one table of object kinds. Five new criteria (IS-TEN-01, IS-CBI-01, IS-FTC-01, IS-FW-01, IS-DNS-01)
  and probe tests for TCP ports and DNS.
- ZPA: App Connector group, provisioning key (secret to the keychain), server and segment groups, the POV app segment
  and an access rule for the pilot SCIM group, placed first. Discovery refuses an app the customer already publishes and
  warns about broad allow rules. `pov-kit zpa template` writes a CloudFormation template for two connectors.
- AI Guard: the demo kit's detection policy, a POV app, a Detection API key and an app-only rule. `pov-kit aiguard
  policy monitor|attacks|data` changes only the POV policy.
- ZDX: a deep trace on each pilot device; CASB/SSPM: a report-only CASB DLP rule on a connected SaaS tenant.
- Automated API proofs (`pov-kit test --api`) for ZPA, AI Guard, ZDX, CASB and Client Connector.
- Probe packs: `pov-kit probe-pack` fills in the POV's own values for the pilot devices.
- Terraform names checked against the provider docs: URL filtering rules, file type control rules, rule labels and
  firewall filtering rules confirmed; the rest are marked "check" in the export.
- Fixed: the POV's own CASB rule changed the plan after apply. A test now holds every product to that.
- Checks are labelled with their product.

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
