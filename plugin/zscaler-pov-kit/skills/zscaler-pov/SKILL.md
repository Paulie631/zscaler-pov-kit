---
name: zscaler-pov
description: Runs the Zscaler POV Kit for a sales engineer's proof of value in a customer's Zscaler tenant. Use when the user says "start a POV for <customer>", "run preflight", "make the change list", "what's left for the customer", "check POV status", "fix drift", "run the API proofs", "build the POV report", "propose a use case", "set up the Claude read-only access for the POV", "hand over the POV" or "tear down the POV", or mentions the POV kit or pov-kit.
---

# Zscaler POV Kit

The kit is a command-line tool plus a browser console that sets up a proof of value in a **customer's** tenant. Every
object it creates is named with the POV prefix and recorded in a ledger. Nothing is written to the tenant until the
customer approves an exact change list, and the kit only ever changes what its ledger owns. A bundled copy lives in
the `kit/` folder next to this file.

## Where to run it

On the user's own computer, never in a cloud sandbox: secrets live in the OS keychain, and the console must open in the
user's browser.

1. Find the kit. Check, in order: a path the user gives, `~/zscaler-pov-kit`, `~/workplace/zscaler-pov-kit`. A git
   checkout is preferred (`git pull` updates it; `pov-kit update` also works).
2. If none exists, copy the bundled `kit/` folder to `~/zscaler-pov-kit` and make `pov-kit` executable.
3. Check that `uv` exists (`command -v uv` or `~/.local/bin/uv`). If not, tell the user to run `brew install uv` (Mac)
   or the PowerShell installer on docs.astral.sh/uv (Windows). Don't install it silently.
4. Use `./pov-kit` on Mac and Linux, `.\pov-kit.cmd` on Windows, from the kit folder. Add `--pov ID` to act on a POV
   other than the current one (`./pov-kit list` shows them).
5. If no shell on the user's computer is available, give the user the exact commands to run themselves.

## Commands

| Goal | Command | Who runs it |
|---|---|---|
| The console (wizard and every tab) | `./pov-kit gui` | Start it in the background; tell the user the printed `http://127.0.0.1:…` address. |
| Start a POV | `./pov-kit new "Acme Corp" --products zia,zcc,zpa --ends YYYY-MM-DD` | Claude, with the customer and products the user names. |
| Settings | `./pov-kit set vanity_domain acme`, `set pilot_group "POV Pilot"`, `set pilot_emails a@x.com,b@x.com`, `set zpa.domains app.acme.internal`, `set customer_id …` | Claude |
| Role spec for the customer's admin | `./pov-kit role-spec` | Claude; give the user the file. |
| Save the API client | `./pov-kit connect` (or the console's Connect step) | **The user**, in their own terminal or the console. Never ask for a client secret in chat or pass it as an argument. |
| Preflight (read-only) | `./pov-kit preflight --json` | Claude. Exit 0 = pass, 2 = warnings, 1 = failures. Relay each failing check's `fix` in plain words. |
| Change list | `./pov-kit plan` | Claude. Then show the user `plan.html` (in the POV folder): it's what the customer reviews. |
| Customer approval | `./pov-kit approve --by "Name, title"` or `--file approval-….json` | **Only when the user says the customer approved this change list**, naming who. Never approve on your own judgement or to unblock a step. The `--file` route is the customer's own approval from the change-list page. |
| Apply | `./pov-kit apply` | Claude, only after an approval exists **and** the user says to apply now. It refuses if the tenant changed since approval; then re-plan and get approval again. Never work around that. |
| Status, drift | `./pov-kit status` (read-only); `status --fix` | Claude. `--fix` repairs only the POV's own objects; ask the user first. |
| What's left for the customer | `./pov-kit status`, then read the "Customer actions" line | Claude |
| Evidence | `./pov-kit probe-pack`, `import-probe FILE`, `test --api`, `attest ID --note "…"`, `test` | Claude, except attestations: record only what the user says a person saw. |
| Report | `./pov-kit report` (`--summary` drafts Claude's executive summary through AI Guard) | Claude |
| Use cases | `./pov-kit usecase ask "…"`, `list`, `show ID`, `refine ID "…"`, `accept ID`, `save ID`, `library`, `use NAME` | Claude. The customer's agreement (`./pov-kit ai consent --by …`) is recorded only when the user says the customer agreed. `accept` puts the change in the change list, which then needs a fresh approval. |
| Claude Desktop's read-only access to the tenant | `./pov-kit mcp consent --by "Name, title"`, `mcp install`, `mcp status`, `mcp remove` | Claude, consent only when the user says the customer agreed. After install, tell the user to quit and reopen Claude Desktop. It is always read-only; never edit its config entry to add write tools or credentials. |
| Safety net | `./pov-kit backup setup FOLDER` (the user types the passphrase), `remind install`, `set ends YYYY-MM-DD` | The user for the passphrase; Claude otherwise. |
| Lost laptop | `./pov-kit backup restore POV-ID`, or `./pov-kit recover POV-ID …` then `recover POV-ID --write` | Claude; show the user what `recover` found before `--write`. |
| Lab self-test | `./pov-kit selftest --lab` on a POV made with `new "Lab" --lab` | Claude, only for the user's own lab tenant. |
| Handover | `./pov-kit handover terraform` or `handover teardown` | **Only after the user confirms in chat** which one and for which customer. Teardown deletes objects from the customer's tenant: list them first (`status`), then run it. Never pass `--include-adopted` unless the user asks for adopted objects to be deleted by name. |
| Diagnostics | `./pov-kit diagnostics` | Claude; no secrets or customer names in it. |

## Reading results

- Checks print `[ok]`, `[warn]`, `[FAIL]` or `[info]`, each warning or failure with a `fix:` line. Relay fixes plainly.
- `plan` lists each object and who it affects; "customer actions" are changes only the customer makes.
- `status` says whether the tenant still matches the approved change list, which objects drifted, the POV's end date
  and its backup.
- Probe and API proofs, attestations and use-case tests roll up in `test` and the report.

## Guardrails

- This runs in a **customer's** tenant. When in doubt about anything that writes, stop and ask the user.
- Writes happen only through `apply`, `status --fix`, `handover teardown` and the AI Guard `policy` switch, each on
  the POV's own objects. Never call Zscaler APIs or another MCP server to change the tenant on the kit's behalf.
- Never ask for, print, or store secrets (client secrets, the provisioning key, test-user passwords, the backup
  passphrase). The kit shows them only on the user's own screen when asked by name.
- Never record a customer's agreement or approval the user hasn't told you about, and never switch use cases to
  `ai.share full` unless the user says the customer agreed to share names.
- Never hand-edit files in `~/.zscaler-pov-kit/` (the ledger, approvals, change lists).
