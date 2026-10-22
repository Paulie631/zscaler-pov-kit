# Security and data handling

| What | Where | When it goes |
| --- | --- | --- |
| API client secrets (discovery, apply) | OS keychain, service `zscaler-pov-kit`, entry `<pov-id>/<client>` | `handover` deletes them |
| ZPA provisioning key, AI Guard detection key | OS keychain, same service | teardown deletes each with its object |
| Hosted DB test user passwords | OS keychain, `<pov-id>/zia-test-user-<n>` | teardown deletes each with its user |
| Discovery snapshot (describes the customer's policy) | `~/.zscaler-pov-kit/povs/<pov-id>/discovery.json` | `handover` deletes it |
| Change list, approval, ledger | the POV folder | kept as the record of what was done |
| Probe results, attestations, report | the POV folder | kept; give the report to the customer |
| Activity log | the POV folder, `activity.jsonl` | kept; secrets are never written to it |

- Nothing secret is written to files, logs or the screen; `connect` reads secrets with a hidden prompt.
- The diagnostics zip masks secret fields and bearer tokens, replaces email addresses and the names of the customer's own
  objects with placeholders, and leaves out the discovery snapshot and plan bodies.
- The probe needs no API keys and sends only safe test data: the EICAR test string, Google Safe Browsing test pages and
  generated fake card numbers.
- The ZPA connector template takes the provisioning key as a hidden (NoEcho) stack parameter, but the key is readable
  in each instance's user data. The POV's key enrolls at most two connectors and teardown deletes it.
- The CASB DLP rule only reports incidents: it never quarantines, deletes or changes the customer's SaaS data.
- AI Guard proofs scan the demo kit's synthetic test prompts; no customer data and no LLM calls.
- The console listens on 127.0.0.1 only, refuses other Host headers, and needs a token minted for each run on every
  API call; the change list, report and diagnostics pages need the token too. Secrets go to the keychain and only come
  back to the page when you ask for one by name (a test user's password, the ZPA provisioning key).
- The identity step only reads users, groups and entitlements; it never changes them.
- **Use cases send the customer's discovery snapshot to Claude** through the SE's AI Guard tenant to Anthropic, only
  after the customer's agreement is recorded in the POV. By default (`ai.share names_only`) the customer's names,
  emails and domains are replaced with placeholders on the laptop first; `full` sends them as discovery read them and
  needs an agreement given for that. Never secrets.
- **The executive summary** sends criterion titles, results and proof details, with the customer's names and emails
  removed; no snapshot and no policy, so it needs the proxy key but not the use-case agreement.
- **Library entries** have the customer's names, emails and domains replaced with "[name]", "[email]", "[domain]",
  and ZPA apps (one customer's domains) left out. Reusing one makes no AI call.
  Proposals and Claude's raw answers stay in the POV folder (`usecases.json`). Claude never calls the tenant: what
  it proposes is validated by the kit against that product's discovery and built only through the approved change
  list, as new POV objects scoped to the pilot users. Use cases can't change the customer's objects or tenant-wide
  settings in any product; a CASB use-case rule is always report-only, whatever Claude asks for.
- **Backups** hold pov.json, the ledger, the approval and the change list (no secrets; the change list names the
  pilot group and the POV app's domains), encrypted with a key derived from the SE's passphrase (scrypt, then Fernet).
  The passphrase is in this laptop's keychain and the SE's password manager, never in the backup folder.
- **`recover`** only reads. `--write` records what it found in the ledger; objects carrying another POV's stamp are
  never recorded, and objects found by name only are recorded as adopted, which teardown keeps unless told otherwise.
- **The customer's approval file** binds a name and title to the change list's full SHA-256. It isn't a signature:
  it proves which change list the customer saw, not who they are. The page makes no network calls.
- **API recordings** stay in the POV folder, with secrets masked (any field named like a key, token, secret or
  password, including the provisioning key) and the customer's names and emails replaced. An export for the
  repository keeps only field names, types and Zscaler's own values.
- **`selftest`** refuses to run without `--lab` (the console asks too), keeps its own ledger, and activates ZIA only if
  nothing else was pending.
- Updates are verified against the SHA-256 published with each release before anything is replaced.
- The kit's API clients can't delete themselves: at handover, remind the customer to delete both in the console.
