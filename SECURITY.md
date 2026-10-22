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
- **Use cases send the customer's discovery snapshot to Claude** (their policy, group and user names; never secrets)
  through the SE's AI Guard tenant to Anthropic, and only after the customer's agreement is recorded in the POV.
  Proposals and Claude's raw answers stay in the POV folder (`usecases.json`). Claude never calls the tenant: what
  it proposes is validated by the kit against that product's discovery and built only through the approved change
  list, as new POV objects scoped to the pilot users. Use cases can't change the customer's objects or tenant-wide
  settings in any product; a CASB use-case rule is always report-only, whatever Claude asks for.
- Updates are verified against the SHA-256 published with each release before anything is replaced.
- The kit's API clients can't delete themselves: at handover, remind the customer to delete both in the console.
