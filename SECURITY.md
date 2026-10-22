# Security and data handling

| What | Where | When it goes |
| --- | --- | --- |
| API client secrets (discovery, apply) | OS keychain, service `zscaler-pov-kit`, entry `<pov-id>/<client>` | `handover` deletes them |
| Discovery snapshot (describes the customer's policy) | `~/.zscaler-pov-kit/povs/<pov-id>/discovery.json` | `handover` deletes it |
| Change list, approval, ledger | the POV folder | kept as the record of what was done |
| Probe results, attestations, report | the POV folder | kept; give the report to the customer |
| Activity log | the POV folder, `activity.jsonl` | kept; secrets are never written to it |

- Nothing secret is written to files, logs or the screen; `connect` reads secrets with a hidden prompt.
- The diagnostics zip masks secret fields and bearer tokens, replaces email addresses and the names of the customer's own
  objects with placeholders, and leaves out the discovery snapshot and plan bodies.
- The probe needs no API keys and sends only safe test data: the EICAR test string, Google Safe Browsing test pages and
  generated fake card numbers.
- Updates are verified against the SHA-256 published with each release before anything is replaced.
- The kit's API clients can't delete themselves: at handover, remind the customer to delete both in the console.
