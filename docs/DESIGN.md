# Design

The full design (lifecycle, safety model, module architecture, success-criteria catalog, handover, phases and open
questions) is in the review doc: https://claude.ai/artifact/Fv9mcFwhvh5N2xGhur3w2b

Once it is reviewed, copy the final version here so it is versioned with the code, as the kit does with its guide.

## The six safety rules, as the code enforces them

| Rule | Where |
| --- | --- |
| Discovery is read-only | `core/guard.py` `ReadOnlyTenant`: anything not `list`/`get`/`search`/`status` is refused before it is sent |
| Only the approved change list is applied | `core/changelist.py` `require_approved`: the plan re-made from the tenant must hash to the approved one |
| The ledger decides ownership | `core/ledger.py` `owns`: ID in the ledger, prefix in the live name, stamp in the live description |
| Existing customer objects are never written | `core/guard.py` `LedgerTenant`: creates only approved items; updates and deletes only owned objects |
| Rules are scoped and placed openly | `products/zia.py` `plan`: pilot group on every rule, placement in the change list |
| Activation never ships someone else's work | `products/zia.py` `guard_activation`: apply, Fix drift and teardown stop on pending changes |

## 0.6: nothing left behind

The ledger is the only record of what a POV created, so 0.6 keeps it safe off the laptop and can rebuild it:

- **Backups** (backup.py): after every change to the tenant, pov.json, the ledger, the approval and the change list go
  to a folder the SE chose, encrypted with a passphrase-derived key. `backup restore` recreates the POV folder on a new
  laptop; the API client is saved again with `connect`.
- **Recover** (recover.py): without a backup, a read-only sweep finds the POV's objects by prefix and stamp. Stamped
  objects are recorded as owned, prefix-only ones as adopted (teardown keeps them unless told otherwise), and another
  POV's stamp means "leave alone". Keys are matched to the saved change list where there is one.
- **End dates and reminders** (remind.py): a status check and a daily, local-only notification.

The AI use cases send less: names are placeholders by default (pseudo.py), and the masking is undone on the laptop
before validation, so the kit's checks always run on real values. Claude answers through a tool with a fixed schema.
