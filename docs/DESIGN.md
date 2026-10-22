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
