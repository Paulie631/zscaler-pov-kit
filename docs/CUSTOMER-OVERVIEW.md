# Zscaler Proof of Value: How the POV Kit Works in Your Tenant

*For your security and IT teams. Your Zscaler sales engineer runs the proof of value (POV) with the Zscaler POV
Kit. This page explains what it does in your tenant, what it never does, and how you stay in control.*

## In one paragraph

The kit reads your tenant, proposes an exact list of new objects for the POV (the **change list**), and creates only
what you approve, only for the pilot users you choose. It never edits, reorders or deletes anything you made. At the
end it removes everything it created, or hands it to you as Terraform so you can keep it.

## What the kit does

- **Reads first.** Before anything else, it reads your configuration to plan the POV: your rules' names and order, your
  pilot group, URL categories, DLP engines, and similar. It changes nothing while reading.
- **Proposes a change list.** Every object it would create, what it does, who it affects (your pilot users only) and
  where it sits in your policy, plus any changes only you make (for example, granting an entitlement).
- **Applies only what you approved.** The approval is bound to that exact list by a SHA-256 hash. If your tenant changes
  afterwards in a way that changes the list, the kit stops and asks for a new approval.
- **Marks everything it creates.** Each object's name starts with the POV prefix (for example `ZPOV:`), its description
  carries the POV's ID, and the kit keeps a ledger of each object's ID.
- **Proves the agreed success criteria** with tests on pilot devices, API checks and notes from your team, collected in
  a report you receive.
- **Leaves cleanly.** At the end, it deletes every object in its ledger, or exports them as Terraform with import
  blocks so you can keep them in place.

## What the kit never does

- **It never changes your own objects:** no edits, reordering, disabling or deleting. Changes to your objects are
  listed as actions for your admin.
- **It never applies to everyone.** POV rules apply to your pilot group (or a SAML attribute you choose) only.
- **It never activates other administrators' work.** If ZIA has pending changes when it needs to activate, it stops
  until your admin activates or discards them.
- **It never needs administration, role, user-management or authentication rights,** except, only if you ask for
  it, the POV's own pilot group in ZIdentity (`ZPOV - pilot users`, with the users you name added to it and, in a lab,
  test users created), or test users when your users live in ZIA itself. Both are in the change list you approve and
  removed at the end; your existing users are only added to the POV's group, never changed. Entitlements stay yours to
  grant.
- **It never writes before your approval,** and only through the approved change list.

## Access you grant

Your admin creates one OneAPI client from the role spec your sales engineer sends: view access to the products in
scope and write access to the object types in the change list only. If you prefer, two clients: a view-only one
first, and one that can write only after you approve. An optional view-only client lets your sales engineer ask
Claude Desktop questions about your tenant, read-only. Delete the clients when the POV ends.

## Your data

- **Credentials** stay in the sales engineer's laptop keychain, never in files, logs, email or chat.
- **Discovery data** (your policy, group and user names) stays on that laptop and is deleted at handover.
- **AI features are opt-in, with your agreement recorded.** If you agree, the kit can ask Claude (Anthropic's AI) to
  propose how to prove a new use case, or to draft the report's summary. By default your names, emails and domains are
  replaced with placeholders before anything leaves the laptop, and the requests pass through Zscaler AI Guard.
  Read-only questions from Claude Desktop, if you allow them, go to Anthropic directly with names as they are.
- **Diagnostics** sent to the kit's maintainers contain no secrets and none of your object names.

## How approval works

1. Your sales engineer runs the read-only checks and makes the change list.
2. You review it: on a call, or on your own in the change-list page, which works offline.
3. You approve it: your sales engineer records your name, or you use the page's approval form, which saves a small
   file tied to that exact list for you to send back.
4. The kit creates exactly that list. Anything new (an extra use case, for example) needs a new approval.

## Questions to ask your sales engineer

- Which success criteria are we proving, and how will each be proved?
- Which pilot users and devices are in scope?
- When does the POV end, and will we tear it down or keep it as Terraform?
- Which AI features, if any, will we use, and with what data?
