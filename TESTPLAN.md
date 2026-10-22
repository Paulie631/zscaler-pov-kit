# Lab test plan (gate before any customer POV)

Run in a lab tenant set up like a customer's: some rules of its own, a pilot group with two users, Client Connector on
one Windows pilot device. Each item settles an open question in the design or breaks a safety rule on purpose.

## Open questions

- [ ] **Activation scope.** Admin A saves a change without activating. Run `apply`: it must stop. Then test with the
  API alone whether `activate` would also activate admin A's change. Record the answer in docs/DESIGN.md.
- [ ] **Role scopes.** Build both clients from `role-spec`. Discovery must pass with the discovery client. With the
  apply client, `apply` must succeed, and a create outside the plan's kinds (for example a firewall rule, by hand with
  the SDK) must be refused by the tenant.
- [ ] **Own role readable?** Can a OneAPI client read its own role? If yes, preflight can show the apply client's rights.
- [ ] **Terraform.** `handover terraform`, then `terraform plan -generate-config-out=generated.tf`: every import resolves
  and the plan shows no changes. Confirm the resource types and import IDs still marked "check" (SSL inspection,
  Cloud App Control, DLP, DNS control, URL categories, network services, every ZPA kind), then set `confirmed` in
  the module's KINDS table.
- [ ] **Label on rules.** Rules accept `labels=[id]` through the SDK, and the label shows on each rule in the console.
- [ ] **Client Connector.** On a tenant that returns the bare 400: the spec printed is enough to build both profiles by
  hand, and `status --fix` adopts them. On one that doesn't: the forwarding profile is created as a copy.
- [ ] **ZIA bodies.** Network service `ports` as lists (not tuples) are accepted; the isolation rule's `cbi_profile`
  shape; a DNS block on UDP/53 comes back as an error or a block-page address (the probe counts both as blocked).
- [ ] **ZPA.** Each create call and body in `products/zpa.py` is accepted; access-rule conditions scope to the SCIM
  group; `reorder_rule` to "1" puts the rule first; the provisioning key's secret comes back in the create response;
  the connector group lists its connectors with a status field the PA-CON-01 proof reads.
- [ ] **App Connector template.** The stack enrolls two connectors from the Marketplace AMI with the user data's steps.
- [ ] **AI Guard.** `aiguard policy attacks` blocks a prompt injection within a minute; the API proofs pass.
- [ ] **ZDX.** `start_deeptrace` returns a trace ID; device app scores are where the DX-SCR-01 proof reads them.
- [ ] **CASB.** The report-only rule is accepted with these fields and raises an incident for a file with fake card numbers.

## Safety rules, broken on purpose

- [ ] Edit a POV rule's description to remove `zpov:<id>`: teardown leaves it and says why.
- [ ] Rename a POV rule without the prefix: teardown leaves it.
- [ ] Create a rule named `ZPOV: test` by hand: discovery lists it as a lookalike; teardown leaves it.
- [ ] Delete the DLP engine the plan uses after approval: `apply` refuses and lists what changed.
- [ ] Disable a POV rule and point it at another group: `status` reports both; `status --fix` restores both.
- [ ] Revoke the apply client's write access: `apply` stops at the label with nothing else created.
- [ ] Diagnostics zip: search it for the pilot group's name, a customer rule name and a user's email. None appear.

## End to end

- [ ] Probe pack on the pilot device: every probe test runs; the run ID shows in the URLs in Web Insights.
- [ ] `test --api`: each automated proof returns pass or fail, not "couldn't run".
- [ ] Report: pass counts match `pov-kit test`; it prints to PDF on one page per criterion.
- [ ] `handover teardown`: the tenant's rule lists match the discovery snapshot taken before apply.
