# Lab test plan (gate before any customer POV)

Run in a lab tenant set up like a customer's: some rules of its own, a pilot group with two users, Client Connector on
one Windows pilot device. Each item settles an open question in the design or breaks a safety rule on purpose.

## First: the self-test and a recording

- [ ] `pov-kit record on`, then `pov-kit selftest --lab`: every product reads, and ZIA, ZPA and AI Guard each create,
  read back and delete their object. Keep recording on for the whole plan, then `pov-kit record export lab-1` and
  commit `tests/fixtures/lab-1.jsonl`; run the tests and fix every field the fake tenant has and the real API doesn't.

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

- [ ] **Identity.** ZIdentity entitlements read with `zid.user_entitlement.get_service_entitlement` name the
  Internet & SaaS and Private Access services as the regexes in `identity.py` expect; ZIA user search by email
  returns each user's groups.
- [ ] **Sign-in bypass.** With Okta and with Entra ID: sign-in and MFA (push, FastPass or Authenticator) still work for a
  pilot user behind the inspect rule; tune `IDP_DOMAINS` if not.
- [ ] **SAML scoping.** `list_saml_attributes_by_idp` finds the attribute by name, and the access rule with a SAML
  condition admits only users with that value.
- [ ] **Test users.** On a Hosted DB tenant: users and group are created with the department, can sign in to Client
  Connector with the keychain password, and teardown removes them.
- [ ] **Console.** The wizard runs end to end on Windows and Mac; Copy report and downloads work in Chrome, Edge and
  Safari.

- [ ] **Use cases.** Through a real AI Guard proxy key: five prompts from the console's examples each return valid
  JSON; the kit builds what passes its checks; the accepted rules work on a pilot device; a prompt that asks for a
  tenant-wide change comes back as directions. With the AI Guard policy blocking, the console says AI Guard blocked it.
- [ ] **Use cases in every product.** One accepted use case per product: a second ZPA app reached by a pilot user
  (and denied to a non-pilot user); an AI Guard use-case key whose test prompts hit its own policy, not the POV's main
  one; a ZDX deep trace that shows in the console; a CASB report-only rule that raises an incident. Teardown removes
  all of them. Check `add_access_rule_v2` with action `deny`, and that more than one POV access rule placed first
  keeps the order the change list shows.
- [ ] **Client Connector app profile.** Apply creates it (`web_policy_edit`): scoped to the pilot group, first in the
  order, installs the certificate, uses the POV forwarding profile; the read-back agrees. A pilot device picks it up
  after Client Connector is turned off and on.
- [ ] **Azure connectors.** Deploy the Azure template in a lab subscription (terms accepted once): both connectors
  enroll; nothing reaches them inbound.
- [ ] **Recover.** Delete the POV folder after apply; `recover` finds every object (ZPA provisioning keys: check the
  list method's name), `--write` and teardown leave the tenant clean. Restore from a backup on a second computer.
- [ ] **Reminders.** `remind install` on Windows and Mac: the notification shows, and `remind uninstall` removes it.
- [ ] **Names only.** Read a real request's body in the AI Guard logs: no customer names, emails or domains. Check
  `list_dlp_engines_lite` really returns `customDlpEngine` / `predefinedEngineName`, so only the customer's own
  engines are masked. Claude's
  proposals are as good as with `ai.share full` on the five console examples.
- [ ] **Customer approval.** Open plan.html from an email attachment on Windows and Mac: the form saves the file and
  `approve --file` accepts it; a file for an older change list is refused.
- [ ] **Model and size.** `claude-sonnet-5-5` answers within the proxy's timeout for a large tenant snapshot (the kit
  cuts it at 150,000 characters).

## Safety rules, broken on purpose

- [ ] Edit a POV rule's description to remove `zpov:<id>`: teardown leaves it and says why.
- [ ] Rename a POV rule without the prefix: teardown leaves it.
- [ ] Create a rule named `ZPOV: test` by hand: discovery lists it as a lookalike; teardown leaves it.
- [ ] Delete the DLP engine the plan uses after approval: `apply` refuses and lists what changed.
- [ ] Disable a POV rule and point it at another group: `status` reports both; `status --fix` restores both.
- [ ] Revoke the apply client's write access: `apply` stops at the label with nothing else created.
- [ ] Diagnostics zip: search it for the pilot group's name, a customer rule name and a user's email. None appear.
- [ ] Ask a use case to "apply this rule to everyone" or "edit the customer's existing rule": the kit's change stays
  pilot-only, and the rest comes back as directions.

## End to end

- [ ] Probe pack on the pilot device: every probe test runs; the run ID shows in the URLs in Web Insights.
- [ ] `test --api`: each automated proof returns pass or fail, not "couldn't run".
- [ ] Report: pass counts match `pov-kit test`; it prints to PDF on one page per criterion.
- [ ] `handover teardown`: the tenant's rule lists match the discovery snapshot taken before apply.
