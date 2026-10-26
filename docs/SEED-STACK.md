# The AI-SPM and DSPM seed stack

AI-SPM and DSPM scan the customer's cloud accounts. A new test account is empty, so a scan finds nothing worth
showing. The seed stack is a CloudFormation template that puts realistic, **entirely synthetic** sensitive data and a
few deliberately risky AI resources into the customer's **test** AWS account, so the POV has real findings to walk
through. Deleting the stack removes everything it made.

The kit never deploys it and never touches AWS: you download the template, and the customer's cloud admin deploys it.

## What's in it

Everything is named `zpov-…` and tagged `zpov=<POV id>` and `zpov-purpose=seed: synthetic test data`.

| Resource | What it holds or does | What it should show | Criteria |
|---|---|---|---|
| S3 `zpov-records-<account>-<pov>` | Synthetic customers (CSV, JSON), payroll (SSNs, IBANs, salaries), patient records (diagnoses, member IDs), a card export, 5 PDF statements, 5 Word HR reviews and a "CONFIDENTIAL" Word roadmap. Public access blocked, versioning on. | Sensitive data found and classified (PII, PCI, PHI) | DS-FND-01 |
| S3 `zpov-misconfigured-<account>-<pov>` | A smaller copy (customer export with SSNs, a patient backup). Bucket public access block **off**, no versioning, no access logging, and a policy that lets any role in the account read it. Optionally one public decoy file. | Sensitive data at risk, with a fix | DS-RSK-01 |
| S3 `zpov-training-data-<account>-<pov>` | JSONL "fine-tuning" files: support chats and claim triage with names, cards, emails, dates of birth and diagnoses inside | Personal data in an AI training store | AS-MOD-01, AS-RSK-01 |
| DynamoDB `zpov-customers-<pov>` | 200 synthetic customers | DSPM covers databases, not just files | DS-FND-01 |
| Lambda `zpov-support-agent-<pov>` | A small AI agent that reads the training data and asks a Bedrock model about it. Its role is **deliberately too broad**: all of Bedrock, plus read on the customer records and table it doesn't need. | An AI agent and model in use; an over-permissioned agent; who can reach sensitive data | AS-MOD-01, AS-RSK-01, DS-ACC-01 |
| Lambda `zpov-mcp-server-<pov>` (optional, off by default) | A tiny MCP server with one tool (`lookup_order`) that returns canned text. Published on a Lambda function URL with **no authentication**. It reads nothing; its role only writes its own logs. | An exposed, unauthenticated MCP server | AS-MOD-01, AS-RSK-01 |
| Lambda `zpov-seeder-<pov>` + a custom resource | Writes the data when the stack is created; empties the buckets (every version) when the stack is deleted, so deletion works. It can touch only the stack's own buckets and table. | (plumbing) | |

**The data is synthetic.** Names are made up (`Avery Testwell`); emails are `@example.com`; phone numbers are
`555-01xx`; card numbers are the card networks' published test numbers (they pass the checksum, so classifiers see
them as cards); SSNs are in `987-65-4320` to `987-65-4329`, the range the US Social Security Administration set aside
for advertising and never issued. Every bucket has a `README-ZPOV.txt` saying so. Check in your lab that Zscaler's
classifiers flag these values: some engines ignore numbers they can tell aren't real.

**Cost:** cents a month (S3, DynamoDB on demand, Lambda). Bedrock is charged per call, only when someone runs the
agent (one test call with Nova Micro is a fraction of a cent).

## Before the POV (at kickoff)

1. **Agree on a test account.** A dedicated AWS test account (or sandbox) that holds nothing real. Never production
   for a POV. Note its Region: pick one where Bedrock and the chosen model run (us-east-1 or us-west-2 are safe).
2. **Security review.** Send the customer's security team:
   - Zscaler's onboarding role for AI-SPM / DSPM (Zscaler help: *DSPM › Onboarding AWS Account* and
     *Viewing Roles and Templates*). It reads the account's configuration and, for classification, the data in it.
   - This page, for the seed stack.
   Their review can take days, which is why it's agreed at kickoff.
3. **Who does it.** The customer's cloud admin, with rights to create IAM roles, Lambda functions, S3 buckets and a
   DynamoDB table in the test account.
4. **Choose the options** (they're asked when you download the template; both can be changed later as stack
   parameters):
   - *MCP server with no authentication*: off by default. It gives AI-SPM an exposed MCP server to find, but it is
     an open internet endpoint (canned answers only). Turn it on only if the customer agrees.
   - *Public decoy file*: off by default. One file of 5 synthetic rows readable by anyone. It needs the account's
     S3 Block Public Access setting to allow public bucket policies; most accounts block them.

The POV's steps for people list both cloud steps ("A test cloud account is connected to Zscaler" and "The POV seed
stack runs in that account"), and Success criteria shows the AI-SPM and DSPM criteria waiting on them.

## Order of operations

1. Connect the test account to Zscaler (step A).
2. Deploy the seed stack (step B).
3. Run the agent once (step C).
4. Wait for the scan (hours to a day), then walk the findings (step D).

Connecting first means the first scan already includes the seed data's arrival; deploying first works too, it just
waits for the next scan.

## A. Connect the test account to Zscaler

1. In the Zscaler console, open the cloud account onboarding for AI-SPM / DSPM (search the console menu for *Cloud
   Accounts* or *Onboarding*) and add an AWS account.
2. Use **Zscaler's own template** (CloudFormation, launched or downloaded from that page). Don't write the role by
   hand: Zscaler's template carries the tenant's trust settings (the external ID).
3. The cloud admin deploys it in the test account and finishes the onboarding in the Zscaler console.
4. Mark the step done in the POV console (Setup › Next steps, or Status) once the account shows as connected.

## B. Deploy the seed stack

**Get the template**, from either:

- the POV console: **Setup › Next steps › Seed stack for AI-SPM and DSPM**, tick the options, **Download the seed
  stack** (it saves `zpov-seed-<pov>.json`); or
- the command line: `pov-kit seed template [--mcp] [--public-decoy] [--out FILE]`.

Send the file to the customer's cloud admin. It holds no secrets and no customer data.

### In the AWS console

1. Sign in to the **test** account and switch to the agreed Region (top right).
2. **CloudFormation › Stacks › Create stack › With new resources (standard)**.
3. **Prepare template:** *Choose an existing template*. **Template source:** *Upload a template file* › choose
   `zpov-seed-<pov>.json` › **Next**.
4. **Stack name:** `zpov-seed-<pov>` (the file name without `.json`).
5. **Parameters** (the defaults are right for most POVs):

   | Parameter | Default | Change it when |
   |---|---|---|
   | IncludeMcpServer | your choice at download | the customer agreed (or no longer agrees) to the open MCP server |
   | PublicDecoy | your choice at download | you want the public file and the account allows public bucket policies |
   | Records | 300 | you want more or fewer synthetic people (50 to 2,000) |
   | AgentModelId | `amazon.nova-micro-v1:0` | the model isn't offered in this Region on demand: use the inference profile `us.amazon.nova-micro-v1:0` (US Regions), or another model the account has |
   | PovId | the POV's ID | never (it's for tags) |

6. **Next** › leave the stack options as they are (no rollback changes needed) › **Next**.
7. Tick **I acknowledge that AWS CloudFormation might create IAM resources** › **Submit**.
8. Wait about two minutes for **CREATE_COMPLETE**. The **Outputs** tab names the buckets, the table, the agent and,
   if you added it, the MCP server's URL.

### Or with the AWS CLI

```bash
aws cloudformation deploy \
  --template-file zpov-seed-<pov>.json \
  --stack-name zpov-seed-<pov> \
  --capabilities CAPABILITY_IAM \
  --region us-east-1 \
  --parameter-overrides IncludeMcpServer=false PublicDecoy=false
aws cloudformation describe-stacks --stack-name zpov-seed-<pov> --region us-east-1 --query "Stacks[0].Outputs"
```

### Check it worked

- **S3:** `zpov-records-…` holds `customers/`, `hr/`, `health/`, `finance/`, `docs/` and `confidential/`;
  `zpov-misconfigured-…` holds `exports/`, `backups/` and `public-decoy/`; `zpov-training-data-…` holds `finetune/`.
- **DynamoDB:** `zpov-customers-…` › Explore items shows 200 rows.
- Mark "The POV seed stack runs in that account" done in the POV console.

## C. Run the agent once

So AI-SPM sees the agent actually using a model:

- **Console:** Lambda › `zpov-support-agent-<pov>` › **Test** › create a test event with `{}` › **Test**. It answers
  with a two-sentence summary of the (synthetic) support chats.
- **CLI:**
  ```bash
  aws lambda invoke --function-name zpov-support-agent-<pov> --payload '{}' \
    --cli-binary-format raw-in-base64-out --region us-east-1 out.json && cat out.json
  ```

If you added the MCP server, check it answers (any MCP client can connect to it, too):

```bash
curl -s -X POST "<McpServerUrl from Outputs>" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## D. What to show, and how to record it

After the next scan (hours to a day), walk the findings with the customer and record each criterion in the POV console
(Success criteria › the row › **Mark demonstrated**, with a screenshot):

| Criterion | Show |
|---|---|
| AS-INV-01 Shadow AI is inventoried | The GenAI apps the pilot devices used (the traffic generator sends GenAI traffic, with ZIA in the POV) |
| AS-MOD-01 AI assets in the cloud found | `zpov-support-agent`, the Bedrock model, `zpov-training-data` and, if deployed, `zpov-mcp-server` |
| AS-RSK-01 Risky AI exposures flagged | The over-permissioned agent role, personal data in the training bucket, the unauthenticated MCP server |
| AS-GOV-01 Governance reported | A NIST AI RMF, EU AI Act or ISO 42001 view for the account |
| DS-FND-01 Sensitive data found and classified | `zpov-records` and `zpov-customers` classified as PII, PCI and PHI, with counts |
| DS-RSK-01 Risky exposure flagged | `zpov-misconfigured` (and the public decoy) as sensitive data at risk, with remediation |
| DS-ACC-01 Access to sensitive data mapped | `zpov-support-agent`'s role among those that can read `zpov-records` |

The criteria are drafts: when Zscaler's internal POV plan for AI-SPM or DSPM is shared, replace them, and the kit will
prove them through the API once the SDK has one.

## At the end of the POV

The POV console lists this under the steps for the end of the POV:

1. **Delete the seed stack:** CloudFormation › `zpov-seed-<pov>` › **Delete** (or
   `aws cloudformation delete-stack --stack-name zpov-seed-<pov>`). The seeder empties the buckets first, then
   everything the stack made is removed. CloudWatch log groups for the three functions (`/aws/lambda/zpov-…`) stay;
   delete them too if the customer wants the account spotless.
2. **Disconnect the account** in the Zscaler console.
3. **Delete Zscaler's onboarding stack** in the test account.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| `MisconfiguredBucketPolicy` CREATE_FAILED, "public policies are blocked" | PublicDecoy=true in an account that blocks public bucket policies. Update the stack with PublicDecoy=false, or leave the decoy out. |
| `SeedData` CREATE_FAILED | The seeder's reason is on the Events tab; its log is CloudWatch › `/aws/lambda/zpov-seeder-<pov>`. The stack rolls back cleanly; fix and create it again. |
| A bucket name is already taken | Bucket names are global. Another stack for the same POV in the same account exists: delete it first. |
| The agent says the model isn't available, or access is denied | Use the inference profile ID (`us.amazon.nova-micro-v1:0`) or another model the account can call; update the stack's AgentModelId. Some accounts need the model enabled once under Bedrock › Model access. |
| The MCP server's URL answers 403 | Lambda › `zpov-mcp-server-<pov>` › Configuration › Function URL › **Edit** › Auth type NONE › **Save**: the console adds the invoke permissions function URLs need. |
| Delete hangs or fails on a bucket | Something outside the stack wrote to it. Empty the bucket (S3 › Empty), then delete the stack again. |
| Nothing shows in AI-SPM / DSPM | The account isn't connected yet, or the first scan hasn't run. Check the account's status and last scan time in the Zscaler console. |
