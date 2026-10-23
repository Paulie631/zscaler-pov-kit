# The POV lab on CloudShare

A CloudShare blueprint for POVs where the customer has no cloud account to hand, or you want the ZPA part running
on day one: two ZPA App Connectors, the POV test app, and a Windows pilot device. You build the blueprint **once**;
it holds software only, with no customer values. Each POV then starts a fresh copy and puts its own values in with
one command per machine, which the POV console fills in.

Nothing here touches a Zscaler tenant except enrolling the connectors with the POV's own provisioning key.

## Build the blueprint (once, about 45 minutes)

1. In CloudShare, create an environment with four machines from the catalog:

   | Machine | Template | Size |
   |---|---|---|
   | `zpov-ac1`, `zpov-ac2` | Rocky Linux 9 (or RHEL 9) | per Zscaler's App Connector sizing guide |
   | `zpov-app` | Rocky Linux 9 (or any small Linux) | the smallest available |
   | `zpov-pilot` | Windows 11 | 2 vCPU, 8 GB |

   They need outbound internet (TCP 443); no inbound ports.
2. On each **connector** machine, as an admin in its terminal:
   ```
   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zpov-connector.sh | sudo bash -s -- prepare
   ```
   It adds Zscaler's package source, checks Zscaler's signing key against the fingerprint in Zscaler's guide, installs
   `zpa-connector` and leaves it **not enrolled**.
3. On the **test app** machine:
   ```
   curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zpov-test-app.sh | sudo bash
   ```
   It serves one page on port 80 and starts on every boot.
4. On the **Windows pilot**, in PowerShell opened with **Run as administrator**:
   ```
   irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/zpov-pilot-prepare.ps1 | iex
   ```
   It installs the POV kit (for its probe) and saves the kit's checked Client Connector installer in `C:\ZPOV`. It
   doesn't install Client Connector, because its cloud, domain and user are per POV.
5. Save the environment as a blueprint, for example **Zscaler POV lab**, and share it with your SE team.

## Each POV (about 15 minutes)

1. Start a new environment from the **Zscaler POV lab** blueprint.
2. In the POV console, apply the POV with ZPA in it, then **Next steps → ZPA App Connectors → CloudShare commands**.
   It shows the command for the connectors with the POV's provisioning key filled in. Paste the key only there.
3. On the test app machine, note its address (`ip -4 addr`, or CloudShare's machine details). On **each connector**,
   run the command from step 2 with that address at the end. It enrolls the connector, and points
   `pov-app.zpov.internal` at the test app on that connector.
4. On the Windows pilot: **Next steps → Set up a pilot device → Windows → Copy the one-line command**, paste it
   into PowerShell opened as administrator, and add `-Msi C:\ZPOV\<the installer file>` at the end. Sign in as the
   pilot user; the POV's tests run once traffic goes through Zscaler.
5. When the POV ends: tear it down in the console (Handover), then delete the CloudShare environment.

## Notes

- Connectors take about 10 minutes to appear in the POV's connector group; **Steps for people → Deploy the POV's App
  Connectors → Check now** ticks once both are up.
- If the customer names a real app instead of the test app, leave the address off the connector command; the
  connectors then need to reach that app from CloudShare, which usually isn't possible. CloudShare suits the test app.
- The provisioning key enrolls at most two connectors and teardown deletes it.
- Not yet tried end to end in CloudShare: first run, check each step, and tell the kit owner what differed.
