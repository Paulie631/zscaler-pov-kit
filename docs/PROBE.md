# Zscaler POV probe

The probe runs on the pilot devices of a Zscaler proof of value (POV). It sends safe test traffic through Zscaler
Client Connector and writes a results file that the Zscaler SE imports into the POV kit.

**What it doesn't do:** it has no console, no API keys and no access to any Zscaler tenant's API, so it can't change
anything. It only browses, and it sends nothing unless ip.zscaler.com confirms the device's traffic goes through
Zscaler.

**Test data is safe:**

- the EICAR antivirus test string (assembled at run time);
- Google's Safe Browsing test pages;
- fake card numbers from the card networks' published test ranges;
- public test sites.

## Install

The SE's pilot device setup installs it for you. To install it by hand:

- macOS or Linux, in Terminal:
  `curl -fsSL https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install-probe.sh | bash`
- Windows, in PowerShell:
  `irm https://github.com/Paulie631/zscaler-pov-kit/releases/latest/download/install-probe.ps1 | iex`

It installs into `~/.zscaler-pov-probe/app` (`%USERPROFILE%\.zscaler-pov-probe\app` on Windows). It also installs
**uv**, the free tool it runs on, if the device doesn't have it.

## Use

```
pov-probe pack install pov-probe-pack-<pov>.json   # the POV's tests, from the SE
pov-probe pack show                                # which POV and which tests the device has
pov-probe test --wait 30                           # run them (waits up to 30 minutes for Client Connector)
pov-probe traffic check                            # is this device in the POV's tenant, as a pilot user?
pov-probe traffic schedule --every 30              # traffic for the dashboards every 30 minutes (--remove stops)
pov-probe cleanup                                  # remove Endpoint AI test items, if the POV tested them
pov-probe trust-ca                                 # trust the Zscaler root CA here (admin), if Client Connector didn't
```

On Windows, the command is `pov-probe.cmd` in the app folder.

**The probe pack decides what runs.** It holds the POV's success criteria, so `test` runs exactly the tests for the
criteria the customer chose. It also tells the traffic generator which kinds of traffic those criteria call for.

**When the criteria change,** the SE sends a new pack. Install it with `pack install`, and run `test` again.

**Results:** each test writes a file to `~/.zscaler-pov-probe/results`. Send it to the SE; it holds test outcomes,
the device name and OS, and nothing else.

## Remove

Delete the `.zscaler-pov-probe` folder. If you scheduled traffic, run `pov-probe traffic schedule --remove` first.
