# Installing the Zscaler POV Kit

## Double-click install (recommended)

1. Download `zscaler-pov-kit-<version>.zip` from the [latest release](https://github.com/Paulie631/zscaler-pov-kit/releases/latest)
   and unzip it anywhere, for example in Downloads. **On Windows, right-click the zip → Extract All.** Running a file
   from inside the zip without extracting won't work.
2. Open the `zscaler-pov-kit` folder and double-click the installer for your computer:
   - **Windows:** `Install Zscaler POV Kit.cmd`
   - **Mac:** `Install Zscaler POV Kit.command`
3. Press a key (Windows) or Return (Mac) to start. The installer:
   - installs **uv**, the free tool the kit runs on, if it isn't installed yet
   - downloads Python 3.12 and the kit's libraries (a minute or two the first time)
   - copies the kit to `~/.zscaler-pov-kit/app` (Windows: `%USERPROFILE%\.zscaler-pov-kit\app`)
   - adds a **Zscaler POV Console** shortcut to your desktop (and the Start menu on Windows)
   - adds the `pov-kit` command, so `pov-kit gui` works from any folder in a new terminal
   - opens the console on its Setup tab
4. From then on, double-click **Zscaler POV Console** on your desktop. A terminal window opens with it: keep it open
   while you use the console, and close it to stop the console.

You can delete the unzipped folder afterwards. Your POVs, their ledgers and secrets stay in `~/.zscaler-pov-kit/povs`
and the system keychain, so reinstalling or upgrading never touches them.

### First-run security prompts

The installers aren't code-signed yet, so your computer asks once:

- **Windows:** "Open File - Security Warning" → **Run**. If you see "Windows protected your PC", click **More info** →
  **Run anyway**.
- **Mac:** "cannot be opened because it is from an unidentified developer". Right-click the installer → **Open** →
  **Open**. On recent macOS, go to **System Settings → Privacy & Security** and click **Open Anyway**.

If your laptop's policy blocks this entirely, use the command line below, or ask IT.

## Updating

The console checks for new versions. When one is out, the **Updates** button at the top turns into **Update to
x.y.z**. Click it, read what's new, and click **Install update**. The console downloads the release from GitHub,
checks it against the release's SHA-256 checksum, installs it and restarts itself. **Roll back** in the same dialog
returns to the previous version. Your POVs, secrets and every tenant are untouched either way.

From a terminal: `pov-kit update` (`--check` to only check, `--rollback` to go back one version).

If your laptop's web policy blocks GitHub downloads, the console says so: download the newest zip from the
[releases page](https://github.com/Paulie631/zscaler-pov-kit/releases/latest) in your browser and run its installer.
A git checkout is never overwritten: update it with `git pull`.

## Uninstalling

- **Windows:** Start menu → **Uninstall Zscaler POV Kit**, or `pov-kit uninstall`
- **Mac:** `pov-kit uninstall`, or double-click `Uninstall Zscaler POV Kit.command` in `~/.zscaler-pov-kit/app`

Uninstalling removes the kit, its shortcuts and its PATH entry. It keeps your POVs and every object in every tenant.
To remove a POV's objects from a customer's tenant, hand the POV over **before** uninstalling.

## Command line

From the unzipped folder or a git checkout:

- **Mac / Linux:** `./pov-kit gui`
- **Windows (PowerShell):** `.\pov-kit.cmd gui`

After installing, `pov-kit gui` works from any folder.

## The Claude plugin

Each release also has `zscaler-pov-kit-<version>.plugin`. Open it in the Claude desktop app to install it, then ask
Claude to run the kit for you ("run preflight for Acme", "what's left for the customer?").

## If the installer can't install uv

Your laptop's security policy may block the download. The installer tries the official installer, then winget
(Windows) or Homebrew (Mac). If all of them fail, ask IT to allow downloads from `astral.sh` and `github.com`, or
install uv another way (https://docs.astral.sh/uv/getting-started/installation/), then run the installer again.
