# Device Inventory

A desktop app for adding custom properties to Intune-managed devices — asset tags, locations, cost centres, anything you need — and for running bulk actions across a selection. Written in Windows PowerShell and WPF, in a single script, with no third-party assemblies.

Properties can optionally be mirrored onto Entra device extension attributes, which makes them usable in dynamic group rules — the thing the Intune notes field can't do on its own.

## Why

Intune has nowhere to record that a laptop belongs to the Middleton site, or which cost centre owns it. The `notes` field on a managed device is the one writable free-text property available, so this app treats it as a small key/value store and puts a real interface on top.

Inspired by [FlorianSLZ/IntuneDeviceInventory](https://github.com/FlorianSLZ/IntuneDeviceInventory), and deliberately storage-compatible with it: properties are JSON in the `notes` field, so anything written here is readable by that module, by plain Graph calls, and in the admin center.

## Features

- **Device list** for the whole tenant, searchable across name, user, serial, model and every custom property value; filterable by platform and compliance.
- **Property editor** with all 15 Entra extension attribute slots laid out, plus unlimited notes-only properties beyond them.
- **Bulk edit** — apply or remove a property across any selection.
- **Device actions** — sync, restart, rotate BitLocker key, Defender quick scan, update Defender signatures. Single or bulk.
- **Dynamic group support** — mirror chosen properties to `extensionAttribute1`–`15` so rules like `device.extensionAttribute1 -eq "Middleton"` work.
- **CSV export** of the current view, with each custom property as its own column.
- **Graph activity log** in-window and on disk, showing every call and status code.

## Requirements

- Windows 10 1809 or later
- Windows PowerShell 5.1 (ships with Windows — PowerShell 7 is not supported, since it has no WPF)
- An Intune RBAC role with the rights you intend to use. Help Desk Operator covers reading devices, sync, restart, and the *Managed devices → Update* permission that writing properties needs.

No modules to install. No DLLs to unblock.

## Quick start

```powershell
powershell.exe -Sta -ExecutionPolicy Bypass -File .\DeviceInventory.ps1 -ShowConsole
```

`-Sta` is required — WPF will not start on an MTA thread. `-ShowConsole` keeps the console visible for troubleshooting; the installed shortcut omits it.

On first run a browser opens for sign-in. Out of the box the app authenticates through **Microsoft Graph Command Line Tools**, the same first-party client `Connect-MgGraph` uses, so there's nothing to register to try it.

### Permissions

The app requests these delegated scopes:

| Scope | Used for |
|---|---|
| `DeviceManagementManagedDevices.ReadWrite.All` | Reading devices, writing the notes field |
| `DeviceManagementManagedDevices.PrivilegedOperations.All` | Device actions |
| `Device.ReadWrite.All` | Writing Entra extension attributes |

All three are admin-consent-required. Granting consent needs Global Administrator, Privileged Role Administrator, or Cloud Application Administrator — **Intune Administrator alone is not enough**. This is a one-time step per tenant and applies whichever client ID you use.

## Using your own app registration

Fine for a single admin, not for a team: with the shared client, sign-in logs show *Microsoft Graph Command Line Tools* rather than this app, Conditional Access can't be scoped to it, and its consent is tenant-wide and cumulative.

To register your own:

1. **Entra admin center → App registrations → New registration.** Single tenant.
2. **Authentication → Add a platform → Mobile and desktop applications**, redirect URI `http://localhost`. Loopback covers any port, so the random port chosen at sign-in is fine.
3. Set **Allow public client flows** to **Yes**.
4. **API permissions** → add the three delegated scopes above → **Grant admin consent**.
5. Put the client and tenant IDs in the CONFIG block at the top of `DeviceInventory.ps1`.

No client secret. This is a public client; a secret sitting in a script on a workstation is a secret you've given away.

## How properties are stored

Custom properties are serialised to JSON in the device's `notes` field:

```json
{"Location":"Middleton","CostCenter":"4400"}
```

Intune caps that field at **1,024 characters**, which is roughly 20–30 short properties. The app rejects anything larger before sending rather than letting Graph return a vague error. A device that already had a plain-text note keeps it under a `_notes` key instead of losing it.

### Dynamic groups

Notes is not one of the device attributes Entra dynamic group rules can read, so properties you want to target with must be mirrored onto the Entra device object. Name a slot in the editor's rows 1–15 and saving writes both places:

```
device.extensionAttribute1 -eq "Middleton"
```

Slot names are tenant-wide by nature — a rule names a specific slot, so slot 1 has to mean the same thing everywhere. They're stored in `%LOCALAPPDATA%\DeviceInventory\config.json`, outside the script, so app updates don't lose them.

Extension attributes 1–15 are a single shared set on each device object. If Autopilot or another tool already writes to a slot, mirroring will overwrite it — check before choosing numbers. Entra re-evaluates dynamic rules a few minutes after an attribute changes.

## Deploying to a helpdesk

```powershell
IntuneWinAppUtil.exe -c .\source -s Install-DeviceInventory.ps1 -o .\output
```

| Setting | Value |
|---|---|
| Install | `powershell.exe -ExecutionPolicy Bypass -File .\Install-DeviceInventory.ps1` |
| Uninstall | `powershell.exe -ExecutionPolicy Bypass -File .\Uninstall-DeviceInventory.ps1` |
| Install behavior | User (add `-System` to both, and edit `$appDir` in the detection script, for all users) |
| Detection | Custom script — upload `Detect-DeviceInventory.ps1` |

The installer copies the script and icon into the user profile and creates a Start Menu entry. Per-user by default, so no admin rights needed.

## Files

| File | Purpose |
|---|---|
| `DeviceInventory.ps1` | The entire app — UI, auth, Graph calls |
| `Install-DeviceInventory.ps1` | Copies the app and creates the Start Menu shortcut |
| `Uninstall-DeviceInventory.ps1` | Removes both |
| `Detect-DeviceInventory.ps1` | Intune Win32 detection rule |
| `DeviceInventory.ico` | Shortcut icon |

App data lives in `%LOCALAPPDATA%\DeviceInventory`: `config.json` (slot names), `token.dat` (DPAPI-encrypted refresh token), `app.log`.

## Implementation notes

Three things that are easy to get wrong in a PowerShell WPF app and are handled here:

**Threading.** Every Graph call runs in a background runspace; a `DispatcherTimer` polls for completion and marshals results back to the UI thread. The window stays responsive during a 4,000-device load or a bulk action across hundreds of devices.

**Closures.** PowerShell scriptblocks are dynamically scoped, not lexically closed, so a completion handler referencing a local variable finds it gone by the time the background job finishes. Every handler that captures state uses `.GetNewClosure()`.

**Non-default properties.** `notes` always comes back null from the managedDevices *list* endpoint regardless of `$select` — it needs a per-device GET. The app fetches it through JSON batching, 20 devices per request, and refuses to save over any device whose properties haven't been read back yet, which would otherwise blank them.

**Authentication** is authorization code + PKCE against a loopback listener, falling back to device code flow if the listener can't bind. The refresh token is cached with DPAPI, so launches after the first are silent.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Device list empty, 403 in the activity log | Signed-in user has no Intune RBAC role |
| Property saves fail with 403 | Role lacks *Managed devices → Update* |
| Consent prompt that can't be approved | Needs Global Admin, Privileged Role Admin, or Cloud App Admin — once per tenant |
| Properties column shows 0 for everything | Background property load hasn't finished; watch the status bar |
| `AADSTS50011` redirect URI mismatch | Missing `http://localhost` platform on your own app registration |
| Window doesn't appear | Launched without `-Sta` |
| Actions succeed but nothing happens | Normal — Intune queues actions until the device checks in |

`%LOCALAPPDATA%\DeviceInventory\app.log` has a line per operation. The **Graph activity** panel in the window shows the same thing live.

## Limitations

- Loads up to 4,000 devices (`MaxPages` in the CONFIG block).
- Bulk operations run sequentially with 429 backoff; a few hundred devices takes a minute or two.
- No wipe, retire, or delete. Add them to `$DeviceActions` if you want them — put a typed confirmation in front of anything destructive.
- Renaming a slot doesn't migrate existing values; the old property name stays in notes on devices that have it.
- Windows-only actions are filtered out for other platforms before the call.


