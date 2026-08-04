<#
.SYNOPSIS
    Installs the Device Inventory desktop app on a helpdesk workstation.

.DESCRIPTION
    Copies DeviceInventory.ps1 and its icon into the user's profile and creates a
    Start Menu shortcut that launches it with an STA PowerShell host and a hidden
    console window.

    Per-user by default so it needs no admin rights; use -System for all users.
    Intended to run as an Intune Win32 app, but works fine by hand.

.EXAMPLE
    .\Install-DeviceInventory.ps1

.EXAMPLE
    .\Install-DeviceInventory.ps1 -System
#>
[CmdletBinding()]
param(
    [switch]$System,
    [string]$Name = 'Device Inventory'
)

$ErrorActionPreference = 'Stop'

try {
    Write-Host "Installing $Name" -ForegroundColor Cyan

    if ($System) {
        $appDir   = Join-Path $env:ProgramData 'DeviceInventory'
        $startDir = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    } else {
        $appDir   = Join-Path $env:LOCALAPPDATA 'DeviceInventory'
        $startDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
    }

    New-Item -Path $appDir -ItemType Directory -Force | Out-Null
    Write-Host "  Target folder: $appDir"

    # --- App + icon ------------------------------------------------------
    $sourceScript = Join-Path $PSScriptRoot 'DeviceInventory.ps1'
    if (-not (Test-Path $sourceScript)) { throw "DeviceInventory.ps1 was not found next to this installer." }

    # Deploying without a dedicated app registration works, but everyone's activity
    # then shows up under Microsoft Graph Command Line Tools. Warn, don't block.
    $head = (Get-Content $sourceScript -TotalCount 60) -join "`n"
    if ($head -match "ClientId\s*=\s*''") {
        Write-Warning "No ClientId set - the app will use the shared Microsoft Graph Command Line Tools client. Fine for a pilot; register your own app before a wide rollout."
    }

    $scriptPath = Join-Path $appDir 'DeviceInventory.ps1'
    Copy-Item $sourceScript $scriptPath -Force
    # Clear the downloaded-from-internet mark so the copy runs cleanly.
    Unblock-File -Path $scriptPath -ErrorAction SilentlyContinue
    Write-Host "  App copied."

    $sourceIcon = Join-Path $PSScriptRoot 'DeviceInventory.ico'
    $iconPath   = Join-Path $appDir 'DeviceInventory.ico'
    if (Test-Path $sourceIcon) {
        Copy-Item $sourceIcon $iconPath -Force
        Write-Host "  Icon copied."
    } else {
        $iconPath = $null
    }

    # --- Shortcut --------------------------------------------------------
    # -Sta is required: WPF will not start on an MTA thread.
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $lnkPath    = Join-Path $startDir "$Name.lnk"

    $shell = New-Object -ComObject WScript.Shell
    $lnk   = $shell.CreateShortcut($lnkPath)
    $lnk.TargetPath       = $powershell
    $lnk.Arguments        = "-Sta -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $lnk.WorkingDirectory = $appDir
    $lnk.Description      = 'Custom device properties and bulk actions for Intune'
    if ($iconPath) { $lnk.IconLocation = "$iconPath,0" }
    $lnk.Save()
    [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    Write-Host "  Shortcut created: $lnkPath"

    # --- Detection marker ------------------------------------------------
    [pscustomobject]@{
        InstalledOn = (Get-Date).ToString('o')
        Scope       = if ($System) { 'System' } else { 'User' }
        Version     = '1.0.0'
        Kind        = 'Desktop'
    } | ConvertTo-Json | Set-Content -Path (Join-Path $appDir 'install.json') -Encoding UTF8

    Write-Host "Done. Staff can search the Start Menu for '$Name'." -ForegroundColor Green
    exit 0
}
catch {
    Write-Error "Install failed: $($_.Exception.Message)"
    exit 1
}
