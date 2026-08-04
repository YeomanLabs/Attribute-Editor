#Requires -Version 5.1
<#
.SYNOPSIS
    Device Inventory - custom properties and bulk actions for Intune-managed devices.

.DESCRIPTION
    A WPF desktop app built on Windows PowerShell 5.1 with no third-party
    assemblies: everything comes from PresentationFramework, which ships with
    Windows. Nothing needs unblocking after download.

    Custom properties are stored as a JSON object in each device's 'notes'
    field, which is the same convention the IntuneDeviceInventory module uses,
    so values written here stay readable from PowerShell and the admin center.

    Sign-in is authorization code + PKCE against a public client app
    registration. The refresh token is cached with DPAPI under the user's
    profile, so day-to-day launches are silent.

.PARAMETER ShowConsole
    Keep the PowerShell console window visible. Useful when debugging.

.NOTES
    Fill in the CONFIG block below before deploying.
#>
[CmdletBinding()]
param([switch]$ShowConsole)

$ErrorActionPreference = 'Stop'

# Entra and Graph require TLS 1.2; Windows PowerShell does not always default to it.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# =====================================================================
#  CONFIG - fill these in before deploying
# =====================================================================
$App = @{
    # Both are optional. Leave ClientId blank to use the Microsoft Graph Command
    # Line Tools client - the same first-party app Connect-MgGraph falls back to.
    # That's fine for one admin running this on their own machine. Register your
    # own app before handing it to a team: see README-desktop.md for why.
    ClientId = ''                      # Application (client) ID
    TenantId = ''                      # Directory (tenant) ID or domain
    Name     = 'Device Inventory'
    Version  = '1.0.0'
    MaxPages = 40                      # 40 x 100 devices = 4000

    # Rebuilt at runtime from the slot names you type in the app, which are stored
    # in config.json next to this script's data. Don't edit it here.
    ExtensionAttributeMap = @{}
}

# Microsoft Graph Command Line Tools - public client, present in every tenant.
$GraphCliClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

$App.UsingSharedClient = [string]::IsNullOrWhiteSpace($App.ClientId)
if ($App.UsingSharedClient)                          { $App.ClientId = $GraphCliClientId }
if ([string]::IsNullOrWhiteSpace($App.TenantId))     { $App.TenantId = 'organizations' }
# =====================================================================

$GraphScopes = @(
    'https://graph.microsoft.com/DeviceManagementManagedDevices.ReadWrite.All'
    'https://graph.microsoft.com/DeviceManagementManagedDevices.PrivilegedOperations.All'
    'https://graph.microsoft.com/Device.ReadWrite.All'
    'offline_access'
) -join ' '

$DeviceSelect = @(
    'id','deviceName','userPrincipalName','userDisplayName','operatingSystem','osVersion'
    'complianceState','lastSyncDateTime','enrolledDateTime','serialNumber','manufacturer'
    'model','managedDeviceOwnerType','azureADDeviceId','notes'
) -join ','

$DeviceActions = @(
    @{ Id = 'syncDevice';                     Label = 'Sync';                 Windows = $false; Confirm = $false }
    @{ Id = 'rebootNow';                      Label = 'Restart';              Windows = $false; Confirm = $true  }
    @{ Id = 'rotateBitLockerKeys';            Label = 'Rotate BitLocker key'; Windows = $true;  Confirm = $false }
    @{ Id = 'windowsDefenderScan';            Label = 'Defender quick scan';  Windows = $true;  Confirm = $false; Body = @{ quickScan = $true } }
    @{ Id = 'windowsDefenderUpdateSignatures';Label = 'Update signatures';    Windows = $true;  Confirm = $false }
)

$DataDir    = Join-Path $env:LOCALAPPDATA 'DeviceInventory'
$TokenFile  = Join-Path $DataDir 'token.dat'
$LogFile    = Join-Path $DataDir 'app.log'
$ConfigFile = Join-Path $DataDir 'config.json'

# ---------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------
if (-not (Test-Path $DataDir)) { New-Item -Path $DataDir -ItemType Directory -Force | Out-Null }

function Write-AppLog {
    param([string]$Message, [string]$Level = 'INFO')
    try {
        "$([DateTime]::Now.ToString('s')) [$Level] $Message" | Add-Content -Path $LogFile -Encoding UTF8
    } catch { }
}

if (-not $ShowConsole) {
    try {
        Add-Type -Namespace Win32Native -Name Win -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
        $consoleHandle = [Win32Native.Win]::GetConsoleWindow()
        if ($consoleHandle -ne [IntPtr]::Zero) { [void][Win32Native.Win]::ShowWindow($consoleHandle, 0) }
    } catch { }
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml

function Show-Message {
    param([string]$Text, [string]$Title = $App.Name, [string]$Icon = 'Information')
    [void][System.Windows.MessageBox]::Show($Text, $Title, 'OK', $Icon)
}

# =====================================================================
#  Authentication - authorization code + PKCE, DPAPI-cached refresh token
# =====================================================================
$script:Token = $null   # @{ AccessToken; ExpiresOn; RefreshToken }

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function New-PkcePair {
    $bytes = New-Object byte[] 32
    ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
    $verifier = ConvertTo-Base64Url -Bytes $bytes
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))
    @{ Verifier = $verifier; Challenge = (ConvertTo-Base64Url -Bytes $hash) }
}

function Get-FreeLoopbackPort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    $port
}

function Save-RefreshToken {
    param([string]$RefreshToken)
    try {
        ConvertTo-SecureString $RefreshToken -AsPlainText -Force |
            ConvertFrom-SecureString |
            Set-Content -Path $TokenFile -Encoding UTF8
    } catch { Write-AppLog "Could not cache refresh token: $($_.Exception.Message)" 'WARN' }
}

function Get-CachedRefreshToken {
    if (-not (Test-Path $TokenFile)) { return $null }
    try {
        $secure = Get-Content $TokenFile -Raw | ConvertTo-SecureString
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try   { [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    } catch {
        Write-AppLog "Cached token unreadable, removing: $($_.Exception.Message)" 'WARN'
        Remove-Item $TokenFile -Force -ErrorAction SilentlyContinue
        $null
    }
}

function Set-TokenFromResponse {
    param($Response)
    $script:Token = @{
        AccessToken  = $Response.access_token
        ExpiresOn    = [DateTime]::UtcNow.AddSeconds([int]$Response.expires_in)
        RefreshToken = $Response.refresh_token
    }
    if ($Response.refresh_token) { Save-RefreshToken -RefreshToken $Response.refresh_token }
}

function Invoke-TokenRequest {
    param([hashtable]$Body)
    $Body['client_id'] = $App.ClientId
    Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($App.TenantId)/oauth2/v2.0/token" `
        -Body $Body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
}

function Invoke-SilentSignIn {
    $refresh = Get-CachedRefreshToken
    if (-not $refresh) { return $false }
    try {
        $response = Invoke-TokenRequest -Body @{
            grant_type    = 'refresh_token'
            refresh_token = $refresh
            scope         = $GraphScopes
        }
        Set-TokenFromResponse -Response $response
        Write-AppLog 'Silent sign-in succeeded.'
        $true
    } catch {
        Write-AppLog "Silent sign-in failed: $($_.Exception.Message)" 'WARN'
        Remove-Item $TokenFile -Force -ErrorAction SilentlyContinue
        $false
    }
}

function Invoke-InteractiveSignIn {
    $port     = Get-FreeLoopbackPort
    $redirect = "http://localhost:$port/"
    $pkce     = New-PkcePair
    $state    = [guid]::NewGuid().ToString('N')

    $query = @(
        "client_id=$($App.ClientId)"
        'response_type=code'
        "redirect_uri=$([uri]::EscapeDataString($redirect))"
        'response_mode=query'
        "scope=$([uri]::EscapeDataString($GraphScopes))"
        "state=$state"
        "code_challenge=$($pkce.Challenge)"
        'code_challenge_method=S256'
        'prompt=select_account'
    ) -join '&'
    $authUrl = "https://login.microsoftonline.com/$($App.TenantId)/oauth2/v2.0/authorize?$query"

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($redirect)
    try { $listener.Start() }
    catch { throw "Could not open a local listener on port $port. $($_.Exception.Message)" }

    try {
        Start-Process $authUrl
        $contextTask = $listener.GetContextAsync()
        if (-not $contextTask.Wait(180000)) { throw 'Sign-in timed out after three minutes.' }
        $context = $contextTask.Result

        $code      = $context.Request.QueryString['code']
        $errorCode = $context.Request.QueryString['error']
        $errorDesc = $context.Request.QueryString['error_description']
        $gotState  = $context.Request.QueryString['state']

        $body = if ($code) { 'Signed in. You can close this tab and return to Device Inventory.' }
                else       { "Sign-in failed: $errorDesc" }
        $html = "<!doctype html><meta charset=utf-8><title>Device Inventory</title>" +
                "<body style='font:15px Segoe UI,system-ui;color:#101820;margin:60px auto;max-width:520px'>" +
                "<h2 style='font-weight:600'>Device Inventory</h2><p>$body</p></body>"
        $buffer = [Text.Encoding]::UTF8.GetBytes($html)
        $context.Response.ContentType     = 'text/html; charset=utf-8'
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.Close()

        if ($errorCode)           { throw "$errorCode - $errorDesc" }
        if ($gotState -ne $state) { throw 'Sign-in state mismatch. Try again.' }

        $response = Invoke-TokenRequest -Body @{
            grant_type    = 'authorization_code'
            code          = $code
            redirect_uri  = $redirect
            code_verifier = $pkce.Verifier
            scope         = $GraphScopes
        }
        Set-TokenFromResponse -Response $response
        Write-AppLog 'Interactive sign-in succeeded.'
    }
    finally {
        if ($listener.IsListening) { $listener.Stop() }
        $listener.Close()
    }
}

function Invoke-DeviceCodeSignIn {
    # Fallback for machines where the loopback listener can't start.
    $codeResponse = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$($App.TenantId)/oauth2/v2.0/devicecode" `
        -Body @{ client_id = $App.ClientId; scope = $GraphScopes } `
        -ContentType 'application/x-www-form-urlencoded'

    try { Set-Clipboard -Value $codeResponse.user_code } catch { }
    Start-Process $codeResponse.verification_uri

    Show-Message "Enter this code in the browser window that just opened:`n`n    $($codeResponse.user_code)`n`n(It's already on your clipboard.)`n`nClick OK once you've finished signing in." 'Sign in'

    $deadline = [DateTime]::UtcNow.AddSeconds([int]$codeResponse.expires_in)
    $interval = [Math]::Max([int]$codeResponse.interval, 3)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $response = Invoke-TokenRequest -Body @{
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                device_code = $codeResponse.device_code
            }
            Set-TokenFromResponse -Response $response
            return
        } catch {
            $detail = ''
            try { $detail = $_.ErrorDetails.Message } catch { }
            if ($detail -notmatch 'authorization_pending|slow_down') { throw }
            if ($detail -match 'slow_down') { $interval += 3 }
        }
    }
    throw 'Device code sign-in timed out.'
}

function Get-AccessToken {
    if ($script:Token -and $script:Token.ExpiresOn -gt [DateTime]::UtcNow.AddMinutes(5)) {
        return $script:Token.AccessToken
    }
    if ($script:Token -and $script:Token.RefreshToken) {
        $response = Invoke-TokenRequest -Body @{
            grant_type    = 'refresh_token'
            refresh_token = $script:Token.RefreshToken
            scope         = $GraphScopes
        }
        Set-TokenFromResponse -Response $response
        return $script:Token.AccessToken
    }
    throw 'Not signed in.'
}

function Get-SignedInUser {
    try {
        $payload = $script:Token.AccessToken.Split('.')[1]
        $pad = '=' * ((4 - ($payload.Length % 4)) % 4)
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($payload.Replace('-','+').Replace('_','/') + $pad)))
        $claims = $json | ConvertFrom-Json
        if ($claims.upn)                { $claims.upn }
        elseif ($claims.preferred_username) { $claims.preferred_username }
        else                            { 'signed in' }
    } catch { 'signed in' }
}

# =====================================================================
#  Background worker - runs Graph calls off the UI thread
# =====================================================================
$Worker = {
    param($Token, $Operation, $Requests, $Options, $Progress)

    function Invoke-Graph {
        param([string]$Method, [string]$Uri, $Body)
        if ($Uri -notlike 'http*') { $Uri = "https://graph.microsoft.com$Uri" }
        $headers = @{ Authorization = "Bearer $Token" }
        for ($attempt = 0; $attempt -lt 4; $attempt++) {
            try {
                $params = @{ Method = $Method; Uri = $Uri; Headers = $headers; UseBasicParsing = $true; ErrorAction = 'Stop' }
                if ($null -ne $Body) {
                    $params.Body        = ($Body | ConvertTo-Json -Depth 6 -Compress)
                    $params.ContentType = 'application/json'
                }
                return Invoke-RestMethod @params
            } catch {
                $response = $_.Exception.Response
                $status = 0
                if ($response) { try { $status = [int]$response.StatusCode } catch { } }
                if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 3) {
                    $wait = 5
                    if ($response) { try { $wait = [int]$response.Headers['Retry-After'] } catch { } }
                    Start-Sleep -Seconds ([Math]::Max($wait, 2))
                    continue
                }
                $message = $_.Exception.Message
                try {
                    $detail = $_.ErrorDetails.Message | ConvertFrom-Json
                    if ($detail.error.message) { $message = $detail.error.message }
                } catch { }
                throw "$message (HTTP $status)"
            }
        }
    }

    function ConvertFrom-DeviceNotes {
        param([string]$Notes)
        $result = @{ Attributes = @{}; FreeText = $null }
        if ([string]::IsNullOrWhiteSpace($Notes)) { return $result }
        try {
            $parsed = $Notes | ConvertFrom-Json -ErrorAction Stop
            if ($parsed -isnot [array] -and $parsed -isnot [string] -and $parsed -isnot [ValueType]) {
                foreach ($property in $parsed.PSObject.Properties) {
                    $result.Attributes[$property.Name] = [string]$property.Value
                }
                return $result
            }
        } catch { }
        $result.FreeText = $Notes
        $result
    }

    switch ($Operation) {

        'Load' {
            $devices = New-Object System.Collections.ArrayList
            $uri = "/beta/deviceManagement/managedDevices?`$select=$($Options.Select)&`$top=100"
            for ($page = 0; $page -lt $Options.MaxPages -and $uri; $page++) {
                $result = Invoke-Graph -Method GET -Uri $uri
                foreach ($raw in $result.value) {
                    $notes = ConvertFrom-DeviceNotes -Notes $raw.notes
                    $lastSync = $null
                    if ($raw.lastSyncDateTime) { try { $lastSync = [DateTime]$raw.lastSyncDateTime } catch { } }
                    $enrolled = $null
                    if ($raw.enrolledDateTime) { try { $enrolled = [DateTime]$raw.enrolledDateTime } catch { } }

                    [void]$devices.Add([pscustomobject]@{
                        Id           = $raw.id
                        Name         = $raw.deviceName
                        User         = $raw.userPrincipalName
                        UserName     = $raw.userDisplayName
                        Platform     = $raw.operatingSystem
                        OsVersion    = $raw.osVersion
                        Compliance   = $raw.complianceState
                        LastSync     = $lastSync
                        Enrolled     = $enrolled
                        Serial       = $raw.serialNumber
                        Manufacturer = $raw.manufacturer
                        Model        = $raw.model
                        Ownership    = $raw.managedDeviceOwnerType
                        AadDeviceId  = $raw.azureADDeviceId
                        Attributes   = $notes.Attributes
                        FreeText     = $notes.FreeText
                        PropertyCount= $notes.Attributes.Count
                        NotesLoaded  = $false
                        SyncText     = ''
                    })
                }
                $Progress.Count = $devices.Count
                $uri = $result.'@odata.nextLink'
            }
            return $devices.ToArray()
        }

        'FetchNotes' {
            # notes is a non-default property: a LIST call always returns it null,
            # so each device needs its own GET. JSON batching does 20 per request.
            $ids = @($Requests)
            $Progress.Total = $ids.Count
            $Progress.Done  = 0
            $collected = New-Object System.Collections.ArrayList

            for ($start = 0; $start -lt $ids.Count; $start += 20) {
                $end   = [Math]::Min($start + 19, $ids.Count - 1)
                $chunk = @($ids[$start..$end])
                $batch = @{ requests = @() }
                $index = 0
                foreach ($id in $chunk) {
                    $index++
                    $batch.requests += @{
                        id     = "$index"
                        method = 'GET'
                        url    = "/deviceManagement/managedDevices('$id')?`$select=id,notes"
                    }
                }
                try {
                    $response = Invoke-Graph -Method POST -Uri '/beta/$batch' -Body $batch
                    foreach ($item in $response.responses) {
                        if ($item.status -eq 200 -and $item.body) {
                            [void]$collected.Add([pscustomobject]@{ Id = $item.body.id; Notes = $item.body.notes })
                        }
                    }
                } catch {
                    # One bad batch shouldn't lose the rest.
                }
                $Progress.Done = [Math]::Min($start + 20, $ids.Count)
            }
            return $collected.ToArray()
        }

        'Batch' {
            $Progress.Total = $Requests.Count
            $Progress.Done  = 0
            $results = New-Object System.Collections.ArrayList
            foreach ($request in $Requests) {
                $entry = @{ Key = $request.Key; Ok = $true; Error = $null; Status = 0 }
                try {
                    if ($request.Kind -eq 'extension') {
                        # managedDevice carries the Entra deviceId; PATCH needs the
                        # directory object id, so look it up through the alternate key.
                        $lookup = Invoke-Graph -Method GET -Uri "/v1.0/devices(deviceId='$($request.AadDeviceId)')?`$select=id"
                        if (-not $lookup.id) { throw "No Entra device object for device ID $($request.AadDeviceId)." }
                        Invoke-Graph -Method PATCH -Uri "/v1.0/devices/$($lookup.id)" `
                            -Body @{ extensionAttributes = $request.ExtensionAttributes } | Out-Null
                    } else {
                        Invoke-Graph -Method $request.Method -Uri $request.Uri -Body $request.Body | Out-Null
                    }
                } catch {
                    $entry.Ok    = $false
                    $entry.Error = $_.Exception.Message
                }
                [void]$results.Add([pscustomobject]$entry)
                $Progress.Done = $results.Count
            }
            return $results.ToArray()
        }
    }
}

# ---------------------------------------------------------------------
# Job plumbing: BeginInvoke + a DispatcherTimer that polls for results
# ---------------------------------------------------------------------
$script:Jobs = New-Object System.Collections.ArrayList

function Start-Work {
    param(
        [Parameter(Mandatory)][string]$Operation,
        [array]$Requests,
        [hashtable]$Options,
        [Parameter(Mandatory)][scriptblock]$OnComplete,
        [string]$Label = 'Working'
    )

    $token = Get-AccessToken
    $progress = [hashtable]::Synchronized(@{ Done = 0; Total = 0; Count = 0 })

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.ThreadOptions  = 'ReuseThread'
    $runspace.Open()

    $shell = [powershell]::Create()
    $shell.Runspace = $runspace
    [void]$shell.AddScript($Worker.ToString()).AddParameters(@{
        Token     = $token
        Operation = $Operation
        Requests  = $Requests
        Options   = $Options
        Progress  = $progress
    })

    $job = [pscustomobject]@{
        Shell      = $shell
        Runspace   = $runspace
        Handle     = $shell.BeginInvoke()
        Progress   = $progress
        OnComplete = $OnComplete
        Label      = $Label
    }
    [void]$script:Jobs.Add($job)
    Set-Busy -On $true -Label $Label
    $job
}

function Complete-Jobs {
    $finished = @($script:Jobs | Where-Object { $_.Handle.IsCompleted })
    foreach ($job in $finished) {
        $script:Jobs.Remove($job)
        $failure = $null
        $output  = $null
        try {
            $output = $job.Shell.EndInvoke($job.Handle)
            if ($job.Shell.Streams.Error.Count -gt 0) {
                $failure = ($job.Shell.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '
            }
        } catch {
            $failure = $_.Exception.Message
        } finally {
            $job.Shell.Dispose()
            $job.Runspace.Close()
            $job.Runspace.Dispose()
        }
        try { & $job.OnComplete $output $failure }
        catch { Write-AppLog "Completion handler failed: $($_.Exception.Message)" 'ERROR' }
    }
    if ($script:Jobs.Count -eq 0) { Set-Busy -On $false }
}

# =====================================================================
#  Interface
# =====================================================================
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Device Inventory" Height="800" Width="1260" MinHeight="620" MinWidth="980"
        WindowStartupLocation="CenterScreen" Background="#F4F6F8"
        FontFamily="Segoe UI" FontSize="12.5" Foreground="#101820">
  <Window.Resources>
    <SolidColorBrush x:Key="Line"   Color="#DCE1E7"/>
    <SolidColorBrush x:Key="Muted"  Color="#5C6875"/>
    <SolidColorBrush x:Key="Accent" Color="#1F4FD8"/>

    <Style TargetType="Button">
      <Setter Property="MinHeight" Value="28"/>
      <Setter Property="Margin" Value="0,0,6,6"/>
      <Setter Property="Foreground" Value="#101820"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Chrome" Background="White" BorderBrush="#DCE1E7" BorderThickness="1"
                    CornerRadius="3" Padding="11,4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="#F5F8FC"/>
                <Setter TargetName="Chrome" Property="BorderBrush" Value="#C6CDD6"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Chrome" Property="Background" Value="#F2F4F6"/>
                <Setter Property="Foreground" Value="#A2ACB8"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="PrimaryButton" TargetType="Button">
      <Setter Property="MinHeight" Value="28"/>
      <Setter Property="Margin" Value="0,0,6,6"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Chrome" Background="#1F4FD8" CornerRadius="3" Padding="11,4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Chrome" Property="Background" Value="#1A44BC"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Chrome" Property="Background" Value="#AEBBDF"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="6,4"/>
      <Setter Property="BorderBrush" Value="#DCE1E7"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="MinHeight" Value="28"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Padding" Value="6,3"/>
      <Setter Property="MinHeight" Value="28"/>
    </Style>

    <Style x:Key="SectionHead" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#5C6875"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,14,0,6"/>
    </Style>
    <Style x:Key="FactLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#5C6875"/>
      <Setter Property="Margin" Value="0,0,10,3"/>
    </Style>
    <Style x:Key="FactValue" TargetType="TextBlock">
      <Setter Property="Margin" Value="0,0,0,3"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,0,0,1" Padding="14,8">
      <DockPanel>
        <StackPanel Orientation="Horizontal" DockPanel.Dock="Left" VerticalAlignment="Center">
          <Border Background="#1F4FD8" CornerRadius="4" Width="22" Height="22" Margin="0,0,9,0">
            <TextBlock Text="DI" Foreground="White" FontSize="10" FontWeight="Bold"
                       HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <TextBlock Text="Device Inventory" FontWeight="SemiBold" FontSize="14" VerticalAlignment="Center"/>
          <TextBlock Text="custom properties for Intune" Foreground="#5C6875" Margin="9,0,0,0" VerticalAlignment="Center"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" DockPanel.Dock="Right" HorizontalAlignment="Right" VerticalAlignment="Center">
          <TextBlock x:Name="AccountText" Foreground="#5C6875" Margin="0,0,12,0" VerticalAlignment="Center"/>
          <Button x:Name="SignOutButton" Content="Sign out" Margin="0"/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Toolbar -->
    <Border Grid.Row="1" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,0,0,1" Padding="14,8,14,2">
      <DockPanel>
        <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
          <TextBox x:Name="SearchBox" Width="260" Margin="0,0,8,6"
                   ToolTip="Search device name, user, serial, model or any custom property"/>
          <ComboBox x:Name="PlatformBox" Width="150" Margin="0,0,8,6"/>
          <ComboBox x:Name="ComplianceBox" Width="150" Margin="0,0,12,6"/>
          <TextBlock x:Name="CountText" Foreground="#5C6875" VerticalAlignment="Center" Margin="0,0,0,6"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" DockPanel.Dock="Right" HorizontalAlignment="Right">
          <Button x:Name="ExportButton" Content="Export CSV"/>
          <Button x:Name="RefreshButton" Content="Refresh" Margin="0,0,0,6"/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Body -->
    <Grid Grid.Row="2" Margin="14,12,14,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="6"/>
        <ColumnDefinition Width="430" MinWidth="330"/>
      </Grid.ColumnDefinitions>

      <DataGrid x:Name="DeviceGrid" Grid.Column="0" AutoGenerateColumns="False" IsReadOnly="True"
                SelectionMode="Extended" SelectionUnit="FullRow" HeadersVisibility="Column"
                RowHeaderWidth="0" GridLinesVisibility="Horizontal" Background="White"
                HorizontalGridLinesBrush="#EDF0F3" BorderBrush="{StaticResource Line}" BorderThickness="1"
                RowHeight="26" AlternationCount="0" CanUserAddRows="False" EnableRowVirtualization="True">
        <DataGrid.Columns>
          <DataGridTextColumn Header="Device" Binding="{Binding Name}" Width="1.4*"/>
          <DataGridTextColumn Header="User" Binding="{Binding User}" Width="1.7*"/>
          <DataGridTextColumn Header="Platform" Binding="{Binding Platform}" Width="0.8*"/>
          <DataGridTextColumn Header="Compliance" Binding="{Binding Compliance}" Width="0.9*"/>
          <DataGridTextColumn Header="Last check-in" Binding="{Binding SyncText}" SortMemberPath="LastSync" Width="0.9*"/>
          <DataGridTextColumn Header="Properties" Binding="{Binding PropertyCount}" Width="80"/>
        </DataGrid.Columns>
      </DataGrid>

      <GridSplitter Grid.Column="1" Width="6" HorizontalAlignment="Stretch" Background="Transparent"/>

      <Border Grid.Column="2" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1">
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="14,12,14,14">
          <StackPanel>
            <TextBlock x:Name="PanelTitle" Text="No device selected" FontSize="15" FontWeight="SemiBold" TextWrapping="Wrap"/>
            <TextBlock x:Name="PanelSubtitle" Foreground="#5C6875" FontFamily="Consolas" FontSize="11"
                       TextWrapping="Wrap" Margin="0,2,0,0"/>

            <!-- Single device -->
            <StackPanel x:Name="SinglePanel" Visibility="Collapsed">
              <TextBlock Text="DEVICE" Style="{StaticResource SectionHead}"/>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="96"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Grid.Column="0" Text="User" Style="{StaticResource FactLabel}"/>
                <TextBlock Grid.Row="0" Grid.Column="1" x:Name="FactUser" Style="{StaticResource FactValue}"/>
                <TextBlock Grid.Row="1" Grid.Column="0" Text="Platform" Style="{StaticResource FactLabel}"/>
                <TextBlock Grid.Row="1" Grid.Column="1" x:Name="FactPlatform" Style="{StaticResource FactValue}"/>
                <TextBlock Grid.Row="2" Grid.Column="0" Text="Model" Style="{StaticResource FactLabel}"/>
                <TextBlock Grid.Row="2" Grid.Column="1" x:Name="FactModel" Style="{StaticResource FactValue}"/>
                <TextBlock Grid.Row="3" Grid.Column="0" Text="Serial" Style="{StaticResource FactLabel}"/>
                <TextBlock Grid.Row="3" Grid.Column="1" x:Name="FactSerial" Style="{StaticResource FactValue}" FontFamily="Consolas" FontSize="11.5"/>
                <TextBlock Grid.Row="4" Grid.Column="0" Text="Ownership" Style="{StaticResource FactLabel}"/>
                <TextBlock Grid.Row="4" Grid.Column="1" x:Name="FactOwnership" Style="{StaticResource FactValue}"/>
                <TextBlock Grid.Row="5" Grid.Column="0" Text="Compliance" Style="{StaticResource FactLabel}"/>
                <TextBlock Grid.Row="5" Grid.Column="1" x:Name="FactCompliance" Style="{StaticResource FactValue}"/>
                <TextBlock Grid.Row="6" Grid.Column="0" Text="Last check-in" Style="{StaticResource FactLabel}"/>
                <TextBlock Grid.Row="6" Grid.Column="1" x:Name="FactSync" Style="{StaticResource FactValue}"/>
              </Grid>

              <TextBlock Text="CUSTOM PROPERTIES" Style="{StaticResource SectionHead}"/>
              <Border x:Name="FreeTextNote" Background="#FDF6E6" BorderBrush="#E7D6AE" BorderThickness="1"
                      Padding="8" Margin="0,0,0,8" Visibility="Collapsed">
                <TextBlock TextWrapping="Wrap" Text="This device has a plain-text note. It is kept under the _notes key when you save."/>
              </Border>
              <DataGrid x:Name="PropertyGrid" AutoGenerateColumns="False" CanUserAddRows="True"
                        CanUserDeleteRows="True" HeadersVisibility="Column" RowHeaderWidth="0"
                        Height="330" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1"
                        HorizontalGridLinesBrush="#EDF0F3" GridLinesVisibility="All" RowHeight="24">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="#" Binding="{Binding Slot}" Width="26" IsReadOnly="True"/>
                  <DataGridTextColumn Header="Property" Binding="{Binding Property}" Width="*"/>
                  <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="1.3*"/>
                </DataGrid.Columns>
              </DataGrid>
              <TextBlock Foreground="#5C6875" FontSize="11.5" TextWrapping="Wrap" Margin="0,5,0,7"
                         Text="Rows 1-15 map to Entra extension attributes and can be used in dynamic group rules. Naming one renames it for every device; the value is per-device. Leave a value blank to clear it. Rows with no number are stored in notes only - add as many as you like."/>
              <StackPanel Orientation="Horizontal">
                <Button x:Name="SaveButton" Content="Save properties" Style="{StaticResource PrimaryButton}"/>
                <Button x:Name="RevertButton" Content="Revert"/>
              </StackPanel>
            </StackPanel>

            <!-- Multiple devices -->
            <StackPanel x:Name="BulkPanel" Visibility="Collapsed">
              <TextBlock Text="SET A PROPERTY ON ALL SELECTED" Style="{StaticResource SectionHead}"/>
              <TextBox x:Name="BulkKeyBox" Margin="0,0,0,6"/>
              <TextBox x:Name="BulkValueBox" Margin="0,0,0,8"/>
              <TextBlock Foreground="#5C6875" FontSize="11.5" TextWrapping="Wrap" Margin="0,0,0,8"
                         Text="Property name on top, value underneath. Other properties on these devices are left alone."/>
              <Button x:Name="BulkApplyButton" Content="Apply to selection" Style="{StaticResource PrimaryButton}"
                      HorizontalAlignment="Left"/>

              <TextBlock Text="REMOVE A PROPERTY" Style="{StaticResource SectionHead}"/>
              <StackPanel Orientation="Horizontal">
                <ComboBox x:Name="RemoveKeyBox" Width="230" Margin="0,0,6,0"/>
                <Button x:Name="BulkRemoveButton" Content="Remove"/>
              </StackPanel>
            </StackPanel>

            <!-- Actions -->
            <StackPanel x:Name="ActionPanel" Visibility="Collapsed">
              <TextBlock x:Name="ActionHead" Text="DEVICE ACTIONS" Style="{StaticResource SectionHead}"/>
              <WrapPanel x:Name="ActionButtons"/>
              <TextBlock Foreground="#5C6875" FontSize="11.5" TextWrapping="Wrap" Margin="0,4,0,0"
                         Text="Actions are queued in Intune and run when the device next checks in."/>
            </StackPanel>
          </StackPanel>
        </ScrollViewer>
      </Border>
    </Grid>

    <!-- Activity -->
    <Expander Grid.Row="3" x:Name="LogExpander" Header="Graph activity" Margin="14,10,14,0" IsExpanded="False" Foreground="#5C6875">
      <ListBox x:Name="LogList" Height="120" FontFamily="Consolas" FontSize="11" Margin="0,6,0,0"
               BorderBrush="{StaticResource Line}" Background="White"/>
    </Expander>

    <!-- Status -->
    <Border Grid.Row="4" Margin="14,8,14,10">
      <DockPanel>
        <ProgressBar x:Name="BusyBar" DockPanel.Dock="Right" Width="180" Height="5" IsIndeterminate="True" Visibility="Collapsed"/>
        <TextBlock x:Name="StatusText" Foreground="#5C6875" VerticalAlignment="Center"/>
      </DockPanel>
    </Border>
  </Grid>
</Window>
'@

[xml]$xamlDocument = $xaml
$reader = New-Object System.Xml.XmlNodeReader $xamlDocument
$window = [Windows.Markup.XamlReader]::Load($reader)

# Resolve named elements
$ui = @{}
foreach ($name in @(
    'AccountText','SignOutButton','SearchBox','PlatformBox','ComplianceBox','CountText',
    'ExportButton','RefreshButton','DeviceGrid','PanelTitle','PanelSubtitle','SinglePanel',
    'FactUser','FactPlatform','FactModel','FactSerial','FactOwnership','FactCompliance','FactSync',
    'FreeTextNote','PropertyGrid','SaveButton','RevertButton','BulkPanel','BulkKeyBox','BulkValueBox',
    'BulkApplyButton','RemoveKeyBox','BulkRemoveButton','ActionPanel','ActionHead','ActionButtons',
    'LogExpander','LogList','BusyBar','StatusText')) {
    $ui[$name] = $window.FindName($name)
}

# ---------------------------------------------------------------------
# State
# ---------------------------------------------------------------------
$script:Devices     = @()
$script:Filtered    = @()
$script:PropTable   = New-Object System.Data.DataTable
[void]$script:PropTable.Columns.Add('Slot', [string])
[void]$script:PropTable.Columns.Add('Property', [string])
[void]$script:PropTable.Columns.Add('Value', [string])
$script:SlotNames   = $null
$script:Suspend     = $false

function Get-SlotNames {
    # Slot 1-15 -> the property name you've given it. Tenant-wide by nature: a
    # dynamic group rule names a specific slot, so the meaning of each slot has to
    # be the same everywhere. Survives app updates because it lives outside the script.
    $names = [ordered]@{}
    for ($i = 1; $i -le 15; $i++) { $names["$i"] = '' }
    if (Test-Path $ConfigFile) {
        try {
            $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            if ($config.SlotNames) {
                foreach ($property in $config.SlotNames.PSObject.Properties) {
                    if ($names.Contains($property.Name)) { $names[$property.Name] = [string]$property.Value }
                }
            }
        } catch { Write-AppLog "config.json unreadable: $($_.Exception.Message)" 'WARN' }
    }
    $names
}

function Save-SlotNames {
    param($Names)
    try {
        $payload = [ordered]@{}
        for ($i = 1; $i -le 15; $i++) { $payload["$i"] = [string]$Names["$i"] }
        [pscustomobject]@{ SlotNames = [pscustomobject]$payload } |
            ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigFile -Encoding UTF8
    } catch { Write-AppLog "Could not save slot names: $($_.Exception.Message)" 'WARN' }
}

function Sync-ExtensionMap {
    $map = @{}
    for ($i = 1; $i -le 15; $i++) {
        $name = [string]$script:SlotNames["$i"]
        if (-not [string]::IsNullOrWhiteSpace($name)) { $map[$name.Trim()] = $i }
    }
    $App.ExtensionAttributeMap = $map
}

function Write-Activity {
    param([string]$Text, [string]$Level = 'INFO')
    $line = "$([DateTime]::Now.ToString('HH:mm:ss'))  $Text"
    $ui.LogList.Items.Insert(0, $line)
    while ($ui.LogList.Items.Count -gt 200) { $ui.LogList.Items.RemoveAt($ui.LogList.Items.Count - 1) }
    Write-AppLog $Text $Level
}

function Set-Status { param([string]$Text) $ui.StatusText.Text = $Text }

function Set-Busy {
    param([bool]$On, [string]$Label)
    $ui.BusyBar.Visibility = if ($On) { 'Visible' } else { 'Collapsed' }
    $ui.RefreshButton.IsEnabled = -not $On
    if ($On -and $Label) { Set-Status $Label }
}

function Get-RelativeTime {
    param($Value)
    if (-not $Value) { return '-' }
    $minutes = [int]([DateTime]::Now - $Value).TotalMinutes
    if ($minutes -lt 1)     { return 'just now' }
    if ($minutes -lt 60)    { return "$minutes" + 'm ago' }
    $hours = [int]($minutes / 60)
    if ($hours -lt 24)      { return "$hours" + 'h ago' }
    $days = [int]($hours / 24)
    if ($days -lt 30)       { return "$days" + 'd ago' }
    $Value.ToShortDateString()
}

# ---------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------
function Update-FilterChoices {
    $script:Suspend = $true
    $platform = $ui.PlatformBox.SelectedItem
    $ui.PlatformBox.Items.Clear()
    [void]$ui.PlatformBox.Items.Add('All platforms')
    foreach ($value in ($script:Devices.Platform | Where-Object { $_ } | Sort-Object -Unique)) {
        [void]$ui.PlatformBox.Items.Add($value)
    }
    $ui.PlatformBox.SelectedItem = if ($platform -and $ui.PlatformBox.Items.Contains($platform)) { $platform } else { 'All platforms' }

    if ($ui.ComplianceBox.Items.Count -eq 0) {
        foreach ($value in 'Any compliance','compliant','noncompliant','inGracePeriod','unknown') {
            [void]$ui.ComplianceBox.Items.Add($value)
        }
        $ui.ComplianceBox.SelectedIndex = 0
    }
    $script:Suspend = $false
}

function Update-DeviceList {
    if ($script:Suspend) { return }
    $search     = $ui.SearchBox.Text.Trim()
    $platform   = [string]$ui.PlatformBox.SelectedItem
    $compliance = [string]$ui.ComplianceBox.SelectedItem

    $rows = $script:Devices
    if ($platform -and $platform -ne 'All platforms') {
        $rows = $rows | Where-Object { $_.Platform -eq $platform }
    }
    if ($compliance -and $compliance -ne 'Any compliance') {
        $rows = $rows | Where-Object { $_.Compliance -eq $compliance }
    }
    if ($search) {
        $rows = $rows | Where-Object {
            $haystack = @($_.Name, $_.User, $_.UserName, $_.Serial, $_.Model, $_.Manufacturer) +
                        @($_.Attributes.Keys) + @($_.Attributes.Values)
            ($haystack -join ' ') -like "*$search*"
        }
    }

    $script:Filtered = @($rows)
    $ui.DeviceGrid.ItemsSource = $script:Filtered
    $ui.CountText.Text = "$($script:Filtered.Count) of $($script:Devices.Count) devices"
}

function Update-Panel {
    $selected = @($ui.DeviceGrid.SelectedItems)

    if ($selected.Count -eq 0) {
        $ui.PanelTitle.Text    = 'No device selected'
        $ui.PanelSubtitle.Text = ''
        $ui.SinglePanel.Visibility = 'Collapsed'
        $ui.BulkPanel.Visibility   = 'Collapsed'
        $ui.ActionPanel.Visibility = 'Collapsed'
        return
    }

    if ($selected.Count -eq 1) {
        $device = $selected[0]
        $ui.PanelTitle.Text    = if ($device.Name) { $device.Name } else { '(unnamed device)' }
        $ui.PanelSubtitle.Text = $device.Id
        $ui.SinglePanel.Visibility = 'Visible'
        $ui.BulkPanel.Visibility   = 'Collapsed'

        $ui.FactUser.Text       = if ($device.User) { "$($device.UserName)`n$($device.User)".Trim() } else { '-' }
        $ui.FactPlatform.Text   = "$($device.Platform) $($device.OsVersion)".Trim()
        $ui.FactModel.Text      = (@($device.Manufacturer, $device.Model) | Where-Object { $_ }) -join ' '
        if (-not $ui.FactModel.Text) { $ui.FactModel.Text = '-' }
        $ui.FactSerial.Text     = if ($device.Serial) { $device.Serial } else { '-' }
        $ui.FactOwnership.Text  = if ($device.Ownership) { $device.Ownership } else { '-' }
        $ui.FactCompliance.Text = if ($device.Compliance) { $device.Compliance } else { 'unknown' }
        $ui.FactSync.Text       = Get-RelativeTime $device.LastSync
        $ui.FreeTextNote.Visibility = if ($device.FreeText) { 'Visible' } else { 'Collapsed' }

        Reset-PropertyGrid -Device $device
        if (-not $device.NotesLoaded) { Start-NotesLoad -Devices @($device) }
    }
    else {
        $ui.PanelTitle.Text    = "$($selected.Count) devices selected"
        $ui.PanelSubtitle.Text = (($selected | Select-Object -First 3).Name -join ', ')
        $ui.SinglePanel.Visibility = 'Collapsed'
        $ui.BulkPanel.Visibility   = 'Visible'

        $keys = New-Object System.Collections.Generic.HashSet[string]
        foreach ($device in $selected) {
            foreach ($key in $device.Attributes.Keys) { [void]$keys.Add($key) }
        }
        $ui.RemoveKeyBox.Items.Clear()
        foreach ($key in ($keys | Sort-Object)) { [void]$ui.RemoveKeyBox.Items.Add($key) }
        $ui.BulkRemoveButton.IsEnabled = $ui.RemoveKeyBox.Items.Count -gt 0
    }

    $ui.ActionPanel.Visibility = 'Visible'
    $ui.ActionHead.Text = if ($selected.Count -eq 1) { 'DEVICE ACTIONS' } else { "DEVICE ACTIONS ON $($selected.Count) DEVICES" }
}

function Reset-PropertyGrid {
    param($Device)
    $script:PropTable.Clear()
    $claimed = @{}
    for ($i = 1; $i -le 15; $i++) {
        $name  = [string]$script:SlotNames["$i"]
        $value = ''
        if ($name -and $Device.Attributes.ContainsKey($name)) {
            $value = $Device.Attributes[$name]
            $claimed[$name] = $true
        }
        [void]$script:PropTable.Rows.Add("$i", $name, $value)
    }
    # Anything stored on the device that isn't mapped to a slot still shows up,
    # just without a slot number - it lives in notes only.
    foreach ($key in ($Device.Attributes.Keys | Sort-Object)) {
        if (-not $claimed.ContainsKey($key)) {
            [void]$script:PropTable.Rows.Add('', $key, $Device.Attributes[$key])
        }
    }
    $script:PropTable.AcceptChanges()
    $ui.PropertyGrid.ItemsSource = $script:PropTable.DefaultView
}

function ConvertTo-NotesJson {
    param([hashtable]$Attributes, [string]$FreeText)
    $ordered = [ordered]@{}
    foreach ($key in ($Attributes.Keys | Sort-Object)) { $ordered[$key] = [string]$Attributes[$key] }
    if ($FreeText) { $ordered['_notes'] = $FreeText }
    if ($ordered.Count -eq 0) { return '' }
    $ordered | ConvertTo-Json -Depth 3 -Compress
}

function Convert-NotesToAttributes {
    param([string]$Notes)
    $result = @{ Attributes = @{}; FreeText = $null }
    if ([string]::IsNullOrWhiteSpace($Notes)) { return $result }
    try {
        $parsed = $Notes | ConvertFrom-Json -ErrorAction Stop
        if ($parsed -isnot [array] -and $parsed -isnot [string] -and $parsed -isnot [ValueType]) {
            foreach ($property in $parsed.PSObject.Properties) {
                $result.Attributes[$property.Name] = [string]$property.Value
            }
            return $result
        }
    } catch { }
    $result.FreeText = $Notes
    $result
}

function Set-DeviceNotes {
    param($Device, [string]$Notes)
    $parsed = Convert-NotesToAttributes -Notes $Notes
    $Device.Attributes    = $parsed.Attributes
    $Device.FreeText      = $parsed.FreeText
    $Device.PropertyCount = $parsed.Attributes.Count
    $Device.NotesLoaded   = $true
}

function Start-NotesLoad {
    # Pulls the notes field for the given devices. Called for the whole fleet after
    # a load, and for a single device the moment it's selected.
    param([array]$Devices)
    $pending = @($Devices | Where-Object { -not $_.NotesLoaded })
    if ($pending.Count -eq 0) { return }

    $lookup = @{}
    foreach ($device in $pending) { $lookup[$device.Id] = $device }
    $ids = @($pending | ForEach-Object { $_.Id })

    $onComplete = {
        param($Output, $Failure)
        if ($Failure) {
            Write-Activity "Could not load properties: $Failure" 'ERROR'
            return
        }
        $withValues = 0
        foreach ($item in @($Output)) {
            $device = $lookup[$item.Id]
            if (-not $device) { continue }
            Set-DeviceNotes -Device $device -Notes $item.Notes
            if ($device.PropertyCount -gt 0) { $withValues++ }
        }
        $ui.DeviceGrid.Items.Refresh()

        # Only redraw the editor if the user isn't part-way through an edit.
        $selected = @($ui.DeviceGrid.SelectedItems)
        if ($selected.Count -eq 1 -and $null -eq $script:PropTable.GetChanges()) { Update-Panel }

        Write-Activity "Properties loaded for $(@($Output).Count) devices, $withValues with values."
        Set-Status "$withValues devices have custom properties."
    }.GetNewClosure()

    Start-Work -Operation 'FetchNotes' -Requests $ids -Label 'Loading properties...' -OnComplete $onComplete | Out-Null
}

function New-PropertyRequests {
    # One PATCH for the Intune notes field, plus - when mirroring is configured -
    # one for the Entra device object so dynamic groups can see the value.
    param($Device, [hashtable]$Attributes, [string]$Notes)

    $list = New-Object System.Collections.ArrayList
    [void]$list.Add(@{
        Key = $Device.Id; Kind = 'graph'; Method = 'PATCH'
        Uri = "/beta/deviceManagement/managedDevices('$($Device.Id)')"
        Body = @{ notes = $Notes }
    })

    if ($App.ExtensionAttributeMap.Count -gt 0 -and $Device.AadDeviceId) {
        $extension = @{}
        foreach ($name in $App.ExtensionAttributeMap.Keys) {
            $slot  = [int]$App.ExtensionAttributeMap[$name]
            $value = $null
            if ($Attributes.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($Attributes[$name])) {
                $value = [string]$Attributes[$name]
            }
            # Null clears the attribute, which is what we want when the property
            # has been removed from the device.
            $extension["extensionAttribute$slot"] = $value
        }
        [void]$list.Add(@{
            Key = "$($Device.Id)#ext"; Kind = 'extension'
            AadDeviceId = $Device.AadDeviceId; ExtensionAttributes = $extension
        })
    }
    $list.ToArray()
}

function Update-DeviceAttributes {
    param($Device, [hashtable]$Attributes)
    $Device.Attributes    = $Attributes
    $Device.PropertyCount = $Attributes.Count
}

# ---------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------
function Start-DeviceLoad {
    Write-Activity 'GET  /beta/deviceManagement/managedDevices'
    Set-Status 'Loading devices...'
    Start-Work -Operation 'Load' -Label 'Loading devices...' `
        -Options @{ Select = $DeviceSelect; MaxPages = $App.MaxPages } `
        -OnComplete {
            param($Output, $Failure)
            if ($Failure) {
                Write-Activity "Load failed: $Failure" 'ERROR'
                Set-Status 'Could not load devices.'
                Show-Message "Could not load devices.`n`n$Failure" 'Load failed' 'Error'
                return
            }
            $script:Devices = @($Output)
            foreach ($device in $script:Devices) { $device.SyncText = Get-RelativeTime $device.LastSync }
            Update-FilterChoices
            Update-DeviceList
            Update-Panel
            Write-Activity "Loaded $($script:Devices.Count) devices."
            Set-Status "$($script:Devices.Count) devices loaded."
            Start-NotesLoad -Devices $script:Devices
        } | Out-Null
}

function Start-PropertySave {
    $selected = @($ui.DeviceGrid.SelectedItems)
    if ($selected.Count -ne 1) { return }
    $device = $selected[0]
    if (-not $device.NotesLoaded) {
        Show-Message 'This device''s properties are still loading. Give it a moment and try again.' 'Still loading' 'Warning'
        return
    }

    # A row the user is still typing in lives in the DataGrid's pending edit, not in
    # the DataTable. Commit the cell, then the row, then any pending new-row on the
    # collection view - otherwise the table reads back empty and we save nothing.
    [void]$ui.PropertyGrid.CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Cell, $true)
    [void]$ui.PropertyGrid.CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row, $true)
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.PropertyGrid.ItemsSource)
    if ($view -is [System.ComponentModel.IEditableCollectionView]) {
        if ($view.IsAddingNew)   { $view.CommitNew() }
        if ($view.IsEditingItem) { $view.CommitEdit() }
    }

    $attributes = @{}
    $slotNames  = [ordered]@{}
    for ($i = 1; $i -le 15; $i++) { $slotNames["$i"] = '' }

    foreach ($rowView in @($script:PropTable.DefaultView)) {
        $rowView.EndEdit()
        $slot  = ([string]$rowView['Slot']).Trim()
        $key   = ([string]$rowView['Property']).Trim()
        $value = [string]$rowView['Value']

        # A slot's name is tenant-wide; the value is per-device.
        if ($slot -and $slotNames.Contains($slot)) { $slotNames[$slot] = $key }

        # An empty value means the property isn't set on this device, so it stays
        # out of notes entirely rather than storing 15 blanks everywhere.
        if ($key -and -not [string]::IsNullOrWhiteSpace($value)) { $attributes[$key] = $value }
    }

    $renamed = $false
    for ($i = 1; $i -le 15; $i++) {
        if ([string]$script:SlotNames["$i"] -ne [string]$slotNames["$i"]) { $renamed = $true }
    }
    if ($renamed) {
        $script:SlotNames = $slotNames
        Save-SlotNames -Names $slotNames
        Write-Activity 'Slot names updated - they apply to every device from now on.'
    }
    Sync-ExtensionMap

    $notes = ConvertTo-NotesJson -Attributes $attributes -FreeText $device.FreeText
    if ($notes.Length -gt 1024) {
        Show-Message "These properties come to $($notes.Length) characters once stored. Intune's notes field holds 1024.`n`nShorten a value or remove a property." 'Too much to store' 'Warning'
        return
    }
    $requests = @(New-PropertyRequests -Device $device -Attributes $attributes -Notes $notes)
    $extCount = @($requests | Where-Object { $_.Kind -eq 'extension' }).Count
    Write-Activity "PATCH $($device.Name): $($attributes.Count) properties, $($notes.Length) chars of notes$(if ($extCount) { ' + extension attributes' })"
    if ($attributes.Count -eq 0) {
        Write-Activity 'No property has both a name and a value, so notes will be cleared.' 'WARN'
    }

    # GetNewClosure captures $device and $attributes; PowerShell scriptblocks are
    # dynamically scoped, so without it these are gone by the time the job finishes.
    $onComplete = {
        param($Output, $Failure)
        $results  = @($Output)
        $notesTry = $results | Where-Object { $_.Key -notlike '*#ext' } | Select-Object -First 1
        $extTry   = $results | Where-Object { $_.Key -like '*#ext' }    | Select-Object -First 1
        if ($Failure -or -not $notesTry -or -not $notesTry.Ok) {
            $message = if ($Failure) { $Failure } else { $notesTry.Error }
            Write-Activity "Save failed: $message" 'ERROR'
            Show-Message "Could not save properties.`n`n$message" 'Save failed' 'Error'
            return
        }
        if ($extTry -and -not $extTry.Ok) {
            Write-Activity "Notes saved, but the Entra extension attributes did not: $($extTry.Error)" 'WARN'
            Show-Message "The properties saved, but writing the Entra extension attributes failed - dynamic groups won't see this change yet.`n`n$($extTry.Error)" 'Partly saved' 'Warning'
        }
        Write-Activity "Notes write returned OK$(if ($extTry -and $extTry.Ok) { '; extension attributes returned OK' })"
        Update-DeviceAttributes -Device $device -Attributes $attributes
        $ui.DeviceGrid.Items.Refresh()
        Reset-PropertyGrid -Device $device
        Write-Activity "Saved $($attributes.Count) properties on $($device.Name)."
        Set-Status "Saved properties on $($device.Name)."
    }.GetNewClosure()

    Start-Work -Operation 'Batch' -Label 'Saving properties...' -OnComplete $onComplete -Requests $requests | Out-Null
}

function Start-BulkPropertySet {
    $selected = @($ui.DeviceGrid.SelectedItems)
    $key = $ui.BulkKeyBox.Text.Trim()
    if (-not $key -or $selected.Count -lt 2) { return }
    if (@($selected | Where-Object { -not $_.NotesLoaded }).Count -gt 0) {
        Show-Message 'Properties are still loading for some of the selected devices. Applying now would wipe values that have not been read back yet.' 'Still loading' 'Warning'
        return
    }
    $value = $ui.BulkValueBox.Text

    $answer = [System.Windows.MessageBox]::Show(
        "Set '$key' to '$value' on $($selected.Count) devices?", 'Apply property', 'OKCancel', 'Question')
    if ($answer -ne 'OK') { return }

    $requests = @()
    $pending  = @{}
    foreach ($device in $selected) {
        $attributes = @{}
        foreach ($existing in $device.Attributes.Keys) { $attributes[$existing] = $device.Attributes[$existing] }
        $attributes[$key] = $value
        $pending[$device.Id] = @{ Device = $device; Attributes = $attributes }
        $requests += New-PropertyRequests -Device $device -Attributes $attributes `
                        -Notes (ConvertTo-NotesJson -Attributes $attributes -FreeText $device.FreeText)
    }

    $onComplete = {
        param($Output, $Failure)
        Complete-BulkResult -Output $Output -Failure $Failure -Pending $pending -Verb "Applied '$key'"
    }.GetNewClosure()

    $tooLong = @($requests | Where-Object { $_.Kind -eq 'graph' -and $_.Body.notes.Length -gt 1024 })
    if ($tooLong.Count -gt 0) {
        Show-Message "$($tooLong.Count) of the selected devices would exceed the 1024-character notes limit with this property added.`n`nNothing was changed." 'Too much to store' 'Warning'
        return
    }

    Write-Activity "PATCH notes on $($requests.Count) devices ('$key')"
    Start-Work -Operation 'Batch' -Label "Applying '$key' to $($requests.Count) devices..." `
        -Requests $requests -OnComplete $onComplete | Out-Null
}

function Start-BulkPropertyRemove {
    $selected = @($ui.DeviceGrid.SelectedItems)
    $key = [string]$ui.RemoveKeyBox.SelectedItem
    if (-not $key -or $selected.Count -lt 2) { return }
    if (@($selected | Where-Object { -not $_.NotesLoaded }).Count -gt 0) {
        Show-Message 'Properties are still loading for some of the selected devices. Try again once loading finishes.' 'Still loading' 'Warning'
        return
    }

    $answer = [System.Windows.MessageBox]::Show(
        "Remove '$key' from $($selected.Count) devices?", 'Remove property', 'OKCancel', 'Warning')
    if ($answer -ne 'OK') { return }

    $requests = @()
    $pending  = @{}
    foreach ($device in $selected) {
        if (-not $device.Attributes.ContainsKey($key)) { continue }
        $attributes = @{}
        foreach ($existing in $device.Attributes.Keys) {
            if ($existing -ne $key) { $attributes[$existing] = $device.Attributes[$existing] }
        }
        $pending[$device.Id] = @{ Device = $device; Attributes = $attributes }
        $requests += New-PropertyRequests -Device $device -Attributes $attributes `
                        -Notes (ConvertTo-NotesJson -Attributes $attributes -FreeText $device.FreeText)
    }
    if ($requests.Count -eq 0) { Set-Status 'None of the selected devices had that property.'; return }

    $onComplete = {
        param($Output, $Failure)
        Complete-BulkResult -Output $Output -Failure $Failure -Pending $pending -Verb "Removed '$key'"
    }.GetNewClosure()

    Write-Activity "PATCH notes on $($requests.Count) devices (remove '$key')"
    Start-Work -Operation 'Batch' -Label "Removing '$key' from $($requests.Count) devices..." `
        -Requests $requests -OnComplete $onComplete | Out-Null
}

function Complete-BulkResult {
    param($Output, $Failure, [hashtable]$Pending, [string]$Verb)
    if ($Failure) {
        Write-Activity "$Verb failed: $Failure" 'ERROR'
        Show-Message "The operation failed.`n`n$Failure" 'Failed' 'Error'
        return
    }
    $all       = @($Output)
    $results   = @($all | Where-Object { $_.Key -notlike '*#ext' })
    $extFailed = @($all | Where-Object { $_.Key -like '*#ext' -and -not $_.Ok })
    $succeeded = 0
    $firstError = $null
    foreach ($result in $results) {
        if ($result.Ok) {
            $succeeded++
            $entry = $Pending[$result.Key]
            if ($entry) { Update-DeviceAttributes -Device $entry.Device -Attributes $entry.Attributes }
        } elseif (-not $firstError) {
            $firstError = $result.Error
        }
    }
    $ui.DeviceGrid.Items.Refresh()
    Update-Panel
    $failed = $results.Count - $succeeded
    $summary = "$Verb on $succeeded of $($results.Count) devices."
    if ($failed -gt 0) { $summary += " $failed failed - $firstError" }
    if ($extFailed.Count -gt 0) { $summary += " Extension attributes failed on $($extFailed.Count) - $($extFailed[0].Error)" }
    Write-Activity $summary $(if ($failed) { 'WARN' } else { 'INFO' })
    Set-Status $summary
}

function Start-DeviceAction {
    param([hashtable]$Action)
    $selected = @($ui.DeviceGrid.SelectedItems)
    if ($selected.Count -eq 0) { return }

    if ($Action.Confirm -or $selected.Count -gt 1) {
        $target = if ($selected.Count -eq 1) { $selected[0].Name } else { "$($selected.Count) devices" }
        $answer = [System.Windows.MessageBox]::Show(
            "$($Action.Label) on $target ?", $Action.Label, 'OKCancel',
            $(if ($Action.Confirm) { 'Warning' } else { 'Question' }))
        if ($answer -ne 'OK') { return }
    }

    $requests = @()
    foreach ($device in $selected) {
        if ($Action.Windows -and $device.Platform -notlike '*Windows*') { continue }
        $requests += @{ Key = $device.Id; Method = 'POST'
                        Uri = "/beta/deviceManagement/managedDevices/$($device.Id)/$($Action.Id)"
                        Body = $(if ($Action.Body) { $Action.Body } else { @{} }) }
    }
    if ($requests.Count -eq 0) { Set-Status 'That action does not apply to the selected devices.'; return }

    $onComplete = {
        param($Output, $Failure)
        if ($Failure) {
            Write-Activity "$($Action.Label) failed: $Failure" 'ERROR'
            Show-Message "The action failed.`n`n$Failure" $Action.Label 'Error'
            return
        }
        $results = @($Output)
        $ok = @($results | Where-Object { $_.Ok }).Count
        $failedResults = @($results | Where-Object { -not $_.Ok })
        $summary = "$($Action.Label) queued on $ok of $($results.Count) devices."
        if ($failedResults.Count -gt 0) { $summary += " $($failedResults.Count) failed - $($failedResults[0].Error)" }
        Write-Activity $summary $(if ($failedResults.Count) { 'WARN' } else { 'INFO' })
        Set-Status $summary
    }.GetNewClosure()

    Write-Activity "POST $($Action.Id) on $($requests.Count) devices"
    Start-Work -Operation 'Batch' -Label "$($Action.Label) on $($requests.Count) devices..." `
        -Requests $requests -OnComplete $onComplete | Out-Null
}

function Export-DeviceCsv {
    if ($script:Filtered.Count -eq 0) { return }
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Filter   = 'CSV file (*.csv)|*.csv'
    $dialog.FileName = "device-inventory-$([DateTime]::Now.ToString('yyyy-MM-dd')).csv"
    if (-not $dialog.ShowDialog()) { return }

    $keys = New-Object System.Collections.Generic.HashSet[string]
    foreach ($device in $script:Filtered) {
        foreach ($key in $device.Attributes.Keys) { [void]$keys.Add($key) }
    }
    $sortedKeys = @($keys | Sort-Object)

    $rows = foreach ($device in $script:Filtered) {
        $row = [ordered]@{
            DeviceName = $device.Name; User = $device.User; Platform = $device.Platform
            OsVersion  = $device.OsVersion; Compliance = $device.Compliance
            Serial     = $device.Serial; Model = $device.Model
            LastSync   = $(if ($device.LastSync) { $device.LastSync.ToString('u') } else { '' })
        }
        foreach ($key in $sortedKeys) {
            $row[$key] = $(if ($device.Attributes.ContainsKey($key)) { $device.Attributes[$key] } else { '' })
        }
        [pscustomobject]$row
    }
    $rows | Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
    Write-Activity "Exported $($script:Filtered.Count) devices to $($dialog.FileName)."
    Set-Status "Exported $($script:Filtered.Count) devices."
}

# ---------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------
foreach ($action in $DeviceActions) {
    $button = New-Object System.Windows.Controls.Button
    $button.Content = $action.Label
    $button.Tag     = $action
    $button.Add_Click({ param($sender, $eventArgs) Start-DeviceAction -Action $sender.Tag })
    [void]$ui.ActionButtons.Children.Add($button)
}

$ui.SearchBox.Add_TextChanged({ Update-DeviceList })
$ui.PlatformBox.Add_SelectionChanged({ Update-DeviceList })
$ui.ComplianceBox.Add_SelectionChanged({ Update-DeviceList })
$ui.DeviceGrid.Add_SelectionChanged({ Update-Panel })
$ui.RefreshButton.Add_Click({ Start-DeviceLoad })
$ui.ExportButton.Add_Click({ Export-DeviceCsv })
$ui.SaveButton.Add_Click({ Start-PropertySave })
$ui.RevertButton.Add_Click({
    $selected = @($ui.DeviceGrid.SelectedItems)
    if ($selected.Count -eq 1) { Reset-PropertyGrid -Device $selected[0] }
})
$ui.BulkApplyButton.Add_Click({ Start-BulkPropertySet })
$ui.BulkRemoveButton.Add_Click({ Start-BulkPropertyRemove })
$ui.SignOutButton.Add_Click({
    Remove-Item $TokenFile -Force -ErrorAction SilentlyContinue
    Show-Message 'Signed out. Device Inventory will close - start it again to sign in as someone else.'
    $window.Close()
})

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(250)
$timer.Add_Tick({
    if ($script:Jobs.Count -gt 0) {
        $job = $script:Jobs[0]
        if ($job.Progress.Total -gt 0) {
            Set-Status "$($job.Label)  $($job.Progress.Done) of $($job.Progress.Total)"
        } elseif ($job.Progress.Count -gt 0) {
            Set-Status "$($job.Label)  $($job.Progress.Count) so far"
        }
        Complete-Jobs
    }
})

$window.Add_Closed({
    $timer.Stop()
    foreach ($job in @($script:Jobs)) {
        try { $job.Shell.Dispose(); $job.Runspace.Dispose() } catch { }
    }
})

# ---------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------
try {
    if (-not (Invoke-SilentSignIn)) {
        try { Invoke-InteractiveSignIn }
        catch {
            Write-AppLog "Loopback sign-in failed, trying device code: $($_.Exception.Message)" 'WARN'
            Invoke-DeviceCodeSignIn
        }
    }
}
catch {
    Show-Message "Sign-in failed.`n`n$($_.Exception.Message)" 'Sign-in failed' 'Error'
    Write-AppLog "Sign-in failed: $($_.Exception.Message)" 'ERROR'
    return
}

$script:SlotNames = Get-SlotNames
Sync-ExtensionMap
$named = @($script:SlotNames.Values | Where-Object { $_ }).Count
if ($named -gt 0) { Write-Activity "$named of 15 extension attribute slots named." }

$ui.AccountText.Text = Get-SignedInUser
if ($App.UsingSharedClient) {
    Write-Activity 'Signed in through Microsoft Graph Command Line Tools (no dedicated app registration).'
}
Update-FilterChoices
Set-Status 'Signed in.'
$timer.Start()
Start-DeviceLoad

[void]$window.ShowDialog()
