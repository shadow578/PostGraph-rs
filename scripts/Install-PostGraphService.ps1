param()

$Repo = "shadow578/PostGraph-rs"
$Asset = "postgraph.exe"

$InstallDir = "C:\Program Files\PostGraph"
$ServiceName = "postgraph"
$ServiceDisplayName = "PostGraph Mail Proxy"
$ServiceDescription = "Receives SMTP messages and forwards them to Microsoft Graph API for delivery."

$MetaUri = "https://api.github.com/repos/$Repo/releases/latest"
$DownloadUri = "https://github.com/$Repo/releases/latest/download/$Asset"
$ExePath = Join-Path -Path $InstallDir -ChildPath $Asset
$ConfigFile = Join-Path -Path $InstallDir -ChildPath "config.yaml"

function Write-Banner() {
  Write-Host "======================================" -ForegroundColor Cyan
  Write-Host "  PostGraph Proxy Service Installer  " -ForegroundColor Cyan
  Write-Host "======================================" -ForegroundColor Cyan
}

function Test-AdminPermission() {
  $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function DownloadServiceExecutable() {
  # fetch metadata about latest release
  $meta = Invoke-RestMethod -Uri $MetaUri
  $releaseName = $meta.name
  $releaseTag = $meta.tag_name
  $releaseDate = $meta.published_at

  # find digest of the release asset.
  $asset = $meta.assets | Where-Object { $_.name -eq $Asset } | Select-Object -First 1
  $exeSize = $asset.size
  $exeDigest = $asset.digest

  # validate then remove sha256: prefix to get raw hash for comparison.
  if (-not $exeDigest.StartsWith('sha256:')) {
    Write-Host "Release digest is not sha256. Aborting installation, as verification would not be possible." -ForegroundColor Red
    exit 1
  }
  $exeDigest = $exeDigest -replace 'sha256:', ''

  Write-Host "Installing PostGraph version $releaseName ($releaseTag) released on $releaseDate..." -ForegroundColor Green
  if ((Read-Host "Do you want to continue? (y/N)") -ine 'y') {
    Write-Host "Installation aborted." -ForegroundColor Yellow
    exit 1
  }
  Write-Host ""

  # create sub-dirs as needed
  if (-not (Test-Path -Path $InstallDir)) {
    Write-Host "Creating installation directory at $InstallDir..." -ForegroundColor Green
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  }

  # delete existing executable if it exists
  if (Test-Path -Path $ExePath) {
    Write-Host "Removing existing executable at $ExePath..." -ForegroundColor Green
    Remove-Item -Path $ExePath -Force
  }

  # download the latest release
  Write-Host "Downloading PostGraph service from $DownloadUri..." -ForegroundColor Green
  Invoke-WebRequest -Uri $DownloadUri -OutFile $ExePath -UseBasicParsing

  # validate size and digest match
  Write-Host "Validating downloaded file..." -ForegroundColor Green
  $ok = $true
  if ((Get-Item -Path $ExePath).length -eq $exeSize) {
    Write-Host " Downloaded file size matches expected size ($exeSize bytes)." -ForegroundColor Green
  }
  else {
    Write-Host " Downloaded file size does not match expected size." -ForegroundColor Red
    $ok = $false
  }
  if ($ok -and (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash -eq $exeDigest) {
    Write-Host " Downloaded file hash matches expected value (SHA256:$exeDigest)." -ForegroundColor Green
  }
  else {
    Write-Host " Downloaded file hash does not match expected value." -ForegroundColor Red
    $ok = $false
  }
  if (-not $ok) {
    Write-Host "Failed to validate downloaded executable. Aborting installation." -ForegroundColor Red
    Remove-Item -Path $ExePath -Force
    exit 1
  }
}

function Test-ProxyServiceExists() {
  return $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
}

function Stop-ProxyService() {
  if (Test-ProxyServiceExists) {
    Write-Host "Stopping existing PostGraph service..." -ForegroundColor Green
    Stop-Service -Name $ServiceName -Force | Out-Null
  }
}

function Update-ProxyService() {
  if (Test-ProxyServiceExists) {
    Write-Host "Restarting PostGraph service..." -ForegroundColor Green
    Restart-Service -Name $ServiceName | Out-Null
  }
  else {
    Write-Host "Installing PostGraph service..." -ForegroundColor Green

    # use LocalService for least privilege.
    # password is required but not used.
    $cred = (New-Object System.Management.Automation.PSCredential("NT AUTHORITY\LocalService", (ConvertTo-SecureString "x" -AsPlainText -Force)))

    New-Service -Name $ServiceName `
      -DisplayName $ServiceDisplayName `
      -Description $ServiceDescription `
      -BinaryPathName "`"$ExePath`" --config `"$ConfigFile`" run --service" `
      -Credential $cred `
      -StartupType Automatic `
      -ErrorAction Stop | Out-Null

    if (-not (Test-ProxyServiceExists)) {
      Write-Host "Failed to install PostGraph service." -ForegroundColor Red
      exit 1
    }
  }
}

function Add-FirewallRule() {
  Write-Host "Do you wish to add a firewall rule to allow incoming connections on port 25?" -ForegroundColor Green
  if ((Read-Host "Do you want to continue? (y/N)") -ine 'y') {
    return
  }
  Write-Host ""

  New-NetFirewallRule -DisplayName "Allow $ServiceDisplayName" -Direction Inbound -Protocol TCP -LocalPort 25 -Program $ExePath -Action Allow
}

function Set-ConfigFilePermissions() {
  $acl = Get-Acl -Path $ConfigFile

  # disable inheritance
  $acl.SetAccessRuleProtection($true, $false)

  # remove any existing rules
  $acl.Access | ForEach-Object {
    $acl.RemoveAccessRule($_)
  }

  # LocalService only needs read access
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\LocalService", "Read", "Allow")
  $acl.AddAccessRule($rule)

  # Administrators group needs full control for configuration
  $admin = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544").Translate(
    [System.Security.Principal.NTAccount]
  )

  $acl.SetOwner($admin)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admin, "FullControl", "Allow")
  $acl.AddAccessRule($rule)

  Write-Host "Setting permissions on configuration file at $ConfigFile..." -ForegroundColor Green
  Set-Acl -Path $ConfigFile -AclObject $acl
}

function Main() {
  Write-Banner

  if (-not (Test-AdminPermission)) {
    Write-Host "This script must be run as an administrator. Please run it with elevated privileges." -ForegroundColor Red
    exit 1
  }

  # stop the service if it exists
  Stop-ProxyService

  # download and verfiy the latest release
  DownloadServiceExecutable

  # create config file if it doesn't exist yet
  if (-not (Test-Path -Path $ConfigFile)) {
    Write-Host "Creating default configuration file at $ConfigFile..." -ForegroundColor Green
    & $ExePath --config "$ConfigFile" config reset
  }

  # register event log source
  Write-Host "Registering PostGraph event log source..." -ForegroundColor Green
  & $ExePath --config "$ConfigFile" register-eventlog

  # setup config acl
  Set-ConfigFilePermissions

  # install the service if it doesn't exist
  # restart if it does exist
  Update-ProxyService

  # prompt to setup firewall rule
  Add-FirewallRule

  # done
  Write-Host ""
  Write-Host "PostGraph service installation complete." -ForegroundColor Green
  Write-Host "You must now configure the service before it can be used." -ForegroundColor Yellow
  Write-Host "To manage configuration, use the configuration cli using this command:" -ForegroundColor Yellow
  Write-Host "  `"$ExePath`" --config `"$ConfigFile`" config (...)" -ForegroundColor Yellow 
  Write-Host "After configuration changes, restart the service using:" -ForegroundColor Yellow
  Write-Host "  Restart-Service -Name `"$ServiceName`"" -ForegroundColor Yellow
  Write-Host "You may run this command again at any time to update the service to the latest release." -ForegroundColor Yellow

  # cd to install dir so user can run cli directly.
  Set-Location -Path $InstallDir
}
Main
