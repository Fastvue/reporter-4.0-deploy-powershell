# ------------------------------------------------------------------------------
# Fastvue Reporter Installation Script
# Copyright © 2023 Fastvue Pty Ltd
# http://go.fastvue.co/?id=170
# ------------------------------------------------------------------------------

<#
.SYNOPSIS
Installs and configures instances of Fastvue Reporter.
.DESCRIPTION
This script is used to install, configure, and uninstall an instance of Fastvue Reporter either on the local machine or on a specified remote machine.

All configuration options can be specified either as parameters to the script, or via a prewritten configuration file using the same parameter names in 'Key=Value' format with one parameter per line, with the path to the configuration file specified using the -ConfigFile parameter. Any parameters specified directly to the script will override settings read from the configuration file if one is specified.

Fastvue Reporter is available for a number of different Firewall vendors, with a separate product per Firewall vendor. The required Fastvue Reporter product must be specified when running the script using the -Product parameter. For a list of available products, run the script with the -ListProducts switch.
.PARAMETER ConfigFile
Path to a configuration file that specifies settings for the installation and configuration of Fastvue Reporter.
.PARAMETER Mode
Mode to run the installation script in. Valid values are 'InstallAndConfigure', 'Install', 'Configure', and 'Uninstall'.
.PARAMETER ConfigTarget
Optional parameter to specify which parts of Fastvue Reporter will be configured, ignoring parts not specified here even if their configurations have been provided.

Specified as either an array or a comma-separated string, can be a combination of any of the following values;

- Auth
- DataRetention
- LDAP
- Mail
- Source
- Productivity
- License
- PublicUrl
- Proxy
- YouTube
.PARAMETER Product
Required. Name of the Fastvue Reporter product you want to install.
.PARAMETER ReleaseChannel
Release Channel to download Fastvue Reporter for. Valid values are 'Stable' and 'Latest'.
.PARAMETER ProductVersion
Version number of Fastvue Reporter product to install.
.PARAMETER InstallerBaseUrl
Alternate base URL to download installers from.
.PARAMETER ShowVars
Debug option to show all variables before proceeding with installation.
.PARAMETER ShowSystemInfo
Show the system information and exit the script without installing.
.PARAMETER Version
Show the script version number and exit the script without installing.
.PARAMETER ListProducts
List available Fastvue Reporter products that can be installed and exits the script without installing.
.PARAMETER ListProductVersions
List available versions of the selected Fastvue Reporter product and exits the script without installing.
.PARAMETER InvokedFromRemote
Flag provided to script automatically when executed on a remote system. Do not specify this parameter manually.
.PARAMETER Server
Remote system to run the installation script on. Requires WinRM enabled on the remote system.
.PARAMETER ServerPort
Remote port to connect to a WinRM session on.
.PARAMETER ServerCredential
Credential for authenticating to the remote system.
.PARAMETER ServerUsername
Username for authenticating to the remote system. Ignored if -ServerCredential is specified.
.PARAMETER ServerPassword
Password for authenticating to the remote system. Can be a plain-text string or a SecureString. Ignored if -ServerCredential is specified.
.PARAMETER TempPath
Temporary path to copy required files to when running the installation script on a remote system.
.PARAMETER InstallerExecutablePath
Path to installer executable. Specifying this will prevent automatic download of the required version.
.PARAMETER ApiCredential
Credential for authenticating to the Fastvue Reporter API.
.PARAMETER ApiUsername
Username for authenticating to the Fastvue Reporter API. Ignored if -ApiCredential is specified.
.PARAMETER ApiPassword
Password for authenticating to the Fastvue Reporter API. Can be a plain-text string or a SecureString. Ignored if -ApiCredential is specified.
.PARAMETER DataPath
Path to where Fastvue Reporter should store its data once installed.
.PARAMETER IISSite
Name of the IIS website to install Fastvue Reporter's web frontend to.
.PARAMETER IISVDir
IIS virtual directory or subpath to install Fastvue Reporter's web frontend to.
.PARAMETER FastvueReporterUrl
Optional. The full URL to the Fastvue Reporter interface. Used to target a specific existing instance or provide the expected URL to access Reporter in case the script cannot automatically determine the correct URL.
.PARAMETER IISAuth
Specifies that IIS Authentication should be configured by the script.
.PARAMETER IISAuthAllowUsers
Comma-separated list of usernames that have permission to access the Fastvue Reporter interface.
.PARAMETER IISAuthAllowRoles
Comma-separated list of roles or security groups that have permission to access the Fastvue Reporter interface.
.PARAMETER IISAuthSharedAllowUsers
Comma-separated list of usernames that have permission to access private shared reports.
.PARAMETER IISAuthSharedAllowRoles
Comma-separated list of roles or security groups that have permission to access private shared reports.
.PARAMETER SyslogSourceHost
Hostname or IP to receive Syslog messages from.
.PARAMETER SyslogSourcePort
Port to receive Syslog messages on.
.PARAMETER MailHost
Hostname or IP of SMTP server to use when sending mail.
.PARAMETER MailPort
Port of the SMTP server.
.PARAMETER MailSSL
Use secure communication with SMTP server.
.PARAMETER MailFrom
Email address to send mail from.
.PARAMETER MailCredential
Credential for authenticating to the SMTP server.
.PARAMETER MailUsername
Username for authenticating to the SMTP server. Ignored if -MailCredential is specified.
.PARAMETER MailPassword
Password for authenticating to the SMTP server. Can be a plain-text string or a SecureString. Ignored if -MailCredential is specified.
.PARAMETER LdapHost
Hostname or IP of LDAP server to import Organizational information from.
.PARAMETER LdapPort
Port of the LDAP server.
.PARAMETER LdapSSL
Use secure communication with LDAP server.
.PARAMETER LdapSearchDN
FQDN to search on the LDAP server.
.PARAMETER LdapCredential
Credential for authenticating to the LDAP server.
.PARAMETER LdapUsername
Username for authenticating to the LDAP server. Ignored if -LdapCredential is specified.
.PARAMETER LdapPassword
Password for authenticating to the LDAP server. Can be a plain-text string or a SecureString. Ignored if -LdapCredential is specified.
.PARAMETER RetentionEnabled
Specifies that the Data Retention policy should be enabled.
.PARAMETER RetentionDays
Number of days to retain imported data for.
.PARAMETER RetentionSize
Maximum size of imported data to retain.
.PARAMETER ProductivityUnacceptable
Array or comma-separated string of category names to mark as Unacceptable in Productivity ratings.
.PARAMETER ProductivityUnproductive
Array or comma-separated string of category names to mark as Unproductive in Productivity ratings.
.PARAMETER ProductivityAcceptable
Array or comma-separated string of category names to mark as Acceptable in Productivity ratings.
.PARAMETER ProductivityProductive
Array or comma-separated string of category names to mark as Productive in Productivity ratings.
.PARAMETER LicenseKey
Array or comma-separated string of License Keys to apply to the installed instance of Fastvue Reporter.
.PARAMETER LicenseKeyMode
How the specified license keys should be applied. Valid values are 'Replace' and 'Add';
	'Replace' - Replaces all keys in Fastvue Reporter with the keys specified, removing existing keys if they were not specified.
	'Add' - Adds the specified keys to Fastvue Reporter, leaving already existing keys in place.
.PARAMETER PublicUrl
Public URL that this Fastvue Reporter instance will be accessible via. Used when emailing reports and alerts to provide the recipient with a link back to the Fastvue Reporter interface.
.PARAMETER YouTubeApiKey
API key to use when performing lookups on YouTube videos.
.PARAMETER ProxyServer
Proxy server that Fastvue Reporter should use when connecting to external sites.
.PARAMETER ProxyPort
Port of the Proxy server.
.PARAMETER ProxyIgnoreCertErrors
Ignores any certificate errors that occur when connecting via the proxy server.
.PARAMETER ProxyCredential
Credential to authenticate to the Proxy server.
.PARAMETER ProxyUsername
Username to authenticate to the Proxy server. Ignored if -ProxyCredential is specified.
.PARAMETER ProxyPassword
Password to authenticate to the Proxy server. Can be a plain-text string or a SecureString. Ignored if -ProxyCredential is specified.
.PARAMETER ProxyAuthDomain
Authentication domain to be specified to the Proxy server.
.EXAMPLE
.NOTES
#>

param (
	[string]$Product = $null,
	[string]$ReleaseChannel = "Stable",
	[string]$ProductVersion = $null,

	[string]$ConfigFile = $null,
	[string]$Mode = "InstallAndConfigure",
	$ConfigTarget = $null,

	[string]$InstallerBaseUrl = $null,

	[Switch]$Version = $false,
	[Switch]$ShowVars = $false,
	[Switch]$ShowSystemInfo = $false,
	[Switch]$ListProducts = $false,
	[Switch]$ListProductVersions = $false,
	[Switch]$InvokedFromRemote = $false,

	[string]$Server = $null,
	[Int32]$ServerPort = 5985,
	[pscredential]$ServerCredential = $null,
	[string]$ServerUsername = $null,
	$ServerPassword = $null,

	[string]$TempPath = "C:\__Fastvue_Install",
	[string]$InstallerExecutablePath = $null,

	[pscredential]$ApiCredential = $null,
	[string]$ApiUsername = $null,
	$ApiPassword = $null,

	[string]$DataPath = $null,
	[string]$IISSite = "Default Web Site",
	[string]$IISVDir = $null,
	[string]$FastvueReporterUrl = $null,

	$IISAuth = $null,
	[string]$IISAuthAllowUsers = $null,
	[string]$IISAuthAllowRoles = $null,
	[string]$IISAuthSharedAllowUsers = $null,
	[string]$IISAuthSharedAllowRoles = $null,

	[string]$SyslogSourceHost = $null,
	[Int32]$SyslogSourcePort = 514,

	[string]$MailHost = $null,
	[Int32]$MailPort = 587,
	[boolean]$MailSSL = $true,
	[string]$MailFrom = $null,
	[pscredential]$MailCredential = $null,
	[string]$MailUsername = $null,
	$MailPassword = $null,

	[string]$LdapHost = $null,
	[Int32]$LdapPort = 389,
	[boolean]$LdapSSL = $false,
	[string]$LdapSearchDN = $null,
	[pscredential]$LdapCredential = $null,
	[string]$LdapUsername = $null,
	$LdapPassword = $null,

	[boolean]$RetentionEnabled = $true,
	[Int32]$RetentionDays = 30,
	[string]$RetentionSize = $null,

	$ProductivityUnacceptable = $null,
	$ProductivityUnproductive = $null,
	$ProductivityAcceptable = $null,
	$ProductivityProductive = $null,

	$LicenseKey = $null,
	[string]$LicenseKeyMode = "Replace",

	[string]$PublicUrl = $null,

	[string]$YouTubeApiKey = $null,

	[string]$ProxyServer = $null,
	[Int32]$ProxyPort = 8080,
	[boolean]$ProxyIgnoreCertErrors = $false,
	[pscredential]$ProxyCredential = $null,
	[string]$ProxyUsername = $null,
	$ProxyPassword = $null,
	[string]$ProxyAuthDomain = $null
)

Set-Variable -Option Constant FastvueReporterInstallScriptVersion "0.1.1"

if ($Version) {
	Write-Output $FastvueReporterInstallScriptVersion
	Exit 0
}

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------

function Split-String {
	param (
		$Value = $null
	)

	if (!$Value) {
		return @()
	}

	return [regex]::Split($Value, ',(?=(?:[^"]|"[^"]*")*$)') | ForEach-Object { $_.Trim('`"') }
}

function Resolve-Array {
	param (
		$Value = $null
	)

	if (!$Value) {
		return @()
	}

	if ($Value.GetType().Name -eq "ArrayList") {
		return $Value.ToArray()
	}

	if (!$Value.GetType().IsArray) {
		return Split-String $Value
	}

	return $Value
}

function Convert-Array-ToJSON {
	param (
		[Array]$Value = $null
	)

	if ($Value.Length -eq 0) {
		return "[]"
	}

	return '["{0}"]' -f ($Value -join '","')
}

function Resolve-Credential {
	param (
		[pscredential]$Provided = $null,
		[string]$Username = $null,
		$Password = $null,
		[boolean]$Ask = $false,
		[string]$AskMessage = "Enter credentials"
	)

	if ($Provided) {
		return $Provided
	} elseif ($Username -and $Password) {
		if ($Password.GetType().Name -eq "string") {
			$Password = ConvertTo-SecureString $Password -AsPlainText -Force
		}

		return New-Object System.Management.Automation.PSCredential($Username, $Password)
	} else {
		if ($Ask) {
			return Get-Credential -Message $AskMessage
		} else {
			return $null
		}
	}
}

function Open-Credential {
	param (
		[pscredential]$Credential = $null
	)

	if ($Credential) {
		return @{Username=$Credential.Username; Password=$Credential.GetNetworkCredential().password}
	} else {
		return @{Username=$null; Password=$null}
	}
}

if (!$Server -and $ShowSystemInfo) {
	$osname = (Get-WmiObject -class Win32_OperatingSystem).Caption
	Write-Host "Machine Name: $env:computername"
	Write-Host "Operating System: $osname"
	Exit 0
}

$ThisScriptPath = $MyInvocation.MyCommand.Definition

if ($ConfigFile) {
	if (-not(Test-Path $ConfigFile -PathType Leaf)) {
		Write-Error "Configuration file '$ConfigFile' could not be found"
		Exit 1
	}

	Get-Content $ConfigFile | Foreach-Object{
		if ($_.length -gt 0 -and !$_.StartsWith('#')) {
			$var = $_.Split('=', 2)

			$varName = $var[0]
			$varValue = $var[1]

			if (!$PSBoundParameters.ContainsKey($varName)) {
				if ($varName.Contains('Password')) {
					$secureValue = ConvertTo-SecureString $varValue -AsPlainText -Force
					Set-Variable -Name $varName -Value $secureValue
				} else {
					if ($varValue -eq 'true' -or $varValue -eq 'yes' -or $varValue -eq '1' -or $varValue -eq '$true') {
						Set-Variable -Name $varName -Value $true
					} elseif ($varValue -eq 'false' -or $varValue -eq 'no' -or $varValue -eq '0' -or $varValue -eq '$false') {
						Set-Variable -Name $varName -Value $false
					} else {
						Set-Variable -Name $varName -Value $varValue
					}
				}
			}
		}
	}
}

# ------------------------------------------------------------------------------
# Show variables before proceeding if ShowVars specified
# ------------------------------------------------------------------------------
if ($ShowVars) {
	Write-Host "--- Showing configured parameters for installation script --------------------"
	Get-Variable
	Read-Host -Prompt "Confirm vars and press enter to continue"
}

# ------------------------------------------------------------------------------
# Validate parameters for valid values, resolve parameters, and apply defaults where needed
# ------------------------------------------------------------------------------
$ValidModes = @("InstallAndConfigure", "Install", "Configure", "Uninstall")

if (!($ValidModes -contains $Mode)) {
	Write-Error "Invalid mode '$Mode' specified. Valid values are $('''{0}''' -f ($ValidModes -join ''','''))"
	Exit 1
}

$PerformConfig = $false
$PerformInstall = $false
$PerformUninstall = $false

if ($Mode -eq "InstallAndConfigure" -or $Mode -eq "Install") {
	$PerformInstall = $true
}

if ($Mode -eq "InstallAndConfigure" -or $Mode -eq "Configure") {
	$PerformConfig = $true
}

if ($Mode -eq "Uninstall") {
	$PerformUninstall = $true
}

$ValidConfigTargets = @("Auth", "DataRetention", "LDAP", "Mail", "Source", "Productivity", "License", "PublicUrl", "Proxy", "YouTube")

$ConfigTarget = Resolve-Array $ConfigTarget

if (!$ConfigTarget) {
	$ConfigTarget = $ValidConfigTargets.Clone()
}

foreach ($ConfigTargetItem in $ConfigTarget) {
	if (!($ValidConfigTargets -contains $ConfigTargetItem)) {
		Write-Error "Invalid ConfigTarget '$ConfigTargetItem'. Valid values are $('''{0}''' -f ($ValidConfigTargets -join ''','''))"
		Exit 1
	}
}

$ValidLicenseKeyModes = @("Replace", "Add")

if (!($ValidLicenseKeyModes -contains $LicenseKeyMode)) {
	Write-Error "Invalid license key mode '$LicenseKeyMode' specified. Valid values are $('''{0}''' -f ($ValidLicenseKeyModes -join ''','''))"
	Exit 1
}

if (!$Product -and $ListProducts -eq $false) {
	Write-Error "Fastvue Reporter product to install was not specified"
	Exit 1
}

if (!$InstallerBaseUrl) {
	$InstallerBaseUrl = "http://installs.fastvue.co/Fastvue/Reporter"
}

if ($ReleaseChannel -eq "Stable") {
	$ReleaseChannelSuffix = "stable"
} elseif ($ReleaseChannel -eq "Latest") {
	$ReleaseChannelSuffix = "latest"
} else {
	Write-Error "Invalid release channel '$ReleaseChannel' specified"
	Exit 1
}

# ------------------------------------------------------------------------------
# Download Fastvue Reporter product manifest and retrieve information for requested product and version.
# ------------------------------------------------------------------------------
$ReleaseManifest = [XML](Invoke-WebRequest -URI "$InstallerBaseUrl/Manifest.xml").Content

if (!$ReleaseManifest) {
	Write-Error "Failed to download release manifest. Exiting"
	Exit 1
}

$ReleaseManifestProduct = $ReleaseManifest.Manifest.Product | Where-Object { $_.ID -eq "Reporter" }

if ($ListProducts) {
	Write-Host "Available Products:"
	$ReleaseManifestProduct.Brand | ForEach-Object { Write-Host "- $($_.ID): $($_.Name)" }
	Exit 0
}

$ReleaseManifestBrand = $ReleaseManifestProduct.Brand | Where-Object { $_.ID -eq $Product }

if (!$ReleaseManifestBrand) {
	Write-Error "Unknown Product '$Product' specified"
	Exit 1
}

if ($ListProductVersions) {
	Write-Host "Available Versions for $($ReleaseManifestBrand.Name):"
	$ReleaseManifestBrand.Release | Sort-Object -Descending -Property "Version" | Select-Object "Version" | ForEach-Object { Write-Host "- $($_.Version)" }
	Exit 0
}

if ($ProductVersion) {
	$ReleaseManifestVersion = $ReleaseManifestBrand.Release | Where-Object { $_.Version -eq $ProductVersion }

	if (!$ReleaseManifestVersion) {
		Write-Error "Unable to find release information for software version $ProductVersion for product $Product"
		Exit 1
	}
} else {
	$ReleaseManifestVersion = $ReleaseManifestBrand.Release | Sort-Object -Descending -Property "Version" | Select-Object -First 1
}

if (!$ReleaseManifestVersion) {
	Write-Error "Unable to find release information for software for product $Product"
	Exit 1
}

$ProductName = $ReleaseManifestBrand.Name
$ProductSourceType = $ReleaseManifestBrand.Configuration.SourceType
$ProductInstallerUrlPath = $ReleaseManifestVersion.Path
$ProductVersion = $ReleaseManifestVersion.Version

$FastvueReporterInstallerDownloadUrl = "${InstallerBaseUrl}/${ProductInstallerUrlPath}_${ReleaseChannelSuffix}.exe".Replace(' ', '%20')

# ------------------------------------------------------------------------------
# Set up variables for configuring IIS
# ------------------------------------------------------------------------------
if (!$IISSite) {
	$IISSite = "Default Web Site"
}

if ($IISVDir -ne "") {
	$IISConfigLocation = "$IISSite/$IISVDir"
	$IISConfigPSPath = "IIS:\sites\$IISSite\$IISVDir"
	$IISConfigSharedPSPathP = "IIS:\sites\$IISSite\$IISVDir\p"
	$IISConfigSharedPSPathUnderscore = "IIS:\sites\$IISSite\$IISVDir\_"
} else {
	$IISConfigLocation = "$IISSite"
	$IISConfigPSPath = "IIS:\sites\$IISSite"
	$IISConfigSharedPSPathP = "IIS:\sites\$IISSite\p"
	$IISConfigSharedPSPathUnderscore = "IIS:\sites\$IISSite\_"
}

if (!$FastvueReporterUrl) {
	$FastvueReporterUrl = "http://localhost/$IISVDir"
}

# ------------------------------------------------------------------------------
# Download installer executable for specified product and version
# ------------------------------------------------------------------------------
if (!$InstallerExecutablePath -and $PerformInstall) {
	$InstallerExecutablePath = "$env:TEMP\FastvueReporterSetup_${Product}_${ReleaseChannelSuffix}.exe"
	
	Write-Host "- Downloading Installer"

	$PerformDownload = $true
	$UseExistingInstallerReason = ""

	if (Test-Path $InstallerExecutablePath -PathType Leaf) {
		$ExistingInstallerFile = Get-ChildItem $InstallerExecutablePath

		$ExistingInstallerAgeLimit = [datetime]::Now.AddDays(-1)

		if ($ExistingInstallerFile.LastWriteTime -gt $ExistingInstallerAgeLimit) {
			$PerformDownload = $false
			$UseExistingInstallerReason = "Downloaded $($ExistingInstallerFile.LastWriteTime)"
		}
	}

	if ($PerformDownload) {
		$oldProgressPreference = $ProgressPreference
		$ProgressPreference = 'SilentlyContinue'

		try {
			Invoke-WebRequest -Uri $FastvueReporterInstallerDownloadUrl -OutFile $InstallerExecutablePath
		} catch {
			Write-Error "Failed to download installer: $_"
			Exit 1
		}

		$ProgressPreference = $oldProgressPreference
	} else {
		Write-Host "- Using Existing Installer ($UseExistingInstallerReason)"
	}
}

if ($Server) {
	# ------------------------------------------------------------------------------
	# REMOTE MODE: Perform script operations on a remote system
	# ------------------------------------------------------------------------------
	if ($PerformUninstall) {
		Write-Host "- Uninstalling from remote server $Server"
	} elseif ($PerformInstall) {
		Write-Host "- Installing to remote server $Server"
	} else {
		Write-Host "- Configuring on remote server $Server"
	}

	$ServerCredential = Resolve-Credential -Provided $ServerCredential -Username $ServerUsername -Password $ServerPassword -Ask $true -AskMessage "Enter credentials for remote session on server '$Server'"

	if (!$ServerCredential) {
		Write-Error "No credentials provided"
		Exit 1
	}

	Write-Host "- Connecting to $Server"
	$RemoteSession = New-PSSession -Port $ServerPort -Credential $ServerCredential $Server
	
	if ($RemoteSession) {
		Write-Host "- Connected to $Server"
		
		Write-Host "- Copying files to remote session"
	
		Invoke-Command -Session $RemoteSession -ScriptBlock { 
			New-Item -Path $using:TempPath -type directory -Force | Out-Null
		}
	
		$RemoteParameters = [hashtable]$PSBoundParameters
		$RemoteParameters["Server"] = $null
		$RemoteParameters["InvokedFromRemote"] = $true

		Copy-Item -ToSession $RemoteSession $ThisScriptPath -Destination "$TempPath\FastvueReporterInstall.ps1" -ErrorAction Stop

		if ($PerformInstall) {
			Copy-Item -ToSession $RemoteSession $InstallerExecutablePath -Destination "$TempPath\FastvueReporterSetup.exe" -ErrorAction Stop
			$RemoteParameters["InstallerExecutablePath"] = "$TempPath\FastvueReporterSetup.exe"
		}

		if ($ConfigFile) {
			Copy-Item -ToSession $RemoteSession $ConfigFile -Destination "$TempPath\FastvueReporter.conf" -ErrorAction Stop
			$RemoteParameters["ConfigFile"] = "$TempPath\FastvueReporter.conf"
		}

		Write-Host "- Performing operations on remote session"
		$RemoteInvokeResult = Invoke-Command -Session $RemoteSession -ScriptBlock {
			& "$using:TempPath\FastvueReporterInstall.ps1" @using:RemoteParameters

			if (!$?) {
				Write-Error "Operation failed"
				Break
			}

			return @{MachineName=$env:computername}
		}

		if ($RemoteInvokeResult) {
			$ServerMachineName = $RemoteInvokeResult.MachineName
		}
	
		Write-Host "- Cleaning up"
		Invoke-Command -Session $RemoteSession -ScriptBlock { 
			Remove-Item -Recurse -Path $using:TempPath -Force 
		}
	
		Write-Host "- Closing remote session"
		Remove-PSSession -Session $RemoteSession
	} else {
		Write-Error "Could not connect to $Server"
	}
} else {
	# ------------------------------------------------------------------------------
	# LOCAL MODE: Perform script operations on local machine
	# ------------------------------------------------------------------------------

	# ------------------------------------------------------------------------------
	# Install Fastvue Reporter if script is in Install mode
	# ------------------------------------------------------------------------------
	if ($PerformInstall) {
		Write-Host "- Installing $ProductName"

		$InstallerArgs = "/silent /verysilent"

		if ($DataPath) {
			$InstallerArgs += " /datapath=`"$DataPath`""
		}

		if ($IISSite) {
			$InstallerArgs += " /iissite=`"$IISSite`""
		}

		if ($IISVDir) {
			$InstallerArgs += " /iisvdir=`"$IISVDir`""
		}

		Start-Process $InstallerExecutablePath -Wait -ArgumentList $InstallerArgs

		Write-Host "- $ProductName Installed!"
	}

	# ------------------------------------------------------------------------------
	# Uninstall Fastvue Reporter if script is in Uninstall mode
	# ------------------------------------------------------------------------------
	if ($PerformUninstall) {
		Write-Host "- Uninstalling $ProductName"

		$RegUninstall = Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
		$RegUninstallEntries = $RegUninstall.GetSubKeyNames()

		foreach ($UninstallEntry in $RegUninstallEntries) {
			$UninstallEntryDisplayName = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallEntry" -Name "DisplayName" -ErrorAction SilentlyContinue).DisplayName

			if ($UninstallEntryDisplayName -eq $ProductName) {
				$UninstallEntryCommand = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallEntry" -Name "UninstallString").UninstallString

				Start-Process $UninstallEntryCommand.Trim('`"') -Wait -ArgumentList "/silent"

				Write-Host "- Uninstallation complete"
				Exit 0
			}
		}

		Write-Warning "- Could not find uninstall entry for '$ProductName', possibly not currently installed. Exiting."
		Exit
	}

	# ------------------------------------------------------------------------------
	# Configure Fastvue Reporter if script is in Configure mode
	# ------------------------------------------------------------------------------
	if ($PerformConfig) {
		$ApiCredential = Resolve-Credential -Provided $ApiCredential -Username $ApiUsername -Password $ApiPassword

		# ------------------------------------------------------------------------------
		# Enable anonymous access in IIS if Auth should be configured but no API credentials have been specified
		# ------------------------------------------------------------------------------
		if ($null -ne $IISAuth -and $ConfigTarget -contains "Auth") {
			if (!$ApiCredential) {
				Write-Host "- Temporarily Enabling Anonymous Access For Configuration"
				Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value "true" -PSPath "IIS:\" -Location $IISConfigLocation
				
				Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigPSPath -name .
				Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigSharedPSPathP -name .
				Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigSharedPSPathUnderscore -name .

				Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="?"} -PSPath $IISConfigPSPath
				Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="?"} -PSPath $IISConfigSharedPSPathP
				Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="?"} -PSPath $IISConfigSharedPSPathUnderscore
			}
		}

		# ------------------------------------------------------------------------------
		# Verify that Fastvue Reporter is installed and its API is responding
		# ------------------------------------------------------------------------------
		Write-Host "- Checking Connection to $ProductName"

		$waitResponsiveStart = Get-Date
		$waitResponsiveDuration = 120
		$oldErrorActionPreference = $ErrorActionPreference
		$ErrorActionPreference = "SilentlyContinue"
		$serviceResponsive = False
		while (!$serviceResponsive) {
			$response = Invoke-RestMethod -Credential $ApiCredential -TimeoutSec 2 -Uri "$FastvueReporterUrl/_/api?f=Service.Status"
			$serviceResponsive = $?

			if ((New-TimeSpan -Start $waitResponsiveStart).TotalSeconds -gt $waitResponsiveDuration) {
				$ErrorActionPreference = $oldErrorActionPreference
				Write-Error "Unable to verify connection to $ProductName at '$FastvueReporterUrl' after $waitResponsiveDuration seconds. Please check the installation configuration and try again."
				Exit 1
			}
		}
		$ErrorActionPreference = $oldErrorActionPreference

		# ------------------------------------------------------------------------------
		# Begin configuration of Fastvue Reporter
		# ------------------------------------------------------------------------------
		Write-Host "- Configuring $ProductName"

		# ------------------------------------------------------------------------------
		# Configure Data Retention Policy
		# ------------------------------------------------------------------------------
		if ($RetentionEnabled -and $RetentionSize -and $ConfigTarget -contains "DataRetention") {
			Write-Host "- Configuring Data Retention Policy"
			$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.General.SetRetentionPolicy" -Method Post -ContentType "application/json" -Body @"
			{
				"Enabled": $RetentionEnabled,
				"Days": $RetentionDays,
				"Size": $RetentionSize
			}
"@

			if ($response.Status -ne 0) {
				Write-Error "Error configuring Data Retention Policy: ${response.Message}" 
			}
		}

		# ------------------------------------------------------------------------------
		# Configure LDAP
		# ------------------------------------------------------------------------------
		if ($LdapHost -and $ConfigTarget -contains "LDAP") {
			Write-Host "- Configuring LDAP Integration"

			$existingLdapSources = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.General.GetLdapSources"
			$ldapSourceID = $existingLdapSources.Data[0].ID

			$LdapCredential = Resolve-Credential -Provided $LdapCredential -Username $LdapUsername -Password $LdapPassword
			$LdapCredentialExtract = Open-Credential -Credential $LdapCredential

			$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.General.SetLdapSource" -Method Post -ContentType "application/json" -Body @"
			{
				"Source": {
					"Enabled": true,
					"ID": "$ldapSourceID",
					"Server": "$LdapHost",
					"Port": $LdapPort,
					"SSL": "$LdapSSL",
					"Roots": ["$LdapSearchDN"],
					"Username": "$($LdapCredentialExtract.Username)",
					"Password": "$($LdapCredentialExtract.Password)"
				}
			}
"@
		}

		# ------------------------------------------------------------------------------
		# Configure Email
		# ------------------------------------------------------------------------------
		if ($MailHost -and $ConfigTarget -contains "Mail") {
			Write-Host "- Configuring Email Settings"

			$MailCredential = Resolve-Credential -Provided $MailCredential -Username $MailUsername -Password $MailPassword
			$MailCredentialExtract = Open-Credential -Credential $MailCredential

			$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.General.SetMail" -Method Post -ContentType "application/json" -Body @"
			{
				"Enabled": true,
				"ID": "",
				"Server": "$MailHost",
				"Port": $MailPort,
				"Secure": "$MailSSL",
				"From": "$MailFrom",
				"Username": "$($MailCredentialExtract.Username)",
				"Password": "$($MailCredentialExtract.Password)"
			}
"@
		}

		# ------------------------------------------------------------------------------
		# Configure Syslog Source
		# ------------------------------------------------------------------------------
		if ($SyslogSourceHost -and $ConfigTarget -contains "Source") {
			Write-Host "- Configuring Syslog Source"

			$existingSources = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Sources.GetSources" -Method Get

			if (!($existingSources.Data | Where-Object { $_.SourceType -eq "$ProductSourceType" -and $_.SourceDescription -eq "${SyslogSourceHost}:${SyslogSourcePort}" })) {
				$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Sources.AddRoot" -Method Post -ContentType "application/json" -Body @"
				{
					"Type":"SonicWall",
					"Options": {
						"Host": "$SyslogSourceHost",
						"Port": $SyslogSourcePort,
						"HistoricalMode": "None"
					}
				}
"@
			}
		}

		# ------------------------------------------------------------------------------
		# Configure Productivity Ratings
		# ------------------------------------------------------------------------------
		if ($ProductivityUnacceptable -or $ProductivityUnproductive -or $ProductivityAcceptable -or $ProductivityProductive) {
			if ($ConfigTarget -contains "Productivity") {
				Write-Host "- Configuring Productivity Ratings"

				$ModifiedProductivityUnacceptable = $(Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Aliases.GetAliasEntryValues&Alias=Productivity&Entry=Unacceptable").Data
				$ModifiedProductivityUnproductive = $(Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Aliases.GetAliasEntryValues&Alias=Productivity&Entry=Unproductive").Data
				$ModifiedProductivityAcceptable = $(Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Aliases.GetAliasEntryValues&Alias=Productivity&Entry=Acceptable").Data
				$ModifiedProductivityProductive = $(Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Aliases.GetAliasEntryValues&Alias=Productivity&Entry=Productive").Data
				$ModifiedProductivityUnassigned = $(Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Aliases.GetAliasEntryValues&Alias=Productivity&Entry=Unassigned").Data

				$ProductivityUnacceptable = Resolve-Array $ProductivityUnacceptable
				$ProductivityUnproductive = Resolve-Array $ProductivityUnproductive
				$ProductivityAcceptable = Resolve-Array $ProductivityAcceptable
				$ProductivityProductive = Resolve-Array $ProductivityProductive

				function Merge-Productivity {
					param (
						[Array]$Target = $null,
						$Categories = $null
					)

					$Output = @()

					if ($Categories) {
						foreach ($Category in $Categories) {
							if ($ModifiedProductivityUnacceptable -contains $Category) {
								$script:ModifiedProductivityUnacceptable = $ModifiedProductivityUnacceptable | Where-Object { $_ -ne $Category }
							}

							if ($ModifiedProductivityUnproductive -contains $Category) {
								$script:ModifiedProductivityUnproductive = $ModifiedProductivityUnproductive | Where-Object { $_ -ne $Category }
							}

							if ($ModifiedProductivityAcceptable -contains $Category) {
								$script:ModifiedProductivityAcceptable = $ModifiedProductivityAcceptable | Where-Object { $_ -ne $Category }
							}

							if ($ModifiedProductivityProductive -contains $Category) {
								$script:ModifiedProductivityProductive = $ModifiedProductivityProductive | Where-Object { $_ -ne $Category }
							}

							if ($ModifiedProductivityUnassigned -contains $Category) {
								$script:ModifiedProductivityUnassigned = $ModifiedProductivityUnassigned | Where-Object { $_ -ne $Category }
							}

							if (!($Output -contains $Category)) {
								$Output += $Category
							}
						}
					}

					foreach ($TargetCategory in $Target) {
						if (!($Output -contains $TargetCategory)) {
							$Output += $TargetCategory
						}
					}

					return $Output
				}

				$ModifiedProductivityUnacceptable = Merge-Productivity -Target $ModifiedProductivityUnacceptable -Categories $ProductivityUnacceptable
				$ModifiedProductivityUnproductive = Merge-Productivity -Target $ModifiedProductivityUnproductive -Categories $ProductivityUnproductive
				$ModifiedProductivityAcceptable = Merge-Productivity -Target $ModifiedProductivityAcceptable -Categories $ProductivityAcceptable
				$ModifiedProductivityProductive = Merge-Productivity -Target $ModifiedProductivityProductive -Categories $ProductivityProductive

				$ModifiedProductivityUnacceptable = $ModifiedProductivityUnacceptable | Sort-Object
				$ModifiedProductivityUnproductive = $ModifiedProductivityUnproductive | Sort-Object
				$ModifiedProductivityAcceptable = $ModifiedProductivityAcceptable | Sort-Object
				$ModifiedProductivityProductive = $ModifiedProductivityProductive | Sort-Object

				$ProductivityUnacceptableJson = Convert-Array-ToJSON $ModifiedProductivityUnacceptable
				$ProductivityUnproductiveJson = Convert-Array-ToJSON $ModifiedProductivityUnproductive
				$ProductivityAcceptableJson = Convert-Array-ToJSON $ModifiedProductivityAcceptable
				$ProductivityProductiveJson = Convert-Array-ToJSON $ModifiedProductivityProductive
				$ProductivityUnassignedJson = Convert-Array-ToJSON $ModifiedProductivityUnassigned

				$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Aliases.SetAliasEntries" -Method Post -ContentType "application/json" -Body @"
				{
					"Alias":"Productivity",
					"Entries": [
						{ "Name": "Productive", "Values": $ProductivityProductiveJson },
						{ "Name": "Unproductive", "Values": $ProductivityUnproductiveJson },
						{ "Name": "Acceptable", "Values": $ProductivityAcceptableJson },
						{ "Name": "Unacceptable", "Values": $ProductivityUnacceptableJson },
						{ "Name": "Unassigned", "Values": $ProductivityUnassignedJson }
					]
				}
"@
			}
		}

		# ------------------------------------------------------------------------------
		# Configure Proxy
		# ------------------------------------------------------------------------------
		if ($ProxyServer -and $ConfigTarget -contains "Proxy") {
			Write-Host "- Configuring Proxy"
			
			$ProxyCredential = Resolve-Credential -Provided $ProxyCredential -Username $ProxyUsername -Password $ProxyPassword
			$ProxyCredentialExtract = Open-Credential -Credential $ProxyCredential

			if ($ProxyCredentialExtract.Username) {
				$ProxyAuthEnabled = $true
			} else {
				$ProxyAuthEnabled = $false
			}

			$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Proxy.SetProxySettings" -Method Post -ContentType "application/json" -Body @"
			{
				"ProxyEnabled": "True",
				"ProxyServer": "$ProxyServer",
				"ProxyPort": $ProxyPort,
				"ProxyIgnoreSSLErrors": "$ProxyIgnoreCertErrors",
				"ProxyAuthEnabled": "$ProxyAuthEnabled",
				"ProxyAuthUsername": "$($ProxyCredentialExtract.Username)",
				"ProxyAuthPassword": "$($ProxyCredentialExtract.Password)",
				"ProxyAuthDomain": "$ProxyAuthDomain"
			}
"@
		}

		# ------------------------------------------------------------------------------
		# Configure License Keys
		# ------------------------------------------------------------------------------
		if ($LicenseKey -and $ConfigTarget -contains "License") {
			Write-Host "- Configuring License"

			$Keys = Resolve-Array $LicenseKey
			$SetKeys = @()

			if ($LicenseKeyMode -eq "Add") {
				$ExistingKeys = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Licensing.GetLicenseKeys" -Method Get
				$SetKeys = [array]($ExistingKeys.Data | Where-Object { $_.Key -ne "" } | ForEach-Object { $_.Key })
			}

			foreach ($key in $Keys) {
				if (!($SetKeys | Where-Object { $_ -eq $key })) {
					$SetKeys += $key
				}
			}

			if ($SetKeys.Length -gt 0) {
				$SetKeysJson = '"{0}"' -f ($SetKeys -join '","')

				$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Licensing.SetLicenseKeys" -Method Post -ContentType "application/json" -Body @"
				{
					"Keys": [$SetKeysJson]
				}
"@

				$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Licensing.ProcessPendingRequests" -Method Post -ContentType "application/json" -Body "{}"
			}
		}

		# ------------------------------------------------------------------------------
		# Configure Public URL
		# ------------------------------------------------------------------------------
		if ($PublicUrl -and $ConfigTarget -contains "PublicUrl") {
			Write-Host "- Configuring Public URL"

			$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.General.SetPublicInterfaceUrl" -Method Post -ContentType "application/json" -Body @"
			{
				"Url": "$PublicUrl"
			}
"@
		}

		# ------------------------------------------------------------------------------
		# Configure YouTube Integration
		# ------------------------------------------------------------------------------
		if ($YouTubeApiKey -and $ConfigTarget -contains "YouTube") {
			Write-Host "- Configuring YouTube Integration"
			
			$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Integrations.Youtube.SetYoutubeSettings" -Method Post -ContentType "application/json" -Body @"
			{
				"apiKey": "$YouTubeApiKey"
			}
"@
			
			$response = Invoke-RestMethod -Credential $ApiCredential -Uri "$FastvueReporterUrl/_/api?f=Settings.Integrations.Youtube.TestSavedYoutubeSettings" -Method Post -ContentType "application/json" -Body "{}"

			if (!$response.Data.Success) {
				Write-Warning "YouTube Integration Configuration Error: $($response.Data.Message)"
			}
		}

		# ------------------------------------------------------------------------------
		# Configure IIS Authentication
		# ------------------------------------------------------------------------------
		if (Get-Variable -Name IISAuth -ErrorAction SilentlyContinue) {
			if ($null -ne $IISAuth) {
				if ($ConfigTarget -contains "Auth") {
					Write-Host "- Configuring Web Server Authentication"

					if ($IISAuth) {
						Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value "false" -PSPath "IIS:\" -Location $IISConfigLocation
						Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value "true" -PSPath "IIS:\" -Location $IISConfigLocation

						Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigPSPath -name .
						Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigSharedPSPathP -name .
						Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigSharedPSPathUnderscore -name .

						if ($IISAuthAllowUsers) {
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="$IISAuthAllowUsers"} -PSPath $IISConfigPSPath
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="$IISAuthAllowUsers"} -PSPath $IISConfigSharedPSPathP
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="$IISAuthAllowUsers"} -PSPath $IISConfigSharedPSPathUnderscore
						}

						if ($IISAuthAllowRoles) {
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; roles="$IISAuthAllowRoles"} -PSPath $IISConfigPSPath
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; roles="$IISAuthAllowRoles"} -PSPath $IISConfigSharedPSPathP
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; roles="$IISAuthAllowRoles"} -PSPath $IISConfigSharedPSPathUnderscore
						}

						if ($IISAuthSharedAllowUsers) {
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="$IISAuthSharedAllowUsers"} -PSPath $IISConfigSharedPSPathP
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="$IISAuthSharedAllowUsers"} -PSPath $IISConfigSharedPSPathUnderscore
						}

						if ($IISAuthSharedAllowRoles) {
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; roles="$IISAuthSharedAllowRoles"} -PSPath $IISConfigSharedPSPathP
							Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; roles="$IISAuthSharedAllowRoles"} -PSPath $IISConfigSharedPSPathUnderscore
						}

						Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Deny"; users="?"} -PSPath $IISConfigPSPath
					} else {
						Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value "true" -PSPath "IIS:\" -Location $IISConfigLocation
						Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value "false" -PSPath "IIS:\" -Location $IISConfigLocation

						Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigPSPath -name .
						Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigSharedPSPathP -name .
						Remove-WebConfigurationProperty -Filter "system.webServer/security/authorization" -PSPath $IISConfigSharedPSPathUnderscore -name .

						Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="?"} -PSPath $IISConfigPSPath
						Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="?"} -PSPath $IISConfigSharedPSPathP
						Add-WebConfiguration -Filter "system.webServer/security/authorization" -Value @{accessType="Allow"; users="?"} -PSPath $IISConfigSharedPSPathUnderscore
					}
				}
			}
		}

		# ------------------------------------------------------------------------------
		Write-Host "- $ProductName Configuration Completed!"
	}
}

# ------------------------------------------------------------------------------
# Verify connectivity to Fastvue Reporter and display URLs where it can be accessed
# ------------------------------------------------------------------------------
if (!$InvokedFromRemote -and !$PerformUninstall -and !($PSBoundParameters.ContainsKey('FastvueReporterUrl'))) {
	$ApiCredential = Resolve-Credential -Provided $ApiCredential -Username $ApiUsername -Password $ApiPassword

	$ExpectedAccessUrls = @()

	if ($Server) {
		$ExpectedAccessUrls += "http://$server/$IISVDir"
	} else {
		$ExpectedAccessUrls += "http://localhost/$IISVDir"
		$ExpectedAccessUrls += "http://$($env:computername)/$IISVDir"

		$networks = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.AddressState -eq "Preferred"}
		foreach ($network in $networks) {
			$ipaddress = $networks[0].IPAddress
			$ExpectedAccessUrls += "http://$ipaddress/$IISVDir"
		}
	}

	if ($ServerMachineName) {
		$ExpectedAccessUrls += "http://$ServerMachineName/$IISVDir"
	}

	if ($PublicUrl) {
		$ExpectedAccessUrls += $PublicUrl
	}

	$ExpectedAccessUrls = $ExpectedAccessUrls | Select-Object -Unique

	$VerifiedAccessUrls = @()
	$UnverifiedAccessUrls = @()

	foreach ($AccessUrl in $ExpectedAccessUrls) {
		$oldErrorActionPreference = $ErrorActionPreference
		$ErrorActionPreference = "SilentlyContinue"
		$response = Invoke-RestMethod -Credential $ApiCredential -TimeoutSec 3 -Uri "$AccessUrl/_/api?f=Service.Status"

		if (!$?) {
			$UnverifiedAccessUrls += $AccessUrl
		} else {
			$VerifiedAccessUrls += $AccessUrl
		}

		$ErrorActionPreference = $oldErrorActionPreference
	}

	if ($UnverifiedAccessUrls) {
		Write-Host ""
		Write-Host -ForegroundColor Yellow "  $ProductName may be accessible at the following URLs, but access could not be verified;"

		foreach ($url in $UnverifiedAccessUrls) {
			Write-Host "  - $url"
		}
	}

	if ($VerifiedAccessUrls) {
		Write-Host ""
		Write-Host -ForegroundColor Cyan "  $ProductName can be accessed at the following URLs;"

		foreach ($url in $VerifiedAccessUrls) {
			Write-Host "  - $url"
		}
	}

	Write-Host ""
}

# ------------------------------------------------------------------------------
# End of script
# ------------------------------------------------------------------------------
