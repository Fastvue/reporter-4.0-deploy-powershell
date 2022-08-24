# Fastvue Reporter 4.0 Installation Script (PowerShell)

# Introduction

Fastvue Reporter 4.0 can be installed and configured as part of an automated deployment using a PowerShell-based installation script, **FastvueReporterInstall.ps1**.

All configuration options can be specified either as parameters to the script, or via a prewritten configuration file using the same parameter names in `Key=Value` format with one parameter per line, with the path to the configuration file specified using the `-ConfigFile` parameter. Any parameters specified directly to the script will override settings read from the configuration file if one is specified.

The only required option is `-Product` which specifies which Fastvue Reporter product to install. The list of available products to install can be shown by invoking the script with the `-ListProducts` parameter;

```powershell
PS> .\FastvueReporterInstall.ps1 -ListProducts
Available Products:
- Sophos: Fastvue Sophos Reporter
- SophosWsa: Fastvue Sophos Reporter for Web Appliance
- SonicWall: Fastvue Reporter for SonicWall
- ContentKeeper: Fastvue Reporter for ContentKeeper
- Barracuda: Fastvue Reporter for Barracuda
- FortiGate: Fastvue Reporter for FortiGate
- PaloAlto: Fastvue Reporter for Palo Alto
- CiscoFirepower: Fastvue Reporter for Cisco Firepower
```

For example, to install Fastvue Reporter for SonicWall using all default settings with no configuration to be applied to the Fastvue Reporter instance, you would run the script with the parameters `-Product SonicWall`

The script will automatically download and install the appropriate version of Fastvue Reporter.

# Parameter Types

The installation script has several parameters that expect a specific type of input or can accept multiple different types of input. See the [Parameter Reference](https://www.notion.so/Fastvue-Reporter-4-0-Installation-Script-PowerShell-913f8ec260d243fc8c368efca63e1f39) below for a list of the expected types for each parameter. This section details how to pass data to each of the types of parameters.

## Arrays

Parameters that accept an array can optionally take an array or a comma-separated string. When using a configuration file, only a comma-separated string is usable.

Arrays can be written in a PowerShell terminal or script using the `@(...)` syntax;

```powershell
PS> $MyArray = @("Item A", "Item, B", "Item C")
  OR
PS> .\FastvueReporterInstall.ps1 -ProductivityUnproductive @("News and Media", "Job Search")
```

Alternatively comma-separated strings can be used instead, and are required if using a configuration file. If a comma is required within a value, the value can be double-quote qualified;

```powershell
PS> $MyArray = 'Item A,"Item, B",Item C'
  OR
PS> .\FastvueReporterInstall.ps1 -ProductivityUnproductive "News and Media,Job Search"
```

## Booleans

Boolean parameters must be provided with either of the PowerShell Boolean constants, `$true` or `$false`.

When using a configuration file, Boolean parameters can be specified using one of the following values; `True`, `False`, `Yes`, `No`, `1`, `0`, `$true`, `$false`.

## Credentials

Credentials are provided via either a `-*Credential` parameter or a pair of `-*Username` and `-*Password` parameters, where the `*` is the system the credentials are being provided for.

When using a `-*Credential` parameter, a `PSCredential` type object is required. These can be created using the `Get-Credential` command, which opens a dialog to prompt for a username and password;

```powershell
PS> $MyCredential = Get-Credential
PS> .\FastvueReporterInstall.ps1 -ServerCredential $MyCredential
```

Alternatively, you can provide a Username and Password to the script. The Password can be provided either as a `SecureString` instance;

```powershell
PS> $MyUsername = Read-Host -Prompt "Enter username"
PS> $MyPassword = Read-Host -AsSecureString -Prompt "Enter password"
PS> .\FastvueReporterInstall.ps1 -ServerUsername $MyUsername -ServerPassword $MyPassword
```

Or as a plain text string;

```powershell
PS> .\FastvueReporterInstall.ps1 -ServerUsername "Administrator" -ServerPassword "P4ssW0rd!"
```

# Installing Fastvue Reporter

## Install on Local Server

To install Fastvue Reporter on the local server, run the script with the parameter `-Product` set to the Fastvue Reporter product you want to install. In this example, Fastvue Reporter for SonicWall is installed;

```powershell
PS> .\FastvueReporterInstall.ps1 -Product SonicWall
- Downloading Installer
- Installing Fastvue Reporter for SonicWall
- Fastvue Reporter for SonicWall Installed!
- Checking Connection to Fastvue Reporter for SonicWall
- Configuring Fastvue Reporter for SonicWall
- Configuring Web Server Authentication
- Fastvue Reporter for SonicWall Configuration Completed!

  Fastvue Reporter for SonicWall can be accessed at the following URLs;
  - http://localhost/
  - http://WIN-FV9DE04DMKT/
  - http://192.168.100.191/
```

## Install on Remote Server

The script can be used to install Fastvue Reporter on a remote Windows Server using the `-Server` parameter. This requires WinRM to be enabled and accessible on the remote server.

```powershell
PS> .\FastvueReporterInstall.ps1 -Product SonicWall -Server 192.168.100.191
- Downloading Installer
- Installing to remote server 192.168.100.191
- Connecting to 192.168.100.191
- Connected to 192.168.100.191
- Copying files to remote session
- Performing operations on remote session
- Installing Fastvue Reporter for SonicWall
- Fastvue Reporter for SonicWall Installed!
- Checking Connection to Fastvue Reporter for SonicWall
- Configuring Fastvue Reporter for SonicWall
- Configuring Web Server Authentication
- Fastvue Reporter for SonicWall Configuration Completed!
- Cleaning up
- Closing remote session

  Fastvue Reporter for SonicWall can be accessed at the following URLs;
  - http://192.168.100.191/
  - http://WIN-FV9DE04DMKT/
```

### Providing Credentials to Remote Server

Without specifying the credentials for the server as parameters, you will be prompted for the credentials when the script connects to the server. To provide the credentials to the script, you can use the `-ServerCredential` parameter by passing a credential object. A credential object can be created by invoking the PowerShell command `Get-Credential`, which will open a dialog and prompt for credentials to be entered, and storing the result in a variable.

```powershell
PS> $MyServerCredential = Get-Credential
cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential

PS> .\FastvueReporterInstall.ps1 -Product SonicWall -Server 192.168.100.191 -ServerCredential $MyServerCredential
- Downloading Installer
- Installing to remote server 192.168.100.191
...
```

Alternatively you can pass a username and password directly to the script using the `-ServerUsername` and `-ServerPassword` parameters. The `-ServerPassword` parameter supports both `SecureString` and `String` instances, so passwords can be passed to the script securely;

```powershell
PS> $MyUsername = Read-Host -Prompt "Enter username"
PS> $MyPassword = Read-Host -AsSecureString -Prompt "Enter password"
PS> .\FastvueReporterInstall.ps1 -Product SonicWall -Server 192.168.100.191 -ServerUsername $MyUsername -ServerPassword $MyPassword
- Downloading Installer
- Installing to remote server 192.168.100.191
...
```

Or if you want to simply provide the credentials directly to the script insecurely, you can use plain strings;

```powershell
PS> .\FastvueReporterInstall.ps1 -Product SonicWall -Server 192.168.100.191 -ServerUsername "Administrator" -ServerPassword "P4ssW0rd!"
- Downloading Installer
- Installing to remote server 192.168.100.191
...
```

When running the installation script with a lot of parameters, it may be more manageable to split the command over multiple lines so that the command can be prepared in another application like Notepad before entering it into a terminal or used in an easily maintainable way in another PowerShell script. PowerShell allows you to do this by using a backquote ``` (typically found at the top left of the keyboard above Tab) at the end of each line except the last one. For example, the above example command split over multiple lines;

```powershell
PS> .\FastvueReporterInstall.ps1 `
  -Product SonicWall `
  -Server 192.168.100.191 `
  -ServerUsername "Administrator" `
  -ServerPassword "P4ssW0rd!"

- Downloading Installer
- Installing to remote server 192.168.100.191
```

## Changing Installation Paths

The installer for Fastvue Reporter configures the location where the software will store its data, and also the website and subpath in IIS that the software’s interface will be hosted on. These options can be set with the installation script. The `-DataPath` parameter controls the location where Fastvue Reporter will store its data, and the `-IISSite` and `-IISVDir` parameters control the website and subpath that the interface is hosted on. These parameters are optional and have default values if left unspecified.

The `-IISSite` parameter is the display name of the website to install the interface to, and defaults to “Default Web Site”, which is automatically created in a new IIS installation.

For example, this command will install Fastvue Reporter for SonicWall and set it to store its data in “*C:\Fastvue Data”* and install the interface to the subpath *“fastvue”* in the default web site in IIS;

```powershell
PS> .\FastvueReporterInstall.ps1 `
  -Product SonicWall `
  -DataPath "C:\Fastvue Data" `
  -IISVDir "fastvue"
```

# Using a Configuration File

The parameters for the installation script can be optionally provided from a configuration file that has been prepared ahead of time instead of via parameters directly to the script. In addition to using a configuration file, parameters can still be passed directly to the script, and any parameters that are passed directly to the script take precedence over parameters from a configuration file. This allows usage of a configuration file as a template for a Fastvue Reporter installation while allowing some parameters in the template to be overridden when the script is run to perform a particular installation or configuration.

The configuration file is written in the form of `Key=Value` with one key/value pair per line. The keys in the configuration file have the same name as the script parameters. For example, the following configuration file will install *Fastvue Reporter for SonicWall* to the remote server *192.168.100.191* using the provided credentials to log in to the server;

***ReporterInstall.conf***

```jsx
Firewall=SonicWall
Server=192.168.100.191
ServerUsername=Administrator
ServerPassword=P4ssW0rd!
```

Then the configuration file can be used with the script using the `-ConfigFile` parameter;

```powershell
PS> .\FastvueReporterInstall.ps1 -ConfigFile ReporterInstall.conf
```

If you want to use the same configuration file but install on a different remote server, you can pass the configuration file and the `-Server` parameter to the script, and the parameter passed directly to the script will take precedence over the same parameter in the configuration file. For example, the following command will use the above configuration file, but will instead install to the remote server *192.168.100.192*;

```powershell
PS> .\FastvueReporterInstall.ps1 -ConfigFile ReporterInstall.conf -Server 192.168.100.192
```

Because the configuration file is text-only this limits how some parameters can be passed, in particular credentials and any parameter that accepts an Array. The PSCredential type parameters cannot be specified in the configuration file, instead a Username and Password must be provided, and Password parameters must be provided in plain text. Most parameters that accept an Array will also accept a comma-separated string, so for these parameters a comma-separated string must be used in the configuration file. Values in the comma-separated string can be double-quote qualified (e.g. The input string `"Item A","Item, B","Item C"` will result in three items; `Item A`, `Item, B`, and `Item C`).

Boolean type parameters can be specified in the configuration file using the values `True` or `False`, `Yes` or `No`, `1` or `0`, and `$true` or `$false`.

# Configuring Fastvue Reporter

In addition to installing Fastvue Reporter, the script can configure various elements of the installed Fastvue Reporter instance. Each of these elements will be automatically configured if their parameters are provided to the script or present in the configuration file (except where restricted by the `-ConfigTarget` parameter, if specified).

All of the following configuration elements can be combined into a single command, so all elements are able to be configured together with a single run of the installation script.

## Configuring Authentication

Authentication is configured in the IIS Web Server with different access granted to the main Fastvue Reporter interface and the private report sharing paths. See [https://kb.fastvue.co/sonicwall/s/article/How-do-I-secure-the-Fastvue-Reporter-interface-with-login-credentials](https://kb.fastvue.co/sonicwall/s/article/How-do-I-secure-the-Fastvue-Reporter-interface-with-login-credentials) for more information about how the Private Report Sharing feature works with authentication.

Authentication will be configured if the `-IISAuth` parameter is specified as `$true`. The users and/or roles that will be granted full permission to Fastvue Reporter are specified using the parameters `-IISAuthAllowUsers` and `-IISAuthAllowRoles`, and the users and/or roles that will be granted permission to access private shared reports are specified using the parameters `-IISAuthSharedAllowUsers` and `-IISAuthSharedAllowRoles`.

The users and roles must be specified as comma-separated strings if multiple users or roles are being granted permission.

To configure authentication granting full access to the *“Fastvue Admins”* security group and private shared report access to the *“Fastvue Viewers”* security group;

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -IISAuth $true `
  -IISAuthAllowRoles "Fastvue Admins" `
  -IISAuthSharedAllowRoles "Fastvue Viewers"
```

To configure authentication granting full access to the users *“Alice”* and *“Bob”*.

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -IISAuth $true `
  -IISAuthAllowUsers "Alice,Bob"
```

To disable authentication and permit anonymous access to the Fastvue Reporter interface.

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -IISAuth $false
```

## Configuring Syslog Source

A source of Syslog data can be configured by the script using the `-SyslogSourceHost` and `-SyslogSourcePort` parameters. Configuration will be performed if the `-SyslogSourceHost` parameter is specified, with the `-SyslogSourcePort` being optional and defaulting to 514.

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -SyslogSourceHost 10.0.0.1 `
  -SyslogSourcePort 514
```

## Configuring Email

Fastvue Reporter has the ability to send email via SMTP to deliver reports, alerts, and other system status updates. This requires an email server to be configured and this is done using `-Mail*` parameters.

Email configuration will be applied if the `-MailHost` parameter is specified.

Credentials for the mail server can be provided either as a PSCredential object via the `-MailCredential` parameter, or as a username and password through the `-MailUsername` and `-MailPassword` parameters.

Example Email configuration;

```powershell
PS> $MyEmailCredential = Get-Credential
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -MailHost mail.example.com `
  -MailPort 587 `
  -MailSSL $true `
  -MailFrom sender@example.com `
  -MailCredential $MyEmailCredential
```

## Configuring LDAP

Fastvue Reporter can import user information from Active Directory using LDAP to provide user’s full names, departments, and other organizational information. This requires an LDAP server to be configured and this is done using `-Ldap*` parameters.

LDAP configuration will be applied if the `-LdapHost` parameter is specified.

Credentials for the LDAP server can be provided either as a PSCredential object via the `-LdapCredential` parameter, or as a username and password through the `-LdapUsername` and `-LdapPassword` parameters.

Example LDAP configuration;

```powershell
PS> $MyLdapCredential = Get-Credential
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -LdapHost ldap.example.com `
  -LdapPort 389 `
  -LdapSearchDN "OU=Staff,DC=example,DC=com" `
  -LdapCredential $MyLdapCredential
```

## Configuring Data Retention Policy

The Data Retention Policy in Fastvue Reporter can be configured using the `-Retention*` parameters. Both the `-RetentionEnabled` and `-RetentionSize` parameters are required for configuration to be applied.

The number of days policy is configured with the `-RetentionDays` parameter. The `-RetentionSize` parameter specifies the maximum amount of data to retain in bytes, and can be provided using unit prefixes, for example it can be specified as `100 GB` or `100G` or `107374182400`. Unit prefixes will be interpreted as binary SI units (1K=1024, 1M=1048576, etc.).

The following example command will configure the retention policy to retain 90 days or 100GB of data, whichever limit is reached first;

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -RetentionEnabled $true `
  -RetentionDays 90 `
  -RetentionSize "100 GB"
```

## Configuring License

You can apply license keys to your Fastvue Reporter instance using the `-LicenseKey` parameter. Multiple license keys can be applied by passing an Array or a comma-separated string of keys.

The `-LicenseKeyMode` parameter allows you to specify how to handle license keys that may already exist in the Fastvue Reporter instance. If the mode is set to `Replace`, then the keys provided to the installation script will completely replace the keys that already exist in Fastvue Reporter. If the mode is set to `Add`, then the keys provided to the script will be added to the existing list of keys in Fastvue Reporter.

The following example command applies a license key to Fastvue Reporter;

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -LicenseKey "FV-XYZ-123456-123456-123456-123456"
```

## Configuring Productivity

The Productivity ratings that Fastvue Reporter applies to firewall-provided categories can be configured by the installation script using the `-Productivity*` parameters.

There are four Productivity ratings; ***Unacceptable***, ***Unproductive***, ***Acceptable***, and ***Productive***. Each of these has a corresponding configuration parameter in the installation script; `-ProductivityUnacceptable`, `-ProductivityUnproductive`, `-ProductivityAcceptable`, and `-ProductivityProductive`. Each of these parameters accept either an array or a comma-separated string with the names of the firewall-provided categories you want to set to that productivity rating.

For example, using the SonicWall categories, the following command will mark the categories “News and Media” and  “Job Search” as “Unproductive” using an array as input, and the categories “Online Banking” and “Games” as “Acceptable” using a comma-separated string as input;

```powershell
PS> .\FastvueReporterInstall.ps1 `
  -Product SonicWall `
  -ProductivityUnproductive @("News and Media", "Job Search") `
  -ProductivityAcceptable "Online Banking,Games"
```

## Configuring YouTube Integration

Fastvue Reporter can lookup YouTube video information to provide video titles, channel names, and categories. To do this, you must configure your YouTube API key in Fastvue Reporter. This can be done with the installation script using the `-YouTubeApiKey` parameter;

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -YouTubeApiKey "abcdefghijklmnopqrstuvwxyz"
```

## Configuring Public URL

If your Fastvue Reporter instance will be accessed by other users via a specific URL, such as via a reverse proxy, you will need to configure this URL in the software so that when reports or alerts are sent out to those users, the email will contain links that point at the correct URL. This can be configured by the installation script using the `-PublicUrl` parameter;

```powershell
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -PublicUrl "https://reportingserver.example.com/fastvue"
```

## Configuring Proxy

When Fastvue Reporter connects to external sites, such as to Fastvue for factory data updates or licensing, or to YouTube for video lookups, it may need to connect via a proxy in your network to be able to connect out to the internet. You can configure the proxy to use for this using the `-Proxy*` parameters;

```powershell
PS> $MyProxyCredential = Get-Credential
PS> .\FastvueReporterInstall.ps1 `
	-Product SonicWall `
  -ProxyServer "proxy.example.com" `
  -ProxyPort 8080 `
  -ProxyIgnoreSSLErrors $false `
  -ProxyAuthEnabled $true `
  -ProxyCredential $MyProxyCredential
```

# Configuring an existing Fastvue Reporter Instance

The installation script can perform the configuration steps using the provided configuration parameters by setting the `-Mode` parameter to `Configure`. This can be used to change the configuration for an already installed Fastvue Reporter instance without running the installer which can take some time to complete and will result in Fastvue Reporter’s service being restarted.

For example, the following command will configure a Syslog Source without running the installation;

```powershell
PS> .\FastvueReporterInstall.ps1 `
  -Product SonicWall `
  -Mode Configure `
  -SyslogSourceHost 10.0.0.1 `
  -SyslogSourcePort 514
```

# Updating Fastvue Reporter

Each time the installation script is run, it will automatically download and install the latest version of Fastvue Reporter from the selected release channel. To update a Fastvue Reporter instance to the latest version, you can simply run the installation script with the same parameters as before and the latest version will be installed. If your script or configuration file is also set to configure some elements of Fastvue Reporter, you can restrict the installation script to only perform the installation without any configuration steps by setting the `-Mode` parameter to `Install`.

# Uninstalling Fastvue Reporter

The script is able to uninstall Fastvue Reporter by setting the `-Mode` parameter to `Uninstall`. The `-Product` parameter is required so that the script knows which product to uninstall.

```powershell
PS> .\FastvueReporterInstall.ps1 -Product SonicWall -Mode Uninstall
```

This can also be done on a remote system using the `-Server` parameter;

```powershell
PS> .\FastvueReporterInstall.ps1 -Product SonicWall -Mode Uninstall -Server 192.168.100.191
```

# Parameter Reference

| Parameter | Description | Default Value |
| --- | --- | --- |
| -ConfigFile <String> | Path to a configuration file that specifies settings for the installation and configuration of Fastvue Reporter. | (null) |
| -Mode <String> | Mode to run the installation script in. Valid values are 'InstallAndConfigure', 'Install', 'Configure', and 'Uninstall'. | InstallAndConfigure |
| -ConfigTarget <Array/String> | Optional parameter to specify which parts of Fastvue Reporter will be configured, ignoring parts not specified here even if their configurations have been provided. Specified as either an array or a comma-separated string, can be a combination of any of the following values; Auth, DataRetention, LDAP, Mail, Source, Productivity, License, PublicUrl, Proxy, YouTube | (null) |
| -Product <String> | Required. Name of the Fastvue Reporter product you want to install. | (null) |
| -ReleaseChannel <String> | Release Channel to download Fastvue Reporter for. Valid values are 'Stable' and 'Latest'. | Stable |
| -ProductVersion <String> | Version of firewall-specific variant of Fastvue Reporter to install. | (null) |
| -InstallerBaseUrl <String> | Alternate base URL to download installers from. | (null) |
| -Version | Show the script version number and exit the script without installing. | False |
| -ShowVars | Debug option to show all variables before proceeding with installation. | False |
| -ShowSystemInfo | Show the system information and exit the script without installing. | False |
| -ListProducts | List available Fastvue Reporter products that can be installed and exits the script without installing. | False |
| -ListProductVersions | List available versions of Fastvue Reporter for the specified Firewall vendor and exits the script without installing. | False |
| -InvokedFromRemote | Flag provided to script automatically when executed on a remote system. Do not specify this parameter manually. | False |
| -Server <String> | Remote system to run the installation script on. Requires WinRM enabled on the remote system. | (null) |
| -ServerPort <Int32> | Remote port to connect to a WinRM session on. | 5985 |
| -ServerCredential <PSCredential> | Credential for authenticating to the remote system. | (null) |
| -ServerUsername <String> | Username for authenticating to the remote system. Ignored if -ServerCredential is specified. | (null) |
| -ServerPassword <String/SecureString> | Password for authenticating to the remote system. Can be a plain-text string or a SecureString. Ignored if -ServerCredential is specified. | (null) |
| -TempPath <String> | Temporary path to copy required files to when running the installation script on a remote system. | C:\\__Fastvue_Install |
| -InstallerExecutablePath <String> | Path to installer executable. Specifying this will prevent automatic download of the required version. | (null) |
| -ApiCredential <PSCredential> | Credential for authenticating to the Fastvue Reporter API. | (null) |
| -ApiUsername <String> | Username for authenticating to the Fastvue Reporter API. Ignored if -ApiCredential is specified. | (null) |
| -ApiPassword <String/SecureString> | Password for authenticating to the Fastvue Reporter API. Can be a plain-text string or a SecureString. Ignored if -ApiCredential is specified. | (null) |
| -DataPath <String> | Path to where Fastvue Reporter should store its data once installed. | (null) |
| -IISSite <String> | Name of the IIS website to install Fastvue Reporter's web frontend to. | Default Web Site |
| -IISVDir <String> | IIS virtual directory or subpath to install Fastvue Reporter's web frontend to. | (null) |
| -FastvueReporterUrl <string> | Optional. The full URL to the Fastvue Reporter interface. Used to target a specific existing instance or provide the expected URL to access Reporter in case the script cannot automatically determine the correct URL. | (null) |
| -IISAuth <Boolean> | Specifies that IIS Authentication should be configured by the script. | False |
| -IISAuthAllowUsers <String> | Comma-separated list of usernames that have permission to access the Fastvue Reporter interface. | (null) |
| -IISAuthAllowRoles <String> | Comma-separated list of roles or security groups that have permission to access the Fastvue Reporter interface. | (null) |
| -IISAuthSharedAllowUsers <String> | Comma-separated list of usernames that have permission to access private shared reports. | (null) |
| -IISAuthSharedAllowRoles <String> | Comma-separated list of roles or security groups that have permission to access private shared reports. | (null) |
| -SyslogSourceHost <String> | Hostname or IP to receive Syslog messages from. | (null) |
| -SyslogSourcePort <Int32> | Port to receive Syslog messages on. | 514 |
| -MailHost <String> | Hostname or IP of SMTP server to use when sending mail. | (null) |
| -MailPort <Int32> | Port of the SMTP server. | 587 |
| -MailSSL <Boolean> | Use secure communication with SMTP server. | True |
| -MailFrom <String> | Email address to send mail from. | (null) |
| -MailCredential <PSCredential> | Credential for authenticating to the SMTP server. | (null) |
| -MailUsername <String> | Username for authenticating to the SMTP server. Ignored if -MailCredential is specified. | (null) |
| -MailPassword <String/SecureString> | Password for authenticating to the SMTP server. Can be a plain-text string or a SecureString. Ignored if -MailCredential is specified. | (null) |
| -LdapHost <String> | Hostname or IP of LDAP server to import Organizational information from. | (null) |
| -LdapPort <Int32> | Port of the LDAP server. | 389 |
| -LdapSSL <Boolean> | Use secure communication with LDAP server. | False |
| -LdapSearchDN <String> | FQDN to search on the LDAP server. | (null) |
| -LdapCredential <PSCredential> | Credential for authenticating to the LDAP server. | (null) |
| -LdapUsername <String> | Username for authenticating to the LDAP server. Ignored if -LdapCredential is specified. | (null) |
| -LdapPassword <String/SecureString> | Password for authenticating to the LDAP server. Can be a plain-text string or a SecureString. Ignored if -LdapCredential is specified. | (null) |
| -RetentionEnabled <Boolean> | Specifies that the Data Retention policy should be enabled. | (null) |
| -RetentionDays <Int32> | Number of days to retain imported data for. | 30 |
| -RetentionSize <String> | Maximum size of imported data to retain. | (null) |
| -ProductivityUnacceptable <Array/String> | Array or comma-separated string of category names to mark as Unacceptable in Productivity ratings. | (null) |
| -ProductivityUnproductive <Array/String> | Array or comma-separated string of category names to mark as Unproductive in Productivity ratings. | (null) |
| -ProductivityAcceptable <Array/String> | Array or comma-separated string of category names to mark as Acceptable in Productivity ratings. | (null) |
| -ProductivityProductive <Array/String> | Array or comma-separated string of category names to mark as Productive in Productivity ratings. | (null) |
| -LicenseKey <Array/String> | Array or comma-separated string of License Keys to apply to the installed instance of Fastvue Reporter. | (null) |
| -LicenseKeyMode <String> | How the specified license keys should be applied. Valid values are 'Replace' and 'Add'; 'Replace' - Replaces all keys in Fastvue Reporter with the keys specified, removing existing keys if they were not specified. 'Add' - Adds the specified keys to Fastvue Reporter, leaving already existing keys in place. | Replace |
| -PublicUrl <String> | Public URL that this Fastvue Reporter instance will be accessible via. Used when emailing reports and alerts to provide the recipient with a link back to the Fastvue Reporter interface. | (null) |
| -YouTubeApiKey <String> | API key to use when performing lookups on YouTube videos. | (null) |
| -ProxyServer <String> | Proxy server that Fastvue Reporter should use when connecting to external sites. | (null) |
| -ProxyPort <Int32> | Port of the Proxy server. | 8080 |
| -ProxyIgnoreCertErrors <Boolean> | Ignores any certificate errors that occur when connecting via the proxy server. | False |
| -ProxyCredential <PSCredential> | Credential to authenticate to the Proxy server. | (null) |
| -ProxyUsername <String> | Username to authenticate to the Proxy server. Ignored if -ProxyCredential is specified. | (null) |
| -ProxyPassword <String/SecureString> | Password to authenticate to the Proxy server. Can be a plain-text string or a SecureString. Ignored if -ProxyCredential is specified. | (null) |
| -ProxyAuthDomain <String> | Authentication domain to be specified to the Proxy server. | (null) |