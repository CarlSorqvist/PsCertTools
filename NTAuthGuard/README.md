# Introduction

NTAuth Guard provides a method of ensuring that the `NTAuthCertificates` object is kept "clean", i.e. if a new certificate is added to its `cACertificate` attribute that is not previously approved, it is automatically removed.

# Description

The cleanup feature is performed by the `Invoke-NTAuthCleanup.ps1` script, which runs on domain controllers in the root domain of the forest through a scheduled task, triggered both by the 5136 event as well as every 5 minutes. To ensure least privilege, the task runs in the context of a group Managed Service Account (gMSA) that is granted permission to write only to the `cACertificate` attribute of the `NTAuthCertificates` object.

## Components

* `Create-Gmsa.ps1` creates a gMSA for running the task.
* `Create-NTAuthGuardTask.ps1` creates the task on domain controllers. It is designed to run on each boot through Startup scripts in GPO, and will check if the task exists and create it if it doesn't.
* `Invoke-NTAuthCleanup.ps1` is the main script that performs the cleanup. It, and the whitelist, is placed in a location (NETLOGON is recommended) that is accessible by all DCs.
* `NTAuthDelegation.ps1` creates the delegation to write to the `cACertificate` attribute, and adds an audit rule that will be used to trigger the task.

Additionally, the whitelist is contained in a simple UTF-8 encoded text file that is named `whitelist.txt` by default. It is not included in the repo, but can simply be created manually.

## Logging

By default, the script logs its actions, warnings and errors to the `Application` event log, using a custom event source `NTAuthGuard`. This can be modified by the parameters in the `Create-NTAuthGuardTask.ps1` task, however remember that the service account needs permission to write to the event log of your choice without admin access.

# Installation

**Important**

The script is designed to not execute any actions until explicitly enabled. To enable the script, set the `adminDisplayName` attribute of the `NTAuthCertificates` object to any non-null value. If you already have a value for this attribute in your environment that you do not wish to remove, consider modifying the `$EnablingAttribute` variable in `Invoke-NTAuthCleanup.ps1` to a different, writable and otherwise unused attribute. It is important that all versions of the script file uses the same attribute, or you will encounter unexpected behavior.

* Create the gMSA by running the `Create-Gmsa.ps1` script on a server in the forest root domain, or create it manually. If you use the script, update the `$FQDN` variable before running it. By default, the account is named `s0ntauthguard`, which is used in the rest of the scripts as well. The script automatically allows the `Domain Controllers` group access to the service account.
* The gMSA is created in the default `Managed Service Accounts` container. If you have an OU specifically for Tier0 service accounts, you can optionally move it.
* Create a delegation group that will be used to delegate `WriteProperty`  rights to the `cACertificate` attribute of the `NTAuthCertificates` object. By default, this group is named `d0_pki_ntauth_cacert__w`. **Take care** that this group cannot be modified by anyone else than Enterprise Admins.
* Add the service account as a member of the newly created delegation group.
* Update the group name in the `NTAuthDelegation.ps1` script if necessary, then run it. It will ask for confirmation before attempting to update the security descriptor of `NTAuthCertificates`.
* Create a new folder named NTAuth in the NETLOGON folder of the forest root domain, for example `\\domain.com\NETLOGON\NTAuth`.
* Copy the `Invoke-NTAuthCleanup.ps1` script to the previously created `NETLOGON\NTAuth` folder.
* Create the whitelist file by opening notepad and saving it (with UTF-8 encoding) in the same `NETLOGON\NTAuth` folder as `whitelist.txt`. The whitelist should contain the thumbprints of each individual CA certificate **that you wish to keep in NTAuth**, one per row. Example:

```
687DA7112CE6EF56DE87157D071FB9403FF7F9AC
5E5391F744BCA147A9BB93B7EA0043D8C1718251
7E7745F647CCC78CC254B684357F920D67772D45
```

* Open the `Create-NTAuthGuardTask.ps1` script in a text or code editor. Modify the parameters in the `#### PARAMETERS ####` section to suit your environment. **Note** that if you modify the event log or event source in this script, you must also update the corresponding `$EventLogParams` values in `Invoke-NTAuthCleanup.ps1`. 

```
#### PARAMETERS ####

$TaskName = "NTAuth Guard"
$TaskPath = "\"

$EventLog = "Application"
$EventSource = "NTAuthGuard"

$ServiceAccount = "CORP\s0ntauthguard$"
$ScriptPath = "\\corp.contoso.com\netlogon\NTAuth\Invoke-NTAuthCleanup.ps1"
$WhiteListPath = "\\corp.contoso.com\netlogon\NTAuth\whitelist.txt"

#### END PARAMETERS ####
```

* Create a GPO that will run `Create-NTAuthGuardTask.ps1` as a Startup script, name it according to your naming convention, for example `Tier0.DomainControllers.NTAuthGuard`. Add the modified `Create-NTAuthGuardTask.ps1` script to Startup scripts.
* Link the GPO to the Domain Controllers OU.
* Optionally, enable [Audit Directory Service Changes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes) on all domain controllers. The script does not require you to, as it will run every 5 minutes anyway, but doing so enables a more immediate response, minimizing impact if an unwanted CA certificate is added.
* Run gpupdate /force on a DC and reboot it. Verify that the `NTAuth Guard` task was created successfully. Do the same with all other DCs.
* When all domain controllers have been rebooted and you have verified that event 97 is logged on all of them (indicating that the script is prevented from taking action), enable the script by assigning any non-null value to the `adminDisplayName` attribute of the `NTAuthCertificates` object. You can use the following PowerShell command to assign the value `1` to `adminDisplayName`:

```
Set-ADObject -Identity ('CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{0}' -f (Get-ADRootDSE).configurationNamingContext) -Replace @{adminDisplayName="1"}
```

## Testing

To verify that the task triggers as expected, you can add a test certificate to the NTAuth container through the following `certutil` command:

`certutil -dspublish C:\temp\cert.crt NTAuthCA`

If configured correctly, an event should be logged in the configured event log and source with event ID 1, confirming that the certificate was removed.

**Please remember** that adding any certificate to NTAuth may put your environment at risk. If the script does not trigger and removes the certificate for some reason, **remove it manually** while troubleshooting. You can read more about NTAuth [here](https://blog.qdsecurity.se/2020/09/04/supply-in-the-request-shenanigans/) and [here](https://blog.qdsecurity.se/2024/04/07/forest-compromise-through-ama-abuse/#introduction-and-background).

# Other notes

## Preventing the script from taking any actions

There may be cases where admins want to temporarily disable the script across all domain controllers. There are multiple methods of accomplishing this.

* If the script is centrally distributed, i.e. it is located in the NETLOGON share and the task uses that script, you can simply rename the script and the task will fail as the script can no longer be found. This is the most immediate method, as DFS Replication is generally instant for small files across all domain controllers, however it is not a graceful method as no events will be logged indicating the situation.
* Similarly, if the whitelist is centrally distributed (through the NETLOGON share or equivalent), you can rename it. This is a also immediate, and a slightly more graceful method as the script will still run but will not be able to find the whitelist, causing it to log errors.
* As previously indicated, the `adminDisplayName` attribute of the `NTAuthCertificates` object must have a value or the script will not execute any actions. This is arguably the most graceful method, however it is not necessarily immediate across all DCs as it is dependent on directory replication. You can use the following command to clear the value:

```
Set-ADObject -Identity ('CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{0}' -f (Get-ADRootDSE).configurationNamingContext) -Clear adminDisplayName
```

To re-enable the script later on, simply undo whatever action you went for and it should start working again.

## CA Certificate Renewal

When an Enterprise CA certificate is renewed and subsequently installed in the CA, it is automatically published to NTAuth. However, as the whitelist has probably not been updated yet, the script would remove the renewed certificate. The script is designed to takes scenarios like this into account if the `-AllowImplicitRenewedCertificates` parameter is provided, which is the default when creating the task.
However, if it does find a renewed certificate, it will log a warning to the Event Log informing administrators that they should update the whitelist with the thumbprint of the renewed certificate.


