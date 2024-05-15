# Introduction

NTAuth Guard provides a method of ensuring that the `NTAuthCertificates` object is kept "clean", i.e. if a new certificate is added to the cACertificate attribute that is not previously approved, it is automatically removed.

# Description

The cleanup feature is performed by the `Invoke-NTAuthCleanup.ps1` script, which runs on domain controllers in the root domain of the forest through a scheduled task, triggered both by the 5136 event as well as every 5 minutes. To ensure least privilege, the task runs in the context of a group Managed Service Account (gMSA) that is granted permission to write only to the `cACertificate` attribute of the `NTAuthCertificates` object.

## Components

* `Create-Gmsa.ps1` creates a gMSA for running the task.
* `Create-NTAuthGuardTask.ps1` creates the task on domain controllers. It is designed to run on each boot through Startup scripts in GPO, and will check if the task exists and create it if it doesn't.
* `Invoke-NTAuthCleanup.ps1` is the main script that performs the cleanup. It, and the whitelist, is placed in a location (NETLOGON is recommended) that is accessible by all DCs.
* `NTAuthDelegation.ps1` creates the delegation to write to the `cACertificate` attribute, and adds an audit rule that will be used to trigger the task.
