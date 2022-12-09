# Introduction

PowerShell 5 module that simplifies generating, submitting and retrieving certificate requests and certificates towards an Active Directory Certificate Services CA.

The module is built to suit a very specific use case - environments where precompiled binares are not allowed, such as OT or otherwise critical platforms. As such, all the code used is completely transparent and uses no third-party tools or equivalent - all the code is compiled inline inside the environment with optional code signing from an internal code signing certificate.

## Prerequisites

* Windows 10 or Windows Server 2019 Desktop (it might be possible to run on Core but I have not tested it)
* Windows PowerShell version 5.0 or 5.1 (newer versions built on .NET Core or .NET 6/7 do not work)
* At least .NET Framework 4.7.2, preferably 4.8
* A Code Signing certificate (optional)

## Install instructions

To install the module, the code first needs to be compiled and .NET wrappers must be created for the built-in Microsoft cert*.dll COM type libraries.

### Compile and prepare module

1. Download the following files from the repo and put them in a folder somewhere (for example, C:\Scripts\CertReqTools)

   * CertRequestTools.psm1
   * CertRequestTools.psd1
   * Install-CertReqUtil.ps1
   * CompileBinaries.ps1

2. Start an elevated PowerShell session (Run as administrator) 

3. Install the RSAT-ADCS-Mgmt feature
```
Install-WindowsFeature -Name RSAT-ADCS-Mgmt
```
4. Navigate to the folder with the files
```
cd C:\Scripts\CertReqTools
```
5. Run the CompileBinaries.ps1 script, optionally with the -Sign parameter if you want to sign the resulting files (code signing certificate required)
```
.\CompileBinaries.ps1
```
```
.\CompileBinaries.ps1 -Sign
```
6. If the -Sign parameter was specified, select the desired Code Signing certificate store location (CurrentUser or LocalMachine), then select a signing certificate 
7. The script will output a ZIP archive with the install script and another ZIP archive containing the module files
```
InstallCertRequestTools.zip
```
8. Transfer the ZIP archive to the target server or servers

### Install module
