<#
.Synopsis
   Adds CA certificates from the local certificate store to the machine-local enterprise NTAuth store.
.DESCRIPTION
   This script finds certificates in the LocalMachine\CA (Intermediate CAs) local certificate store based on Certificate Policy OID and/or subject name, and adds
   them to the machine-local enterprise NTAuth store. This is useful when a CA certificate is not trusted in the directory-wide NTAuth but some application requires
   it to be locally added on a subset of machines or servers.

   For the script to find the CA certificates, their entire chain must already be trusted by the local machine, i.e. the Root CA certificate and any Intermediate
   CAs must be present in the appropriate LocalMachine store.

   Note that only valid certificates are considered.
.EXAMPLE
   PS C:\> .\Add-CertificateToLocalNTAuth.ps1 -FindByCertificatePolicy "1.2.840.113556.1.4.803"

   Finds CA certificates that contain the 1.2.840.113556.1.4.803 OID in the Certificate Policies extension, and adds it to the NTAuth store.
.EXAMPLE
   PS C:\> .\Add-CertificateToLocalNTAuth.ps1 -FindBySubjectName "My CA name"

   Finds CA certificates whose Subject CN starts with 'My CA name', and adds it to the NTAuth store.
.EXAMPLE
   PS C:\> .\Add-CertificateToLocalNTAuth.ps1 -FindByCertificatePolicy "1.2.840.113556.1.4.803" -FindBySubjectName "My CA name"

   Finds CA certificates that contain the 1.2.840.113556.1.4.803 OID in the Certificate Policies extension, *or* whose Subject CN starts with 'My CA name', and adds
   any found certificates to the NTAuth store.
.INPUTS
   None.
.OUTPUTS
   String
    Outputs the command output of certutil.
.NOTES
   Created by Carl Sörqvist, 2023

   It is possible to add additional find criteria to the script by adding the appropriate parameter and adding that parameter name to the $FindTypes dictionary.
   As an example, to allow finding certificates using Application Policy:

   Add a parameter:
  
    , [Parameter(Mandatory = $false)]
    [String[]]
    $FindByApplicationPolicy
   
   Add it to the dictionary:

    $FindTypes.Add("FindByApplicationPolicy", [X509FindType]::FindByApplicationPolicy)

   Note that the parameter type must match the value expected by the X509Certificate2Collection.Find() method.
#>

#Requires -version 5 -RunAsAdministrator

using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [String[]]
    $FindByCertificatePolicy

    , [Parameter(Mandatory = $false)]
    [String[]]
    $FindBySubjectName
)

# If the parameter name always matches the X509FindType enum name, we can use a List[X509FindType] instead, with the appropriate code modifications
# Currently we allow custom mappings, which is why we use a Dictionary

$FindTypes = [Dictionary[String, X509FindType]]::new()
$FindTypes.Add("FindByCertificatePolicy", [X509FindType]::FindByCertificatePolicy)
$FindTypes.Add("FindBySubjectName", [X509FindType]::FindBySubjectName)

# Open the local Intermediate Certification Authorities store using LocalMachine context
$Store = [X509Store]::new([StoreName]::CertificateAuthority, [StoreLocation]::LocalMachine)
$Store.Open([OpenFlags]::ReadOnly -bor [OpenFlags]::OpenExistingOnly)

# Create a HashSet for the final list of certificates
$Certs = [HashSet[X509Certificate2]]::new()

# Enumerate over the values in $FindTypes, check if there is a parameter with that name, and try to find certificates based on its value if present
# Each individual certificate is only added once, even if it is found by multiple criteria
Foreach ($FindTypeKvp in $FindTypes.GetEnumerator())
{
    $ParameterName = $FindTypeKvp.Key
    $FindType = $FindTypeKvp.Value

    $ParameterValue = $null
    If ($PSBoundParameters.TryGetValue($ParameterName, [ref] $ParameterValue))
    {
        Foreach ($Value in $ParameterValue)
        {
            # Need to convert the result of the Find() method to an array for UnionWith() to accept it
            $Certs.UnionWith([X509Certificate2[]]$Store.Certificates.Find($FindType, $Value, $true))
        }
    }
}

# Iterate over the resulting certificates and add them to NTAuth using certutil
# Certutil cannot take a certificate as a parameter, so we need to use a temporary file instead
Foreach ($Cert in $Certs)
{
    $TempFile = [Path]::GetTempFileName()
    [File]::WriteAllBytes($TempFile, $Cert.RawData)

    certutil -enterprise -addstore NTAuth $TempFile
    
    [File]::Delete($TempFile)
}

$Store.Close()
$Store.Dispose()