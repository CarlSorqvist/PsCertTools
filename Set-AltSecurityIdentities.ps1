#Requires -version 5

<#
.SYNOPSIS
   Sets the altSecurityIdentities attribute on user accounts.

.DESCRIPTION
   Takes one or more certificates as input, converts them to altSecurityIdentities strings and adds them to the attribute of the appropriate user. The target user account is automatically identified based on the UPN in the Subject Alternative Name extension, although it is possible to override this behaviour by supplying a CSV with the SamAccountName and corresponding certificate instead.

.PARAMETER Domain
   Specifies the domain name of the target users' domain. Defaults to the current domain of the calling user. If the target users are in different domains, the function must be called once for users in each domain.

.PARAMETER Replace
   Instructs the function to *replace* the contents of the altSecurityIdentities attribute of users instead of only adding to it. Use with caution, as the function does *not* back up/preserve the previous values nor ask for confirmation before overwriting them.

.PARAMETER Quiet
   When specified, suppresses the input choice (but not the fallback file dialog) in AutoDetect mode, and does not pause the function after outputting the result. Can be useful in scenarios where using the clipboard to input multiple PEM encoded certificates, one at a time, or using the clipboard to input multiple file lists, also one at a time.
   
   Can only be specified for the AutoDetect parameter set.

.PARAMETER MappingType
   Defines the mapping type for the resultant altSecurityIdentities strings. The only supported values are 'IssuerSerialNumber' (default) and 'SubjectKeyIdentifier'.

.PARAMETER X509Certificate2
   A pre-instantiated X509Certificate2 object containing a certificate to provision to a user account. Each certificate provided through this parameter must contain the Subject Alternative Name extension with a User Principal Name value.

.PARAMETER File
   A FileInfo object pointing to a file representing a certificate. Each certificate provided through this parameter must contain the Subject Alternative Name extension with a User Principal Name value.

.PARAMETER Base64Cert
   A single Base64 encoded certificate, with or without PEM headers. Can be combined with the SamAccountName parameter to explicitly specify the target user account. If used without the SamAccountName parameter, each encoded certificate provided through this parameter must contain the Subject Alternative Name extension with a User Principal Name value.

.PARAMETER SamAccountName
   The sAMAccountName of the target user account for which the altSecurityIdentities attribute will be provisioned. Can only be used together with the Base64Cert parameter, and is intended to allow piping a CSV to the function containing the SamAccountName and Base64Cert columns. The provided SamAccountName overrides any User Principal Name contained in the certificate.

.EXAMPLE
   .\Set-AltSecurityIdentities.ps1
    
   Certificate input source
   Select how to fetch certificates
   [A] Auto-detect  [P] PEM (Clipboard)  [L] File List (Clipboard)  [F] File dialog  [?] Help (default is "A"):

   Asks the user whether to fetch a single PEM encoded certificate or a list of copied files from clipboard, to present a file dialog to manually select files, or to automatically detect the appropriate option. If the selected option fails, the file dialog is displayed as a fallback option. After execution, pauses the script before continuing to allow the user to inspect the result.

   The target user accounts are automatically resolved from the UPN in the Subject Alternative Name extension. If the certificates does not contain the Subject Alternative Name extension, or if it does not contain a UPN, the function fails.
   Multiple certificates can be provided per user.
.EXAMPLE
   .\Set-AltSecurityIdentities.ps1 -Quiet

   Automatically tries to fetch a single base64 encoded certificate or a list of copied files from clipboard. If both options fails, presents a file dialog for manual selection of certificate files. Does not pause the script after execution.

   The target user accounts are automatically resolved from the UPN in the Subject Alternative Name extension. If the certificates does not contain the Subject Alternative Name extension, or if it does not contain a UPN, the function fails.
   Multiple certificates can be provided per user.
.EXAMPLE
   Get-ChildItem -Path Cert:\CurrentUser\My | .\Set-AltSecurityIdentities.ps1

   Gets a set of X509Certificate2 objects from the Current User\Personal certificate store and adds the appropriate altSecurityIdentities strings to the user accounts identified by the UPN in the Subject Alternative Name extension of each certificate. If the certificates do not contain the Subject Alternative Name extension, or if it does not contain a UPN, the function fails.
   Multiple certificates can be provided per user.
.EXAMPLE
   Get-ChildItem -Path C:\*.cer | .\Set-AltSecurityIdentities.ps1

   Gets a list of files, attempts to process them as certificates, and adds the appropriate altSecurityIdentities strings to the user accounts identified by the UPN in the Subject Alternative Name extension of each certificate. If the certificates do not contain the Subject Alternative Name extension, or if it does not contain a UPN, the function fails.
   Multiple certificates can be provided per user.
.EXAMPLE
   Get-Content -Path C:\Base64EncodedCertificates.txt | .\Set-AltSecurityIdentities.ps1

   Gets one or more base64 encoded certificates from a text file (one complete certificate per line) and adds the appropriate altSecurityIdentities strings to the user accounts identified by the UPN in the Subject Alternative Name extension of each certificate. If the certificates do not contain the Subject Alternative Name extension, or if it does not contain a UPN, the function fails.
   Multiple certificates can be provided per user.

   Example text file:

   MIIDVTCCAtugAwIBAgITZgAAAiDIo+C7AbCF...
   MIIDUzCCAtmgAwIBAgITZgAAAiXPxeIogv/m...
   MIIDVjCCAtugAwIBAgITZgAAAh5ze0IfUYs2...
   MIIDVDCCAtmgAwIBAgITZgAAAhsKOI4USPke...
   MIIDUjCCAtmgAwIBAgITZgAAAiHdNUP3mAYg...
   MIIDVTCCAtugAwIBAgITZgAAAiT4YCMly4zd...
   MIIDVTCCAtugAwIBAgITZgAAAiLhoXbDgcH8...
   ...
.EXAMPLE
   Import-Csv -Path C:\UsersAndCerts.csv | .\Set-AltSecurityIdentities.ps1
    
   Imports a CSV with the SamAccountName and Base64Cert columns, containing the sAMAccountName of a user and a base64 encoded certificate per line. The value in the SamAccountName column overrides any UPN in the provided certificates, which can be useful if the provided certificates do not contain a UPN or if it does not directly match the value of users' userPrincipalName attribute.
   Multiple certificates can be provided per user.

   Example CSV:

   SamAccountName,Base64Cert
   user1,MIIDVTCCAtugAwIBAgITZgAAAiDIo+C7AbCF...
   user1,MIIDUzCCAtmgAwIBAgITZgAAAiXPxeIogv/m...
   user2,MIIDVjCCAtugAwIBAgITZgAAAh5ze0IfUYs2...
   user3,MIIDVDCCAtmgAwIBAgITZgAAAhsKOI4USPke...
   user3,MIIDVTCCAtugAwIBAgITZgAAAiT4YCMly4zd...
.INPUTS
   [System.IO.FileInfo]
     One or more FileInfo objects, each representing a certificate in DER or Base64 format.
   
   [System.Security.Cryptography.X509Certificates.X509Certificate2]
     One or more managed X509Certificate2 objects that have already been instantiated outside of the function.

   [String]
     One or more Base64 encoded strings, each representing a full certificate. The strings may contain PEM headers and line breaks.

   [PSObject]
     One or more PSObject objects, with the SamAccountName and Base64Cert properties.
.OUTPUTS
   [PSObject]
     An object detailing the username and SID, certificate subject and thumbprint, the derived altSecId string, and whether the operation was successful.
.NOTES
   Written by Carl Sörqvist, 2025.
   
   GitHub repository: https://github.com/CarlSorqvist/PsCertTools
#>


using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.ObjectModel
using namespace System.DirectoryServices.Protocols
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Management.Automation.Host
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text.RegularExpressions
using namespace System.Windows.Forms
using module ActiveDirectory

[CmdletBinding(DefaultParameterSetName = "AutoDetect")]
Param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Domain = $env:USERDNSDOMAIN

    , [Parameter(Mandatory = $false)]
    [Switch]
    $Replace

    , [Parameter(Mandatory = $false, ParameterSetName = "AutoDetect")]
    [Alias("Silent")]
    [Switch]
    $Quiet

    , [Parameter(Mandatory = $false)]
    [ValidateSet("IssuerSerialNumber","SubjectKeyIdentifier")]
    [String]
    $MappingType = "IssuerSerialNumber"

    , [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "X509Certificate2")]
    [X509Certificate2]
    $X509Certificate2

    , [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "File")]
    [FileInfo]
    $File

    , [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Base64Cert")]
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "CSV")]
    [Alias("Cert", "Certificate")]
    [String]
    $Base64Cert

    , [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "CSV")]
    [Alias("Identity","Username")]
    [String]
    $SamAccountName
)
Begin
{
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

    enum X509EncodingType {
        Base64Header = 0x00000000
        Base64 = 0x00000001
        Binary = 0x00000002
        Base64RequestHeader = 0x00000003
        Hex = 0x00000004
        HexAscii = 0x00000005
        Base64Any = 0x00000006
        Any = 0x00000007
        HexAny = 0x00000008
        Base64CrlHeader = 0x00000009
        HexAddr = 0x0000000A
        HexAsciiAddr = 0x0000000B
        HexRaw = 0x0000000C
        Base64Uri = 0x0000000D
    }
    enum AutoDetectSelection
    {
        AutoDetect = 0
        ClipboardCert = 1
        ClipboardFileList = 2
        FileDialog = 3
    }

    # This regex validates PEM input and can be used to extract the base64 encoded string, in case the CBinaryConverter fails for some reason.
    # Not currently used.
    #$PEMRegexPattern = '^(?<header>-----BEGIN (?<label>[\w\.]+?)-----\r?\n)(?<encoded>[a-z\d/\+=\r\n]+?)(?<footer>\r?\n-----END \k<label>-----)(\r?\n)?$'
    #$RegexOptions = [RegexOptions]::Compiled -bor [RegexOptions]::ExplicitCapture -bor [RegexOptions]::IgnoreCase
    #$PEMRegex = [Regex]::new($PEMRegexPattern, $RegexOptions)

    $CIComparer = [StringComparer]::InvariantCultureIgnoreCase

    $X509Converter = New-Object -ComObject X509Enrollment.CBinaryConverter

    $Certs = [List[X509Certificate2]]::new()
    $UserAndCert = [List[Object]]::new() # Only used in CSV parameter set

    # Used to cache user lookups for the CSV parameter set 
    $CsvUserCache = [Dictionary[String, Bool]]::new($CIComparer)

    $IssuerSerialNumberFormat = "X509:<I>{0}<SR>{1}"
    $SKIFormat = "X509:<SKI>{0}"

    $DC = Get-ADDomainController -DomainName $Domain -Discover -ForceDiscover -Writable -Service ADWS, KDC | Select-Object -ExpandProperty HostName | Select-Object -First 1
}
Process
{
    If ($PSCmdlet.ParameterSetName -ieq "X509Certificate2")
    {
        $Certs.Add($X509Certificate2)
    }
    ElseIf ($PSCmdlet.ParameterSetName -ieq "File")
    {
        Try
        {
            $Cert = [X509Certificate2]::new($File.FullName)
        }
        Catch
        {
            $Ex = $_.Exception.GetBaseException()
            $Message = "Failed to convert '{0}' to a certificate." -f $File.FullName
            Write-Error -Message $Message -Exception $Ex -TargetObject $File
            return
        }
        $Certs.Add($Cert)
    }
    ElseIf ($PSCmdlet.ParameterSetName -ieq "Base64Cert")
    {
        Try
        {
            # Attempt to convert the input string from any Base64 format (including with headers) to straight base 64.
            $Converted = $X509Converter.StringToString($Base64Cert, [X509EncodingType]::Base64Any, [X509EncodingType]::Base64)

            # If the conversion was successful, attempt to convert it to a certificate
            $Cert = [X509Certificate2]::new([Convert]::FromBase64String($Converted))
        }
        Catch
        {
            $Ex = $_.Exception.GetBaseException()
            $Message = "Failed to convert input string to a certificate."
            Write-Error -Message $Message -Exception $Ex -TargetObject $Base64Cert
            return
        }
        $Certs.Add($Cert)
    }
    ElseIf ($PSCmdlet.ParameterSetName -ieq "CSV")
    {
        # Trim whitespace
        $TrimmedUserName = $SamAccountName.Trim()

        # Try to resolve the user account. If not found, do not process the certificate
        $UserExists = $false
        If (!$CsvUserCache.TryGetValue($TrimmedUserName, [ref] $UserExists))
        {
            # This user has not yet been processed

            $User = $null
            $User = Get-ADUser -Server $DC -Filter { sAMAccountName -eq $TrimmedUserName }
            $UserExists = $User -ne $null
            $CsvUserCache.Add($TrimmedUserName, $UserExists)

            If (!$UserExists)
            {
                # Write an error if the user does not exist
                $Message = "A user account with username '{0}' could not be found in {1}." -f $TrimmedUserName, $Domain
                Write-Error -Message $Message -TargetObject $TrimmedUserName
            }
        }
        If ($UserExists)
        {
            Try
            {
                # When present in a CSV, only straight base 64 format without headers is supported
                $Cert = [X509Certificate2]::new([Convert]::FromBase64String($Base64Cert))
            }
            Catch
            {
                $Ex = $_.Exception.GetBaseException()
                $Message = "Failed to convert input string to a certificate."
                Write-Error -Message $Message -Exception $Ex -TargetObject $Base64Cert
                return
            }
            $Obj = [pscustomobject][ordered]@{
                Username = $TrimmedUserName
                Certificate = $Cert
            }
            $UserAndCert.Add($Obj)
        }
    }
    Else
    {
        If (!$Quiet)
        {
            $Choices = [Collection[ChoiceDescription]]::new()
            $Choices.Add([ChoiceDescription]::new("&Auto-detect", "Automatically detect the appropriate certificate source. Will prioritize clipboard content, if present."))
            $Choices.Add([ChoiceDescription]::new("&PEM (Clipboard)", "Fetch a single base64-encoded (PEM) certificate from clipboard."))
            $Choices.Add([ChoiceDescription]::new("File &List (Clipboard)", "Get a list of certificate files from clipboard. (Note: does not work with RDP file copy)"))
            $Choices.Add([ChoiceDescription]::new("&File dialog", "Open a file dialog to manually select one or more files to fetch."))

            $SelectedSource = [AutoDetectSelection]$Host.UI.PromptForChoice("Certificate input source", "Select how to fetch certificates", $Choices, 0)
        }

        If ($Quiet -or $SelectedSource -eq [AutoDetectSelection]::ClipboardCert -or $SelectedSource -eq [AutoDetectSelection]::AutoDetect)
        {
            $ClipboardCert = Get-Clipboard -Format Text -Raw
            If (![String]::IsNullOrWhiteSpace($ClipboardCert))
            {
                "Fetching certificate from clipboard" | Write-Verbose -Verbose

                # TODO: Check input data from clipboard. If not valid base64 with or without headers, go to next section instead.

                Try
                {
                    # Attempt to convert clipboard data to Base64 format (including with headers) to straight base 64.
                    $Converted = $X509Converter.StringToString($ClipboardCert, [X509EncodingType]::Any, [X509EncodingType]::Base64)

                    # If the conversion was successful, attempt to convert it to a certificate
                    $Cert = [X509Certificate2]::new([Convert]::FromBase64String($Converted))

                    # Add the certificate to the list
                    $Certs.Add($Cert)
                }
                Catch
                {
                    $Ex = $_.Exception.GetBaseException()
                    $Message = "Failed to convert clipboard text to a certificate."

                    # Write an error with the associated exception information, but suppress it and write a warning instead. This allows
                    # further troubleshooting through inspecting the $Error variable.
                    Write-Error -Message $Message -Exception $Ex -TargetObject $ClipboardCert -ErrorAction SilentlyContinue

                    $Message | Write-Warning
                }
            }
            Else
            {
                # If the clipboard didn't contain any text, we need to check whether the user explicitly selected a single certificate
                # from clipboard. If this is the case, throw an error to indicate it failed, then exit the Process block.
                
                If (!$Quiet -and $SelectedSource -eq [AutoDetectSelection]::ClipboardCert)
                {
                    $Message = "Selected input source (clipboard) did not contain any text."
                    Write-Error -Message $Message
                    return
                }
            }
        }

        If ($Quiet -or $SelectedSource -eq [AutoDetectSelection]::ClipboardFileList -or $SelectedSource -eq [AutoDetectSelection]::AutoDetect)
        {
            # Instead of checking if the previous step succeeded, we can simply attempt to get clipboard data as a file list. Both these formats
            # are mutually exclusive; if the clipboard contained text, this will return null and subsequently not execute, and vice versa.
            $ClipboardFileList = Get-Clipboard -Format FileDropList
            If ($ClipboardFileList -ne $null)
            {
                "Fetching certificates from clipboard file list" | Write-Verbose -Verbose
                $FilelistErrors = $false
                :CertFile Foreach ($CertFile in $ClipboardFileList)
                {
                    If ($CertFile.Attributes.HasFlag([FileAttributes]::Directory))
                    {
                        "'{0}' is a directory; skipping" -f $CertFile.FullName | Write-Warning
                        continue CertFile
                    }
                    Try
                    {
                        # Attempt to parse the certificate from file
                        $Cert = [X509Certificate2]::new($CertFile.FullName)

                        # Add the certificate to the list
                        $Certs.Add($Cert)
                    }
                    Catch
                    {
                        $FilelistErrors = $true
                        $Ex = $_.Exception.GetBaseException()
                        $Message = "Failed to convert '{0}' to a certificate." -f $CertFile.FullName

                        # Write an error with the associated exception information, but suppress it and write a warning instead.
                        Write-Error -Message $Message -Exception $Ex -TargetObject $CertFile -ErrorAction SilentlyContinue

                        $Message | Write-Warning
                    }
                }
                # Check whether there were any errors during processing of the file list. If this is the case, ask the
                # user to for permission to continue.
                If ($FilelistErrors)
                {
                    If (!$PSCmdlet.ShouldContinue("At least one file from the clipboard could not be converted to a certificate. Continue anyway?", "Data mismatch"))
                    {
                        # Clear the Certs list to ensure that the End block doesn't execute any actions.
                        $Certs.Clear()
                        return
                    }
                }
            }
            Else
            {
                # If the clipboard didn't contain any text, we need to check whether the user explicitly selected a single certificate
                # from clipboard. If this is the case, throw an error to indicate it failed, then exit the Process block.
                
                If (!$Quiet -and $SelectedSource -eq [AutoDetectSelection]::ClipboardFileList)
                {
                    $Message = "Selected input source (clipboard) did not contain a file list."
                    Write-Error -Message $Message
                    return
                }
            }
        }

        # Check if the $Certs variable contains any data. If we reach this stage and it is empty, one of the following must be true:

        # 1) The Quiet flag is true, and the clipboard did not contain a valid PEM certificate nor a file list with any valid certificates
        # 2) The Quiet flag is false, the user selected Auto-detect, and the clipboard did not contain a valid PEM certificate nor a file list with any valid certificates
        # 3) The Quiet flag is false, and the user selected File dialog

        # If the Quiet flag is false, the user explicitly selected any of the clipboard options, and that option failed, the code would have exited before this block.
        If ($Certs.Count -eq 0)
        {
            $OFD = [OpenFileDialog]::new()
            $OFD.InitialDirectory = $PSScriptRoot
            $OFD.AutoUpgradeEnabled = $true
            $OFD.Title = "Select certificates"
            $OFD.Filter = "Certificates (*.cer;*.crt)|*.cer;*.crt"
            $OFD.Multiselect = $true
            If ($OFD.ShowDialog() -ne [DialogResult]::OK)
            {
                throw "User cancelled out of file dialog"
            }
            :Certs Foreach ($FileName in $OFD.FileNames)
            {
                Try
                {
                    $Cert = [X509Certificate2]::new($FileName)
                }
                Catch
                {
                    $Ex = $_.Exception.GetBaseException()
                    $Message = "Failed to convert '{0}' to a certificate." -f $FileName
                    Write-Error -Message $Message -Exception $Ex -TargetObject $FileName
                    continue Certs
                }
                $Certs.Add($Cert)
            }
        }
    }
}
End
{
    enum AlternativeNameType {
      Unknown = 0
      OtherName = 1
      Rfc822Name = 2
      DnsName = 3
      X400Address = 4
      DirectoryName = 5
      EdiPartyName = 6
      URL = 7
      IpAddress = 8
      RegisteredId = 9
      Guid = 10
      UserPrincipalName = 11
    }
    $SanExtensionOid = "2.5.29.17"
    $SkiExtensionOid = "2.5.29.14"
    $AltSecIdAttribute = "altSecurityIdentities"

    $UserToCertMapping = [Dictionary[String, List[X509Certificate2]]]::new($CIComparer)

    If ($PSCmdlet.ParameterSetName -ieq "CSV")
    {
        # Get Username and Certificate properties from each entry in the $UserAndCert list
        Foreach ($Pair in $UserAndCert)
        {
            $CertList = $null
            If (!$UserToCertMapping.TryGetValue($Pair.Username, [ref] $CertList))
            {
                $CertList = [List[X509Certificate2]]::new()
                $UserToCertMapping.Add($Pair.Username, $CertList)
            }
            $CertList.Add($Pair.Certificate)
        }

        # Possible enhancement: extract the UPN, find a matching user, ensure that the provided username matches the sAMAccountName of the found account
    }
    Else
    {
        :Cert Foreach ($Cert in $Certs)
        {
            # Get the SAN extension, if present
            $SanExtension = $Cert.Extensions[$SanExtensionOid]
            If ($SanExtension -eq $null)
            {
                $Message = "Certificate issued to '{0}' ({1}) does not contain the Subject Alternative Name ({2}) extension and cannot be processed." -f $Cert.Subject, $Cert.Thumbprint, $SanExtensionOid
                Write-Error -TargetObject $Cert -Message $Message
                continue Cert
            }

            # Attempt to extract the UPN. Only the first UPN present in the extension is considered, in case there are multiple.

            $UPN = $null

            $AlternativeNames = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $AlternativeNames.InitializeDecode(1, [Convert]::ToBase64String($SanExtension.RawData))
            Foreach ($AlternativeName in $AlternativeNames.AlternativeNames)
            {
                If ($AlternativeName.Type -eq [AlternativeNameType]::UserPrincipalName)
                {
                    $UPN = $AlternativeName.strValue
                }
                break
            }
            If ([String]::IsNullOrEmpty($UPN))
            {
                $Message = "Certificate issued to '{0}' ({1}) contains the Subject Alternative Name ({2}) extension but does not contain a User Principal Name and cannot be processed." -f $Cert.Subject, $Cert.Thumbprint, $SanExtensionOid
                Write-Error -TargetObject $Cert -Message $Message
                continue Cert
            }

            # Use the UPN to find a user in the domain

            $User = $null
            $User = Get-ADUser -Server $DC -Filter { userPrincipalName -eq $UPN }
            If ($User -eq $null)
            {
                $Message = "The user principal name '{0}' in the certificate issued to '{1}' ({2}) could not be resolved to a user account in {3}." -f $UPN, $Cert.Subject, $Cert.Thumbprint, $Domain
                Write-Error -TargetObject $Cert -Message $Message
                continue Cert
            }

            # We successfully found a user with the matching UPN. Add the username and the certificate to the $UserToCertMapping dictionary

            $CertList = $null
            If (!$UserToCertMapping.TryGetValue($User.SamAccountName, [ref] $CertList))
            {
                $CertList = [List[X509Certificate2]]::new()
                $UserToCertMapping.Add($User.SamAccountName, $CertList)
            }
            $CertList.Add($Cert)
        }
    }

    # We now have a dictionary containing the sAMAccountName for each applicable user and a list of certificates. Next, we need to
    # create the altSecurityIdentities strings for each user and add them to the accounts.

    # If the dictionary is empty, do nothing
    If ($UserToCertMapping.Count -eq 0)
    {
        return
    }

    # Create an LDAP connection. This is used for the modify operation to enable the PermissiveModify control.
    $LdapIdentifier = [LdapDirectoryIdentifier]::new($DC, 389, $true, $false)
    $Ldap = [LdapConnection]::new($LdapIdentifier)
    $Ldap.AutoBind = $false
    $Ldap.ClientCertificates.Clear()
    $SessionOptions = $Ldap.SessionOptions
    $SessionOptions.LocatorFlag = [LocatorFlags]::WriteableRequired -bor [LocatorFlags]::DirectoryServicesRequired -bor [LocatorFlags]::ForceRediscovery
    $SessionOptions.Signing = $true
    $SessionOptions.Sealing = $true
    $SessionOptions.ProtocolVersion = 3
    $SessionOptions.ReferralChasing = [ReferralChasingOptions]::None
    # Set this callback to always return null. This ensures that client smartcard certificates are not queried needlessly as we authenticate using Kerberos SSO.
    $SessionOptions.QueryClientCertificate = { Param([LdapConnection] $Connection, [Byte[][]] $TrustedCAs) { return $null } }
    $Ldap.Bind()

    # The Permissive Modify control instructs the server to always return Success even if a value was already present in the attribute. This way,
    # we don't have to add each value individually.
    $PermissiveModifyControl = [PermissiveModifyControl]::new()

    :UserCertKvp Foreach ($UserCertKvp in $UserToCertMapping.GetEnumerator())
    {
        $Username = $UserCertKvp.Key
        $UserCertificates = $UserCertKvp.Value

        # Construct the altSecId strings and attempt to set them

        $User = $null
        Try
        {
            $User = Get-ADUser -Identity $Username -Server $DC -Properties altSecurityIdentities -ErrorAction Stop
        }
        Catch
        {
            # Users should already have been resolved at this point, so this should not happen, but do it anyway for hygiene purposes
            $_ | Write-Error
            continue UserCertKvp
        }

        $AltSecIdList = [Dictionary[String, String]]::new($CIComparer)
        $CertList = [Dictionary[String, X509Certificate2]]::new($CIComparer)

        :AltSecId Foreach ($Cert in $UserCertificates)
        {
            $AltSecIdString = $null
            If ($MappingType -ieq "IssuerSerialNumber")
            {
                $Issuer = $Cert.IssuerName.Format($true) -split "`r?`n" -join "," -replace ",$",""
                $ReversedSerial = ($Cert.GetSerialNumber() | % { "{0:X2}" -f $_ }) -join ""
                $AltSecIdString = $IssuerSerialNumberFormat -f $Issuer, $ReversedSerial
            }
            Else
            {
                $SKI = $null
                $SKI = [X509SubjectKeyIdentifierExtension]$Cert.Extensions[$SkiExtensionOid]
                If ($SKI -eq $null)
                {
                    $Message = "The certificate issued to '{0}' ({1}) does not contain the Subject Key Identifier ({2}) extension. The altSecId value cannot be constructed for this certificate." -f $Cert.Subject, $Cert.Thumbprint, $SkiExtensionOid
                    Write-Error -TargetObject $Cert -Message $Message
                    continue AltSecId
                }
                $AltSecIdString = $SKIFormat -f $SKI.SubjectKeyIdentifier
            }
            If (!$AltSecIdList.ContainsKey($Cert.Thumbprint))
            {
                $AltSecIdList.Add($Cert.Thumbprint, $AltSecIdString)
                $CertList.Add($Cert.Thumbprint, $Cert)
            }
            Else
            {
                "Duplicate certificate encountered for user {0} ({1})." -f $User.SamAccountName, $Cert.Thumbprint | Write-Warning
            }
        }

        If ($AltSecIdList.Count -eq 0)
        {
            "Could not construct any valid altSecId strings for user '{0}'. Either no valid certificates were provided for this user, or none of them contained the prerequisite information." -f $Username | Write-Warning
            continue UserCertKvp
        }

        $Operation = [DirectoryAttributeOperation]::Add
        If ($Replace)
        {
            $Operation = [DirectoryAttributeOperation]::Replace
        }

        # Alternate solution: add each value individually for the Add operation, and all-in-one for Replace. This way we get
        # an individual result code for each entry if adding values, indicating whether a value already existed in the list

        $ModifyRequest = [ModifyRequest]::new($User.DistinguishedName, $Operation, $AltSecIdAttribute, [String[]]$AltSecIdList.Values)
        [Void]$ModifyRequest.Controls.Add($PermissiveModifyControl)

        Try
        {
            $Response = [ModifyResponse]$Ldap.SendRequest($ModifyRequest)
        }
        Catch [DirectoryOperationException]
        {
            $Response = [ModifyResponse]$_.Exception.GetBaseException().Response
        }
        Catch
        {
            $Ex = $_.Exception.GetBaseException()
            $Message = "Failed to update object '{0}'." -f $User.SamAccountName
            Write-Error -TargetObject $User.DistinguishedName -Message $Message -Exception $Ex
            continue UserCertKvp
        }

        # Report the result
        Foreach ($Kvp in $AltSecIdList.GetEnumerator())
        {
            [pscustomobject][ordered]@{
                Username = $User.SamAccountName
                SID = $User.SID
                Subject = $CertList[$Kvp.Key].Subject
                Thumbprint = $Kvp.Key
                Value = $Kvp.Value
                Result = $Response.ResultCode
            }
        }
    }
    If ($PSCmdlet.ParameterSetName -ieq "AutoDetect" -and !$Quiet)
    {
        # If the script was run through the "Run with PowerShell" context menu action, or without any parameters at all,
        # we pause the action to allow the caller to inspect the output.
        pause
    }
}