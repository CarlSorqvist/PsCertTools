#Requires -version 5

using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.DirectoryServices.Protocols
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Windows.Forms
using module ActiveDirectory

[CmdletBinding(DefaultParameterSetName = "Dialog")]
Param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Domain = $env:USERDNSDOMAIN

    , [Parameter(Mandatory = $false)]
    [Switch]
    $Replace
    
    , [Parameter(Mandatory = $false)]
    [ValidateSet("IssuerSerialNumber","SubjectKeyIdentifier")]
    [String]
    $MappingType = "IssuerSerialNumber"

    , [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Clipboard")]
    [Switch]
    $FromClipboard

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
            Write-Error -Message $Message -Exception $Ex
            return
        }
        $Certs.Add($Cert)
    }
    ElseIf ($PSCmdlet.ParameterSetName -ieq "Clipboard")
    {
        Try
        {
            # Attempt to get text from clipboard
            $ClipboardCert = Get-Clipboard -Format Text -Raw

            # Attempt to convert clipboard data to Base64 format (including with headers) to straight base 64.
            $Converted = $X509Converter.StringToString($ClipboardCert, [X509EncodingType]::Base64Any, [X509EncodingType]::Base64)

            # If the conversion was successful, 
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
    ElseIf ($PSCmdlet.ParameterSetName -ieq "Base64Cert")
    {
        Try
        {
            # Attempt to convert the input string from any Base64 format (including with headers) to straight base 64.
            $Converted = $X509Converter.StringToString($Base64Cert, [X509EncodingType]::Base64Any, [X509EncodingType]::Base64)

            # If the conversion was successful, 
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
                Write-Error -TargetObject $TrimmedUserName -Message $Message
            }
        }
        If ($UserExists)
        {
            Try
            {
                # When present in a CSV, only straight base 64 format is supported
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
                Write-Error -Message $Message -Exception $Ex
                continue Certs
            }
            $Certs.Add($Cert)
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

        $User = Get-ADUser -Identity $Username -Server $DC -Properties altSecurityIdentities

        $AltSecIdList = [Dictionary[String, String]]::new($CIComparer)

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
            $AltSecIdList.Add($Cert.Thumbprint, $AltSecIdString)
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
                Thumbprint = $Kvp.Key
                Value = $Kvp.Value
                Result = $Response.ResultCode
            }
        }
    }
}