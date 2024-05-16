#Requires -version 5

using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.Diagnostics.Eventing
using namespace System.DirectoryServices.Protocols
using namespace System.IO
using namespace System.Security.AccessControl
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Principal
using namespace System.Text

[CmdletBinding()]
Param(
    # Plain text file that contains a list of thumbprints, one per row. Should be in ASCII or UTF8 encoding.
    [Parameter(Mandatory = $true)]
    [String]
    $FilePath

    # Should be the fully qualified domain name (FQDN) of the root domain of the forest
    , [Parameter(Mandatory = $true)]
    [String]
    $ForestDomainName

    # If this parameter is provided, a renewed CA certificate that is not in the whitelist is accepted if the thumbprint in
    # the Previous CA Certificate Hash (1.3.6.1.4.1.311.21.2) extension is present in the whitelist.
    # Note that this is only intended as a failsafe - it does not work recursively, i.e. if a CA certificate has been renewed twice,
    # but only the original CA certificate is published in NTAuth, then the first renewed CA certificate will match the original,
    # but the second renewed CA certificate will not match. This is intentional, as admins are expected to react to the logged
    # events and manually publish the first renewed CA certificate to NTAuth after they were first alerted to it being missing.
    , [Parameter(Mandatory = $false)]
    [Switch]
    $AllowImplicitRenewedCertificates

    # There may be cases where the whitelist is completely empty, i.e. it does not contain any thumbprints at all.
    # In such cases, the script will log an error and exit, as it may be an error. This parameter can be used to
    # override that behaviour and allow an empty whitelist, in which case the NTAuth object will be kept empty.
    , [Parameter(Mandatory = $false)]
    [Switch]
    $AllowEmptyWhitelist
)
Begin
{
    enum Events
    {
        CertificateRemoved = 1
        ModifyRequestFailed = 3
        ModifyRequestException = 5
        GenericError = 7
        InvalidWhitelistEntry = 11
        WhitelistLoadFailed = 13
        EmptyWhitelistError = 17
        LdapBindFailed = 19
        RootDseSearchFailed = 23
        EmptyRootDseResult = 29
        RootDseMissingAttribute = 31
        NTAuthSearchFailed = 37
        NTAuthEmptyResult = 41
        NTAuthMissingAttribute = 43
        NTAuthCertificatesEmpty = 47
        AttributeValueError = 53
        ImplicitMappingFound = 59
        WhitelistEntryCleanupRecommended = 61
        ScriptDisabled = 97
    }
    Function Write-ScriptEvent
    {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [EventLogEntryType]
            $EntryType

            , [Parameter(Mandatory = $true)]
            [String]
            $LogName

            , [Parameter(Mandatory = $true)]
            [String]
            $Source

            , [Parameter(Mandatory = $true)]
            [Int16]
            $Category

            , [Parameter(Mandatory = $true)]
            [Events]
            $EventId

            , [Parameter(Mandatory = $true)]
            [String]
            $Message

            , [Parameter(Mandatory = $false)]
            [Object[]]
            $MessageParameters

            , [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
            [System.Management.Automation.ErrorRecord]
            $ErrorRecord
        )
        Process
        {
            # Format the message
            $FormattedMessage = $Message -f $MessageParameters

            $FinalMessage = $FormattedMessage
            If ($ErrorRecord -ne $null)
            {
                $Exception = $ErrorRecord.Exception.GetBaseException()
                $InvInfo = $ErrorRecord.InvocationInfo

                $FinalMessage = "{0}`n`nScript: {1}`nOn line {2}, position {3}, exception of type {4}, message: {5}`n`nStack trace: {6}" -f $FormattedMessage, $InvInfo.ScriptName, $InvInfo.ScriptLineNumber, $InvInfo.OffsetInLine, $Exception.GetType().Name, $Exception.Message, $Exception.StackTrace
            }

            Write-EventLog -LogName $LogName -Source $Source -EntryType $EntryType -Category $Category -EventId ([int]$EventId) -Message $FinalMessage
        }
    }

    $EventLogParams = @{
        LogName = "Application"
        Source = "NTAuthGuard" # Event source. Must match the configured event source in the Startup script that creates the scheduled task
        Category = 0
    }

    # Since this script is triggered by an event by default, we need to account for cases where multiple certificates are added at once (for example,
    # through a Replace operation, where each replaced value is logged as an added entry). If the task is triggered multiple times through multiple events, 
    # we need to throttle it by introducing a short delay before the script executes.

    Start-Sleep -Seconds 2

    $NTAuthContainerDnTemplate = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{0}'
    $PreviousCACertificateHashExtensionOID = "1.3.6.1.4.1.311.21.2"
    $Encoding = [Encoding]::UTF8
    
    # Use the case-insensitive comparer to ensure that upper/lowercase characters in the thumbprint does not matter.
    $StringComparer = [StringComparer]::InvariantCultureIgnoreCase

    # Create a HashSet that will contain the thumbprints in the whitelist for easy lookup.
    $Whitelist = [HashSet[String]]::new($StringComparer)

    # Create a list of existing values in the cACertificates attribute. We need to keep this at hand to determine if a Delete operation
    # is attempting to remove the last value, in which case it needs to be replaced with a single value of \00 instead of deleted, as 
    # the attribute is mandatory.
    $NTAuthCertificateList = [Dictionary[String, X509Certificate2]]::new($StringComparer)

    $Assembly = "System.DirectoryServices.Protocols"
    Try
    {
        Add-Type -AssemblyName $Assembly -ErrorAction Stop
    }
    Catch
    {
        $_ | Write-ScriptEvent @EventLogParams -EntryType Error -EventId GenericError `
                -Message "Failed to load assembly '{0}'. Verify that it exists." `
                -MessageParameters $Assembly
        
        throw
    }

    Try
    {
        :Line Foreach ($Line in [File]::ReadAllLines($FilePath, $Encoding))
        {
            # Ignore empty/whitespace lines
            If ([String]::IsNullOrWhiteSpace($Line))
            {
                continue Line
            }
            
            # Trim excessive whitespace.
            $TrimmedLine = $Line.Trim()

            # Remove non-hexadecimal characters.
            $SanitizedLine = $TrimmedLine -ireplace "[^\da-f]",""
            If ($SanitizedLine.Length -ne 40) # SHA1 thumbprint is 20 byte or 40 hexadecimal characters
            {
                Write-ScriptEvent @EventLogParams -EntryType Warning -EventId InvalidWhitelistEntry `
                    -Message "One of the entries in the whitelist file contains an invalid thumbprint.`n`nOriginal value: '{0}' ({1} characters)`nSanitized value: '{2}' ({3} characters)`n`nEnsure that the thumbprint consists of exactly 40 hexadecimal characters." `
                    -MessageParameters $TrimmedLine, $TrimmedLine.Length, $SanitizedLine, $SanitizedLine.Length
            }
            Else
            {
                If ($Line.Length -ne $SanitizedLine.Length)
                {
                    Write-ScriptEvent @EventLogParams -EntryType Warning -EventId WhitelistEntryCleanupRecommended `
                        -Message "An entry in the whitelist contains one or more invalid characters, but the sanitized value was correctly processed as a valid certificate thumbprint.`n`nOriginal value: '{0}' ({1} characters)`nSanitized value: '{2}' ({3} characters)`n`nPlease clean up any non-hexadecimal characters from the thumbprints, including excessive whitespace." `
                        -MessageParameters $TrimmedLine, $TrimmedLine.Length, $SanitizedLine, $SanitizedLine.Length
                }

                [Void]$Whitelist.Add($SanitizedLine)
            }
        }
    }
    Catch
    {
        $_ | Write-ScriptEvent @EventLogParams -EntryType Error -EventId WhitelistLoadFailed `
                -Message "Failed to load whitelist from file '{0}'." `
                -MessageParameters $FilePath

        throw
    }

    # Check if the whitelist is empty. If it is, do not process NTAuth at all...
    If ($Whitelist.Count -eq 0)
    {
        # ...unless we explicitly allow it
        If (!$AllowEmptyWhitelist)
        {
            Write-ScriptEvent @EventLogParams -EntryType Error -EventId EmptyWhitelistError `
                -Message "Script halted due to an empty whitelist. Verify that the thumbprints in the file at '{0}' are valid, or use the -AllowEmptyWhitelist parameter to bypass this restriction." `
                -MessageParameters $FilePath
            
            throw
        }
    }
    
    # Connect to $ForestDomainName
    $Identifier = [LdapDirectoryIdentifier]::new($ForestDomainName, 389, $false, $false)
    $Ldap = [LdapConnection]::new($Identifier, $null, [AuthType]::Kerberos)
    $Ldap.AutoBind = $false
    $Ldap.ClientCertificates.Clear()
    $SessionOptions = $Ldap.SessionOptions
    $SessionOptions.LocatorFlag = [LocatorFlags]::WriteableRequired -bor [LocatorFlags]::DirectoryServicesRequired -bor [LocatorFlags]::ForceRediscovery
    $SessionOptions.Signing = $true
    $SessionOptions.Sealing = $true
    $SessionOptions.ProtocolVersion = 3
    $SessionOptions.ReferralChasing = [ReferralChasingOptions]::None
    $SessionOptions.QueryClientCertificate = { Param([LdapConnection] $Connection, [Byte[][]] $TrustedCAs) { return $null } }

    Try
    {
        $Ldap.Bind()
    }
    Catch
    {
        $_ | Write-ScriptEvent @EventLogParams -EntryType Error -EventId LdapBindFailed `
                -Message "LDAP bind to '{0}' failed; script cannot continue." `
                -MessageParameters $ForestDomainName

        throw
    }

    # Get configurationNamingContext
    $ConfigNamingContext = "configurationNamingContext"

    $RootDseSearchRequest = [SearchRequest]::new([String]::Empty, "(&(objectClass=*))", [SearchScope]::Base, $ConfigNamingContext)
    Try
    {
        $RootDseSearchResponse = [SearchResponse]$Ldap.SendRequest($RootDseSearchRequest)
    }
    Catch
    {
        $_ | Write-ScriptEvent @EventLogParams -EntryType Error -EventId RootDseSearchFailed `
                -Message "RootDSE search request for '{0}' failed." `
                -MessageParameters $ForestDomainName

        throw
    }
    If ($RootDseSearchResponse.Entries.Count -eq 0)
    {
        Write-ScriptEvent @EventLogParams -EntryType Error -EventId EmptyRootDseResult `
            -Message "RootDSE search request for '{0}' succeeded, but did not return any entries." `
            -MessageParameters $ForestDomainName

        throw
    }
    $RootDse = $RootDseSearchResponse.Entries[0]

    If (!$RootDse.Attributes.Contains($ConfigNamingContext))
    {
        Write-ScriptEvent @EventLogParams -EntryType Error -EventId RootDseMissingAttribute `
            -Message "RootDSE search request for '{0}' did not contain the requested '{1}' attribute." `
            -MessageParameters $ForestDomainName, $ConfigNamingContext

        throw
    }

    $Configuration = $RootDse.Attributes[$ConfigNamingContext][0]
    $NTAuthDn = $NTAuthContainerDnTemplate -f $Configuration
}
Process
{
    # Create a list of CA certificates to remove from NTAuth
    $CertificatesToRemove = [List[X509Certificate2]]::new()

    # The script will not perform any write actions unless this attribute is set on the NTAuthCertificates object. The attribute
    # can have any value, as long as it is set.
    # This allows administrators to enable and disable the script at will across all domain controllers.
    $EnablingAttribute = "adminDisplayName"

    # Fetch the cACertificates attribute of the NTAuth object
    $CertAttribute = "cACertificate"
    $NTAuthSearchRequest = [SearchRequest]::new($NTAuthDn, "(&(objectClass=certificationAuthority))", [SearchScope]::Base, $CertAttribute, $EnablingAttribute)

    Try
    {
        $NTAuthSearchResponse = [SearchResponse]$Ldap.SendRequest($NTAuthSearchRequest)
    }
    Catch
    {
        $_ | Write-ScriptEvent @EventLogParams -EntryType Error -EventId NTAuthSearchFailed `
                -Message "Search request for the object '{0}' failed." `
                -MessageParameters $NTAuthDn

        throw
    }
    If ($NTAuthSearchResponse.Entries.Count -eq 0)
    {
        Write-ScriptEvent @EventLogParams -EntryType Error -EventId NTAuthEmptyResult `
            -Message "Search request for the object '{0}' succeeded, but did not return any entries. This is likely due to an incorrect search filter, or the permissions on the object does not allow the current user to read it." `
            -MessageParameters $NTAuthDn

        throw
    }
    $NTAuth = $NTAuthSearchResponse.Entries[0]

    # Check if the enabling attribute is present in the search result.
    If (!$NTAuth.Attributes.Contains($EnablingAttribute))
    {
        # If the attribute is not present, do not execute any actions, but log an informational event indicating the situation.
        Write-ScriptEvent @EventLogParams -EntryType Information -EventId ScriptDisabled `
            -Message "The '{0}' attribute is not set on {1}. The script will not execute any actions until this attribute has a non-null value, and will continue logging this event until the attribute is set." `
            -MessageParameters $EnablingAttribute, $NTAuthDn

        throw
    }

    # These checks are here for consistency purposes and future compatibility. The cACertificate attribute is mandatory, so by definition it can't be missing or empty.

    If (!$NTAuth.Attributes.Contains($CertAttribute))
    {
        Write-ScriptEvent @EventLogParams -EntryType Error -EventId NTAuthMissingAttribute `
            -Message "Search request for the object '{0}' succeeded, but the returned entry did not contain the requested attribute '{1}'." `
            -MessageParameters $NTAuthDn, $CertAttribute

        throw
    }
    $CACertificatesAttribute = $NTAuth.Attributes[$CertAttribute]

    If ($CACertificatesAttribute.Count -eq 0)
    {
        Write-ScriptEvent @EventLogParams -EntryType Warning -EventId NTAuthCertificatesEmpty `
            -Message "Search request for the object '{0}' succeeded, but the '{1}' attribute is empty; there are no certificates to validate against the whitelist." `
            -MessageParameters $NTAuthDn, $CertAttribute

        throw
    }

    # In environments where NTAuth does not contain any certificates, the attribute is still present but contains a single value equalling '0'. Before we iterate
    # over the certificates (if any) we need to check if this is the case, and simply quit if so as there is nothing to check against.

    If ($CACertificatesAttribute.Count -eq 1)
    {
        # Get the value as a byte[][] array
        $Values = $CACertificatesAttribute.GetValues([byte[]])

        # Check if the first (and only) value is a single byte. If it is, simply exit with no action.
        # We do not log any entries to the event log if this is the case to avoid log bloat.
        If ($Values[0].Length -eq 1)
        {
            return
        }
    }
    
    # Convert each attribute value to an X509Certificate2 object and add it to the dictionary with its thumbprint as key
    :CACert Foreach ($Value in $CACertificatesAttribute.GetValues([byte[]]))
    {
        $Cert = $null
        Try
        {
            $Cert = [X509Certificate2]::new($Value)
        }
        Catch
        {
            # Write warning event. The value could not be converted to a certificate
            # Afterwards, go to the next value

            $_ | Write-ScriptEvent @EventLogParams -EntryType Warning -EventId AttributeValueError `
                    -Message "Failed to convert one of the binary values of the '{0}' attribute to an X509Certificate2 object. Verify that all values are valid certificates." `
                    -MessageParameters $CertAttribute

            continue CACert
        }

        # Add the certificate to the list.
        $NTAuthCertificateList.Add($Cert.Thumbprint, $Cert)

        # Check if the thumbprint is present in the whitelist.
        If (!$Whitelist.Contains($Cert.Thumbprint))
        {
            # The certificate is not present in the whitelist.
            If ($AllowImplicitRenewedCertificates)
            {
                # Check if the certificate has the Previous CA Certificate Hash extension.
                $PreviousCACertificateHashExtension = $Cert.Extensions[$PreviousCACertificateHashExtensionOID]
                If ($PreviousCACertificateHashExtension -ne $null)
                {
                    # Format the hash value and remove any non-hex characters.
                    $PreviousHash = $PreviousCACertificateHashExtension.Format($false) -ireplace "[^\da-f]",""

                    # Check if the previous hash is present in the whitelist.
                    If (!$Whitelist.Contains($PreviousHash))
                    {
                        # If the previous hash is *not* in the whitelist, add the certificate to the remove list.
                        $CertificatesToRemove.Add($Cert)    
                    }
                    Else
                    {
                        # If the previous hash *is* in the whitelist, write a warning event to notify operators that they should add
                        # the new CA certificate to it.

                        Write-ScriptEvent @EventLogParams -EntryType Warning -EventId ImplicitMappingFound `
                            -Message "A CA certificate with subject '{0}' ({1}) was allowed due to having a value in the Previous CA Certificate Hash ({2}) extension that is included the whitelist. This likely means that the CA certificate has been renewed, but the whitelist has not been updated. Please update the whitelist file '{3}' to include the thumbprint of the renewed certificate." `
                            -MessageParameters $Cert.Subject, $Cert.Thumbprint, $PreviousCACertificateHashExtensionOID, $FilePath
                    }
                }
                Else
                {
                    # If the extension is not present, add the certificate to the remove list.
                    $CertificatesToRemove.Add($Cert)
                }
            }
            Else
            {
                # If we do not allow implicit mappings, simply add the certificate to the remove list.
                $CertificatesToRemove.Add($Cert)
            }
        }
    }

    # We now have a list of CA certificates to remove from NTAuth. They can be removed by using the ModifyRequest class.

    # Initialize a byte array with a single value. The value is always initialized to 0.
    $NullValue = [Byte[]]::new(1)

    :NTAuth Foreach ($CACert in $CertificatesToRemove)
    {
        $Operation = [DirectoryAttributeOperation]::Delete
        $Value = $CACert.RawData

        # If we are deleting the last certificate from NTAuth, we need to instead replace it with a null value. Attempting to delete
        # the last value will otherwise cause an ObjectClassViolation error. 
        If ($NTAuthCertificateList.Count -eq 1 -and $NTAuthCertificateList.ContainsKey($CACert.Thumbprint))
        {
            # If there is only one certificate left in the list, and that certificate matches the one we want to remove,
            # we change the operation to Replace and the value to a single byte with value 0.
            $Operation = [DirectoryAttributeOperation]::Replace
            $Value = $NullValue
        }

        $ModifyRequest = [ModifyRequest]::new($NTAuthDn, $Operation, $CertAttribute, $Value)
        $Response = $null

        Try
        {
            $Response = [ModifyResponse]$Ldap.SendRequest($ModifyRequest)
        }
        Catch [DirectoryOperationException]
        {
            $Response = $_.Exception.GetBaseException().Response
        }
        Catch
        {
            $Ex = $_.Exception.GetBaseException()

            $_ | Write-ScriptEvent @EventLogParams -EntryType Error -EventId ModifyRequestException `
                -Message "An exception of type {0} was raised while attempting to remove certificate '{1}' ({2}) from NTAuth. The following exception message was reported: '{3}'" `
                -MessageParameters $Ex.GetType().Name, $CACert.Subject, $CACert.Thumbprint, $Ex.Message

            continue NTAuth
        }

        If ($Response.ResultCode -eq [ResultCode]::Success)
        {
            Write-ScriptEvent @EventLogParams -EntryType Information -EventId CertificateRemoved `
                -Message "A CA certificate with subject '{0}' ({1}) was successfully removed from NTAuth." `
                -MessageParameters $CACert.Subject, $CACert.Thumbprint

            # If the certificate was successfully removed, also remove it from the $NTAuthCertificateList variable.
            $NTAuthCertificateList.Remove($CACert.Thumbprint)
        }
        Else
        {
            Write-ScriptEvent @EventLogParams -EntryType Warning -EventId ModifyRequestFailed `
                -Message "Failed to remove CA certificate with subject '{0}' ({1}) from NTAuth.`n`nResult code: {2}`nError message: {3}" `
                -MessageParameters $CACert.Subject, $CACert.Thumbprint, $Response.ResultCode, $Response.ErrorMessage
        }
    }
}
End
{
    If ($Ldap -ne $null)
    {
        $Ldap.Dispose()
        $Ldap = $null
    }
}