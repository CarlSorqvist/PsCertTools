using namespace System
using namespace System.DirectoryServices
using namespace System.DirectoryServices.Protocols
using namespace System.Security
using namespace System.Security.AccessControl
using namespace System.Security.Principal
using module ActiveDirectory
     
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

$NTAuthDelegationGroupName = "d0_pki_ntauth_cacert__w"

Try
{
    $Everyone = [SecurityIdentifier]::new([WellKnownSidType]::WorldSid, $null)
    $SDControl = [SecurityDescriptorFlagControl]::new([Protocols.SecurityMasks]::Dacl -bor [Protocols.SecurityMasks]::Sacl)
    $NTSecDesc = "nTSecurityDescriptor"

    $RootDSE = Get-ADRootDSE 
    $Configuration = $RootDSE.configurationNamingContext
    $Schema = $RootDSE.schemaNamingContext
    $Forest = Get-ADForest

    "Target forest {0}" -f $Forest.Name | Write-Host -ForegroundColor Yellow

    $DC = Get-ADDomainController -DomainName $Forest.RootDomain -ForceDiscover -Writable -Discover | Select-Object -ExpandProperty HostName -First 1

    "Using domain controller {0}" -f $DC | Write-Host -ForegroundColor Yellow

    $NTAuthDN = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{0}' -f $Configuration

    "Target object {0}" -f $NTAuthDN | Write-Host -ForegroundColor Yellow

    "Querying schema..." | Write-Host -ForegroundColor Yellow

    $CACertificatesAttribute = Get-ADObject -SearchBase $Schema -Filter { attributeID -eq "2.5.4.37" } -Properties lDAPDisplayName, schemaIDGUID -Server $DC
    $CACertificatesAttributeGuid = [guid]::new($CACertificatesAttribute.schemaIDGUID)

    "Found attribute '{0}' with schemaIDGUID {1}" -f $CACertificatesAttribute.lDAPDisplayName, $CACertificatesAttributeGuid | Write-Host -ForegroundColor Yellow

    "Retrieving group '{0}'" -f $NTAuthDelegationGroupName | Write-Host -ForegroundColor Yellow

    $Group = $null
    $Group = Get-ADGroup -Identity $NTAuthDelegationGroupName -Server $DC -ErrorAction Stop

    "Establishing LDAP connection to '{0}'" -f $DC | Write-Host -ForegroundColor Yellow

    $Identifier = [LdapDirectoryIdentifier]::new($DC, 389, $true, $false)
    $Ldap = [LdapConnection]::new($Identifier, $null, [AuthType]::Kerberos)
    $Ldap.AutoBind = $false
    $Ldap.ClientCertificates.Clear()
    $Ldap.SessionOptions.Signing = $true
    $Ldap.SessionOptions.Sealing = $true
    $Ldap.SessionOptions.ProtocolVersion = 3
    $Ldap.SessionOptions.ReferralChasing = [ReferralChasingOptions]::None
    $Ldap.SessionOptions.QueryClientCertificate = { Param([LdapConnection] $Connection, [Byte[][]] $TrustedCAs) { return $null } }
    $Ldap.Bind()

    "Retrieving security descriptor for '{0}'..." -f $NTAuthDN | Write-Host -ForegroundColor Yellow

    $SDReq = [SearchRequest]::new($NTAuthDN, "(&(objectClass=*))", [Protocols.SearchScope]::Base, $NTSecDesc)
    [Void]$SDReq.Controls.Add($SDControl)
    $SDResponse = [SearchResponse]$Ldap.SendRequest($SDReq)
    $BinarySD = $SDResponse.Entries[0].Attributes[$NTSecDesc].GetValues([byte[]])[0]
    $SD = [ActiveDirectorySecurity]::new()
    $SD.SetSecurityDescriptorBinaryForm($BinarySD)

    "Adding audit rule" | Write-Host -ForegroundColor Yellow

    $AuditRule = [ActiveDirectoryAuditRule]::new($Everyone, [ActiveDirectoryRights]::WriteProperty, [AuditFlags]::Success, $CACertificatesAttributeGuid)
    $SD.AddAuditRule($AuditRule)

    "Adding WriteProperty rule for '{0}'" -f $NTAuthDelegationGroupName | Write-Host -ForegroundColor Yellow
    $AccessRule = [PropertyAccessRule]::new($Group.SID, [AccessControlType]::Allow, [PropertyAccess]::Write, $CACertificatesAttributeGuid)
    $SD.AddAccessRule($AccessRule)

    $NewBinarySD = $SD.GetSecurityDescriptorBinaryForm()

    $Message = "About to update security descriptor on object '{0}'. Press Enter to continue or Ctrl + C to abort" -f $NTAuthDN
    Read-Host -Prompt $Message | Out-Null
    
    "Updating security descriptor" | Write-Host -ForegroundColor Yellow
    $ModReq = [ModifyRequest]::new($NTAuthDN, [DirectoryAttributeOperation]::Replace, $NTSecDesc, $NewBinarySD)
    [Void]$ModReq.Controls.Add($SDControl)
    $Ldap.SendRequest($ModReq)
}
Catch
{
    throw
}