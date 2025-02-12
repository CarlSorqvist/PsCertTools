$RootDSE = Get-ADRootDSE
$Configuration = $RootDSE.configurationNamingContext
$TemplatesContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}" -f $Configuration

$AutoEnrollExtendedRightGuid = [Guid]::new("a05b8cc2-17bc-4802-a710-e7c15ab866a2")
$EnrollExtendedRightGuid = [Guid]::new("0e10c968-78fb-11d2-90d4-00c04f79dc55")

$TemplateNameFilter = "*"
$Templates = Get-ADObject -SearchBase $TemplatesContainer -Filter { name -like $TemplateNameFilter } -Properties msPKI-Cert-Template-OID, nTSecurityDescriptor, displayName

$Results = [System.Collections.Generic.List[Object]]::new()
Foreach ($Template in $Templates)
{
    $SD = $Template.nTSecurityDescriptor

    $AccessRules = $SD.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

    Foreach ($Rule in $AccessRules)
    {
        $Permission = ""
        If ($Rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight))
        {
            If ($Rule.ObjectType -eq $EnrollExtendedRightGuid)
            {
                $Permission = "Enroll"
            }
            ElseIf ($Rule.ObjectType -eq $AutoEnrollExtendedRightGuid)
            {
                $Permission = "AutoEnroll"
            }
        }
        $Obj = [pscustomobject][ordered]@{
            Name = $Template.Name
            Owner = $SD.Owner
            Group = $SD.Group
            Principal = $Rule.IdentityReference
            Rights = $Rule.ActiveDirectoryRights
            ExtendedRight = $Permission
        }
        $Results.Add($Obj)
    }
}
$Results | Export-Csv -LiteralPath C:\temp\templates.csv -Delimiter `t -Encoding Unicode -NoTypeInformation