﻿using namespace System.Collections.Generic

$RootDSE = Get-ADRootDSE
$Configuration = $RootDSE.configurationNamingContext

$EnrollmentServicesContainer = "CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}" -f $Configuration
$TemplatesContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}" -f $Configuration

# Get templates, add to lookup
$TemplateLookup = [Dictionary[String, Object]]::new([System.StringComparer]::CurrentCultureIgnoreCase)
Foreach ($ADTemplate in Get-ADObject -SearchBase $TemplatesContainer -Filter { objectClass -eq "pKICertificateTemplate" } -Properties *)
{
    $TemplateLookup.Add($ADTemplate.Name, $ADTemplate)
}

$CAs = Get-ADObject -SearchBase $EnrollmentServicesContainer -Filter { objectClass -eq "pKIEnrollmentService" } -Properties certificateTemplates

Foreach ($CA in $CAs)
{
    Foreach ($CATemplate in $CA.certificateTemplates)
    {
        $Template = $null
        If ($TemplateLookup.TryGetValue($CATemplate, [ref] $Template))
        {
            $EKUs = [List[System.Security.Cryptography.Oid]]::new()
            Foreach ($EKU in $Template.pKIExtendedKeyUsage)
            {
                $Oid = [System.Security.Cryptography.Oid]::new($EKU)
                $EKUs.Add($Oid)
            }
            
            [pscustomobject][ordered]@{
                CA = $CA.Name
                Template = $Template.Name
                DisplayName = $Template.DisplayName
                SITR = ($Template.'msPKI-Certificate-Name-Flag' -band 0x1) -eq 0x1
                ReqApproval = ($Template.'msPKI-Enrollment-Flag' -band 0x2) -eq 0x2
                EKU = ($EKUs | Sort-Object -Property FriendlyName | Select-Object -ExpandProperty FriendlyName) -join ";"
            }
        }
        Else
        {
            "Orphaned template '{0}' on CA '{1}'" -f $CATemplate, $CA.Name | Write-Warning
        }
    }
}
