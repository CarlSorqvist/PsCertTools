using namespace System
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.Linq
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text
using namespace System.Text.RegularExpressions

$CertAdmin = New-Object -ComObject CertificateAuthority.Admin
$CertConfig = New-Object -ComObject CertificateAuthority.Config

# Save a compiled list of EKUs and certificates for later export
$Results = [List[Object]]::new()

$Columns = "RawCertificate","CertificateTemplate"
$Disposition = "Disposition"

$AnyPurpose = [Oid]::FromOidValue("2.5.29.37.0", [OidGroup]::EnhancedKeyUsage)
$FormattedAnyPurpose = "{0} ({1})" -f $AnyPurpose.FriendlyName, $AnyPurpose.Value

# Get Enrollment services from AD
$EnrollmentPolicy = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyActiveDirectory
$PolicyServerUrl = "LDAP:"
$EnrollmentPolicy.Initialize($PolicyServerUrl, "", 0, $false, 1) # X509AuthNone(0), ContextUser(1)
$EnrollmentPolicy.LoadPolicy(2) # X509EnrollmentPolicyLoadOption(2) = LoadOptionReload (Always reload)

Foreach ($CA in $EnrollmentPolicy.GetCAs())
{
    $ConfigString = "{0}\{1}" -f $CA.Property(5), $CA.Property(1)

    $CAName = $CertAdmin.GetCAProperty($ConfigString, 6, 0, 4, 0)
    $NormalizedCAName = $CAName -replace "\s",""

    $CertList = [Dictionary[String, X509Certificate2]]::new([StringComparer]::InvariantCultureIgnoreCase) # Thumbprint, List of certificates
    $CertsByEKU = [Dictionary[String, List[X509Certificate2]]]::new([StringComparer]::InvariantCultureIgnoreCase) # EKU, list of certificates
    $TemplateByCertificate = [Dictionary[String, String]]::new([StringComparer]::InvariantCultureIgnoreCase) # Thumbprint, OID/name

    Try
    {
        $CertView = New-Object -ComObject CertificateAuthority.View
        $CertView.OpenConnection($ConfigString)
        $CertView.SetResultColumnCount($Columns.Count)

        Foreach ($RequestColumn in $Columns)
        {
            $ColumnId = $CertView.GetColumnIndex(0, $RequestColumn)
            $CertView.SetResultColumn($ColumnId)
        }
        $DispositionID = $CertView.GetColumnIndex(0, $Disposition)
        $NotAfterID = $CertView.GetColumnIndex(0, "NotAfter")

        # Restrict results to "Issued" requests
        $CertView.SetRestriction($DispositionID, 1, 0, 20)

        # Only find certs that have a NotAfter in the future (i.e. still time valid)
        $CertView.SetRestriction($NotAfterID, 8, 0, [DateTime]::UtcNow)

        $View = $null
        $View = $CertView.OpenView()

        "Retrieving certificates from {0}..." -f $CAName | Write-Verbose -Verbose

        :Row While ($View.Next() -ne -1)
        {
            $RequestCol = $View.EnumCertViewColumn()
            $Row = [pscustomobject][ordered]@{
                Template = $null
                Cert = $null
            }
            :RequestCol While ($RequestCol.Next() -ne -1)
            {
                # If the raw binary request was included in the result, ignore it
                If ($RequestCol.GetName() -eq "Request.RawRequest")
                {
                    continue RequestCol
                }

                If ($RequestCol.GetName() -eq "RawCertificate")
                {
                    $Cert = [X509Certificate2]::new([Convert]::FromBase64String($RequestCol.GetValue(1)))
                    $CertList.Add($Cert.Thumbprint, $Cert)
                    $Row.Cert = $Cert
                }
                If ($RequestCol.GetName() -eq "CertificateTemplate")
                {
                    $Row.Template = $RequestCol.GetValue(2)
                }
            }

            $Template = "<Undefined>"
            If (![String]::IsNullOrWhiteSpace($Row.Template))
            {
                # If the template is not an OID, use it as-is
                $Template = $Row.Template

                # Otherwise, try to resolve the OID
                If ($Row.Template -imatch "^\d(\.\d+)+$")
                {
                    $TemplateOid = [Oid]::new($Row.Template)
                    If (![String]::IsNullOrWhiteSpace($TemplateOid.FriendlyName))
                    {
                        $Template = "{0} ({1})" -f $TemplateOid.FriendlyName, $TemplateOid.Value
                    }
                    Else
                    {
                        $Template = "<Unknown> ({0})" -f $TemplateOid.Value
                    }
                }
            }
            $TemplateByCertificate.Add($Row.Cert.Thumbprint, $Template)

            # Cleanup
            [Void][Marshal]::FinalReleaseComObject($RequestCol)
        }

        "Processing EKUs..." -f $CAName | Write-Verbose -Verbose

        :Cert Foreach ($Certificate in $CertList.Values)
        {
            $EkuExtension = $Certificate.Extensions["2.5.29.37"]
            If ($EkuExtension -ne $null)
            {
                Foreach ($EKUOid in ([X509EnhancedKeyUsageExtension]$EkuExtension).EnhancedKeyUsages)
                {
                    # Construct the EKU OID in a readable format
                    $FriendlyName = "<Unknown>"
                    If (![String]::IsNullOrWhiteSpace($EKUOid.FriendlyName))
                    {
                        $FriendlyName = $EKUOid.FriendlyName
                    }
                    $FormattedValue = "{0} ({1})" -f $FriendlyName, $EKUOid.Value
                
                    $List = $null
                    If (!$CertsByEKU.TryGetValue($FormattedValue, [ref] $List))
                    {
                        $List = [List[X509Certificate2]]::new()
                        $CertsByEKU.Add($FormattedValue, $List)
                    }
                    $List.Add($Certificate)
                }
            }
            Else
            {
                $List = $null
                If (!$CertsByEKU.TryGetValue($FormattedAnyPurpose, [ref] $List))
                {
                    $List = [List[X509Certificate2]]::new()
                    $CertsByEKU.Add($FormattedAnyPurpose, $List)
                }
                $List.Add($Certificate)
            }
        }
        $Line = "Found the following EKUs in {0}:" -f $CAName
        $Line | Write-Host -ForegroundColor Yellow
        "-"*$Line.Length | Write-Host
        Foreach ($Entry in $CertsByEKU.GetEnumerator())
        {
            $EKU = $Entry.Key

            "{0,-10}{1}" -f $Entry.Value.Count, $EKU
        
            Foreach ($Cert in $Entry.Value)
            {
                $Result = [pscustomobject][ordered]@{
                    Issuer = $CAName
                    EKU = $EKU
                    Subject = $Cert.Subject
                    NotBefore = $Cert.NotBefore
                    NotAfter = $Cert.NotAfter
                    Template = $TemplateByCertificate[$Cert.Thumbprint]
                    Thumbprint = $Cert.Thumbprint
                }
                $Results.Add($Result)
            }
        }
    }
    Finally
    {
        # Cleanup
        If ($View -ne $null)
        {
            [Void][Marshal]::FinalReleaseComObject($View)
            $View = $null
        }
        If ($CertView -ne $null)
        {
            [Void][Marshal]::FinalReleaseComObject($CertView)
            $CertView = $null
        }
    }
}

# Export the results

$OutputPath = $PSScriptRoot

$Filename = "EKUsAndCertificates_{0:yyyy-MM-dd_HHmmss}.csv" -f [Datetime]::Now
$FullPath = Join-Path -Path $OutputPath -ChildPath $Filename

"Exporting results to '{0}'" -f $FullPath | Write-Verbose -Verbose
$Results | Export-Csv -LiteralPath $FullPath -NoTypeInformation -Delimiter `t -Encoding Unicode