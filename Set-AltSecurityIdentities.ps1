#Requires -version 5

using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Windows.Forms
using module ActiveDirectory

[CmdletBinding(DefaultParameterSetName = "Dialog")]
Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Identity
    
    , [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Domain = $env:USERDNSDOMAIN
    
    , [Parameter(Mandatory = $false)]
    [ValidateSet("IssuerSerialNumber","SubjectKeyIdentifier")]
    [String]
    $MappingType = "IssuerSerialNumber"

    , [Parameter(Mandatory = $false)]
    [Switch]
    $Replace

    , [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Certificate")]
    [X509Certificate2]
    $Certificate

    , [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "File")]
    [FileInfo]
    $File
)
Begin
{
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    $Certs = [List[X509Certificate2]]::new()
    $User = Get-ADUser -Identity $Identity -Server $Domain -Properties altSecurityIdentities -ErrorAction Stop
}
Process
{
    If ($PSCmdlet.ParameterSetName -ieq "Certificate")
    {
        $Certs.Add($Certificate)
    }
    ElseIf ($PSCmdlet.ParameterSetName -ieq "File")
    {
        $Cert = [X509Certificate2]::new($File.FullName)
        $Certs.Add($Cert)
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
        Foreach ($FileName in $OFD.FileNames)
        {
            $Cert = [X509Certificate2]::new($FileName)
            $Certs.Add($Cert)
        }
    }
}
End
{
    $AltSecId = [List[String]]::new()
    $IssuerSerialNumberFormat = "X509:<I>{0}<SR>{1}"
    $SKIFormat = "X509:<SKI>{0}"
    Foreach ($Cert in $Certs)
    {
        If ($MappingType -ieq "IssuerSerialNumber")
        {
            $Issuer = $Cert.IssuerName.Format($true) -split "`r?`n" -join "," -replace ",$",""
            $ReversedSerial = ($Cert.GetSerialNumber() | % { "{0:X2}" -f $_ }) -join ""
            $IssuerSerialString = $IssuerSerialNumberFormat -f $Issuer, $ReversedSerial
            "Adding '{0}'" -f $IssuerSerialString | Write-Verbose
            $AltSecId.add($IssuerSerialString)
        }
        Else
        {
            $SKI = $null
            $SKI = [X509SubjectKeyIdentifierExtension]$Cert.Extensions["2.5.29.14"]
            If ($SKI -eq $null)
            {
                throw "Could not find the SubjectKeyIdentifier extension on certificate with thumbprint {0}." -f $Cert.Thumbprint
            }
            $SKIString = $SKIFormat -f $SKI.SubjectKeyIdentifier
            "Adding '{0}'" -f $SKIString | Write-Verbose
            $AltSecId.Add($SKIString)
        }
    }
    $Hash = @{altSecurityIdentities = $AltSecId.ToArray()}
    $Operation = "Add"
    If ($Replace)
    {
        $Operation = "Replace"
        If ($User.altSecurityIdentities -ne $null -and $User.altSecurityIdentities.Count -gt 0)
        {
            "Replacing the following altSecurityIdentities values on user {0}:`n`n{1}" -f $User.DistinguishedName, ($User.altSecurityIdentities -join "`n") | Write-Warning
        }
    }
    $Params = @{$Operation = $Hash}
    $User | Set-ADUser -Server $Domain @Params
}