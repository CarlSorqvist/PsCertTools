#Requires -version 5 -runasadministrator

Function New-PrivateKey
{
    [CmdletBinding(DefaultParameterSetName = "RSA")]
    [OutputType([System.Security.Cryptography.RSACng], ParameterSetName = "RSA")]
    [OutputType([System.Security.Cryptography.ECDsaCng], ParameterSetName = "ECC")]
    Param
    (
        [Parameter(Mandatory = $false, ParameterSetName = "RSA")]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(512, [Int32]::MaxValue)]
        [Int32]
        $RsaKeySize = 2048

        , [Parameter(Mandatory = $false, ParameterSetName = "ECC")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("ECDSA_P256","ECDSA_P384","ECDSA_P521","ECDH_P256","ECDH_P384","ECDH_P521")]
        [System.Security.Cryptography.CngAlgorithm]
        $EccAlgorithm = [System.Security.Cryptography.CngAlgorithm]::ECDiffieHellmanP256

        , [Parameter(Mandatory = $false)]
        [String]
        $KeyName

        , [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Security.Cryptography.CngProvider]
        $Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider

        , [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Security.Cryptography.CngKeyUsages]
        $KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages

        , [Parameter(Mandatory = $false)]
        [ValidateNotNull()]
        [System.Security.Cryptography.CngExportPolicies]
        $ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport

        , [Parameter(Mandatory = $false)]
        [Switch]
        $MachineKey

        , [Parameter(Mandatory = $false)]
        [Switch]
        $OverwriteExistingKey
    )
    Begin
    {
        $KeyParams = [System.Security.Cryptography.CngKeyCreationParameters]::new()
        $KeyParams.Provider = $Provider
        $KeyParams.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::None
        $KeyParams.ExportPolicy = $ExportPolicy
        $KeyParams.KeyUsage = $KeyUsage

        If ($PSCmdlet.ParameterSetName -eq "RSA")
        {
            $KeySize = [BitConverter]::GetBytes($RsaKeySize)
            $KeyLengthProperty = [System.Security.Cryptography.CngProperty]::new("Length", $KeySize, [System.Security.Cryptography.CngPropertyOptions]::None)
            $KeyParams.Parameters.Add($KeyLengthProperty)
            $Algorithm = [System.Security.Cryptography.CngAlgorithm]::Rsa
        }
        Else
        {
            $Algorithm = [System.Security.Cryptography.CngAlgorithm]$EccAlgorithm
        }
    }
    Process
    {
        If ($MachineKey)
        {
            $KeyParams.KeyCreationOptions = $KeyParams.KeyCreationOptions -bor [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
        }
        If ($OverwriteExistingKey)
        {
            $KeyParams.KeyCreationOptions = $KeyParams.KeyCreationOptions -bor [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
        }
        If ([String]::IsNullOrEmpty($KeyName))
        {
            # Ephemeral key (in-memory only, no key name)
            $Key = [System.Security.Cryptography.CngKey]::Create($Algorithm, [NullString]::Value, $KeyParams)
        }
        Else
        {
            # Persistent key, stored in the selected provider
            $Key = [System.Security.Cryptography.CngKey]::Create($Algorithm, $KeyName, $KeyParams)
        }
        If ($PSCmdlet.ParameterSetName -eq "RSA")
        {
            [System.Security.Cryptography.RSACng]::new($Key)
        }
        Else
        {
            [System.Security.Cryptography.ECDsaCng]::new($Key)
        }
    }
}

Function New-SubjectAlternativeNameExtension
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Extension])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $DnsName

        , [Parameter(Mandatory = $false)]
        [String[]]
        $EmailAddress

        , [Parameter(Mandatory = $false)]
        [System.Net.IPAddress[]]
        $IPAddress

        , [Parameter(Mandatory = $false)]
        [Uri[]]
        $Uri

        , [Parameter(Mandatory = $false)]
        [String[]]
        $UserPrincipalName
    )
    Process
    {
        "The New-SubjectAlternativeNameExtension cmdlet is obsolete. Please use the DnsName, EmailAddress, IPAddress, Uri and/or UserPrincipalName of the New-CertificateRequest or Submit-CertificateRequest cmdlets instead." | Write-Warning
        $SANBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        If ($PSBoundParameters.ContainsKey("DnsName"))
        {
            Foreach ($Value in $DnsName)
            {
                $SANBuilder.AddDnsName($Value)
            }
        }
        If ($PSBoundParameters.ContainsKey("EmailAddress"))
        {
            Foreach ($Value in $EmailAddress)
            {
                $SANBuilder.AddEmailAddress($Value)
            }
        }
        If ($PSBoundParameters.ContainsKey("IPAddress"))
        {
            Foreach ($Value in $IPAddress)
            {
                $SANBuilder.AddIpAddress($Value)
            }
        }
        If ($PSBoundParameters.ContainsKey("Uri"))
        {
            Foreach ($Value in $Uri)
            {
                $SANBuilder.AddUri($Value)
            }
        }
        If ($PSBoundParameters.ContainsKey("UserPrincipalName"))
        {
            Foreach ($Value in $UserPrincipalName)
            {
                $SANBuilder.AddUserPrincipalName($Value)
            }
        }
        $SANBuilder.Build($false)
    }
}

Function Import-CertificateRequest
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [Alias("Filename", "FilePath")]
        [String]
        $Path

        , [Parameter(Mandatory = $false)]
        [Alias("ShowContent")]
        [Switch]
        $Dump
    )
    Process
    {
        $Converter = [CERTENROLLlib.CBinaryConverterClass]::new()
        If ([String]::IsNullOrEmpty($Path))
        {
            $OFD = [System.Windows.Forms.OpenFileDialog]::new()
            $OFD.Title = "Select CSR to import"
            $OFD.InitialDirectory = $PSCmdlet.SessionState.Path.CurrentFileSystemLocation
            $OFD.RestoreDirectory = $true
            $OFD.Filter = "Certificate request (*.csr;*.req;*.txt)|*.csr;*.req;*.txt"
            If ($OFD.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK)
            {
                throw "User cancelled out of file dialog"
            }
            $Path = $OFD.FileName
        }

        If ($Dump)
        {
            certutil -dump $Path | Out-Host
        }

        # Try reading the file as text first
        Try
        {
            $Contents = [System.IO.File]::ReadAllText($Path)
            
            # Because a binary file can often be read as plain text, we don't know if it is in text or not.
            # However, we can assume that the input is base64 encoded with headers, and attempt to convert it to the same format. If it fails, it is not the correct format.

            $Result = $Converter.StringToString($Contents, [CERTENClib.EncodingType]::XCN_CRYPT_STRING_BASE64REQUESTHEADER, [CERTENClib.EncodingType]::XCN_CRYPT_STRING_BASE64REQUESTHEADER)
            
            # If the conversion was successful, simply return the initial contents as it is properly formatted.
            return $Contents
        }
        Catch
        {
            # Do nothing
        }

        # Next, as a fallback option, attempt to read the file as binary. 
        
        Try
        {
            $Contents = [System.IO.File]::ReadAllBytes($Path)

            # This time, we assume that the input is ASN encoded data. If it is incorrectly formatted, it will fail.
            $Result = [System.Security.Cryptography.AsnEncodedData]::new($Contents)
            
            # If the ASN parsing succeeded, we have properly formatted data. Convert it to base64 and add headers.
            return $Converter.StringToString([Convert]::ToBase64String($Contents), [CERTENClib.EncodingType]::XCN_CRYPT_STRING_BASE64, [CERTENClib.EncodingType]::XCN_CRYPT_STRING_BASE64REQUESTHEADER)
        }
        Catch
        {
            throw
        }
    }
}

Function Show-X509Object
{
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [Alias("Filename", "FilePath")]
        [String]
        $Path
    )
    Process
    {
        If ([String]::IsNullOrEmpty($Path))
        {
            $OFD = [System.Windows.Forms.OpenFileDialog]::new()
            $OFD.Title = "Select request, certificate, or other X509 object to display"
            $OFD.InitialDirectory = $PSCmdlet.SessionState.Path.CurrentFileSystemLocation
            $OFD.RestoreDirectory = $true
            $OFD.Filter = "X509 objects (*.csr;*.req;*.txt;*.cer;*.crt;*.crl;*.pem;*.key)|*.csr;*.req;*.txt;*.cer;*.crt;*.crl;*.pem;*.key"
            If ($OFD.ShowDialog() -ne [Windows.Forms.DialogResult]::OK)
            {
                throw "User cancelled out of file dialog"
            }
            $Path = $OFD.FileName
        }
        certutil -dump $Path | Out-Host
    }
}

Function Get-X509Chain
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )
    Process
    {
        $Chain = [System.Security.Cryptography.X509Certificates.X509Chain]::Create()
        $Chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $Chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllFlags
        $Result = $Chain.Build($Certificate)
        $Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        Foreach ($Element in $Chain.ChainElements)
        {
            $PSCmdlet.WriteObject($Element.Certificate, $true)
        }
    }
}

Function ConvertTo-Pem
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )
    Begin
    {
        $StringBuilder = [System.Text.StringBuilder]::new()
        $Converter = [CERTENROLLlib.CBinaryConverterClass]::new()
    }
    Process
    {
        $Base64Cert = [Convert]::ToBase64String($Certificate.RawData)
        $Base64WithHeaders = $Converter.StringToString($Base64Cert, [CERTENClib.EncodingType]::XCN_CRYPT_STRING_BASE64, [CERTENClib.EncodingType]::XCN_CRYPT_STRING_BASE64HEADER)
        [Void]$StringBuilder.Append($Base64WithHeaders)
    }
    End
    {
        $StringBuilder.ToString()
    }
}

Function Get-ExtendedKeyUsage
{
    [CmdletBinding(DefaultParameterSetName = "All")]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "PatternMatch", ValueFromPipeline = $true)]
        [Alias("EKU")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name

        , [Parameter(Mandatory = $false)]
        [Switch]
        $Select
    )
    Process
    {
        $OidList = $null
        If ($PSCmdlet.ParameterSetName -ieq "All")
        {
            $OidList = [System.Collections.Generic.List[System.Security.Cryptography.Oid]]::new([System.Security.Cryptography.Oid[]][X509Extensions.ExtendedKeyUsage]::SystemOidList)
        }
        Else
        {
            $OidList = [X509Extensions.ExtendedKeyUsage]::FindMatchingOids($Name)
        }
        If ($Select)
        {
            $OidList | Out-GridView -OutputMode Multiple
        }
        Else
        {
            $OidList | Sort-Object -Property FriendlyName
        }
    }
}

Function New-SidExtension
{
    [CmdletBinding(DefaultParameterSetName = "Sid")]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "Sid")]
        [System.Security.Principal.SecurityIdentifier]
        $Sid

        , [Parameter(Mandatory = $true, ParameterSetName = "NTAccount")]
        [System.Security.Principal.NTAccount]
        $NTAccount
    )
    Process
    {
        If ($PSCmdlet.ParameterSetName -ieq "NTAccount")
        {
            Try
            {
                $Sid = $NTAccount.Translate([System.Security.Principal.SecurityIdentifier])
            }
            Catch
            {
                throw
            }
        }
        [System.Security.Cryptography.X509Certificates.X509Extension]::new("1.3.6.1.4.1.311.25.2", [X509Extensions.SidExtension]::Encode($Sid), $false)
    }
}

Function Get-CAConfigString
{
    [CmdletBinding(DefaultParameterSetName = "Select")]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Lookup")]
        [Alias("Name","DnsHostName")]
        [String]
        $ComputerName
    )
    Process
    {
        If ($PSCmdlet.ParameterSetName -ieq "Select")
        {
            $Config = [CERTCLIlib.CCertConfigClass]::new()
            $Config.GetConfig(1) # 1 = display a list of published CAs and let the user select one
        }
        Else
        {
            Try
            {
                $CCertAdmin = [CERTADMIN.CCertAdminClass]::new()
                $CAName = $CCertAdmin.GetConfigEntry($ComputerName, $null, "Active")
                $CADirtyName = "{0}\{1}" -f $ComputerName, $CAName
                $CADnsName = $CCertAdmin.GetConfigEntry($CADirtyName, $null, "CAServerName")
                $CACleanName = "{0}\{1}" -f $CADnsName, $CAName
                $CACleanName
            }
            Catch
            {
                throw
            }
        }
    }
}

Function Get-IssuedCertificate
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param(
        [Parameter(Mandatory = $true)]
        [String]
        $ConfigString

        , [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Int32]
        $RequestId
    )
    Process
    {
        $Req = [CERTCLIlib.CCertRequestClass]::new()
        $Disposition = [RequestDisposition]$Req.GetIssuedCertificate($ConfigString, $RequestId, $null)
        If ($Disposition -ne [RequestDisposition]::Issued)
        {
            throw "Request {0}, disposition: {1}. If the disposition is Denied, the provided RequestID may not exist in the CA." -f $RequestId, $Disposition
        }
        $Base64 = $Req.GetCertificate(1)
        $PSCmdlet.WriteObject([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($Base64)), $true)
    }
}

Function Export-CertificateToPfx
{
    [CmdletBinding(DefaultParameterSetName = "Password")]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate

        , [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutputDirectory = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)

        , [Parameter(Mandatory = $false)]
        [Switch]
        $ShowFileDialog

        , [Parameter(Mandatory = $false)]
        [Switch]
        $NoChain

        , [Parameter(Mandatory = $true, ParameterSetName = "Principal")]
        [String[]]
        $ProtectTo

        , [Parameter(Mandatory = $true, ParameterSetName = "Password")]
        [securestring]
        $Password

        , [Parameter(Mandatory = $true, ParameterSetName = "Generate")]
        [Switch]
        $GeneratePassword
    )
    Process
    {
        If (!$Certificate.HasPrivateKey)
        {
            throw "Provided certificate does not have a private key. This cmdlet can only be used to export a certificate where the private key was generated within the script."
        }
        If (![System.IO.Directory]::Exists($OutputDirectory))
        {
            $MyDocuments = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)
            "Attempting to create directory '{0}'..." -f $OutputDirectory | Write-Verbose
            Try
            {
                [System.IO.Directory]::CreateDirectory($OutputDirectory)
            }
            Catch
            {
                "Failed to create output directory {0}, defaulting to user Documents folder {1}" -f $OutputDirectory, $MyDocuments | Write-Warning
                $OutputDirectory = $MyDocuments
            }
        }
        $OutputFilename = $null
        If ($ShowFileDialog)
        {
            $SFD = [System.Windows.Forms.SaveFileDialog]::new()
            $SFD.Title = "Select file name for PFX archive"
            $SFD.AddExtension = $true
            $SFD.DefaultExt = "pfx"
            $SFD.FileName = "{0}.{1}" -f $Certificate.Thumbprint, $SFD.DefaultExt
            $SFD.InitialDirectory = $OutputDirectory
            $SFD.RestoreDirectory = $true
            $SFD.OverwritePrompt = $true
            $SFD.Filter = "PFX Archives (*.pfx)|*.pfx"
            If ($SFD.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK)
            {
                # Because this may be the last cmdlet in the pipeline and the private key may be lost if this function fails,
                # we generate a random filename based on the thumbprint and timestamp
                
                "User cancelled out of file dialog, generating unique filename" | Write-Warning
                $Filename = "{0}_{1:yyyy-MM-dd_HHmmssfff}.pfx" -f $Certificate.Thumbprint, [Datetime]::Now
                $OutputFilename = [System.IO.Path]::Combine($OutputDirectory, $Filename)
            }
            Else
            {
                $OutputFilename = $SFD.FileName
            }
        }
        Else
        {
            # If ShowFileDialog was not set, generate a filename based on the thumbprint and timestamp
            # We add the timestamp in case 
            $Filename = "{0}_{1:yyyy-MM-dd_HHmmssfff}.pfx" -f $Certificate.Thumbprint, [Datetime]::Now
            $OutputFilename = [System.IO.Path]::Combine($OutputDirectory, $Filename)
        }

        $ChainOption = [Microsoft.CertificateServices.Commands.ExportChainOption]::BuildChain
        If ($NoChain)
        {
            $ChainOption = [Microsoft.CertificateServices.Commands.ExportChainOption]::EndEntityCertOnly
        }
        $PfxData = [Microsoft.CertificateServices.Commands.PfxData]::new()
        $PfxData.EndEntityCertificates = [System.Security.Cryptography.X509Certificates.X509Certificate2[]]::new(1)
        $PfxData.EndEntityCertificates[0] = $Certificate

        $Properties = @{
            FilePath = $OutputFilename
            ChainOption = $ChainOption
            CryptoAlgorithmOption = [Microsoft.CertificateServices.Commands.CryptoAlgorithmOptions]::AES256_SHA256
            Force = $true
        }
        $Credential = $null
        $Principal = $null
        Switch ($PSCmdlet.ParameterSetName)
        {
            "Password"
            {
                $Credential = [System.Net.NetworkCredential]::new($null, $Password)
                $Properties.Add("Password", $Credential.SecurePassword)
                break;
            }
            "Generate"
            {
                $PfxPassword = New-StrongPassword -Length 16
                $Credential = [System.Net.NetworkCredential]::new($null, $PfxPassword)
                $Properties.Add("Password", $Credential.SecurePassword)
                break;
            }
            "Principal"
            {
                $Principal = $ProtectTo
                $Credential = [System.Net.NetworkCredential]::new($null, $null)
                $Properties.Add("ProtectTo", $ProtectTo)
                break;
            }
        }

        Try
        {
            "Exporting PFX to directory {0}" -f $OutputDirectory | Write-Verbose
            $PfxFile = $PfxData | Export-PfxCertificate @Properties -ErrorAction Stop

            [PfxCertificateInfo]::new($PfxFile, $Principal, $Credential.SecurePassword, $Credential.Password)
        }
        Catch
        {
            # TODO: Add inner exception
            "Failed to save PFX data to the file '{0}'. To recover the certificate, use Get-LastSubmissionResult; to recover the private key, use Get-LastRequestAndKey." -f $OutputFilename | Write-Error
        }
    }
}

Function Export-PemCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate

        , [Parameter(Mandatory = $false)]
        [Alias("FullChain", "FullResponse")]
        [Switch]
        $IncludeChain

        , [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutputDirectory = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)

        , [Parameter(Mandatory = $false)]
        [Switch]
        $ShowFileDialog

        , [Parameter(Mandatory = $false)]
        [Switch]
        $CopyToClipboard
    )
    Process
    {
        If (![System.IO.Directory]::Exists($OutputDirectory))
        {
            $MyDocuments = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)
            "Attempting to create directory '{0}'..." -f $OutputDirectory | Write-Verbose
            Try
            {
                [System.IO.Directory]::CreateDirectory($OutputDirectory)
            }
            Catch
            {
                "Failed to create output directory {0}, defaulting to user Documents folder {1}" -f $OutputDirectory, $MyDocuments | Write-Warning
                $OutputDirectory = $MyDocuments
            }
        }
        $DefaultExtension = "cer"
        $OutputFilename = $null
        If ($ShowFileDialog)
        {
            $SFD = [System.Windows.Forms.SaveFileDialog]::new()
            $SFD.Title = "Select file name for exported certificate"
            $SFD.AddExtension = $true
            $SFD.DefaultExt = $DefaultExtension
            $SFD.FileName = "{0}.{1}" -f $Certificate.Thumbprint, $SFD.DefaultExt
            $SFD.InitialDirectory = $OutputDirectory
            $SFD.RestoreDirectory = $true
            $SFD.OverwritePrompt = $true
            $SFD.Filter = "Certificates (*.cer; *.pem)|*.cer;*.pem"
            If ($SFD.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK)
            {
                # Because this may be the last cmdlet in the pipeline and the private key may be lost if this function fails,
                # we generate a random filename based on the thumbprint and timestamp
                
                "User cancelled out of file dialog, generating unique filename" | Write-Warning
                $Filename = "{0}_{1:yyyy-MM-dd_HHmmssfff}.{2}" -f $Certificate.Thumbprint, [Datetime]::Now, $DefaultExtension
                $OutputFilename = [System.IO.Path]::Combine($OutputDirectory, $Filename)
            }
            Else
            {
                $OutputFilename = $SFD.FileName
            }
        }
        Else
        {
            # If ShowFileDialog was not set, generate a filename based on the thumbprint and timestamp
            # We add the timestamp in case 
            $Filename = "{0}_{1:yyyy-MM-dd_HHmmssfff}.{2}" -f $Certificate.Thumbprint, [Datetime]::Now, $DefaultExtension
            $OutputFilename = [System.IO.Path]::Combine($OutputDirectory, $Filename)
        }

        $Certificates = $null
        If ($IncludeChain)
        {
            $Certificates = $Certificate | Get-X509Chain
        }
        Else
        {
            $Certificates = $Certificate
        }
        $Pem = $Certificates | ConvertTo-Pem
        If ($CopyToClipboard)
        {
            $Pem | Set-Clipboard
        }

        Try
        {
            "Exporting certificate to directory {0}" -f $OutputDirectory | Write-Verbose
            [System.IO.File]::WriteAllText($OutputFilename, $Pem)
            [System.IO.FileInfo]::new($OutputFilename)
            explorer.exe /select,$OutputFilename
        }
        Catch
        {
            "Failed to save certificates to the file '{0}'. To recover the certificate, use Get-LastSubmissionResult." -f $OutputFilename | Write-Error
        }
    }
}

Function Get-LastSubmissionResult
{
    [CmdletBinding()]
    [OutputType([SubmissionResult])]
    Param()
    Process
    {
        $PSCmdlet.WriteObject([SubmissionResult]::LastResult, $true)
    }
}

Function Get-LastRequestAndKey
{
    [CmdletBinding()]
    [OutputType([CertificateRequestAndKey])]
    Param()
    Process
    {
        $PSCmdlet.WriteObject([CertificateRequestAndKey]::LastRequest, $true)
    }
}

Function Convert-X509Data
{
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Request")]
        [String]
        $InputObject

        , [Parameter(Mandatory = $true)]
        [Alias("InputFormat", "InForm")]
        [CERTENClib.EncodingType]
        $FromType

        , [Parameter(Mandatory = $true)]
        [Alias("OutputFormat", "OutForm")]
        [CERTENClib.EncodingType]
        $ToType
    )
    Begin
    {
        $Converter = [CERTENROLLlib.CBinaryConverterClass]::new()
    }
    Process
    {
        $Converter.StringToString($InputObject, $FromType, $ToType)
    }
}

Function New-CertificatePoliciesExtension
{
    [CmdletBinding(DefaultParameterSetName = "SimpleOID")]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Extension])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "SimpleOID")]
        [System.Security.Cryptography.Oid]
        $Oid

        , [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Policy")]
        [CERTENROLLlib.CCertificatePolicyClass]
        $Policy
    )
    Begin
    {
        $CertificatePolicies = [CERTENROLLlib.CCertificatePoliciesClass]::new()
    }
    Process
    {
        If ($PSCmdlet.ParameterSetName -ieq "SimpleOID")
        {
            $OidClass = [CERTENROLLlib.CObjectIdClass]::new()
            [Void]$OidClass.InitializeFromValue($Oid.Value)

            $Policy = [CERTENROLLlib.CCertificatePolicyClass]::new()
            [Void]$Policy.Initialize($OidClass)
        }
        [Void]$CertificatePolicies.Add($Policy)
    }
    End
    {
        $CertificatePoliciesExtension = [CERTENROLLlib.CX509ExtensionCertificatePoliciesClass]::new()
        [Void]$CertificatePoliciesExtension.InitializeEncode($CertificatePolicies)
        [System.Security.Cryptography.X509Certificates.X509Extension]::new($CertificatePoliciesExtension.ObjectId.Value, [Convert]::FromBase64String($CertificatePoliciesExtension.RawData(1)), $CertificatePoliciesExtension.Critical)
    }
}

Function New-CertificatePolicy
{
    [CmdletBinding()]
    [OutputType([CERTENROLLlib.CCertificatePolicyClass])]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.Oid]
        $Oid

        , [Parameter(Mandatory = $false)]
        [String]
        $Qualifier

        , [Parameter(Mandatory = $false)]
        [CERTENROLLlib.PolicyQualifierType]
        $QualifierType = [CERTENROLLlib.PolicyQualifierType]::PolicyQualifierTypeUserNotice
    )
    Process
    {
        $OidClass = [CERTENROLLlib.CObjectIdClass]::new()
        [Void]$OidClass.InitializeFromValue($Oid.Value)

        $Policy = [CERTENROLLlib.CCertificatePolicyClass]::new()
        [Void]$Policy.Initialize($OidClass)

        If ($PSBoundParameters.ContainsKey("Qualifier"))
        {
            $QualifierClass = [CERTENROLLlib.CPolicyQualifierClass]::new()
            [Void]$QualifierClass.InitializeEncode($Qualifier, $QualifierType)
            [Void]$Policy.PolicyQualifiers.Add($QualifierClass)
        }
        $PSCmdlet.WriteObject($Policy, $false)
    }
}

Function Install-Certificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate

        , [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.StoreLocation]
        $Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine

        , [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.StoreName]
        $Name = [System.Security.Cryptography.X509Certificates.StoreName]::My
    )
    Begin
    {
        $Store = [System.Security.Cryptography.X509Certificates.X509Store]::new($Name, $Location)
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    }
    Process
    {
        If (!$Certificate.HasPrivateKey)
        {
            "No private key found for certificate '{0}' ({1}). To import a public certificate, use the built-in Import-Certificate cmdlet." -f $Certificate.Thumbprint, $Certificate.Subject | Write-Error
            return
        }
        Else
        {
            # Assume that we have an RSA private key by default

            $PrivateKey = $null
            $PrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
            If ($PrivateKey -eq $null)
            {
                $PrivateKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)

                # If the public key is still null, we have a non-supported algorithm
                If ($PrivateKey -eq $null)
                {
                    "Only RSA and ECC certificates are supported." | Write-Error
                    return
                }

                # To persist a certificate, the private key must not be ephemeral
                If ($PrivateKey.Key.IsEphemeral)
                {
                    "Can only install certificate with non-ephemeral keys (where KeyName is not null or empty). If the private key was created with New-PrivateKey, use the -KeyName parameter to create a persisted key." | Write-Error
                    return
                }
            }
            $Store.Add($Certificate)
        }
    }
    End
    {
        $Store.Close()
        $Store.Dispose()
    }
}
New-Alias -Name Save-Certificate -Value Install-Certificate

Export-ModuleMember -Function * -Cmdlet * -Alias *