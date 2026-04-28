using namespace System
using namespace System.IO

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [DirectoryInfo]
    $OutputDirectory
)

Process
{
    Try
    {
        If (!$OutputDirectory.Exists)
        {
            $OutputDirectory.Create()
        }
        
        # Delete previous contents

        $OutputDirectory.FullName | Get-ChildItem -Force | Remove-Item -Recurse -Force -Verbose

        # Get CA certificates
        $Config = New-Object -ComObject CertificateAuthority.Config
        $ConfigString = $Config.GetConfig(0)

        $Admin = New-Object -ComObject CertificateAuthority.Admin
        $CASignCertCount = $Admin.GetCAProperty($ConfigString, 0x0000000B, 0, 0x1, 0) # Get number of signing certificates
        $CAName = $Admin.GetCAProperty($ConfigString, 0x00000006, 0, 4, 0) # Get the CA name

        # Create a temporary folder
        $TempDirName = [Path]::Combine([Path]::GetTempPath(), [Guid]::NewGuid().Guid) 
        $TempDir = [Directory]::CreateDirectory($TempDirName)

        For ($i = 0; $i -lt $CASignCertCount; $i++)
        {
            $Suffix = $null
            If ($i -gt 0)
            {
                $Suffix = "({0})" -f $i
            }
            $Filename = "{0}{1}.crt" -f $CAName, $Suffix

            $CACert = $Admin.GetCAProperty($ConfigString, 0x0000000C, $i, 3, 0)

            $CertPath = [Path]::Combine($TempDir.FullName, $Filename)
            [File]::WriteAllText($CertPath, $CACert)
        }

        $ZipFileName = "{0}.zip" -f $CAName
        $OutputPath = [Path]::Combine($OutputDirectory.FullName, $ZipFileName)

        Get-ChildItem -Path $TempDir.FullName -Force | Compress-Archive -DestinationPath $OutputPath -CompressionLevel NoCompression -Force

        # Export registry settings

        $RegistryOutputFile = [Path]::Combine($OutputDirectory.FullName, "caconfig.reg")
        reg export HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration $RegistryOutputFile /y

        # Copy CAPolicy.inf
        $WindowsFolder = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
        $CAPolicyPath = [Path]::Combine($WindowsFolder, "CAPolicy.inf")
        Copy-Item -LiteralPath $CAPolicyPath -Destination $OutputDirectory.FullName -Force

        # Backup CA DB

        $DBFolder = [Path]::Combine($OutputDirectory.FullName, "DB")
        certutil -backupDB $DBFolder
    }
    Finally
    {
        If ($TempDir -ne $null -and $TempDir.Exists)
        {
            $TempDir.FullName | Remove-Item -Recurse -Force
        }
    }
}