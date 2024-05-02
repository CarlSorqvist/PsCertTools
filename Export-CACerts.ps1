using namespace System
using namespace System.IO
using namespace System.Windows.Forms

Try
{
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop

    $Config = New-Object -ComObject CertificateAuthority.Config
    $ConfigString = $Config.GetConfig(0)

    $Admin = New-Object -ComObject CertificateAuthority.Admin
    $CASignCertCount = $Admin.GetCAProperty($ConfigString, 0x0000000B, 0, 0x1, 0)
    $CAName = $Admin.GetCAProperty($ConfigString, 0x00000006, 0, 4, 0)

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

    $ZipFileName = "{0}_{1:yyyyMMddHHmmss}.zip" -f $CAName, [DateTime]::Now

    $SFD = [SaveFileDialog]::new()
    $SFD.AutoUpgradeEnabled = $false
    $SFD.Title = "Select ZIP file name"
    $SFD.AddExtension = $true
    $SFD.DefaultExt = "zip"
    $SFD.FileName = $ZipFileName
    $SFD.InitialDirectory = [Path]::GetPathRoot([Environment]::SystemDirectory)
    $SFD.OverwritePrompt = $true
    $SFD.Filter = "ZIP archive (*.zip)|*.zip"
    If ($SFD.ShowDialog() -ne [DialogResult]::OK)
    {
        $Host.UI.WriteErrorLine("Aborted.")
        return
    }

    Get-ChildItem -Path $TempDir.FullName -Force | Compress-Archive -DestinationPath $SFD.FileName -CompressionLevel NoCompression -Force
    "CA certificates exported to '{0}'" -f $SFD.FileName
}
Finally
{
    If ($TempDir -ne $null -and $TempDir.Exists)
    {
        $TempDir.FullName | Remove-Item -Recurse -Force
    }
}