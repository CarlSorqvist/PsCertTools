#Requires -version 5 -runasadministrator

using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.ObjectModel
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Net
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text
using namespace System.Windows.Forms

Add-Type -AssemblyName System.Security -ErrorAction Stop
Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop

$ModuleName = "CertRequestTools"
$ZipArchiveName = "CertRequestTools.zip"

$TargetModuleBasePath = $PSHOME
$TargetModulePath = [Path]::Combine($TargetModuleBasePath, "Modules", $ModuleName)
New-Item -ItemType Directory -Path $TargetModulePath -Force -ErrorAction Stop | Out-Null

$ZipArchive = [Path]::Combine($PSScriptRoot, $ZipArchiveName)

If (![File]::Exists($ZipArchive))
{
    "Could not find '{0}'. Please select the zip archive containing the CertRequestUtil binaries." -f $ZipArchive | Write-Host -ForegroundColor Red
    $OFD = [OpenFileDialog]::new()
    $OFD.Title = "Select archive"
    $OFD.InitialDirectory = $PSScriptRoot
    $OFD.RestoreDirectory = $true
    $OFD.Filter = "ZIP archives (*.zip)|*.zip"
    If ($OFD.ShowDialog() -ne [DialogResult]::OK)
    {
        throw "User cancelled out of file dialog"
    }
    $ZipArchive = $OFD.FileName
}

Expand-Archive -LiteralPath $ZipArchive -DestinationPath $TargetModulePath -Force -ErrorAction Stop