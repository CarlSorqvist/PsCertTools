using namespace System.Diagnostics
using namespace System.Security
using namespace System.Security.AccessControl
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates


$Cert = gi Cert:\LocalMachine\My\5055EEA730F88887CDE16E4C97238AC1D964FE58
$PrivateKey = [ECDsaCertificateExtensions]::GetECDsaPrivateKey($Cert)
$Options = [CngPropertyOptions]::None -bor 0x04 # 0x04 = DACL, see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/62175da4-e30f-4c12-b1c4-dae0434e38af
$SDProperty = $PrivateKey.Key.GetProperty("Security Descr", $Options)
$AclBytes = $SDProperty.GetValue()
$SD = [RawSecurityDescriptor]::new($AclBytes, 0)
$CSD = [CommonSecurityDescriptor]::new($false, $false, $AclBytes, 0)
[CryptoKeySecurity]::new($CSD).GetAccessRules($true, $true, [Principal.NTAccount])
