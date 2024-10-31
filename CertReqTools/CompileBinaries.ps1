#Requires -version 5 -runasadministrator

using namespace System
using namespace System.CodeDom.Compiler
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.ObjectModel
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Net
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [SwitchParameter]
    $Sign
)

Add-Type -AssemblyName System.Security -ErrorAction Stop

$ModuleName = "CertRequestTools.psm1"
$ManifestName = "CertRequestTools.psd1"
$InstallScript = "Install-CertReqUtil.ps1"

$TempFolderName = [Guid]::NewGuid().ToString()
$MyPath = $PSScriptRoot
$TempPath = [Path]::Combine($MyPath, $TempFolderName)
"Creating temporary directory {0}" -f $TempPath | Write-Verbose
New-Item -ItemType Directory -Path $TempPath -Force -ErrorAction Stop | Out-Null

$FilesToProcess = [List[String]]::new()

$TlbConverterCode = @"
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

// This utility extracts COM type library definition from unmanaged DLL and creates matching managed wrapper assembly.
public static class TlbConvert
{
    private enum RegKind
    {
        RegKind_Default = 0,
        RegKind_Register = 1,
        RegKind_None = 2
    }

    [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
   private static extern void LoadTypeLibEx(String strTypeLibName, RegKind regKind,
        [MarshalAs(UnmanagedType.Interface)] out Object typeLib);

    public static void Convert(String srcDll, String outDll)
    {
        try
        {
            Object typeLib;
            LoadTypeLibEx(srcDll, RegKind.RegKind_None, out typeLib);
            TypeLibConverter tlbConv = new TypeLibConverter();
            AssemblyBuilder asm = tlbConv.ConvertTypeLibToAssembly(typeLib, outDll, 0, new ConversionEventHandler(), null, null, null, null);
            asm.Save(outDll);
        }
        catch (Exception e)
        {
            Console.WriteLine("Exception: {0}\n{1}", e.Message, e.StackTrace);
            return;
        }

        Console.WriteLine("\nConversion successful.");
    }
}

public class ConversionEventHandler : ITypeLibImporterNotifySink
{
    public void ReportEvent(ImporterEventKind eventKind, int eventCode, string eventMsg)
    {
        Console.WriteLine("{0}", eventMsg);
    }

    public Assembly ResolveRef(object typeLib)
    {
        return null;
    }
}
"@
"Compiling type library converter helpers" | Write-Verbose
Add-Type -TypeDefinition $TlbConverterCode -Language CSharp -ReferencedAssemblies mscorlib, System.Security, System.Management.Automation, System.Linq -ErrorAction Stop

# Create wrapper libraries for the certificate COM libraries so we can call the methods from managed code instead of COM.
# The wrapper DLLs are created alongside the original COM DLLs in System32. (which is also why we need Admin privileges to run the script, unfortunately)
# Note that certadm.dll is handled manually with some custom method signatures in the next $Code block.
$CertLibs = @{
    "C:\Windows\System32\certcli.dll" = "CERTCLIlib.dll"
    "C:\Windows\System32\CertEnroll.dll" = "CERTENROLLlib.dll"
    "C:\Windows\System32\certenc.dll" = "CERTENClib.dll"
}

[Directory]::SetCurrentDirectory($TempPath)
Foreach ($Lib in $CertLibs.GetEnumerator())
{
    $Folder = [Path]::GetDirectoryName($Lib.Key)
    $TargetFile = [Path]::Combine($TempPath, $Lib.Value)
    If ([File]::Exists($TargetFile))
    {
        "Removing item {0}" -f $TargetFile | Write-Verbose
        Remove-Item -LiteralPath $TargetFile -Force -ErrorAction Stop
    }
    Try
    {
        "Creating type library {0} over COM DLL {1}" -f $Lib.Value, $Lib.Key | Write-Verbose
        [TlbConvert]::Convert($Lib.Key, $Lib.Value)
    }
    Catch
    {
        throw $_.Exception
    }
    $FilesToProcess.Add($TargetFile)
}

$Code = @"
using CERTADMIN;
using CERTENROLLlib;
using CERTENClib;
using CERTCLIlib;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

// COM interface definitions for ICertAdmin. We cannot use the TlbConverter signatures, as we need a custom signature for the SetCertificateExtension() method(s).
namespace CERTADMIN
{
	[ComImport]
	[Guid("34DF6950-7FB6-11D0-8817-00A0C903B83C")]
	[TypeLibType(4160)]
	public interface ICertAdmin
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743808)]
		int IsValidCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strSerialNumber);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743809)]
		int GetRevocationReason();

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743810)]
		void RevokeCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strSerialNumber, [In] int Reason, [In] DateTime Date);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743811)]
		void SetRequestAttributes([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strAttributes);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743812)]
		void SetCertificateExtension([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strExtensionName, [In] int Type, [In] int Flags, [In] IntPtr pvarValue);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743813)]
		void DenyRequest([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743814)]
		int ResubmitRequest([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743815)]
		void PublishCRL([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] DateTime Date);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743816)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetCRL([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743817)]
		int ImportCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strCertificate, [In] int Flags);
	}
	[ComImport]
	[Guid("F7C3AC41-B8CE-4FB4-AA58-3D1DC0E36B39")]
	[TypeLibType(4160)]
	public interface ICertAdmin2 : ICertAdmin
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743808)]
		new int IsValidCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strSerialNumber);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743809)]
		new int GetRevocationReason();

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743810)]
		new void RevokeCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strSerialNumber, [In] int Reason, [In] DateTime Date);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743811)]
		new void SetRequestAttributes([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strAttributes);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743812)]
		new void SetCertificateExtension([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strExtensionName, [In] int Type, [In] int Flags, [In] IntPtr pvarValue);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743813)]
		new void DenyRequest([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743814)]
		new int ResubmitRequest([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743815)]
		new void PublishCRL([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] DateTime Date);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743816)]
		[return: MarshalAs(UnmanagedType.BStr)]
		new string GetCRL([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743817)]
		new int ImportCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strCertificate, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809344)]
		void PublishCRLs([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] DateTime Date, [In] int CRLFlags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809345)]
		[return: MarshalAs(UnmanagedType.Struct)]
		object GetCAProperty([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId, [In] int PropIndex, [In] int PropType, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809346)]
		void SetCAProperty([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId, [In] int PropIndex, [In] int PropType, [In][MarshalAs(UnmanagedType.Struct)] ref object pvarPropertyValue);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809347)]
		int GetCAPropertyFlags([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809348)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetCAPropertyDisplayName([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809349)]
		[return: MarshalAs(UnmanagedType.BStr)]
		string GetArchivedKey([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809350)]
		[return: MarshalAs(UnmanagedType.Struct)]
		object GetConfigEntry([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strNodePath, [In][MarshalAs(UnmanagedType.BStr)] string strEntryName);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809351)]
		void SetConfigEntry([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strNodePath, [In][MarshalAs(UnmanagedType.BStr)] string strEntryName, [In][MarshalAs(UnmanagedType.Struct)] ref object pvarEntry);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809352)]
		void ImportKey([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strCertHash, [In] int Flags, [In][MarshalAs(UnmanagedType.BStr)] string strKey);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809353)]
		int GetMyRoles([In][MarshalAs(UnmanagedType.BStr)] string strConfig);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809354)]
		int DeleteRow([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int Flags, [In] DateTime Date, [In] int Table, [In] int RowId);
	}
	[ComImport]
	[CoClass(typeof(CCertAdminClass))]
	[Guid("F7C3AC41-B8CE-4FB4-AA58-3D1DC0E36B39")]
	public interface CCertAdmin : ICertAdmin2
	{
	}
	[ComImport]
	[TypeLibType(2)]
	[ClassInterface((short)0)]
	[Guid("37EABAF0-7FB6-11D0-8817-00A0C903B83C")]
	public class CCertAdminClass : ICertAdmin2, CCertAdmin
	{
		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743808)]
		public virtual extern int IsValidCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strSerialNumber);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743809)]
		public virtual extern int GetRevocationReason();

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743810)]
		public virtual extern void RevokeCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strSerialNumber, [In] int Reason, [In] DateTime Date);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743811)]
		public virtual extern void SetRequestAttributes([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strAttributes);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743812)]
		public virtual extern void SetCertificateExtension([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strExtensionName, [In] int Type, [In] int Flags, [In] IntPtr pvarValue);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743813)]
		public virtual extern void DenyRequest([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743814)]
		public virtual extern int ResubmitRequest([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743815)]
		public virtual extern void PublishCRL([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] DateTime Date);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743816)]
		[return: MarshalAs(UnmanagedType.BStr)]
		public virtual extern string GetCRL([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610743817)]
		public virtual extern int ImportCertificate([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strCertificate, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809344)]
		public virtual extern void PublishCRLs([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] DateTime Date, [In] int CRLFlags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809345)]
		[return: MarshalAs(UnmanagedType.Struct)]
		public virtual extern object GetCAProperty([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId, [In] int PropIndex, [In] int PropType, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809346)]
		public virtual extern void SetCAProperty([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId, [In] int PropIndex, [In] int PropType, [In][MarshalAs(UnmanagedType.Struct)] ref object pvarPropertyValue);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809347)]
		public virtual extern int GetCAPropertyFlags([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809348)]
		[return: MarshalAs(UnmanagedType.BStr)]
		public virtual extern string GetCAPropertyDisplayName([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int PropId);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809349)]
		[return: MarshalAs(UnmanagedType.BStr)]
		public virtual extern string GetArchivedKey([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In] int Flags);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809350)]
		[return: MarshalAs(UnmanagedType.Struct)]
		public virtual extern object GetConfigEntry([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strNodePath, [In][MarshalAs(UnmanagedType.BStr)] string strEntryName);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809351)]
		public virtual extern void SetConfigEntry([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In][MarshalAs(UnmanagedType.BStr)] string strNodePath, [In][MarshalAs(UnmanagedType.BStr)] string strEntryName, [In][MarshalAs(UnmanagedType.Struct)] ref object pvarEntry);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809352)]
		public virtual extern void ImportKey([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int RequestId, [In][MarshalAs(UnmanagedType.BStr)] string strCertHash, [In] int Flags, [In][MarshalAs(UnmanagedType.BStr)] string strKey);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809353)]
		public virtual extern int GetMyRoles([In][MarshalAs(UnmanagedType.BStr)] string strConfig);

		[MethodImpl(MethodImplOptions.InternalCall)]
		[DispId(1610809354)]
		public virtual extern int DeleteRow([In][MarshalAs(UnmanagedType.BStr)] string strConfig, [In] int Flags, [In] DateTime Date, [In] int Table, [In] int RowId);
	}
}
namespace X509Extensions
{
    public enum CertAltNameType
    {
        OtherName = 1,
        RFC822 = 2,
        DNS = 3,
        X400Address = 4,
        DirectoryName = 5,
        EdiPartyName = 6,
        URL = 7,
        IPAddress = 8,
        RegisteredId = 9
    }

    [Flags]
    public enum CryptEncodeFlags
    {
        CRYPT_ENCODE_ALLOC_FLAG = 0x8000,
        CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG = 0x20000,
        CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG = 0x40000000,
        CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG = unchecked((int)0x80000000),
        CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG = 0x20000000,
        CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG = 0x10000000
    }
    [Flags]
    public enum CertEncodingType : int
    {
        X509 = 0x1,
        PKCS7 = 0x10000
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_ALT_NAME_INFO
    {
        public int cAltEntry;
        public IntPtr rgAltEntry;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CERT_ALT_NAME_ENTRY
    {
        public CertAltNameType dwAltNameChoice;
        public CERT_ALT_NAME_ENTRY_UNION Value;
    }
    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    public struct CERT_ALT_NAME_ENTRY_UNION
    {
        [FieldOffset(0)]
        public IntPtr pOtherName;
        [FieldOffset(0)]
        public IntPtr pwszRfc822Name;
        [FieldOffset(0)]
        public IntPtr pwszDNSName;
        [FieldOffset(0)]
        public CRYPT_BLOB DirectoryName;
        [FieldOffset(0)]
        public IntPtr pwszURL;
        [FieldOffset(0)]
        public CRYPT_BLOB IPAddress;
        [FieldOffset(0)]
        public IntPtr pszRegisteredID;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_OTHER_NAME
    {
        [MarshalAs(UnmanagedType.LPStr)]
        public String pszObjId;
        [MarshalAs(UnmanagedType.Struct)]
        public CRYPT_BLOB Value;
    }
    public static class SidExtension
    {
        [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptEncodeObjectEx(
            CertEncodingType dwCertEncodingType,
            [MarshalAs(UnmanagedType.LPStr)]
            String lpszStructType,
            IntPtr pvStructInfo,
            CryptEncodeFlags dwFlags,
            IntPtr pEncodePara,
            IntPtr pvEncoded,
            [MarshalAs(UnmanagedType.I4)]
            ref int pcbEncoded
        );
        public const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";

        public static byte[] Encode(SecurityIdentifier sid)
        {
            if (sid == null)
                throw new ArgumentNullException("sid");

            var stringSid = sid.Value;
            var sidOid = "1.3.6.1.4.1.311.25.2.1";
            var unmanagedSidString = IntPtr.Zero;
            var unmanagedpOtherName = IntPtr.Zero;
            var unmanagedAltNameEntry = IntPtr.Zero;
            var unmanagedAltNameInfo = IntPtr.Zero;
            var outputPtr = IntPtr.Zero;

            try
            {
                var sidLength = stringSid.Length;

                // The actual SID value needs to be encoded as an X.690 OCTET_STRING. Since this is somewhat tricky to do with P/Invoke,
                // We just do it manually as the SID is never expected to exceed 127 bytes, but verify it anyway.

                if (sidLength > 127)
                    throw new ArgumentOutOfRangeException("sid", "String representation of the provided security identifier must not exceed 127 characters.");

                var octetString = new byte[sidLength + 2];
                octetString[0] = 0x04; // Tag identifier for an OCTET_STRING
                octetString[1] = (byte)sidLength; // Length of the OCTET_STRING value, in bytes
                Array.Copy(Encoding.ASCII.GetBytes(stringSid), 0, octetString, 2, sidLength);

                unmanagedSidString = Marshal.AllocHGlobal(octetString.Length);
                Marshal.Copy(octetString, 0, unmanagedSidString, octetString.Length);

                var otherName = new CERT_OTHER_NAME();
                otherName.pszObjId = sidOid;
                otherName.Value = new CRYPT_BLOB();
                
                otherName.Value.cbData = sidLength + 2;
                otherName.Value.pbData = unmanagedSidString;
                
                unmanagedpOtherName = Marshal.AllocHGlobal(Marshal.SizeOf(otherName));
                Marshal.StructureToPtr(otherName, unmanagedpOtherName, false);

                var altName = new CERT_ALT_NAME_ENTRY_UNION();
                altName.pOtherName = unmanagedpOtherName;

                var altNameEntry = new CERT_ALT_NAME_ENTRY();
                altNameEntry.dwAltNameChoice = CertAltNameType.OtherName;
                altNameEntry.Value = altName;

                unmanagedAltNameEntry = Marshal.AllocHGlobal(Marshal.SizeOf(altNameEntry));
                Marshal.StructureToPtr(altNameEntry, unmanagedAltNameEntry, false);

                var altNames = new CERT_ALT_NAME_INFO();
                altNames.cAltEntry = 1;
                altNames.rgAltEntry = unmanagedAltNameEntry;

                unmanagedAltNameInfo = Marshal.AllocHGlobal(Marshal.SizeOf(altNames));
                Marshal.StructureToPtr(altNames, unmanagedAltNameInfo, false);

                int resultSize = 0;
                var result = CryptEncodeObjectEx(CertEncodingType.X509, szOID_SUBJECT_ALT_NAME2, unmanagedAltNameInfo, 0, IntPtr.Zero, outputPtr, ref resultSize);
                if (resultSize > 1)
                {
                    outputPtr = Marshal.AllocHGlobal(resultSize);
                    result = CryptEncodeObjectEx(CertEncodingType.X509, szOID_SUBJECT_ALT_NAME2, unmanagedAltNameInfo, 0, IntPtr.Zero, outputPtr, ref resultSize);
                    var output = new byte[resultSize];
                    Marshal.Copy(outputPtr, output, 0, resultSize);
                    return output;
                }
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                if (unmanagedSidString != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedSidString);
                }
                if (unmanagedpOtherName != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedpOtherName);
                }
                if (unmanagedAltNameEntry != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedAltNameEntry);
                }
                if (unmanagedAltNameInfo != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedAltNameInfo);
                }
                if (outputPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(outputPtr);
                }
            }
        }
    }

    // Courtesy of https://github.com/NoMoreFood/Crypture/blob/master/Code/CertificateNative.cs
    // Used to enumerate all ExtendedKeyUsages known to the local system (including the ones defined in AD).
    public static class ExtendedKeyUsage
    {
#pragma warning disable 0649
        internal struct CRYPT_OID_INFO
        {
            internal uint cbSize;

            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszOID;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszName;

            internal uint dwGroupId;
            internal uint Algid;
        }

        internal delegate bool CryptEnumCallback(IntPtr pInfo, ref OidCollection pvParam);

        [DllImport("crypt32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptEnumOIDInfo(OidGroup oGroupId, UInt32 dwFlags, ref OidCollection pvParam, CryptEnumCallback oFunc);

        internal static bool GetExtendedKeyUsagesCallback(IntPtr pInfo, ref OidCollection pvParam)
        {
            CRYPT_OID_INFO oInfo = (CRYPT_OID_INFO) Marshal.PtrToStructure(pInfo, typeof(CRYPT_OID_INFO));
            OidCollection ExtendedKeyUsages = (OidCollection)pvParam;
            ExtendedKeyUsages.Add(new Oid(oInfo.pszOID, oInfo.pwszName));
            return true;
        }

        internal static OidCollection GetExtendedKeyUsages()
        {
            OidCollection ExtendedKeyUsages = new OidCollection();
            CryptEnumOIDInfo(OidGroup.EnhancedKeyUsage, 0, ref ExtendedKeyUsages, GetExtendedKeyUsagesCallback);
            return ExtendedKeyUsages;
        }
    
        public static readonly OidCollection SystemOidList = GetExtendedKeyUsages();
    
        internal static ILookup<String, Oid> GetEkuLookupTable()
        {
            return SystemOidList.Cast<Oid>().ToLookup(oid => Regex.Replace(CultureInfo.InvariantCulture.TextInfo.ToTitleCase(oid.FriendlyName), "\\s", ""), StringComparer.CurrentCultureIgnoreCase);
        }
    
        public static readonly ILookup<String, Oid> EkuLookup = GetEkuLookupTable();

        private static readonly Regex WildcardRegex = new Regex("\\\\\\*", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static String ToWildcardPattern(this String pattern)
        {
            // Build a wildcard matching regex by replacing all instances of the "*" character with ".*".
            // To avoid problems, first replace multiple consecutive "*" with a single one, and Regex.Escape the string before replacing the characters.
            // Finally, surround the pattern with "^" and "$" to make it a literal match, giving the user full control of the pattern with "*"'s.
            return new StringBuilder("^")
                .Append(
                    WildcardRegex.Replace(
                        Regex.Escape(
                            Regex.Replace(pattern, "\\*+", "*")
                        )
                        , ".*")
                    )
                .Append("$").ToString();
        }

        public static List<Oid> FindMatchingOids(String pattern)
        {
            if (String.IsNullOrEmpty(pattern))
                throw new ArgumentNullException("pattern");

            var regex = new Regex(pattern.ToWildcardPattern(), RegexOptions.IgnoreCase | RegexOptions.Compiled);

            var list = new List<Oid>();

            foreach (var oidGroup in EkuLookup)
            {
                var keyMatch = regex.IsMatch(oidGroup.Key); // Match the key (shorthand friendly name) first
            
                foreach (var oid in oidGroup)
                {
                    if (keyMatch || regex.IsMatch(oid.FriendlyName)) // If the key matched, skip matching each entry for increased performance (lazy evaluation)
                        list.Add(oid);
                }
            }
            return list;
        }
    }
}

public static class Crypt
{
    private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

    // Generates a cryptographically strong (kind of) random number between 0 and max.
    public static ulong GetPRNGNumber(ulong max)
    {
        var bytes = new byte[8];
        rng.GetBytes(bytes);
        return ((ulong)bytes[0] << 56 |
                (ulong)bytes[1] << 48 |
                (ulong)bytes[2] << 40 |
                (ulong)bytes[3] << 32 |
                (ulong)bytes[4] << 24 |
                (ulong)bytes[5] << 16 |
                (ulong)bytes[6] << 8 |
                (ulong)bytes[7]) % max;
    }
    // Overload to the above method that allows an int as input instead of a ulong.
    public static int GetPRNGNumber(int max)
    {
        if (max < 1)
            throw new ArgumentOutOfRangeException("max");
        return (int)GetPRNGNumber((ulong)max);
    }
}

public enum EnterpriseStoreName
{
    NTAuthCertificates,
    TrustedRootCertificationAuthorities,
    IntermediateCertificationAuthorities
}
public class EnterpriseStore
{
    public readonly String Name;

    public EnterpriseStore(String name)
    {
        if (String.IsNullOrEmpty(name))
            throw new ArgumentException("Store name must not be null or empty. Use 'certutil -enterprise -enumstore' to enumerate enterprise certificate stores.", "name");
        Name = name;
    }

    public EnterpriseStore(EnterpriseStoreName name)
    {
        Name = GetStoreNameFromEnum(name);
    }

    private String GetStoreNameFromEnum(EnterpriseStoreName name)
    {
        switch (name)
        {
            case EnterpriseStoreName.NTAuthCertificates:
                return "NTAuth";
            case EnterpriseStoreName.TrustedRootCertificationAuthorities:
                return "Root";
            case EnterpriseStoreName.IntermediateCertificationAuthorities:
            default:
                return "CA";
        }
    }

    public override String ToString()
    {
        return Name;
    }

    public static implicit operator EnterpriseStore(String name)
    {
        return new EnterpriseStore(name);
    }
}

public static class X509StoreExtensions
{
    private const string Crypt32 = "Crypt32.dll";

    private const int CERT_STORE_PROV_SYSTEM_A = 9;

    private const int CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;
    private const int CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID = 9;
    private const int CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;

    private const int CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
    private const int CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000;

    [DllImport(Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CertOpenStore(
        [In]
        int lpszStoreProvider,

        [MarshalAs(UnmanagedType.I4), In]
        int dwEncodingType,

        [In]
        IntPtr hCryptProv,

        [MarshalAs(UnmanagedType.I4), In]
        int dwFlags,

        [In]
        IntPtr pvPara
    );

    [DllImport(Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CertCloseStore(
        [In]
        IntPtr hCertStore,

        [MarshalAs(UnmanagedType.I4), In]
        int dwFlags
    );

    public static X509Store OpenEnterpriseStore(EnterpriseStore store)
    {
        if (store == null)
            throw new ArgumentNullException("store");

        IntPtr storeName = IntPtr.Zero;
        IntPtr handle = IntPtr.Zero;
        try
        {
            storeName = Marshal.StringToHGlobalAnsi(store.Name);
            handle = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, IntPtr.Zero, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_MAXIMUM_ALLOWED_FLAG, storeName);
            if (handle != IntPtr.Zero)
                return new X509Store(handle);

            throw new Win32Exception(Marshal.GetHRForLastWin32Error());
        }
        finally
        {
            if (storeName != IntPtr.Zero)
                Marshal.FreeHGlobal(storeName);
            if (handle != IntPtr.Zero)
                CertCloseStore(handle, 0);
        }
    }
}

// Some helper methods that simplifies creating generic collection types using an existing array or IEnumerable as input, but as params.
public static class CollectionUtil
{
    public static List<T> CreateList<T>(params T[] values)
    {
        return new List<T>(values);
    }
    public static Collection<T> CreateCollection<T>(params T[] values)
    {
        return new Collection<T>(values);
    }
    public static HashSet<T> CreateHashSet<T>(params T[] values)
    {
        return new HashSet<T>(values);
    }
    public static HashSet<T> CreateHashSet<T>(IEqualityComparer<T> comparer, params T[] values)
    {
        return new HashSet<T>(values, comparer);
    }
}
public static class DebugHelper
{
    public static bool DebugOutput = false;
    public static bool IsAdmin { get { return IsElevated; } }
    
    private static readonly WindowsPrincipal CurrentPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
    private static readonly bool IsElevated = CurrentPrincipal.IsInRole(WindowsBuiltInRole.Administrator);

    private const String DateFormat = "yyyy-MM-dd HH:mm:ss.fff";
    private const String MessageFormat = "[{0}] {1}";

    public static void WriteDebug(String message, params object[] parameters)
    {
        if (!DebugOutput)
            return;

        var timestamp = DateTime.Now.ToString(DateFormat);
        var formattedMessage = String.Format(message, parameters);

        Console.WriteLine(MessageFormat, timestamp, formattedMessage);
    }
}

public static class CertAdminHelper
{
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct BSTRVARIANT
    {
        public Int16 vt;
        public Int16 wReserved1;
        public Int16 wReserved2;
        public Int16 wReserved3;
        public IntPtr ptrToBstr;
    }
    public unsafe static void SetExtension(String config, int requestId, X509Extension extension)
    {
        var certadmin = new CCertAdminClass();
        /*
            Many, many versions of this code was tried in development, but this is the only one that appears to work flawlessly.
            Essentially, we are emulating a native BSTR by directly manipulating unmanaged memory through the Bstr class, and then
            creating our own managed VARIANT structure which then points to the Bstr handle.

            Finally, this managed structure is (unsafely, could probably Marshal it instead) passed by reference to the SetCertificateExtension
            method.
        */
        using (var bstr = new Bstr(extension.RawData))
        {
            var v = new BSTRVARIANT();
            v.vt = 8;
            v.ptrToBstr = bstr.StartOfString;
            certadmin.SetCertificateExtension(config, requestId, extension.Oid.Value, 3, 0, new IntPtr(&v));
        }
    }
}

// This class was created to emulate a native BSTR, where the pointer points to the start of a string,
// but the preceding 4 bytes is an Int32 containing the string length excluding the terminator, and 
// adding said terminator as two null bytes at the end.
// It is used as input to the ICertAdmin.SetCertificateExtension() method.
// In native code, a BSTR generally represents literal strings, but for our purposes we need to marshal
// a byte array completely independent from a string.
public class Bstr
    : SafeHandleZeroOrMinusOneIsInvalid
{
    public Bstr(byte[] data)
        : base(true)
    {
        if (data == null)
            throw new ArgumentNullException("data");
        if (data.Length == 0)
            throw new ArgumentOutOfRangeException("data");

        var _data = new List<byte>(data.Length + 6); // 4 bytes for prefix, 2 bytes for terminator
        _data.AddRange(BitConverter.GetBytes(data.Length)); // Add length of array as prefix
        _data.AddRange(data); // Add the data
        _data.AddRange(new byte[] { 0, 0 }); // Add the terminator (two null bytes)

        SetHandle(Marshal.AllocHGlobal(_data.Count));
        Marshal.Copy(_data.ToArray(), 0, handle, _data.Count);
    }

    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(handle);
        return true;
    }
    public IntPtr StartOfString
    {
        get
        {
            if (IsClosed || IsInvalid)
                throw new InvalidOperationException();
            return IntPtr.Add(handle, 4);
        }
    }
}
// This class stores a reference to the generated private key and the subsequent certificate request in base64 format.
public class CertificateRequestAndKey
{
    // Used by New-CertificateRequest to store the last created private key and request in case the used didn't have any other references to it,
    // such as if a pipeline was used
    public static CertificateRequestAndKey LastRequest { get; internal set; }

    public readonly AsymmetricAlgorithm Key;
    public readonly String Request;

    public CertificateRequestAndKey(AsymmetricAlgorithm key, byte[] request)
    {
        if (key == null)
            throw new ArgumentNullException("key");
        if (request == null)
            throw new ArgumentNullException("request");
        Key = key;
        Request = Convert.ToBase64String(request);
    }
}
public enum RequestDisposition
{
    Incomplete = 0,
    Failed = 1,
    Denied = 2,
    Issued = 3,
    IssuedOutOfBand = 4,
    Pending = 5,
    Revoked = 6
}

// This class is used to combine the RequestID with the certificate after issuance by the CA
public class SubmissionResult
{
    // Used by Submit-CertificateRequest to store a reference to the last issued certificate and request ID, in case something went wrong in the PS pipeline
    public static SubmissionResult LastResult { get; internal set; }

    public int RequestId { get; private set; }
    public RequestDisposition Disposition { get; private set; }
    
    // We have a property and a field for the certificate, both can be used but only the property will be displayed by default in PowerShell.
    // The reason we do this is to allow using any built-in cmdlet which expects a named "Cert" parameter as pipeline input
    public X509Certificate2 Certificate
    {
        get
        {
            return Cert;
        }
    }
    public readonly X509Certificate2 Cert;

    public SubmissionResult(int requestId, RequestDisposition disp, X509Certificate2 cert)
    {
        if (cert == null)
            throw new ArgumentNullException("cert");
        RequestId = requestId;
        Disposition = disp;
        Cert = cert;
    }

    // Allow implicit conversion to X509Certificate2. This allows us to use SubmissionResult in any parameter or pipeline that expects a X509Certificate2 object.
    public static implicit operator X509Certificate2(SubmissionResult result)
    {
        if (result == null)
            throw new ArgumentNullException("result");
        return result.Certificate;
    }
}

public class PfxCertificateInfo
{
    public FileInfo FilePath { get; private set; }
    public String[] ProtectTo { get; private set; }
    public SecureString SecurePassword { get; private set; }
    public String Password { get; private set; }

    public PfxCertificateInfo(FileInfo file, String[] protectTo, SecureString securePassword, String password)
    {
        FilePath = file;
        ProtectTo = protectTo;
        SecurePassword = securePassword;
        Password = password;
    }
}

public static class StringExtensions
{
    // Allows us to use "here is a placeholder: {0}".Format(variable) as an extension method instead of String.Format()
    public static String Format(this String value, params object[] parameters)
    {
        return String.Format(value, parameters);
    }
}

// Base class for all cmdlets that allow us to call (for example) WriteWarningEx("Message: {0}", message) over WriteWarning(String.Format("Message: {0}", message))
public abstract class CmdletBase
    : PSCmdlet
{
    protected void WriteWarningEx(String message, params object[] parameters)
    {
        WriteWarning(message.Format(parameters));
    }
    protected void WriteVerboseEx(String message, params object[] parameters)
    {
        WriteVerbose(message.Format(parameters));
    }
    protected void WriteDebugEx(String message, params object[] parameters)
    {
        WriteDebug(message.Format(parameters));
    }
}

// Used to generate strong passwords, but more importantly, using a PRNG as to generate *unique* passwords for each call (unlike System.Random which may return the same value) 
[Cmdlet(VerbsCommon.New, "StrongPassword")]
public class NewStrongPasswordCommand
    : CmdletBase
{
    private static readonly String Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static readonly String Lower = Upper.ToLower();
    private static readonly String Digits = "0123456789";
    private static readonly String Specials = "!@#%&/-_.";
    private static readonly String[] Classes = new[] { Upper, Lower, Digits, Specials };
    private static readonly String Chars = new StringBuilder(Upper).Append(Lower).Append(Digits).Append(Specials).ToString();

    public NewStrongPasswordCommand() { }

    [Parameter(Mandatory = true), ValidateRange(8, 2048)]
    public int Length;

    protected override void ProcessRecord()
    {
        base.ProcessRecord();
        var list = new List<String>(Classes);
        list.RemoveAt(Crypt.GetPRNGNumber(Classes.Length));
        var pwd = new StringBuilder(Length);
        foreach (var @class in list)
        {
            pwd.Append(@class[Crypt.GetPRNGNumber(@class.Length)]);
        }
        while (pwd.Length < Length)
        {
            pwd.Append(Chars[Crypt.GetPRNGNumber(Chars.Length)]);
        }
        for (int i = pwd.Length - 1; i > 0; i--)
        {
            int newIndex = Crypt.GetPRNGNumber(i);
            var c = pwd[i];
            pwd[i] = pwd[newIndex];
            pwd[newIndex] = c;
        }
        WriteObject(pwd.ToString());
    }
}

// Base class for *-CertificateRequest cmdlets, includes some shared methods and parameters
public abstract class StandardExtensionsCmdletBase
    : CmdletBase
{
    [Parameter(Mandatory = false)]
    public System.Security.Cryptography.X509Certificates.X509KeyUsageFlags KeyUsage;

    [Parameter(Mandatory = false)]
    [Alias("EnhancedKeyUsage","EKU")]
    [ValidateNotNullOrEmpty()]
    public Object[] ExtendedKeyUsage;

    [Parameter(Mandatory = false)]
    public X509Extension[] OtherExtension;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public String[] DnsName;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public String[] EmailAddress;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public IPAddress[] IPAddress;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public Uri[] Uri;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public String[] UserPrincipalName;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public SecurityIdentifier Sid;

    // Used to generate the SID URI in the SAN extension.
    protected readonly String SidUriFormat = "tag:microsoft.com,2022-09-14:sid:{0}";

    // This method is used to inform the user that certain parameters have no meaning in certain conditions.
    // For example, if the result of New-CertificateRequest is passed via pipeline to Submit-CertificateRequest,
    // none of the parameters herein are useful as they need to be defined in the first call to New-CertificateRequest.
    public static String[] GetParameters()
    {
        // Get all declared instance parameters in this class
        var list = typeof(StandardExtensionsCmdletBase)
            .GetFields(BindingFlags.Instance | BindingFlags.DeclaredOnly | BindingFlags.Public)
            .Where(f => f.CustomAttributes.Any(c => c.AttributeType == typeof(ParameterAttribute)))
            .Select(f => f.Name)
            .ToList();
        return list.ToArray();
    }

    protected bool BuildEku(out X509EnhancedKeyUsageExtension eku)
    {
        var parameters = MyInvocation.BoundParameters;
        eku = null;

        if (parameters.ContainsKey("ExtendedKeyUsage"))
        {
            var ekuCollection = new OidCollection();
            foreach (var obj in ExtendedKeyUsage)
            {
                var oid = obj as Oid;
                if (oid != null)
                {
                    ekuCollection.Add(oid);
                }
                else
                {
                    var oidString = obj as String;
                    if (!String.IsNullOrEmpty(oidString))
                    {
                        if (Regex.IsMatch(oidString, "^\\d(\\.\\d+)+$"))
                        {
                            // String is a dotted OID string
                            var o = new Oid(oidString);
                            WriteVerboseEx("Adding EKU {0} ('{1}') to request", o.Value, String.IsNullOrEmpty(o.FriendlyName) ? "<unknown>" : o.FriendlyName);
                            ekuCollection.Add(o);
                        }
                        else
                        {
                            // String is literal. Do a wildcard match against the OID lookup list
                            // Possible future enhancement: save each individual wildcard pattern together with its result in a dictionary, and return the saved result if it is found

                            // Get all matching OIDs and write a warning if there were no matches
                            var matchingOids = X509Extensions.ExtendedKeyUsage.FindMatchingOids(oidString);
                            if (matchingOids.Count == 0)
                                WriteWarningEx("Could not find an OID matching the friendly name '{0}'. Either use the dotted numerical OID, or use the Get-ExtendedKeyUsage cmdlet to find a matching OID.", oidString);

                            foreach (var entry in matchingOids)
                            {
                                WriteVerboseEx("Adding EKU {0} ('{1}') to request", entry.Value, entry.FriendlyName);
                                ekuCollection.Add(entry);
                            }
                        }
                    }
                }
            }
            if (ekuCollection.Count > 0)
            {
                eku = new X509EnhancedKeyUsageExtension(ekuCollection, false);
                return true;
            }
        }
        return false;
    }

    protected Uri GenerateSidUri(SecurityIdentifier sid)
    {
        return new Uri(String.Format(SidUriFormat, sid.Value));
    }

    protected bool BuildSan(out X509Extension san)
    {
        var parameters = MyInvocation.BoundParameters;
        var sanBuilder = new SubjectAlternativeNameBuilder();
        var hasContent = false;

        if (parameters.ContainsKey("DnsName"))
        {
            foreach (var value in DnsName)
            {
                WriteVerboseEx("Adding DNS name '{0}' to request", value);
                sanBuilder.AddDnsName(value);
            }
            hasContent = true;
        }
        if (parameters.ContainsKey("EmailAddress"))
        {
            foreach (var value in EmailAddress)
            {
                WriteVerboseEx("Adding email address '{0}' to request", value);
                sanBuilder.AddEmailAddress(value);
            }
            hasContent = true;
        }
        if (parameters.ContainsKey("IPAddress"))
        {
            foreach (var value in IPAddress)
            {
                WriteVerboseEx("Adding IP address '{0}' to request", value);
                sanBuilder.AddIpAddress(value);
            }
            hasContent = true;
        }
        if (parameters.ContainsKey("Uri"))
        {
            foreach (var value in Uri)
            {
                WriteVerboseEx("Adding URI '{0}' to request", value);
                sanBuilder.AddUri(value);
            }
            hasContent = true;
        }
        if (parameters.ContainsKey("UserPrincipalName"))
        {
            foreach (var value in UserPrincipalName)
            {
                WriteVerboseEx("Adding user principal name '{0}' to request", value);
                sanBuilder.AddUserPrincipalName(value);
            }
            hasContent = true;
        }
        if (parameters.ContainsKey("Sid"))
        {
            WriteVerboseEx("Adding security identifier '{0}' to request", Sid.Value);
            sanBuilder.AddUri(GenerateSidUri(Sid));
            hasContent = true;
        }
        san = hasContent ? sanBuilder.Build(false) : null;
        return hasContent;
    }
}

[Cmdlet(VerbsCommon.New, "CertificateRequest")]
[OutputType(typeof(CertificateRequestAndKey))]
public class NewCertificateRequestCommand
    : StandardExtensionsCmdletBase
{
    public NewCertificateRequestCommand()
    {
    }

    [Parameter(Mandatory = true, ValueFromPipeline = true)]
    public AsymmetricAlgorithm PrivateKey;

    [Parameter(Mandatory = true)]
    public X500DistinguishedName Subject;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA256;

    private RSASignaturePadding rsaPadding = RSASignaturePadding.Pkcs1;

    protected override void ProcessRecord()
    {
        var parameters = MyInvocation.BoundParameters;

        CertificateRequest request = null;
        if (PrivateKey is ECDsa)
        {
            WriteVerboseEx("Creating new X509 certificate request using a {0} {1} key", PrivateKey.GetType().Name, PrivateKey.KeySize);
            request = new CertificateRequest(Subject, (ECDsa)PrivateKey, HashAlgorithm);
        }
        else
        {
            WriteVerboseEx("Creating new X509 certificate request using a RSA{0} key", ((RSA)PrivateKey).KeySize);
            request = new CertificateRequest(Subject, (RSA)PrivateKey, HashAlgorithm, rsaPadding);
        }

        // If there is no defined KeyUsage, add a default one based on the private key algorithm
        if (!parameters.ContainsKey("KeyUsage"))
        {
            // Both RSA and ECC use DigitalSignature by default
            KeyUsage = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.DigitalSignature;

            // However ECC use KeyAgreement when it is a ECDH key
            if (PrivateKey is ECDsa)
            {
                // Only add KeyAgreement if the key is a Diffie-Hellman key.
                var key = PrivateKey as ECDsaCng; // The Key property exists only on the Cng version of this class, attempt to cast to it gracefully
                if (key != null && key.Key.AlgorithmGroup == CngAlgorithmGroup.ECDiffieHellman)
                    KeyUsage |= System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyAgreement;
            }
            else
                KeyUsage |= System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyEncipherment;
        }
        WriteVerboseEx("Adding KeyUsage extension with value {0} to request", KeyUsage);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(KeyUsage, false));

        // Add EKUs
        X509EnhancedKeyUsageExtension eku;
        if (BuildEku(out eku))
        {
            request.CertificateExtensions.Add(eku);
        }

        // Add Subject Alternative Name extension if provided
        X509Extension san;
        if (BuildSan(out san))
        {
            request.CertificateExtensions.Add(san);
        }
        
        // Add additional extensions
        if (parameters.ContainsKey("OtherExtension") && OtherExtension != null && OtherExtension.Length > 0)
        {
            foreach (var extension in OtherExtension)
            {
                WriteVerboseEx("Adding custom extension {0} ({1}) to request", extension.Oid.Value, String.IsNullOrEmpty(extension.Oid.FriendlyName) ? "<unknown>" : extension.Oid.FriendlyName);
                request.CertificateExtensions.Add(extension);
            }
        }
        var result = new CertificateRequestAndKey(PrivateKey, request.CreateSigningRequest());
        CertificateRequestAndKey.LastRequest = result;
        WriteObject(result);
    }
}

[Cmdlet(VerbsLifecycle.Submit, "CertificateRequest", DefaultParameterSetName = PSN_REQUESTANDKEY)]
[OutputType(typeof(SubmissionResult))]
public class SubmitCertificateRequestCommand
    : StandardExtensionsCmdletBase
{
    private const String PSN_REQUESTANDKEY = "RequestAndKey";
    private const String PSN_REQUESTONLY = "RequestOnly";

    public SubmitCertificateRequestCommand()
    {
    }

    [Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = PSN_REQUESTANDKEY)]
    public CertificateRequestAndKey RequestAndKey;

    [Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = PSN_REQUESTONLY)]
    [Alias("Csr", "Request")]
    public String CertificateSigningRequest;
    
    [Parameter(Mandatory = true)]
    [Alias("CA")]
    public String ConfigString;

    [Parameter(Mandatory = false)]
    [ValidateNotNullOrEmpty()]
    public String Template;

    private const String TEMPLATE_FORMAT = "CertificateTemplate:{0}";

    // Helper method that creates a SubmissionResult without the private key.
    protected SubmissionResult GetCertificate(CCertRequestClass request)
    {
        return GetCertificate(request, null);
    }

    // Helper method that creates a SubmissionResult with the private key.
    protected SubmissionResult GetCertificate(CCertRequestClass request, AsymmetricAlgorithm key)
    {
        WriteVerboseEx("Retrieving issued certificate");
        var b64cert = request.GetCertificate(1); // 1 = CR_OUT_BASE64
        var cert = new X509Certificate2(Convert.FromBase64String(b64cert));

        // Reserve the use of Disposition for future purposes
        if (key != null)
        {
            WriteVerboseEx("Combining certificate and private key");

            X509Certificate2 certWithKey = null;
            if (key is ECDsa)
                certWithKey =  cert.CopyWithPrivateKey((ECDsa)key);
            else
                certWithKey =  cert.CopyWithPrivateKey((RSA)key);
            
            var keyresult = new SubmissionResult(request.GetRequestId(), RequestDisposition.Issued, certWithKey);
            SubmissionResult.LastResult = keyresult;
            return keyresult;
        }
        var result = new SubmissionResult(request.GetRequestId(), RequestDisposition.Issued, cert);
        SubmissionResult.LastResult = result;
        return result;
    }

    protected void ThrowRequestException(RequestDisposition disposition, CCertRequestClass req)
    {
        var caException = Marshal.GetExceptionForHR(req.GetLastStatus());
        var dispMessage = req.GetDispositionMessage();
        var message = String.Format("Request failed with status {0} ({1}). Extended error message: '{2}'", disposition, dispMessage, caException.Message);
        throw new Exception(message, caException);
    }

    protected override void ProcessRecord()
    {
        var parameters = MyInvocation.BoundParameters;
        var converter = new CBinaryConverterClass();
        var certadmin = new CCertAdminClass();
        var req = new CCertRequestClass();

        String attributes = null;
        if (parameters.ContainsKey("Template"))
        {
            WriteVerboseEx("Adding template '{0}' to request", Template);
            attributes = String.Format(TEMPLATE_FORMAT, Template);
        }

        // Request was created through New-CertificateRequest, which means we have a key
        if (ParameterSetName == PSN_REQUESTANDKEY)
        {
            WriteVerboseEx("Processing dynamic certificate request (no additional modifications will be made in the CA)");

            // Inform the user that the KeyUsage, SAN, OtherExtension and ExtendedKeyUsage parameters have no effect if the request was created by New-CertificateRequest
            var invalidParams = GetParameters();
            foreach (var parameter in invalidParams)
            {
                if (parameters.ContainsKey(parameter))
                {
                    WriteWarning(String.Format("The following parameters can only be used when pre-generated certificate request is provided: {0}\n\nPlease use the New-CertificateRequest cmdlet if you wish to add any of these extensions to the request.", String.Join(", ", invalidParams)));
                    break;
                }
            }

            // Submit request to CA
            WriteVerboseEx("Submitting request to CA ({0})", ConfigString);
            var requestString = converter.StringToString(RequestAndKey.Request, CERTENROLLlib.EncodingType.XCN_CRYPT_STRING_BASE64, CERTENROLLlib.EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER); // Convert pure base64 to base64 with certificate request headers
            var disposition = (RequestDisposition)req.Submit(0x100, requestString, attributes, ConfigString); // The 0x100 is CR_IN_BASE64HEADER | CR_IN_PKCS10
            
            WriteVerboseEx("Request disposition: {0}", disposition);

            string b64cert = null;
            int requestId = 0;
            // Account for having "PEND_ALL_REQUESTS" by checking if the request was set to Pending
            if (disposition == RequestDisposition.Pending || disposition == RequestDisposition.Issued)
            {
                requestId = req.GetRequestId();
                WriteVerboseEx("Request ID: {0}", requestId);
                if (disposition == RequestDisposition.Pending)
                {
                    // Automatically approve the request. No more attributes or extensions to add as they were all included in the initial request.
                    disposition = (RequestDisposition)certadmin.ResubmitRequest(ConfigString, requestId);

                    // If the resubmitted request fails, throw an exception
                    if (disposition != RequestDisposition.Issued)
                    {
                        ThrowRequestException(disposition, req);
                    }
                    
                    // Fetch the issued certificate
                    req.GetIssuedCertificate(ConfigString, requestId, null);
                }

                WriteObject(GetCertificate(req, RequestAndKey.Key));
                return;
            }
            else
            {
                ThrowRequestException(disposition, req);
            }
        }
        // User submitted an out-of-band CSR (i.e., there is no private key for us to use)
        // In this case we will also add any provided extensions to the request, but only if the request was put in Pending state
        else
        {
            WriteVerboseEx("Processing fixed certificate request (extensions may be added in the CA)");
            var requestString = converter.StringToString(CertificateSigningRequest, CERTENROLLlib.EncodingType.XCN_CRYPT_STRING_BASE64_ANY, CERTENROLLlib.EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER); // Convert any base64 format to base64 with certificate request headers

            WriteVerboseEx("Submitting request to CA ({0})", ConfigString);
            var disposition = (RequestDisposition)req.Submit(0x100, requestString, attributes, ConfigString); // The 0x100 is CR_IN_BASE64HEADER | CR_IN_PKCS10

            int requestId = req.GetRequestId();
            WriteVerboseEx("Request ID: {0}", requestId);

            WriteVerboseEx("Request disposition: {0}", disposition);

            // After submitting the request, we can add extensions to it, provided that the passed them in the function call.
            // To add extensions, the request must be in the Pending state, which means that we now need to check whether the certificate was immediately issued.

            if (disposition == RequestDisposition.Issued)
            {
                // The certificate was issued immediately, write a warning in case any of the extension parameters were used and simply return the certificate

                var extensionParams = GetParameters();
                foreach (var parameter in extensionParams)
                {
                    if (parameters.ContainsKey(parameter))
                    {
                        WriteWarning(String.Format("At least one extension parameter was provided, but the CA issued the certificate immediately. To add extensions to a pre-generated certificate request, configure the CA to require manager approval either globally or for the template."));
                        break;
                    }
                }
                WriteObject(GetCertificate(req));
            }
            else if (disposition == RequestDisposition.Pending)
            {
                // If the request was put in the Pending state, we can continue with adding additional extensions to it

                if (parameters.ContainsKey("KeyUsage"))
                {
                    WriteVerboseEx("Adding KeyUsage extension with value {0} to request", KeyUsage);
                    var keyUsage = new X509KeyUsageExtension(KeyUsage, false);
                    CertAdminHelper.SetExtension(ConfigString, requestId, keyUsage);
                }

                // Add EKUs
                X509EnhancedKeyUsageExtension eku;
                if (BuildEku(out eku))
                {
                    CertAdminHelper.SetExtension(ConfigString, requestId, eku);
                }

                // Add Subject Alternative Name extension if provided
                X509Extension san;
                if (BuildSan(out san))
                {
                    CertAdminHelper.SetExtension(ConfigString, requestId, san);
                }
        
                // Add additional extensions
                if (parameters.ContainsKey("OtherExtension") && OtherExtension != null && OtherExtension.Length > 0)
                {
                    foreach (var extension in OtherExtension)
                    {
                        WriteVerboseEx("Adding custom extension {0} ({1}) to request", extension.Oid.Value, String.IsNullOrEmpty(extension.Oid.FriendlyName) ? "<unknown>" : extension.Oid.FriendlyName);
                        CertAdminHelper.SetExtension(ConfigString, requestId, extension);
                    }
                }

                // Approve the request
                WriteVerboseEx("Approving request {0}", requestId);
                disposition = (RequestDisposition)certadmin.ResubmitRequest(ConfigString, requestId);

                // If the resubmitted request fails, throw an exception
                if (disposition != RequestDisposition.Issued)
                {
                    ThrowRequestException(disposition, req);
                }

                // Fetch the issued certificate
                req.GetIssuedCertificate(ConfigString, requestId, null);

                // If the request was successful, get the issued certificate and return it
                WriteObject(GetCertificate(req));
            }
            else
            {
                ThrowRequestException(disposition, req);
            }
        }
    }
}
"@

$CertReqUtilDllName = "CertReqUtil.dll"
$CertReqUtilDllPath = [Path]::Combine($TempPath, $CertReqUtilDllName)

$BaseAssemblies = [String[]]@("mscorlib.dll", "System.dll", "System.Core.dll", "System.Runtime.dll", "System.Security.dll", "System.Linq.dll", [PSCmdlet].Assembly.Location)
$Assemblies = [List[String]]::new($BaseAssemblies)
$Assemblies.AddRange($FilesToProcess)
$Parameters = [CompilerParameters]::new($Assemblies)
$Parameters.CompilerOptions = "/unsafe"
$Parameters.OutputAssembly = $CertReqUtilDllPath
$Parameters.GenerateInMemory = $false

$Provider = [System.CodeDom.Compiler.CodeDomProvider]::CreateProvider("CSharp")
"Compiling {0}" -f $CertReqUtilDllName | Write-Verbose
$Results = $Provider.CompileAssemblyFromSource($Parameters, $Code)
$Results.Errors | Out-Host
$FilesToProcess.Add($CertReqUtilDllPath)

$ModuleName,$ManifestName | ForEach-Object -Process {
    $ItemPath = [Path]::Combine($MyPath, $_)
    $Item = Copy-Item -Path $ItemPath -Destination $TempPath -PassThru -Force
    $FilesToProcess.Add($Item)
}

$InstallerPath = [Path]::Combine($TempPath, $InstallScript)
Copy-Item -LiteralPath ([Path]::Combine($MyPath, $InstallScript)) -Destination $TempPath -Force

If ($Sign)
{
    "Signing certificate selection" | Write-Host
    $Location = [Enum]::Parse([StoreLocation], ([Enum]::GetNames([StoreLocation]) | Out-GridView -OutputMode Single -Title "Select a certificate store location"))
    $Name = [StoreName]::My
    $Store = [X509Store]::new($Name, $Location)
    $Store.Open("ReadOnly, MaxAllowed, OpenExistingOnly")
    $Certs = [X509Certificate2UI]::SelectFromCollection(
        $Store.Certificates.Find("FindByApplicationPolicy", "1.3.6.1.5.5.7.3.3", $true) # Code Signing
        , "Certificate selection"
        , "Select a signing certificate"
        , [X509SelectionFlag]::SingleSelection)
    $Store.Dispose()

    If ($Certs.Count -eq 0)
    {
        throw "No signing certificate selected"
    }
    $SigningCert = $Certs[0]
    If (!$SigningCert.HasPrivateKey)
    {
        throw "Selected signing certificate does not have a private key"
    }
    "Signing files" | Write-Verbose
    $SigningResults = $FilesToProcess | Set-AuthenticodeSignature -Certificate $SigningCert -IncludeChain All -HashAlgorithm SHA256 -Force -ErrorAction Stop
    $InstallerPath | Set-AuthenticodeSignature -Certificate $SigningCert -IncludeChain all -HashAlgorithm SHA256 -Force -ErrorAction Stop | Out-Null
}

$ZipArchiveName = [Path]::ChangeExtension([Path]::GetFileName($ModuleName),"zip")
$ZipPath = [Path]::Combine($MyPath, $ZipArchiveName)
$FilesToProcess | Compress-Archive -DestinationPath $ZipPath -Force -CompressionLevel Optimal

$CombinedZipName = "Install{0}" -f $ZipArchiveName
$CombinedZipPath = [Path]::Combine($PSScriptRoot, $CombinedZipName)

$InstallerPath,$ZipPath | Compress-Archive -DestinationPath $CombinedZipPath -Force -CompressionLevel Optimal

[Directory]::SetCurrentDirectory([Directory]::GetParent($TempPath))

Remove-Item -LiteralPath $TempPath -Recurse -Force
Remove-Item -LiteralPath $ZipPath -Force