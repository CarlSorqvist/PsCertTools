﻿#Requires -version 5 -runasadministrator

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
# SIG # Begin signature block
# MIIOYAYJKoZIhvcNAQcCoIIOUTCCDk0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCFA13lZAVkrFnQ
# KWJ81c7effjTdMaqK4nTxcShSEsBnaCCDDYwggOAMIIDBaADAgECAhB0CEyiBINe
# hU2MPucrVyLqMAoGCCqGSM49BAMDME8xCzAJBgNVBAYTAlNFMRAwDgYDVQQKDAdD
# b250b3NvMRIwEAYDVQQLDAlDb3Jwb3JhdGUxGjAYBgNVBAMMEUNvbnRvc28gUm9v
# dCBDQSAxMCAXDTIyMDkxNjA4MDIzMFoYDzIwNzIwOTE2MDgxMjI5WjBPMQswCQYD
# VQQGEwJTRTEQMA4GA1UECgwHQ29udG9zbzESMBAGA1UECwwJQ29ycG9yYXRlMRow
# GAYDVQQDDBFDb250b3NvIFJvb3QgQ0EgMTB2MBAGByqGSM49AgEGBSuBBAAiA2IA
# BL293FOstEiiCFwL09RLya1pCfAb8HJi2wFp0FiNB97HTfnTocPBjixnWnfrJMKj
# crKu8JosEME9QVGDHhy2QU944CTsaTfl/Vf1wiAx5YVhVap6S+FGVY4k1ND8vKcP
# p6OCAaIwggGeMAsGA1UdDwQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1Ud
# DgQWBBRadv4213Qdeb3CSzidIxVtVLr3PjAQBgkrBgEEAYI3FQEEAwIBADCCAUgG
# A1UdIASCAT8wggE7MFQGDCsGAQQBgu8DA2MBATBEMEIGCCsGAQUFBwICMDYeNABD
# AG8AbgB0AG8AcwBvACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAUABvAGwAaQBj
# AHkwgYAGDCsGAQQBgu8DA2MCATBwMG4GCCsGAQUFBwICMGIeYABDAG8AbgB0AG8A
# cwBvACAAUgBvAG8AdAAgAEMAQQAgADEAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUA
# IABQAHIAYQBjAHQAaQBjAGUAIABTAHQAYQB0AGUAbQBlAG4AdDBYBgwrBgEEAYLv
# AwNjBAEwSDBGBggrBgEFBQcCAjA6HjgAQwBvAG4AdABvAHMAbwAgAFIAbwBvAHQA
# IABDAEEAIAAxACAASQBkAGUAbgB0AGkAZgBpAGUAcjAGBgRVHSAAMAoGCCqGSM49
# BAMDA2kAMGYCMQCnsdUtbA+pJpuJq8jmYKjjbQSrdr7oSXCvDhHAZQZLPb8R33QA
# T+l+jx/SCpZ5yikCMQDaema7BXv1rB+nde1RL5b0f4e4WwF/pSIsFWpg4bJ+G+Ei
# Kpwj3wYpfzCmBgwahJMwggQoMIIDraADAgECAhNmAAAAVot9kWhlNr6vAAAAAABW
# MAoGCCqGSM49BAMDMFUxCzAJBgNVBAYTAlNFMRAwDgYDVQQKDAdDb250b3NvMRIw
# EAYDVQQLDAlDb3Jwb3JhdGUxIDAeBgNVBAMMF0NvbnRvc28gRW50ZXJwcmlzZSBD
# QSAxMB4XDTIyMTExMTEzMzQxMFoXDTI3MTExMDEzMzQxMFowfDETMBEGCgmSJomT
# 8ixkARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2NvbnRvc28xFDASBgoJkiaJk/Is
# ZAEZFgRjb3JwMQ4wDAYDVQQLDAVUaWVyMDEWMBQGA1UECwwNQWRtaW5BY2NvdW50
# czEOMAwGA1UEAwwFYTBjc28wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARfTVcwTqG+
# 9tP3Uymlpk6cUoiVtsD8OqA7O8m9OuM6fJm6nGOpjNZ3XDO7jYCLzY3hJszGf57c
# AKi3brLSfJ9WC/B3vf0NiR/az7L3m0CVXr4jJZvGM6hLYRZjJ1Vx8TOjggIWMIIC
# EjA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiDrd9CgaqUUYfNmyCHobxuhMi+
# OWCBl6JXh62ydwIBZAIBAzAfBgNVHSUEGDAWBgorBgEEAYI3PQEBBggrBgEFBQcD
# AzAOBgNVHQ8BAf8EBAMCB4AwKQYJKwYBBAGCNxUKBBwwGjAMBgorBgEEAYI3PQEB
# MAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTFMioPPHzORqBCYg9GADhXjvLuqzAfBgNV
# HSMEGDAWgBSVn1UTHsa/xUr4lO0O0YkkNcmYmTBSBgNVHR8ESzBJMEegRaBDhkFo
# dHRwOi8vcGtpLmNvcnAuY29udG9zby5jb20vY2RwL0NvbnRvc28lMjBFbnRlcnBy
# aXNlJTIwQ0ElMjAxLmNybDBdBggrBgEFBQcBAQRRME8wTQYIKwYBBQUHMAKGQWh0
# dHA6Ly9wa2kuY29ycC5jb250b3NvLmNvbS9haWEvQ29udG9zbyUyMEVudGVycHJp
# c2UlMjBDQSUyMDEuY3J0MDEGA1UdEQQqMCigJgYKKwYBBAGCNxQCA6AYDBZhMGNz
# b0Bjb3JwLmNvbnRvc28uY29tME8GCSsGAQQBgjcZAgRCMECgPgYKKwYBBAGCNxkC
# AaAwBC5TLTEtNS0yMS0yMDk4NTk2MTgxLTIxNjEzNTkzODYtMzM4OTYxNDcyNy0x
# MTA1MAoGCCqGSM49BAMDA2kAMGYCMQCIq0jIrS7grEwrRDMXJg8+cXN19n1WVHir
# QIHhdXuxlfEDDYRTz+03J4eX6ShX+E4CMQCDRX4LEGaBF+09ufiBVafHy1GjBvLg
# CYCA985kzdfP5ZbKHL6Yi4SpZqUS//k2j78wggSCMIIEB6ADAgECAhMfAAAAAjTH
# fS9X6OVUAAAAAAACMAoGCCqGSM49BAMDME8xCzAJBgNVBAYTAlNFMRAwDgYDVQQK
# DAdDb250b3NvMRIwEAYDVQQLDAlDb3Jwb3JhdGUxGjAYBgNVBAMMEUNvbnRvc28g
# Um9vdCBDQSAxMB4XDTIyMDkxOTA2NDYyNVoXDTQ3MDkxOTA2NTYyNVowVTELMAkG
# A1UEBhMCU0UxEDAOBgNVBAoMB0NvbnRvc28xEjAQBgNVBAsMCUNvcnBvcmF0ZTEg
# MB4GA1UEAwwXQ29udG9zbyBFbnRlcnByaXNlIENBIDEwdjAQBgcqhkjOPQIBBgUr
# gQQAIgNiAARK2mp4AdjJNvzciMTXoFjlb+TZfAffd03fyUCbyi3dSkReX1EIAxN1
# Zor4scw6Lj3K7TEL+P+tX4aTi5Kio/ddo6q4ks9daHgyemjN4JJLEgRaZ2EVKeYf
# Zuu8bz8u856jggKdMIICmTAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUlZ9V
# Ex7Gv8VK+JTtDtGJJDXJmJkwggFgBgNVHSAEggFXMIIBUzBUBgwrBgEEAYLvAwNj
# AQEwRDBCBggrBgEFBQcCAjA2HjQAQwBvAG4AdABvAHMAbwAgAEMAZQByAHQAaQBm
# AGkAYwBhAHQAZQAgAFAAbwBsAGkAYwB5MIGMBgwrBgEEAYLvAwNjAgIwfDB6Bggr
# BgEFBQcCAjBuHmwAQwBvAG4AdABvAHMAbwAgAEUAbgB0AGUAcgBwAHIAaQBzAGUA
# IABDAEEAIAAxACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAUAByAGEAYwB0AGkA
# YwBlACAAUwB0AGEAdABlAG0AZQBuAHQwZAYMKwYBBAGC7wMDYwQCMFQwUgYIKwYB
# BQUHAgIwRh5EAEMAbwBuAHQAbwBzAG8AIABFAG4AdABlAHIAcAByAGkAcwBlACAA
# QwBBACAAMQAgAEkAZABlAG4AdABpAGYAaQBlAHIwBgYEVR0gADAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAfBgNVHSMEGDAWgBRadv4213Qdeb3CSzidIxVtVLr3PjBMBgNVHR8ERTBDMEGg
# P6A9hjtodHRwOi8vcGtpLmNvcnAuY29udG9zby5jb20vY2RwL0NvbnRvc28lMjBS
# b290JTIwQ0ElMjAxLmNybDBXBggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0
# dHA6Ly9wa2kuY29ycC5jb250b3NvLmNvbS9haWEvQ29udG9zbyUyMFJvb3QlMjBD
# QSUyMDEuY3J0MAoGCCqGSM49BAMDA2kAMGYCMQCFWE+m8SJxPd+5uz/dlDtm6w/F
# OkJ3Oks+zV3IUYmm8c3T+LbgoFFic84Q6uRQFucCMQDFK7ZZcrbM24RJoTMaPfN2
# G6Dt7PVrE/II5bb62myozUajeXChRUCzKP/BxRurZJIxggGAMIIBfAIBATBsMFUx
# CzAJBgNVBAYTAlNFMRAwDgYDVQQKDAdDb250b3NvMRIwEAYDVQQLDAlDb3Jwb3Jh
# dGUxIDAeBgNVBAMMF0NvbnRvc28gRW50ZXJwcmlzZSBDQSAxAhNmAAAAVot9kWhl
# Nr6vAAAAAABWMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGNgiBHofjVsAnnD2lndg3bs
# kCjnogVMcvFb1q1VFhB0MAsGByqGSM49AgEFAARmMGQCMDBUHyonphhF0D0Rnn32
# SXm7UlANmevYXSWm4GQe7OnVkJfnyq4TgqtZTTaRaVoX9gIwU+vxaQ4EZ+OyAE4S
# uw1uI/sJcSR2Qh0XAdDSEv3ZWtC6Kire/FU3Iv0mLH3D0byR
# SIG # End signature block