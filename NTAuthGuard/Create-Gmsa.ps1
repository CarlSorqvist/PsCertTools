$FQDN = "ntauthguard.contoso.com"
$Name = "s0ntauthguard"
New-ADServiceAccount -Description "NTAuth Guard Service Account" `
 -DisplayName $Name `
 -DNSHostName $FQDN `
 -CompoundIdentitySupported $true `
 -Enabled $true `
 -Name $Name `
 -KerberosEncryptionType AES128,AES256 `
 -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers" `
 -ServicePrincipalNames "host/$FQDN"
