* Add cmdlet/function to get/set Officer and Enrollment Agent Rights
* Update Submit-CertificateRequest to allow setting extensions on a pending request even if the original request was created with New-CertificateRequest
* Create new cmdlet to retrieve published templates from AD
* Create new cmdlet to get all Enrollment Services from AD
* Create new cmdlet to get all CAs that publish a certain template
* Update Submit-CertificateRequest to support scenarios where the user is not a certificate manager (i.e. the request status is Pending)
* Update Submit-CertificateRequest to allow empty ConfigStrings if a Template is specified, in which case it looks up which CAs publish the template and ask the user to select the issuing CA in case there is more than one result
* Allow submitting custom request attributes in Submit-CertificateRequest
* Add cmdlet or function to parse a certificate request and display its contents
