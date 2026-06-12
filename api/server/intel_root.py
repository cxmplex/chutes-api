"""Pinned Intel SGX/TDX provisioning root certificate.

The TDX quote's PCK certificate chain roots at the "Intel SGX Root CA" (the same root anchors
SGX and TDX provisioning). We pin it explicitly and verify quotes via dcap-qvl's
``verify_with_root_ca`` instead of delegating to the library's built-in root -- the same
deliberate trust-anchor posture as the AMD ARK pin in snp_verify (ARK_PUBKEY_SHA384) and the
Google EK/AK CA Root pin in gcp_vtpm.

Provenance (verified 2026-06-12 from two independent sources, byte-identical):
  - Intel PCS: https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem
  - the root embedded in the dcap-qvl 0.3.12 verification library itself
  sha256(DER) = 44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3
  subject == issuer == CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US
  validity    2018-05-21 .. 2049-12-31 (self-signed, ECDSA P-256)
"""

import ssl

INTEL_SGX_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
"""

INTEL_SGX_ROOT_CA_DER = ssl.PEM_cert_to_DER_cert(INTEL_SGX_ROOT_CA_PEM)
