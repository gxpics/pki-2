# PKI Lab

This project is a hands-on lab built for learning how to set up, operate,
and troubleshoot a public key infrastructure (PKI). It uses Python and
OpenSSL to automate certificate requests, issuance, and verification.

The lab uses an offline root CA on an Ubuntu VM with a signing key stored
in SoftHSM. Intermediate CAs on Ubuntu and AWS EC2 issue TLS server
certificates. Nginx serves the resulting certificates, and OpenSSL is
used to verify the certificate chain and hostname during a TLS connection.

## Roadmap

- **Certificate lifecycle management (CLM):** Track issued certificates and
  automate expiration alerts and renewals. Add revocation checks using CRLs
  and OCSP.
- **Hardware security modules (HSMs):** Extend the lab beyond SoftHSM by
  testing AWS CloudHSM for intermediate CA signing keys and certificate issuance.