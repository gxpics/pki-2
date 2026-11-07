"""
Intermediate CA operations on EC2
- Verify intermediate CA certs
- Sign server's CSR
- More to be added for CLM
"""
from pathlib import Path
import shutil
import ipaddress
import re
from cryptography import x509
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS
from common import BASE_DIR, run_command

def export_csr(ca_dir, ca_name, export_dir):
    """
    Export the intermediate CA's CSR for transfer to the offline root CA
    """
    csr_path = ca_dir / "csr" / f"{ca_name}.csr"
    export_path = export_dir / f"{ca_name}.csr"

    if not csr_path.exists():
        raise FileNotFoundError(f"CSR not found: {csr_path}")
    export_dir.mkdir(parents=True, exist_ok = True)
    shutil.copy2(csr_path, export_path)
    print(f"Exported CSR to: {export_path}")

def verify_intermediate_cert(ca_dir, ca_name):
    """
    Verify the intermediate certificate against the root
    """
    command = [
        "openssl",
        "verify",
        "-CAfile",
        ca_dir / "certs" / "rootCA.crt",
        ca_dir / "certs" / f"{ca_name}.crt"
    ]

    run_command(command)


def verify_csr_san(csr_path, approved_san):
    """
    Verify that the SAN requested in the CSR
    exactly matches the approved SAN.
    """

    csr_path = Path(csr_path)

    # Load the CSR
    csr = x509.load_pem_x509_csr(
        csr_path.read_bytes()
    )

    # Extract the SAN extension
    try:
        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        raise ValueError("CSR does not contain a SAN")

    # Construct the expected SAN
    if approved_san.startswith("IP:"):
        expected = x509.IPAddress(
            ipaddress.ip_address(approved_san[3:])
        )

    elif approved_san.startswith("DNS:"):
        expected = x509.DNSName(approved_san[4:])

    else:
        raise ValueError("Invalid approved SAN format")

    # Compare requested SAN with approved SAN
    requested = list(san_ext)

    if requested != [expected]:
        raise ValueError(
            f"CSR SAN does not match approved SAN: {approved_san}"
        )

    print("CSR SAN verification successful")

def sign_server_csr(approved_san, server_name="server1", intermediate_ca_name="intermediateCA1", #csr_path, approved_san, output_path, 
validity_days=365):
    """
    Sign a TLS server CSR using the Intermediate CA.

    The approved_san must be specified independently
    of the CSR, for example:
        IP:203.0.113.10
        DNS:web.example.com
    """
    intermediate_ca_dir = BASE_DIR / intermediate_ca_name 
    csr_path = intermediate_ca_dir / 'csr' / f'{server_name}.csr' 
    output_path = intermediate_ca_dir / 'issued' / f'{server_name}.crt' 

    # 1. Validate the approved SAN
    if approved_san.startswith("IP:"):
        ip = approved_san[3:]
        ipaddress.ip_address(ip)
        san = f"IP:{ip}"

    elif approved_san.startswith("DNS:"):
        dns = approved_san[4:]
        if (
            len(dns) > 253
            or not re.fullmatch(
                r"(?=.{1,253}$)[A-Za-z0-9]"
                r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                r"(?:\.[A-Za-z0-9]"
                r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
                dns
            )
        ):
            raise ValueError("Invalid DNS name")
        san = f"DNS:{dns}"

    else:
        raise ValueError(
            "SAN must start with IP: or DNS:"
        )

    # 2. Verify CSR signature
    '''
    The verify option checks the digital signature on the CSR file. 
    That proves the requester holds the private key for the 
    included public key. But it doesn't prove their identity or control 
    of a domain. So the intermediate CA should do both that 
    signature check and also validate the domain separately.
    '''
    run_command([
        "openssl", "req",
        "-in", str(csr_path),
        "-noout", "-verify"
    ])

    # Inspect the CSR before issuing
    run_command([
        "openssl", "req",
        "-in", str(csr_path),
        "-noout", "-text"
    ])
    # 3. Verify CSR SAN matches approved SAN
    verify_csr_san(csr_path, approved_san)

    # 4. Create certificate extension configuration
    ext_path = intermediate_ca_dir / "server_ext.cnf"  # temporary config file openssl uses

    ext_path.write_text(
        "[server_cert]\n"
        "basicConstraints = critical,CA:FALSE\n"
        "keyUsage = critical,digitalSignature\n"
        "extendedKeyUsage = serverAuth\n"
        f"subjectAltName = {san}\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid,issuer\n"
    )

    # 5. Issue certificate
    run_command([
        "openssl", "ca",
        "-config", str(intermediate_ca_dir / "openssl.cnf"),
        "-extensions", "server_cert",
        "-extfile", str(ext_path),
        "-in", str(csr_path),
        "-out", str(output_path),
        "-days", str(validity_days),
        "-batch",
        "-notext"
    ])

    # 6. Verify issued certificate
    run_command([
        "openssl", "verify",
        "-CAfile", str(intermediate_ca_dir / "certs" / "rootCA.crt"),
        "-untrusted", str(intermediate_ca_dir / "certs" / f"{intermediate_ca_name}.crt"),
        str(output_path)
    ])

    print(f"Certificate issued: {output_path}")

def revoke_certificate():
    pass

def generate_crl():
    pass

def export_csr_for_intermediate_ca_on_local_VM():
    ca_name = "intermediateCA1"
    ca_dir = BASE_DIR / ca_name
    export_dir = Path("/mnt/transfer")
    export_csr(ca_dir, ca_name, export_dir)

    ca_name = "intermediateCA2"
    ca_dir = BASE_DIR / ca_name
    export_csr(ca_dir, ca_name, export_dir)

def main():
    # Intermediate CAs on EC2 
    intermediate_ca_name = "intermediateCA4"
    server_name = "server4"
    # ca_dir = BASE_DIR / intermediate_ca_name
    # csr_path = ca_dir / "csr" / f"{server_name}.csr"
    # output_path = ca_dir / "issued" / f"{server_name}.crt"
    approved_san = f"DNS:{server_name}"# "IP:3.128.35.251",  # currently manual approval is used, 
        # Later, approved_sans should be managed by RA or database that stores each server's identity, 
        # its approved SANs, and other relevant informationf
    sign_server_csr(approved_san, server_name, intermediate_ca_name)
    pass

if __name__ == "__main__":
    main()
    