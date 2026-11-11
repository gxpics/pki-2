'''
PKI uses three software components:
1. SoftHSM stores the root CA's private and public keys.
2. PKCS#11 provider allows OpenSSL to access those keys.
3. OpenSSL generates the root CA certificate using the key.

'''
from pathlib import Path
import subprocess
import shutil
from common import BASE_DIR, run_command

# move csr from /mnt/fghs/transfer --> rootCA/csr
def import_csr(csr_name, source_dir="/mnt/hgfs/transfer", 
               dest_dir="/home/gxpics/pki-2/offline_root_ca/csr"):
    """
    The purpose is to import an intermediate CA's CSR from the 
    VMware shared folder into the root CA's internal csr/ directory
    """
    
    source = Path(source_dir) / csr_name # VMWare shared folder
    destination = Path(dest_dir) / csr_name # Root CA CSR directory
    if not source.is_file():
        raise FileNotFoundError(f"CSR not found: {source}")

    # Avoid accidentally overwriting an existing CSR
    if destination.exists():
        raise FileExistsError(f"CSR already exists: {destination}")
    
    # Validate CSR structure and signature before importing
    # CSR signature verification establishes proof of possession of the corresponding 
    # private key. It does not establish that the requester is authorized to receive 
    # an intermediate CA certificate. That requires a separate approval step.
    subprocess.run(
        ["openssl", "req", "-in", str(source),
         "-noout", "-verify"],
        check=True
    )

    # Copy CSR
    shutil.copy2(source, destination)

    print(f"CSR imported: {destination}")

def sign_intermediate(intermediate_name, source_dir = BASE_DIR / "csr", dest_dir = BASE_DIR / "issued"):
    """
    The intermediate's csr should be in BASE_DIR / csr
    The signed certificate will be placed in BASE_DIR / issued 
    """
    source_path = source_dir / f"{intermediate_name}.csr"
    cert_path = dest_dir / f"{intermediate_name}.crt"

    if cert_path.exists():
        print(f"Certificate already exists: {cert_path}")
        print("Skipping intermediate signing.")
        return

    command = [
        "openssl", "ca",
        "-batch",
        "-config", BASE_DIR / "openssl.cnf",
        "-extensions", "v3_intermediate_ca",
        "-days", "3650",
        "-in", source_path,
        "-out", cert_path,
    ]

    run_command(command)


def verify_intermediate(intermediate_cert_file, root_cert_dir = BASE_DIR / "certs", intermediate_cert_dir = BASE_DIR / "issued"):
    command = [
        "openssl","verify",
        "-purpose",
        "any",      # Tell OpenSSL not to assume a specific end use when verifying, used to avoid restricting verification to a specific certificate purpose.
        "-CAfile",
        root_cert_dir / "rootCA.crt",
        intermediate_cert_dir / intermediate_cert_file
    ]

    run_command(command)

def revoke_certificate(intermediate_name, cert_dir=BASE_DIR / "issued"):
    """
    Revoke an intermediate CA certificate.

    The certificate must have been issued by this Root CA.
    OpenSSL updates the CA database (index.txt).
    """

    cert_path = cert_dir / f"{intermediate_name}.crt"

    if not cert_path.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {cert_path}"
        )

    command = [
        "openssl","ca",
        "-config", BASE_DIR / "openssl.cnf",
        "-revoke", cert_path,
        "-crl_reason", "superseded"
    ]

    run_command(command)
    generate_crl()
    
    print(f"Certificate revoked: {cert_path}")

def generate_crl(crl_dir=BASE_DIR / "crl"):
    """
    Generate a Certificate Revocation List (CRL)
    using the Root CA database.
    The CRL contains certificates revoked by this Root CA.
    """

    if not crl_dir.is_dir():
        raise NotADirectoryError(
            f"CRL directory not found: {crl_dir}"
        )

    crl_path = crl_dir / "rootCA.crl"

    command = [
        "openssl",
        "ca",
        "-gencrl",
        "-config",
        BASE_DIR / "openssl.cnf",
        "-out",
        crl_path
    ]

    run_command(command)

    print(f"CRL generated: {crl_path}")

    return crl_path

def archive_certificate(
    intermediate_name,
    source_dir=BASE_DIR / "issued",
    archive_dir=BASE_DIR / "archive"
):
    """
    Archive a revoked intermediate CA certificate.
    The archived filename includes the certificate serial number.
    """

    cert_path = source_dir / f"{intermediate_name}.crt"

    if not cert_path.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {cert_path}"
        )

    # Retrieve the certificate serial number
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-in", str(cert_path),
            "-noout",
            "-serial"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    serial = result.stdout.strip().split("=", 1)[1]

    archive_dir.mkdir(parents=True, exist_ok=True)

    archive_path = archive_dir / f"{intermediate_name}-{serial}.crt"

    # Prevent overwriting archived certificates
    if archive_path.exists():
        raise FileExistsError(
            f"Archived certificate already exists: {archive_path}"
        )

    shutil.move(str(cert_path), str(archive_path))

    print(f"Certificate archived: {archive_path}")

    return archive_path

def export_to_media(source_path, transfer_dir):  #dev only
    source_path = Path(source_path)
    destination_dir = Path(transfer_dir)

    # Check that source file exists
    if not source_path.is_file():
        raise FileNotFoundError(f"Source file not found: {source_path}")
   

    # Check that destination directory exists
    if not destination_dir.is_dir():
        raise NotADirectoryError(f"Transfer directory not found: {destination_dir}")

    destination = destination_dir / source_path.name
    shutil.copy2(source_path, destination)

    return destination

def export_cert(cert_name, source_dir = None, transfer_dir = "/mnt/hgfs/transfer"):
    if source_dir is None:
        source_dir = BASE_DIR / "issued"
    
    source = source_dir / cert_name

    # Verify certificate exists
    if not source.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {source}"
        )

    # Validate certificate format
    subprocess.run(
        ["openssl", "x509", "-in", str(source), "-noout"],
        check=True
    )

    # Export certificate to transfer directory
    destination = export_to_media(source, transfer_dir)

    print(f"Certificate exported: {destination}")

    return destination

def main():
    # import_csr(csr_name="intermediateCA1.csr")
    
    #sign_intermediate("intermediateCA1")
    #verify_intermediate("intermediateCA1.crt")
    
    # revoke_certificate("intermediateCA1")
    # archive_certificate("intermediateCA1")
    
    # export_cert("intermediateCA1.crt")  # offline root CA --> transfer
    # export_cert("rootCA.crt", source_dir = root_dir / "certs") # offline root CA --> transfer
    
    # Check ls /mnt/hgfs/transfer/
    intermediate_ca_name = "intermediateCA4"
    sign_intermediate(intermediate_ca_name)  
    verify_intermediate(f"{intermediate_ca_name}.crt")

if __name__ == "__main__":
    main()

