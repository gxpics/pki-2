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
from tempfile import TemporaryDirectory
import os
import subprocess
from datetime import datetime, timezone

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
    run_command(
        ["openssl", "req", "-in", str(source),
         "-noout", "-verify"])

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

def generate_crl(crl_dir=BASE_DIR / "crl", *, export_path=None):
    """Generate a signed root CA CRL and optionally export it as DER."""
    crl_dir = Path(crl_dir)
    if not crl_dir.is_dir():
        raise NotADirectoryError(f"CRL directory not found: {crl_dir}")

    pem_path = crl_dir / "root-ca.crl"
    root_cert = BASE_DIR / "certs" / "rootCA.crt"

    if export_path is not None:
        export_path = Path(export_path)
        if export_path.resolve() == pem_path.resolve():
            raise ValueError("Use separate paths for the PEM CRL and DER export.")
        export_path.parent.mkdir(parents=True, exist_ok=True)

    with TemporaryDirectory(dir=crl_dir) as temp_dir:
        staged_pem = Path(temp_dir) / "root-ca.crl"

        run_command([
            "openssl", "ca", "-gencrl",
            "-config", BASE_DIR / "openssl.cnf",
            "-out", staged_pem,
        ])

        if export_path is not None:
            with TemporaryDirectory(dir=export_path.parent) as export_temp_dir:
                staged_der = Path(export_temp_dir) / "root-ca.crl"

                run_command([
                    "openssl", "crl",
                    "-inform", "PEM", "-in", staged_pem,
                    "-outform", "DER", "-out", staged_der,
                ])
                run_command([
                    "openssl", "crl",
                    "-inform", "DER", "-in", staged_der,
                    "-CAfile", root_cert, "-no-CApath", "-no-CAstore",
                    "-verify", "-noout", "-lastupdate", "-nextupdate",
                ])

                staged_pem.replace(pem_path)
                staged_der.replace(export_path)
            print(f"Verified DER CRL exported: {export_path}")
        else:
            staged_pem.replace(pem_path)

    print(f"PEM CRL generated: {pem_path}")
    return pem_path


def verify_root_crl(crl_path, root_cert_path):
    """Verify the signature and validity period of a DER root CA CRL."""
    result = subprocess.run(
        [
            "openssl", "crl",
            "-inform", "DER",
            "-in", str(crl_path),
            "-CAfile", str(root_cert_path),
            "-no-CApath",
            "-no-CAstore",
            "-verify",
            "-noout",
            "-lastupdate",
            "-nextupdate",
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )

    fields = dict(
        line.split("=", 1)
        for line in result.stdout.splitlines()
        if "=" in line
    )

    date_format = "%b %d %H:%M:%S %Y GMT"
    try:
        last_update = datetime.strptime(
            fields["lastUpdate"], date_format
        ).replace(tzinfo=timezone.utc)
        next_update = datetime.strptime(
            fields["nextUpdate"], date_format
        ).replace(tzinfo=timezone.utc)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Missing or invalid CRL update dates in {crl_path}") from exc

    now = datetime.now(timezone.utc)
    if not last_update <= now < next_update:
        raise ValueError(
            f"CRL is outside its validity period: "
            f"lastUpdate={last_update.isoformat()}, "
            f"nextUpdate={next_update.isoformat()}"
        )

    print(f"CRL verified: {crl_path}")
    print(f"Next update: {next_update.isoformat()}")


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
    # intermediate_ca_name = "intermediateCA4"
    # sign_intermediate(intermediate_ca_name)  
    # verify_intermediate(f"{intermediate_ca_name}.crt")
    
    export_path = BASE_DIR / "export" / "root-ca.crl"
    #generate_crl(export_path=export_path)
  
    verify_root_crl(
    export_path,
    BASE_DIR / "certs" / "rootCA.crt",
    )
if __name__ == "__main__":
    main()

