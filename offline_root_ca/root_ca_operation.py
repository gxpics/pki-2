from pathlib import Path
import subprocess
import shutil
from common import root_dir, run_command

# move csr from /mnt/fghs/transfer --> rootCA/csr
def import_csr(csr_name, source_dir="/mnt/hgfs/transfer", 
               dest_dir="/home/gxpics/aws-pki-root/rootCA/csr"):
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

def sign_intermediate(intermediate_name, source_dir = root_dir / "csr", dest_dir = root_dir / "issued"):
    """
    The intermediate's csr should be in root_dir / csr
    The signed certificate will be placed in root_dir / issued 
    """
    source_path = source_dir / f"{intermediate_name}.csr"
    cert_path = dest_dir / f"{intermediate_name}.crt"

    if cert_path.exists():
        print(f"Certificate already exists: {cert_path}")
        print("Skipping intermediate signing.")
        return

    command = [
        "openssl",
        "ca",
        "-batch",
        "-config",
        root_dir / "openssl.cnf",
        "-extensions",
        "v3_intermediate_ca",
        "-days",
        "3650",
        "-in",
        source_path,
        "-out",
        cert_path,
    ]

    run_command(command)


def verify_intermediate(intermediate_cert_file, root_cert_dir = root_dir / "certs", intermediate_cert_dir = root_dir / "issued"):
    command = [
        "openssl",
        "verify",
        "-purpose",
        "any",      # Tell OpenSSL not to assume a specific end use when verifying, used to avoid restricting verification to a specific certificate purpose.
        "-CAfile",
        root_cert_dir / "rootCA.crt",
        intermediate_cert_dir / intermediate_cert_file
    ]

    run_command(command)

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
        source_dir = root_dir / "issued"
    
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
    # sign_intermediate("intermediateCA1.csr")
    # verify_intermediate("intermediateCA1.crt")
    export_cert("intermediateCA1.crt")  # offline root CA --> transfer
    export_cert("rootCA.crt", source_dir = root_dir / "certs") # offline root CA --> transfer
    # Check ls /mnt/hgfs/transfer/
    # sign_intermediate(root_dir, "intermediateCA2")
    # verify_intermediate(root_dir, "intermediateCA2")

if __name__ == "__main__":
    main()

