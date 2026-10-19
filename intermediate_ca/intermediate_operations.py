from pathlib import Path
import subprocess
import shutil
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS

BASE_DIR = Path.home() / "aws-pki-intermediate"

root_dir = BASE_DIR /"rootCA"
intermediate1_dir = BASE_DIR / "intermediateCA1"
intermediate2_dir = BASE_DIR / "intermediateCA2"

def run_command(command):
    try:
        print("\nRunning:")
        print(" ".join(str(x) for x in command))
        print()

        subprocess.run(
            [str(x) for x in command],
            check=True
        )

    except subprocess.CalledProcessError as e:
        print("Command failed.")
        print(e)
        raise

# Verify the intermediate certificate against the root
def verify_intermediate_cert(ca_dir, ca_name):
    command = [
        "openssl",
        "verify",
        "-CAfile",
        ca_dir / "certs" / "rootCA.crt",
        ca_dir / "certs" / f"{ca_name}.crt"
    ]

    run_command(command)

# Export the intermediate CA's CSR for transfer to the offline root CA
def export_csr(ca_dir, ca_name, export_dir):
    csr_path = ca_dir / "csr" / f"{ca_name}.csr"
    export_path = export_dir / f"{ca_name}.csr"

    if not csr_path.exists():
        raise FileNotFoundError(f"CSR not found: {csr_path}")
    export_dir.mkdir(parents=True, exist_ok = True)
    shutil.copy2(csr_path, export_path)
    print(f"Exported CSR to: {export_path}")

# Import the signed intermediate certificate returned by the root
def import_certificate():
    pass

# Install an authenticated copy of the root CA certificate
def install_root_certificate():
    pass

# Confirm the signed certificate matches the intermediate's private key
def verify_key_pair():
    pass

# Combine intermediate and root certificates into ca-chain.crt
def create_ca_chain():
    pass

def sign_server_certificate():
    pass

def revoke_certificate():
    pass

def generate_crl():
    pass

def main():
    ca_name = "intermediateCA1"
    ca_dir = BASE_DIR / ca_name
    export_dir = Path("/mnt/transfer")
    export_csr(ca_dir, ca_name, export_dir)

if __name__ == "__main__":
    main()
    