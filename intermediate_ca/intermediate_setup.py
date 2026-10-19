""" 
This program creates a PQ PKI including a root CA and 2 intermediate CAs.
"""

from pathlib import Path
import subprocess
import shutil
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS

# BASE_DIR = Path.home() / "pki" / "classical-pki"
# BASE_DIR = Path.home() / "pki" / "pq-pki"
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

def create_ca_directories(ca_dir):  # used for any CAs including root or intermediate
    directories = [
        "certs",
        "crl",
        "csr",
        "newcerts",
        "private",
        "issued"   # new for offline root CA
    ]

    for directory in directories:
        path = ca_dir / directory
        path.mkdir(parents=True, exist_ok=True)

    print(f"Created CA directory structure: {ca_dir}")


def initialize_ca(ca_dir): #  # used for root and intermediate CAs
    index_file = ca_dir / "index.txt"
    serial_file = ca_dir / "serial"
    crl_file = ca_dir/"crlnumber"   # new feature added
    attr_file = ca_dir / "index.txt.attr"  # it's a small config file that tells OpenSSL how to handle its certificate database.

    if not index_file.exists():
        index_file.touch()

    if not serial_file.exists():
        serial_file.write_text("1000\n")

    if not crl_file.exists():
        crl_file.write_text("01\n")

    if not attr_file.exists():
        attr_file.write_text("unique_subject = no\n")

    print(f"Initialized CA database: {ca_dir}")


def generate_intermediate_config(ca_dir, ca_name, default_md = None):
    md_line = ""
    if default_md:
        md_line = f"default_md = {default_md}"
    config = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {ca_dir}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/{ca_name}.key
certificate       = $dir/certs/{ca_name}.crt

# CRL configuration
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate.crl.pem
default_crl_days  = 30

# Allow certificate renewal with the same subject name
unique_subject    = no # permits multiple valid certificates with the same subject name

{md_line}
default_days      = 1825
policy            = policy_loose
copy_extensions   = copy  # allows requested extensions such as Subject Alternative Names (SANs) to be copied from CSRs. Never use this setting to approve arbitrary CSRs automatically.

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
prompt             = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C  = US
ST = New York
L  = Rochester
O  = PKI Lab
OU = Intermediate CA
CN = {ca_name}

[ server_cert ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
"""

    config_path = ca_dir / "openssl.cnf"
    config_path.write_text(config)

    print(f"Created {config_path}")

# Later, add encryption at rest or HSM integration
def generate_key(key_path, algorithm, options=None):
    if key_path.exists():
        print(f"Key already exists: {key_path}")
        print("Skipping key generation.")
        return

    command = [
        "openssl",
        "genpkey",
        "-algorithm",
        algorithm
    ]

    if options:
        for option in options:
            command.extend([
                "-pkeyopt",
                option
            ])

    command.extend([
        "-out",
        str(key_path)
    ])

    run_command(command)

def generate_intermediate_csr(ca_dir, ca_name):
    csr_path = ca_dir / "csr" / f"{ca_name}.csr"

    if csr_path.exists():
        print(f"CSR already exists: {csr_path}")
        print("Skipping CSR generation.")
        return

    command = [
        "openssl",
        "req",
        "-new",
        "-key",
        ca_dir / "private" / f"{ca_name}.key",
        "-out",
        csr_path,
        "-config",
        ca_dir / "openssl.cnf"
    ]

    run_command(command)

def setup(mode = "classical"):

    create_ca_directories(intermediate1_dir)
    create_ca_directories(intermediate2_dir)

    initialize_ca(intermediate1_dir)
    initialize_ca(intermediate2_dir)

    intermediate1_name = "intermediateCA1"
    intermediate1_key = intermediate1_dir / "private" / f"{intermediate1_name}.key"
    intermediate1_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["intermediate"]]
    generate_key(intermediate1_key, intermediate1_policy["algorithm"], intermediate1_policy["options"])
    generate_intermediate_config(intermediate1_dir, intermediate1_name, intermediate1_policy["digest"]) 
    generate_intermediate_csr(intermediate1_dir, intermediate1_name)

    intermediate2_name = "intermediateCA2"
    intermediate2_key = intermediate2_dir / "private" / f"{intermediate2_name}.key"
    intermediate2_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["intermediate"]]
    generate_key(intermediate2_key, intermediate2_policy["algorithm"], intermediate2_policy["options"])
    generate_intermediate_config(intermediate2_dir, intermediate2_name, intermediate2_policy["digest"])
    generate_intermediate_csr(intermediate2_dir, intermediate2_name)
 

def main():
    setup("classical")
    #setup("post_quantum")

if __name__ == "__main__":
    main()
