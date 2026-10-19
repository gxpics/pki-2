""" 
This program creates an offline root CA structure.
"""

from pathlib import Path
import subprocess
from common import root_dir, run_command
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS

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

def create_ca_directories(ca_dir):
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

def initialize_ca(ca_dir):
    index_file = ca_dir / "index.txt"
    serial_file = ca_dir / "serial"
    crl_file = ca_dir/"crlnumber"   # new feature added

    if not index_file.exists():
        index_file.touch()

    if not serial_file.exists():
        serial_file.write_text("1000\n")

    if not crl_file.exists():
        crl_file.write_text("01\n")

    print(f"Initialized CA database: {ca_dir}")


def generate_root_config(root_dir, default_md=None):
    md_line = ""
    if default_md:
        md_line = f"default_md = {default_md}"

    config = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {root_dir}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/rootCA.key
certificate       = $dir/certs/rootCA.crt
crlnumber         = $dir/crlnumber
crl               = $dir/crl/root.crl.pem
{md_line}
default_days      = 3650
default_crl_days  = 30                  # publish a new CRL within 30 days, CRL validity, not revocation duration
policy            = policy_loose
copy_extensions   = none        # the root won't copy any requested extensions from a CSR, For the root, the extensions should come only from your config, like v3_intermediate_ca, not from the CSR, so that none fits the offline root model.

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
x509_extensions = v3_root_ca

[ req_distinguished_name ]
C  = US
ST = New York
L  = Rochester
O  = PKI Lab
OU = Root CA
CN = Hybrid Root CA

[ v3_root_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
"""

    config_path = root_dir / "openssl.cnf"
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

def create_root_certificate(root_dir):
    cert_path = root_dir / "certs" / "rootCA.crt"

    if cert_path.exists():
        print(f"Root certificate already exists: {cert_path}")
        print("Skipping root certificate generation.")
        return

    command = [
        "openssl",
        "req",
        "-new",
        "-x509",
        "-key",
        root_dir / "private" / "rootCA.key",
        "-out",
        cert_path,
        "-config",
        root_dir / "openssl.cnf",
        "-extensions",
        "v3_root_ca",                # so that the root certificate will have the correct extensions
        "-days",
        "3650"                       # otherwise, 30 days will be used by openssl by default
    ]

    run_command(command)

def setup(mode = "classical"):

    create_ca_directories(root_dir)

    initialize_ca(root_dir)

    root_key = root_dir / "private" / "rootCA.key"
    root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["root"]]

    generate_key(root_key, root_policy["algorithm"], root_policy["options"])
    generate_root_config(root_dir, root_policy["digest"])
    create_root_certificate(root_dir)


if __name__ == "__main__":
    #setup("classical")
    root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY["classical"]["root"]]
    generate_root_config(root_dir, root_policy["digest"])
