""" 
This program creates an offline root CA structure.
"""

from pathlib import Path
from common import BASE_DIR, run_command
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS

def create_root_ca_directories():
    directories = [
        "certs",
        "crl",
        "csr",
        "newcerts",
        "private",
        "issued"   # new for offline root CA
    ]

    for directory in directories:
        path = BASE_DIR / directory
        path.mkdir(parents=True, exist_ok=True)

    print(f"Created CA directory structure: {BASE_DIR}")

def initialize_root_ca():
    index_file = BASE_DIR/ "index.txt"
    serial_file = BASE_DIR / "serial"
    crl_file = BASE_DIR / "crlnumber"   

    if not index_file.exists():
        index_file.touch()

    if not serial_file.exists():
        serial_file.write_text("1000\n")

    if not crl_file.exists():
        crl_file.write_text("01\n")

    print(f"Initialized CA database: {BASE_DIR}")


def generate_root_config(default_md=None):
    md_line = ""
    if default_md:
        md_line = f"default_md = {default_md}"

    config = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {BASE_DIR}
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

    config_path = BASE_DIR/ "openssl.cnf"
    config_path.write_text(config)

    print(f"Created {config_path}")

# Later, add encryption at rest or HSM integration
def generate_key(algorithm, key_name="rootCA", options=None):
    key_path = BASE_DIR / "private" / f"{key_name}.key"
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

def create_root_certificate():
    cert_path = BASE_DIR / "certs" / "rootCA.crt"

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
        BASE_DIR / "private" / "rootCA.key",
        "-out",
        cert_path,
        "-config",
        BASE_DIR / "openssl.cnf",
        "-extensions",
        "v3_root_ca",                # so that the root certificate will have the correct extensions
        "-days",
        "3650"                       # otherwise, 30 days will be used by openssl by default
    ]

    run_command(command)

def setup(mode = "classical"):

    create_root_ca_directories()

    initialize_root_ca()

    root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["root"]]

    generate_key(root_policy["algorithm"], key_name="rootCA", options=root_policy["options"])
    generate_root_config(root_policy["digest"])
    create_root_certificate()


if __name__ == "__main__":
    setup(mode="classical")
    # root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY["classical"]["root"]]
    # generate_root_config(root_policy["digest"])
