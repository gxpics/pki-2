""" 
This program is used to set up intermediate CAs on EC2
- CA directories
- Generate CSRs
"""

from pathlib import Path
import subprocess
import shutil
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS
from common import BASE_DIR, run_command

def create_ca_directories(ca_name):  # used for any CAs including root or intermediate
    ca_dir = BASE_DIR / ca_name
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


def initialize_ca(ca_name): 
    ca_dir = BASE_DIR / ca_name
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


def generate_intermediate_config(ca_name, default_md = None):
    ca_dir = BASE_DIR / ca_name
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
def generate_key(ca_name, algorithm, key_name_extension="", options=None):

    key_path = BASE_DIR /ca_name / "private" / f"{ca_name}{key_name_extension}.key"
    if key_path.exists():
        print(f"Key already exists: {key_path}")
        print("Skipping key generation.")
        return

    command = ["openssl", "genpkey", "-algorithm", algorithm]

    if options:
        for option in options:
            command.extend(["-pkeyopt", option])

    command.extend(["-out", str(key_path)])

    run_command(command)

def generate_intermediate_csr(ca_name, key_name_extension="", csr_name_extension=""):
    ca_dir = BASE_DIR / ca_name
    csr_path = ca_dir / "csr" / f"{ca_name}{csr_name_extension}.csr"
    key_path = ca_dir / "private" / f"{ca_name}{key_name_extension}.key"

    if csr_path.exists():
        print(f"CSR already exists: {csr_path}")
        print("Skipping CSR generation.")
        return

    command = ["openssl", "req", "-new",
        "-key", str(key_path),
        "-out", str(csr_path),
        "-config", ca_dir / "openssl.cnf"
    ]

    run_command(command)

def setup(mode = "classical"):
    ca1_name = "intermediateCA3"
    ca2_name = "intermediateCA4"
    create_ca_directories(ca1_name)
    create_ca_directories(ca2_name)

    initialize_ca(ca1_name)
    initialize_ca(ca2_name)

    ca1_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["intermediate"]]
    generate_key(ca1_name, ca1_policy["algorithm"], key_name_extension="", options=ca1_policy["options"])
    generate_intermediate_config(ca1_name, ca1_policy["digest"]) 
    generate_intermediate_csr(ca1_name)

    ca2_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["intermediate"]]
    generate_key(ca2_name, ca2_policy["algorithm"], key_name_extension="", options=ca2_policy["options"])
    generate_intermediate_config(ca2_name, ca2_policy["digest"])
    generate_intermediate_csr(ca2_name)
 

def main():
    setup("classical")
    #setup("post_quantum")

if __name__ == "__main__":
    main()
