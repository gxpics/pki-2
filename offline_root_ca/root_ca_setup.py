""" 
This program creates an offline root CA structure.
"""
from pathlib import Path
from common import BASE_DIR, run_command
from policy import PKI_POLICY, SUPPORTED_ALGORITHMS
from hsm_setup import generate_key, inspect_keys, verify_root_key

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

# Before calling this function, verify:
# 1. The RootCA token is initialized.
# 2. The OpenSSL PKCS#11 provider is installed. 
#    SoftHSM2 and the OpenSSL PKCS#11 provider are separate components.
#    To locate the OpenSSL PKCS#11 provider
#    find /usr/lib /usr/local/lib -name 'pkcs11.so' 2>/dev/null
#    To Locate the SoftHSM PKCS#11 library
#    find /usr/lib /usr/local/lib -name 'libsofthsm2.so' 2>/dev/null
def generate_root_config(
    default_md=None,
    pkcs11_module=None,
    softhsm_module=None,
    token_label="RootCA",
    key_label="rootCA"
):
    md_line = ""
    if default_md:
        md_line = f"default_md = {default_md}"

    # PKCS#11 URI identifies the root CA private key
    key_uri = (
        f"pkcs11:token={token_label};"
        f"object={key_label};type=private"
    )

    config = f"""


# OpenSSL 3 provider configuration
openssl_conf = openssl_init

[ openssl_init ]
providers = provider_sect

[ provider_sect ]
default = default_sect
pkcs11 = pkcs11_sect

[ default_sect ]
activate = 1

[ pkcs11_sect ]
module = {pkcs11_module}
pkcs11-module-path = {softhsm_module}
pkcs11-module-cache-sessions = 0
pkcs11-module-quirks = no-deinit
activate = 1

[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {BASE_DIR}
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial

private_key       = {key_uri}
certificate       = $dir/certs/rootCA.crt

crlnumber         = $dir/crlnumber
crl               = $dir/crl/root.crl.pem

{md_line}
default_days      = 3650
default_crl_days  = 30
policy            = policy_loose
copy_extensions   = none

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
x509_extensions    = v3_root_ca

[ req_distinguished_name ]
C  = US
ST = New York
L  = Rochester
O  = PKI Lab
OU = Root CA
CN = Root CA

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

    config_path = BASE_DIR / "openssl.cnf"
    config_path.write_text(config)

    print(f"Created {config_path}")

def create_root_certificate(root_policy):
    digest =  root_policy["digest"]
    cert_path = BASE_DIR / "certs" / "rootCA.crt"

    if cert_path.exists():
        print(f"Root certificate already exists: {cert_path}")
        print("Skipping root certificate generation.")
        return

    key_uri = "pkcs11:token=RootCA;object=rootCA;type=private"

    command = [
        "openssl", "req",
        "-new", "-x509",
        "-key", key_uri,
        "-out", cert_path,
        "-config", BASE_DIR / "openssl.cnf",
        "-extensions", "v3_root_ca",
        "-days", "3650",
        f"-{digest}"
    ]


    run_command(command)

# An old version can generate a eitherclassical or post quantum key.
# But softhsm does not support ML-DSA, so this function uses a key stored in a file.
def generate_key_openssl(algorithm, key_name="rootCA", options=None):
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

# def create_root_certificate():
#     cert_path = BASE_DIR / "certs" / "rootCA.crt"

#     if cert_path.exists():
#         print(f"Root certificate already exists: {cert_path}")
#         print("Skipping root certificate generation.")
#         return

#     command = [
#         "openssl",
#         "req",
#         "-new",
#         "-x509",
#         "-key",
#         BASE_DIR / "private" / "rootCA.key",
#         "-out",
#         cert_path,
#         "-config",
#         BASE_DIR / "openssl.cnf",
#         "-extensions",
#         "v3_root_ca",                # so that the root certificate will have the correct extensions
#         "-days",
#         "3650"                       # otherwise, 30 days will be used by openssl by default
#     ]

#     run_command(command)

def setup(mode = "classical"):

    # create_root_ca_directories()

    # initialize_root_ca()
    
    root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["root"]]
    
    # generate_root_config(
    # default_md=root_policy["digest"], #"sha384"
    # pkcs11_module="/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",
    # softhsm_module="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    # token_label="RootCA",
    # key_label="rootCA"
    # )

    # generate_key(
    # algorithm=root_policy,
    # key_name="rootCA",
    # token_label="RootCA"
    # )

    # inspect_keys(token_label="RootCA")
    
    # generate_key_openssl(root_policy["algorithm"], key_name="rootCA", options=root_policy["options"])

    create_root_certificate(root_policy)
    verify_root_key(
        cert_path=BASE_DIR / "certs" / "rootCA.crt",
        token_label="RootCA",
        key_name="rootCA"
        )

if __name__ == "__main__":
    setup(mode="classical")

    # root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY["classical"]["root"]]
    # generate_root_config(root_policy["digest"])
