"""
TLS certificate management
"""

from pathlib import Path
from common import  run_command, BASE_DIR
from policy import SUPPORTED_ALGORITHMS, PKI_POLICY

def create_server_dir(server_name):
    directories = ["certs", "csr", "private"]
    server_dir = BASE_DIR / server_name
    for directory in directories:
        (server_dir / directory).mkdir(
            parents=True,
            exist_ok=True
        )

def generate_key(server_name, algorithm, key_name_extension="", options=None):

    key_path = BASE_DIR / server_name / "private" / f"{server_name}{key_name_extension}.key"
    if key_path.exists():
        print(f"Key already exists: {key_path}")
        print("Skipping key generation.")
        return

    command = ["openssl","genpkey","-algorithm", algorithm]

    if options:
        for option in options:
            command.extend(["-pkeyopt", option])

    command.extend(["-out", str(key_path)])

    run_command(command)

def generate_server_csr(server_name, overwrite=False):
    server_dir = BASE_DIR / server_name
    key_path = server_dir / "private" / f"{server_name}.key"
    csr_path = server_dir / "csr" / f"{server_name}.csr"
    if csr_path.exists() and not overwrite:
        print(f"CSR already exists: {csr_path}")
        print("Skipping CSR generation.")
        return
    command = [
        "openssl","req",
        "-new",
        "-key", str(key_path),
        "-out", str(csr_path),
        "-subj", f"/C=US/ST=New York/L=Rochester/O=Hybrid PKI Lab/CN={server_name}",
        "-addext", "subjectAltName=DNS:localhost"
    ]

    run_command(command)

def upload_server_csr(
    server_name, remote_host, remote_csr_path,
    remote_user="ec2-user",
    ssh_key_path="~/.ssh/my-ec2-key.pem",
):
    """
    Copy a server CSR from the Ubuntu VM to its issuing CA on EC2.
    Vulnerable to HNDL
    """
    local_csr = BASE_DIR / server_name / "csr" / f"{server_name}.csr"
    if not local_csr.is_file():
        raise FileNotFoundError(f"Server CSR not found: {local_csr}")

    ssh_key = Path(ssh_key_path).expanduser()
    if not ssh_key.is_file():
        raise FileNotFoundError(f"SSH key not found: {ssh_key}")

    command = [
        "scp",
        "-i", str(ssh_key),
        str(local_csr),
        f"{remote_user}@{remote_host}:{remote_csr_path}",
    ]
    run_command(command)

def create_server_chain(server_name, intermediate_name):
    """
    The server must wait until the Intermediate CA has signed its CSR.
    Once the server's crt and intermediate crt are placed in certs/, 
    prepare the certificate chain that the server will present to TLS clients.
    server chain certificate = server certificate + intermediate certificate
    After that, verify the server certificate against the Root CA before 
    you configure Nginx.
    """
    server_dir = BASE_DIR / server_name
    server_cert = server_dir / "certs" / f"{server_name}.crt"
    intermediate_cert = server_dir / "certs" / f"{intermediate_name}.crt"
    chain_file = server_dir / "certs" / f"{server_name}-chain.crt"

    if not server_cert.exists():
        raise FileNotFoundError(f"Server certificate not found: {server_cert}")

    if not intermediate_cert.exists():
        raise FileNotFoundError(
            f"Intermediate certificate not found: {intermediate_cert}"
        )   

    chain_content = (
    server_cert.read_text().rstrip() + "\n" +
    intermediate_cert.read_text().rstrip() + "\n"
    )

    if chain_file.exists():
        if chain_file.read_text() == chain_content:
            print(f"Chain already up to date: {chain_file}")
            return
        
    chain_file.write_text(server_cert.read_text() + intermediate_cert.read_text())

    print(f"Created chain: {chain_file}")

def verify_server(server_name, 
                  hostname="localhost",
                  intermediate_ca_name="intermediateCA1", 
                  root_ca_name="rootCA"):
    """
    Verify the server cert chain
    This function assumes that root CA's crt is availabe in the server's certs directory.
    Checks:
      - Certificate signatures and chain
      - Certificate validity periods
      - CA constraints and key usage
      - TLS server authentication purpose
      - Server hostname
    """
    server_dir = BASE_DIR / server_name
    
    root_crt = server_dir / "certs" / f"{root_ca_name}.crt"
    intermediate_crt = server_dir / "certs" / f"{intermediate_ca_name}.crt"
    server_crt = server_dir / "certs" / f"{server_name}.crt"

    for cert in [root_crt, intermediate_crt, server_crt]:
        if not cert.is_file():
            raise FileNotFoundError(
                f"Required certificate file not found: {cert}"
            )
    
    command = [
        "openssl", "verify",
        "-CAfile", str(root_crt),
        "-untrusted", str(intermediate_crt),
        "-purpose", "sslserver",    # checks whether the certificate is suitable for TLS server authentication, 
                                    #including relevant key usage and extended key usage restrictions.
        "-verify_hostname", hostname,
        str(server_crt)
    ]
    run_command(command)

def initialize_server(server_name="server1", mode = "classical"):
    """
    mode = either "classical" or "post_quantum"
    """
    
    create_server_dir(server_name)

    server_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["server"]]
    print("server policy:", server_policy)
    generate_key(server_name, server_policy["algorithm"], key_name_extension="", options=server_policy["options"])

    generate_server_csr(server_name)

def main():

    mode_choice  = "c"# input("Choose the mode (c for classical, p for post quantum): ")
    if mode_choice == "c":
        mode = "classical" 
    else:
        mode = "post_quantum"

    server_name = "server3"
    hostname ="localhost"
    intermediate_ca_name = "intermediateCA3"
    root_ca_name = "rootCA"
    
    #initialize_server(server_name, mode)
    
    upload_server_csr(
    server_name=server_name,
    remote_host="18.189.229.149",
    remote_csr_path=f"~/pki-2/aws_intermediate_ca/{intermediate_ca_name}/csr/{server_name}.csr")
    # The intermediate CA signs the server's csr
    # Server cert and the intermediate cert should be placed in the server's certs directory 
    
    #create_server_chain(server_name, intermediate_ca_name)
    #verify_server(server_name, hostname, intermediate_ca_name, root_ca_name)
    
    # 
    # install_nginx_certificate(server_name)
    # generate_nginx_config(server_name)
    # enable_nginx_site(server_name)
    # test_nginx()
    # reload_nginx()


if __name__ == "__main__":
    main()
