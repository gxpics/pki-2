"""
A strictly offline root CA receives CSRs and exports signed certificates
through removable media without ever connecting to the network.

For convenience, this lab uses direct network transfers initiated
from the root CA VM.

Workflow: Connect the VM's network adapter (NAT) -> download the CSR
or upload the signed certificate -> disconnect immediately.

Inspect and sign the CSR while the VM is disconnected.
"""

from pathlib import Path
from common import run_command, BASE_DIR


def download_csr(intermediate_ca_name, remote_host,
                 remote_csr_path="~/pki-2/aws_intermediate_ca/intermediateCA3/csr/intermediateCA3.csr", 
                 remote_user="ec2-user", ssh_key_path="~/.ssh/my-ec2-key.pem"):
    """
    Download an intermediate CA's CSR from EC2
    into the local root CA's csr directory.

    ssh_key_path is the SSH private key on the root CA VM
    """
    ssh_key_path = Path(ssh_key_path).expanduser()

    if not ssh_key_path.is_file():
        raise FileNotFoundError(f"SSH key not found: {ssh_key_path}")

    local_csr = BASE_DIR / "csr" / f"{intermediate_ca_name}.csr"

    command = [
        "scp",
        "-i", str(ssh_key_path),
        f"{remote_user}@{remote_host}:{remote_csr_path}",
        str(local_csr),
    ]

    run_command(command)
    print(f"Downloaded CSR to: {local_csr}")
    return local_csr

def upload_certificate(
    intermediate_ca_name, remote_host,
    remote_cert_path,
    remote_user="ec2-user",
    ssh_key_path="~/.ssh/my-ec2-key.pem", 
    root_cert=False):
    
    """Copy a signed intermediate CA certificate from the root CA VM to EC2."""
    
    ssh_key_path = Path(ssh_key_path).expanduser()
    if not ssh_key_path.is_file():
        raise FileNotFoundError(f"SSH key not found: {ssh_key_path}")
    if root_cert:
        local_cert = BASE_DIR / "certs" / "rootCA.crt"
    else:
        local_cert = BASE_DIR / "issued" / f"{intermediate_ca_name}.crt"
    if not local_cert.is_file():
        raise FileNotFoundError(f"Signed certificate not found: {local_cert}")

    command = [
        "scp",
        "-i", str(ssh_key_path),
        str(local_cert),
        f"{remote_user}@{remote_host}:{remote_cert_path}",
    ]
    run_command(command)

def main():
    intermediate_ca_name = "intermediateCA3"
    remote_host = "18.189.229.149" #"3.128.35.251"
    remote_csr_path =f"~/pki-2/aws_intermediate_ca/{intermediate_ca_name}/csr/{intermediate_ca_name}.csr"
    remote_user = "ec2-user"
    ssh_key_path="~/.ssh/my-ec2-key.pem"
    # chmod 400 "$HOME/.ssh/my-ec2-key.pem"  -- lock down the ssh private key so it is only accessible from the user
    # download_csr(intermediate_ca_name=intermediate_ca_name, remote_host=remote_host,
    #              remote_csr_path=remote_csr_path, 
    #              remote_user=remote_user, ssh_key_path=ssh_key_path)
    
    remote_cert_path =f"~/pki-2/aws_intermediate_ca/{intermediate_ca_name}/certs/{intermediate_ca_name}.crt"
    remote_cert_path =f"~/pki-2/aws_intermediate_ca/{intermediate_ca_name}/certs/rootCA.crt"    
    upload_certificate(intermediate_ca_name=intermediate_ca_name,
                       remote_host=remote_host, 
                       remote_cert_path=remote_cert_path,
                       remote_user=remote_user,
                       ssh_key_path=ssh_key_path,
                       root_cert=True
                       )

if __name__ == "__main__":
    main()