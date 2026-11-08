from pathlib import Path
from tempfile import TemporaryDirectory

from common import run_command


def download_server_certificate(
    remote_host,
    remote_cert_path,
    local_cert_path,
    ssh_key_path,
    remote_user="ec2-user",
):
    """Pull an issued server certificate from EC2 to Ubuntu."""
    local_cert = Path(local_cert_path).expanduser()
    ssh_key = Path(ssh_key_path).expanduser()
    remote_source = f"{remote_user}@{remote_host}:{remote_cert_path}"

    with TemporaryDirectory(dir=local_cert.parent) as temp_dir:
        downloaded_cert = Path(temp_dir) / local_cert.name
        run_command([
            "scp",
            "-i", str(ssh_key),
            remote_source,
            str(downloaded_cert),
        ])
        downloaded_cert.replace(local_cert)

def main():
    intermediate_ca_name = "intermediateCA3"
    server_name = "server3"
    download_server_certificate(
    remote_host="18.189.229.149",
    remote_cert_path=(
        f"/home/ec2-user/pki-2/aws_intermediate_ca/{intermediate_ca_name}/issued/{server_name}.crt"
    ),
    local_cert_path=f"{server_name}/certs/{server_name}.crt",
    ssh_key_path="~/.ssh/my-ec2-key.pem",
    )

if __name__ == "__main__":
    main()