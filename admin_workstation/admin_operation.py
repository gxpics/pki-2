"""
The admin workstation acts as the transfer coordinator between the 
intermediate CAs and the offline root CA.

<Intermedate CA create csr and export it to admin workstation>
1. download_csr(): intermedate CA--> admin, Download CSR using SFTP
2. export_to_media(): Admin --> Copy CSR to shared folder or removable media
<The offline root CA imports the CSR, validates and approves it, signs the 
intermediate certificate, and exports the signed certificate and root CA 
public certificate>
3. import_from_media(): Transfer media --> Admin, Copy signed certificates to pki-admin/certs/
4. upload_certificate(): Admin --> Upload signed intermediate and root CA certificates using SFTP
<intermediate CA receives and verifies the certs.

Note:
download_csr() and upload_certificates() use SSH/SFTP to communicate with the intermediate CA.
export_to_media() and import_from_media() use local file copying (shutil.copy2()), not SSH.
The VMware shared folder is a development substitute for removable media.
"""
from pathlib import Path
import paramiko
import shutil
import posixpath
import subprocess

# Download csr from EC2 or local ubuntu VM
def download_csr(hostname, username, key_path,
                 remote_csr_path, local_dir):

    local_dir = Path(local_dir)
    local_dir.mkdir(parents=True, exist_ok=True)

    local_csr_path = local_dir / Path(remote_csr_path).name

    if local_csr_path.exists():
        raise FileExistsError(f"CSR already exists: {local_csr_path}")
    
    ssh = paramiko.SSHClient()

    # Load trusted SSH host keys
    ssh.load_system_host_keys()

    # Reject unknown SSH servers
    ssh.set_missing_host_key_policy(
        paramiko.RejectPolicy()
    )

    try:
        ssh.connect(
            hostname=hostname,
            username=username,
            key_filename=str(key_path),
            timeout=10
        )

        with ssh.open_sftp() as sftp:
            sftp.get(
                remote_csr_path,
                str(local_csr_path)
            )

        print(f"CSR downloaded: {local_csr_path}")

        return local_csr_path

    finally:
        ssh.close()

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

    if destination.exists():
        raise FileExistsError(f"File already exits: {destination}")
    
    shutil.copy2(source_path, destination)

    return destination


def import_from_media(cert_name, transfer_dir, destination_dir, overwrite=False):
    source = Path(transfer_dir) / cert_name
    destination_dir = Path(destination_dir)

    # Verify source exists
    if not source.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {source}"
        )

    # Verify destination directory exists
    if not destination_dir.is_dir():
        raise NotADirectoryError(
            f"Destination directory not found: {destination_dir}"
        )

    destination = destination_dir / cert_name

    # Prevent accidental overwriting
    if not overwrite and destination.exists():
        raise FileExistsError(
            f"Destination already exists: {destination}"
        )

    # Copy certificate
    shutil.copy2(source, destination)

    print(f"Certificate imported: {destination}")

    return destination

def upload_certificates(hostname, username, key_path,
                        local_cert_dir, remote_cert_dir,
                        cert_names):

    local_cert_dir = Path(local_cert_dir)

    # Verify local certificates before connecting
    for cert_name in cert_names:
        if not (local_cert_dir / cert_name).is_file():
            raise FileNotFoundError(
                f"Certificate not found: {local_cert_dir / cert_name}"
            )

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.load_host_keys(str(Path.home() / ".ssh" / "known_hosts"))
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

    try:
        ssh.connect(
            hostname=hostname,
            username=username,
            key_filename=str(key_path),
            look_for_keys=False,
            allow_agent=False,
            timeout=10
        )

        with ssh.open_sftp() as sftp:
            for cert_name in cert_names:
                local_path = local_cert_dir / cert_name
                remote_path = posixpath.join(
                    remote_cert_dir, cert_name
                )

                # Prevent overwriting existing certificates
                try:
                    sftp.stat(remote_path)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError(
                        f"Remote certificate already exists: {remote_path}"
                    )

                sftp.put(str(local_path), remote_path)

                print(f"Uploaded: {remote_path}")

    finally:
        ssh.close()

def main():
    intermediate_ca_name = "intermediateCA2"
    # Download intermediate csr from the local Ubuntu VM to admin workstation 
    # download_csr(
    #     hostname="192.168.216.130",
    #     username="gxpics",
    #     key_path="C:/Users/gxpics/.ssh/id_ed25519",  # Windows
    #     remote_csr_path="/home/gxpics/aws-pki-intermediate/intermediateCA1/csr/intermediateCA1.csr",
    #     local_dir="C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/csr"  # Windows
    # )

    # Download intermediate csr from EC2 to admin workstation 
    download_csr(
        hostname="18.189.229.149",
        username="ec2-user",
        key_path="C:/Users/gxpics/Documents/Capstone/AWS2/my-ec2-key.pem",  # Windows
        remote_csr_path=f"/home/ec2-user/aws-pki-intermediate/intermediateCA1/csr/{intermediate_ca_name}.csr",
        local_dir="C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/csr"  # Windows
    )

    # After downloading csr, inspect it from the pki-admin directory:
    # openssl req -in csr/intermediateCA1.csr -noout -text
    
    export_to_media(source_path= \
                    f"C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/csr/{intermediate_ca_name}.csr", \
                    transfer_dir="C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/transfer")

   
    #
    # Once certs are transferred from rootCA to admin workstation, copy them to the certs directory
    #

    transfer_dir = "C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/transfer"
    cert_dir = "C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/certs"
    # import_from_media("rootCA.crt", transfer_dir, cert_dir)
    import_from_media(f"{intermediate_ca_name}.crt", transfer_dir, cert_dir)
   
    
    # # cert: admin worstation --> intermediate CA on local VM
    # upload_certificates(
    # hostname="192.168.216.130",
    # username="gxpics",
    # key_path="C:/Users/gxpics/.ssh/id_ed25519",
    # local_cert_dir="C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/certs",
    # remote_cert_dir="/home/gxpics/aws-pki-intermediate/intermediateCA1/certs",
    # cert_names=[
    #     "intermediateCA1.crt",
    #     "rootCA.crt"
    # ]
    # )

    # cert: admin worstation --> intermediate CA on EC2
    upload_certificates(
        hostname="18.189.229.149",
        username="ec2-user",
        key_path="C:/Users/gxpics/Documents/Capstone/AWS2/my-ec2-key.pem",
        local_cert_dir="C:/Users/gxpics/Documents/Capstone/AWS2/pki-admin/certs",
        remote_cert_dir=f"/home/ec2-user/aws-pki-intermediate/{intermediate_ca_name}/certs",
        cert_names=[f"{intermediate_ca_name}.crt"]
        )


if __name__ == "__main__":
    main()