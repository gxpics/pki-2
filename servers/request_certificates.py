from getpass import getpass
from pathlib import Path
import subprocess
import sys
from .common import BASE_DIR

API_URL = (
    "https://243bjs8e34.execute-api.us-east-2.amazonaws.com"
    "/test/certificates"
)

def main():
    BASE_DIR = Path.home() / "pki-2" / "servers"
    server_name = "server3"
    
    csr_path = BASE_DIR / f"{server_name}" / "csr" / f"{server_name}.csr"
    cert_path = BASE_DIR / f"{server_name}" / "certs" / f"{server_name}.crt"
   
    if not csr_path.is_file():
        sys.exit(f"CSR file not found: {csr_path}")

    token = getpass("Enrollment token: ")

    command = [
        "awscurl",
        "--service", "execute-api",
        "--region", "us-east-2",
        "-X", "POST",
        "-H", f"X-Enrollment-Token: Bearer {token}",
        "-H", "Content-Type: application/pkcs10",
        "--data-binary", f"@{csr_path}",
        API_URL,
    ]

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
        )
    except FileNotFoundError:
        sys.exit(
            "Could not start awscurl. Check that it is installed "
            "on this client EC2."
        )
    except subprocess.CalledProcessError as error:
        details = error.stderr.decode(errors="replace") if error.stderr else ""
        sys.exit(f"awscurl failed.\n{details}")

    certificate = result.stdout

    if not certificate.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        response = certificate.decode(errors="replace")
        sys.exit(f"The API response was not a PEM certificate:\n{response}")

    try:
        cert_path.write_bytes(certificate)
    except OSError as error:
        sys.exit(f"Could not write the certificate to {cert_path}: {error}")

    print(f"Certificate saved to {cert_path}")


if __name__ == "__main__":
    main()

'''
read -rsp "Enrollment token: " ENROLLMENT_TOKEN
echo

awscurl --service execute-api --region us-east-2 -X POST \
  -H "X-Enrollment-Token: Bearer ${ENROLLMENT_TOKEN}" \
  -H "Content-Type: application/pkcs10" \
  --data-binary @server3.csr \
  "https://243bjs8e34.execute-api.us-east-2.amazonaws.com/test/certificates" \
  > server3.crt

unset ENROLLMENT_TOKEN
'''