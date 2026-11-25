from getpass import getpass
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from .common import BASE_DIR

REGION = "us-east-2"
API_URL = (
    "https://243bjs8e34.execute-api.us-east-2.amazonaws.com"
    "/test/certificates"
)

SERVER_NAME = "server5"
DNS_NAME = "server5.com"
INTERMEDIATE_CA_NAME = "intermediateCA4"

SERVER_DIR = BASE_DIR / SERVER_NAME
KEY_PATH = SERVER_DIR / "private" / f"{SERVER_NAME}.key"
CSR_PATH = SERVER_DIR / "csr" / f"{SERVER_NAME}.csr"
CERT_PATH = SERVER_DIR / "certs" / f"{SERVER_NAME}.crt"
FULLCHAIN_PATH = SERVER_DIR / "certs" / f"{SERVER_NAME}-fullchain.crt"

# On Amazon Linux EC2, place intermediate's cert and fullchian cert 
# under /etc/pki/tls/certs 
# and keys under /etc/pki/tls/private
INTERMEDIATE_CERT_PATH = Path(f"/etc/pki/tls/certs/{INTERMEDIATE_CA_NAME}.crt")

def create_key_and_csr():
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    CSR_PATH.parent.mkdir(parents=True, exist_ok=True)

    if KEY_PATH.exists() and CSR_PATH.exists():
        print(f"Using existing key and CSR for {SERVER_NAME}.")
        return

    if KEY_PATH.exists() or CSR_PATH.exists():
        sys.exit(
            "Only one of the key and CSR exists. Check these files before "
            "continuing:\n"
            f"  {KEY_PATH}\n"
            f"  {CSR_PATH}"
        )

    command = [
        "openssl", "req",
        "-new",
        "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout", str(KEY_PATH),
        "-out", str(CSR_PATH),
        "-subj", f"/CN={SERVER_NAME}",
        "-addext", f"subjectAltName=DNS:{DNS_NAME}",
    ]

    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        sys.exit("OpenSSL was not found. Install it on this EC2 instance.")
    except subprocess.CalledProcessError as error:
        sys.exit(f"OpenSSL could not create the key and CSR: {error}")

    KEY_PATH.chmod(0o600)
    print(f"Created private key: {KEY_PATH}")
    print(f"Created CSR: {CSR_PATH}")


def request_certificate(enrollment_token):
    session = boto3.Session()
    credentials = session.get_credentials()

    if credentials is None:
        sys.exit("No AWS credentials found. Check the EC2 instance IAM role.")

    csr = CSR_PATH.read_bytes()
    headers = {
        "Content-Type": "application/pkcs10",
        "X-Enrollment-Token": f"Bearer {enrollment_token}",
    }

    aws_request = AWSRequest(
        method="POST",
        url=API_URL,
        data=csr,
        headers=headers,
    )
    SigV4Auth(credentials, "execute-api", REGION).add_auth(aws_request)
    signed_request = aws_request.prepare()

    request = urllib.request.Request(
        API_URL,
        data=csr,
        headers=dict(signed_request.headers),
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            certificate = response.read()
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        sys.exit(f"API returned HTTP {error.code}:\n{body}")
    except urllib.error.URLError as error:
        sys.exit(f"Could not connect to the API: {error}")

    if not certificate.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        sys.exit(
            "The API response was not a PEM certificate:\n"
            + certificate.decode(errors="replace")
        )

    return certificate


def main():
    if not INTERMEDIATE_CERT_PATH.is_file():
        sys.exit(
            "Intermediate CA certificate not found. Check this path:\n"
            f"{INTERMEDIATE_CERT_PATH}"
        )

    create_key_and_csr()
    token = getpass("Enrollment token: ")
    certificate = request_certificate(token)

    CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CERT_PATH.write_bytes(certificate)

    # Nginx serves the leaf certificate followed by its issuing intermediate.
    fullchain = certificate + b"\n" + INTERMEDIATE_CERT_PATH.read_bytes()
    FULLCHAIN_PATH.write_bytes(fullchain)

    print(f"Certificate saved: {CERT_PATH}")
    print(f"Full chain saved: {FULLCHAIN_PATH}")
    print(f"Private key: {KEY_PATH}")


if __name__ == "__main__":
    main()