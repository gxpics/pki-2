"""
Simplified PKI client enrollment example.

Demonstrates how a client submits a certificate signing request (CSR)
to a certificate-issuing REST API and receives the issued certificate.
The server identity, API endpoint, and file paths can be configured 
for a particular client.
"""

from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

SERVER_NAME = "server6"
DNS_NAME = "server6.com"

SERVER_DIR = Path.home() / "pki-2" / "simple_REST_test" / SERVER_NAME
KEY_PATH = SERVER_DIR / f"{SERVER_NAME}.key"
CSR_PATH = SERVER_DIR / f"{SERVER_NAME}.csr"
CERT_PATH = SERVER_DIR / f"{SERVER_NAME}.crt"

# The CA server's private IP here.
CA_PRIVATE_IP = "172.31.3.250"
API_URL = f"http://{CA_PRIVATE_IP}:8000/certificates"


def create_key_and_csr():
    SERVER_DIR.mkdir(parents=True, exist_ok=True)

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

    subprocess.run(command, check=True)
    KEY_PATH.chmod(0o600)

    print(f"Created private key: {KEY_PATH}")
    print(f"Created CSR: {CSR_PATH}")


def request_certificate():
    csr = CSR_PATH.read_bytes()

    request = urllib.request.Request(
        API_URL,
        data=csr,
        headers={"Content-Type": "application/pkcs10"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            certificate = response.read()
            print(f"HTTP status: {response.status}")
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        sys.exit(f"Server returned HTTP {error.code}:\n{body}")
    except urllib.error.URLError as error:
        sys.exit(f"Could not connect to the server: {error}")

    if not certificate.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        sys.exit("The response did not contain a PEM certificate.")

    CERT_PATH.write_bytes(certificate)
    print(f"Certificate saved: {CERT_PATH}")


if __name__ == "__main__":
    create_key_and_csr()
    request_certificate()
