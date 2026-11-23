import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from intermediate_ca.intermediate_operations import sign_server_csr
from contextlib import closing
from .enrollment import authorize_enrollment, ALLOWED_DNS_BY_SERVER, EnrollmentError
import sqlite3


TOP_DIR = Path.home() / "pki-2"  # TOP_DIR = Path(__file__).resolve().parents[1] 
ENROLLMENT_DB_PATH = TOP_DIR / "aws_api" / "enrollment.db"
MAX_CSR_BYTES = 16 * 1024


class IssuanceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return

        self.send_error(404)
    
    def do_POST(self):
        if self.path != "/certificates": 
            self.send_error(404, "Unknown endpoint")
            return

        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        #parts = self.headers.get("Authorization", "").split()
        parts = self.headers.get("X-Enrollment-Token", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        token = parts[1]

        if not 0 < size <= MAX_CSR_BYTES:
            self.send_error(400, "Send a PEM CSR up to 16 KiB")
            return

        csr = self.rfile.read(size)  # Receoved CSR file
        
        # Authorize the token and CSR before signing
        if len(csr) != size:
            self.send_error(400, "Incomplete CSR")
            return

        try:
            with closing(sqlite3.connect(ENROLLMENT_DB_PATH)) as db:
                with db:
                    server_id, approved_san = authorize_enrollment(
                        token, csr, db, ALLOWED_DNS_BY_SERVER
                    )
    
        except EnrollmentError as exc:
            print(f"Enrollment rejected: {exc!r}", flush=True)
            self.send_error(403, "Enrollment rejected")
            return
        except sqlite3.Error as error:
            self.log_error("%s", error)
            self.send_error(500, "Could not check enrollment")
            return
        
        try:
            with TemporaryDirectory() as directory:
                csr_path = Path(directory) / "request.csr"
                cert_path = Path(directory) / "certificate.pem"
                csr_path.write_bytes(csr)

                sign_server_csr(
                    approved_san=approved_san,
                    server_name=server_id,
                    intermediate_ca_name=self.server.intermediate_ca_name,
                    csr_path=csr_path,
                    cert_path=cert_path,
                )
                certificate = cert_path.read_bytes()
        except subprocess.CalledProcessError as error:
            self.log_error("%s", error.stderr.decode(errors="replace"))
            self.send_error(422, "Issuance failed. Check the server log.")
            return
        except (OSError, subprocess.TimeoutExpired) as error:
            self.log_error("%s", error)
            self.send_error(500, "Could not complete issuance")
            return

        self.send_response(201)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Length", str(len(certificate)))
        self.end_headers()
        self.wfile.write(certificate)


if __name__ == "__main__":
    intermediate_ca_name = "intermediateCA3"
    with HTTPServer(("0.0.0.0", 8000), IssuanceHandler) as httpd:
        httpd.intermediate_ca_name = intermediate_ca_name
        print("Listening on http://0.0.0.0:8000")
        httpd.serve_forever()


