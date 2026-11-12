import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_DIR = Path(__file__).resolve().parents[1]
CA_DIR = REPO_DIR / "intermediateCA1"
CERT_PROFILE = "server_cert"
MAX_CSR_BYTES = 16 * 1024


class IssuanceHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/certificates":
            self.send_error(404, "Unknown endpoint")
            return

        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        if not 0 < size <= MAX_CSR_BYTES:
            self.send_error(400, "Send a PEM CSR up to 16 KiB")
            return

        csr = self.rfile.read(size)

        try:
            with TemporaryDirectory() as directory:
                csr_path = Path(directory) / "request.csr"
                cert_path = Path(directory) / "certificate.pem"
                csr_path.write_bytes(csr)

                subprocess.run(
                    [
                        "openssl", "ca",
                        "-batch", "-notext",
                        "-config", str(CA_DIR / "openssl.cnf"),
                        "-extensions", CERT_PROFILE,
                        "-in", str(csr_path),
                        "-out", str(cert_path),
                    ],
                    cwd=CA_DIR,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=True,
                    timeout=15,
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
    with HTTPServer(("127.0.0.1", 8000), IssuanceHandler) as server:
        print("Listening on http://127.0.0.1:8000")
        server.serve_forever()