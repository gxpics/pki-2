from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from aws_intermediate_ca.intermediate_operations import sign_server_csr

MAX_CSR_BYTES = 16 * 1024


def issue_certificate(server_name,intermediate_ca_name, csr_path, cert_path):
    """
    Ask the existing Intermediate CA code to sign this CSR.
    """
    approved_san = f"DNS:{server_name}.com"
    sign_server_csr(approved_san, server_name, intermediate_ca_name, 
validity_days=365, csr_path=csr_path, cert_path=cert_path)
    


class IssuanceHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/certificates":
            self.send_error(404, "Not found")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        if content_length <= 0 or content_length > MAX_CSR_BYTES:
            self.send_error(400, "CSR body is empty or too large")
            return

        csr = self.rfile.read(content_length)

        try:
            with TemporaryDirectory() as temp_dir:
                server_name = self.server.server_name
                intermediate_ca_name = self.server.intermediate_ca_name
                
                temp_path = Path(temp_dir)
                csr_path = temp_path / "request.csr"
                certificate_path = temp_path / "certificate.pem"

                csr_path.write_bytes(csr)
                issue_certificate(server_name, intermediate_ca_name, csr_path, certificate_path)

                certificate = certificate_path.read_bytes()

            self.send_response(201, "Created")
            self.send_header("Content-Type", "application/pem-certificate-chain")
            self.send_header("Content-Length", str(len(certificate)))
            self.end_headers()
            self.wfile.write(certificate)

        except Exception as error:
            message = f"Certificate issuance failed: {error}\n".encode()
            self.send_response(500, "Internal Server Error")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)


if __name__ == "__main__":
    address = ("0.0.0.0", 8000)
    print(f"Listening on http://{address[0]}:{address[1]}")
    httpd = HTTPServer(("0.0.0.0", 8000), IssuanceHandler)
    httpd.server_name = "server5"
    httpd.intermediate_ca_name = "intermediateCA4"
    httpd.serve_forever()
   