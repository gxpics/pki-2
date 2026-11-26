from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from aws_intermediate_ca.intermediate_operations import sign_server_csr

BASE_INT_DIR = Path.home() / "pki-2" / "aws_intermediate_ca"
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
            full_chain = self.get_full_chain(csr)

            self.send_response(201, "Created")
            self.send_header("Content-Type", "application/pem-certificate-chain")
            self.send_header("Content-Length", str(len(full_chain)))
            self.end_headers()
            self.wfile.write(full_chain)

        except Exception as error:
            message = f"Certificate issuance failed: {error}\n".encode()
            self.send_response(500, "Internal Server Error")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)

    def get_full_chain(self, csr):
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            csr_path = temp_path / "request.csr"
            cert_path = temp_path / "certificate.pem"
            csr_path.write_bytes(csr)
            
            server_name = self.server.server_name
            approved_san = f"DNS:{server_name}.com"
            intermediate_ca_name = self.server.intermediate_ca_name
            sign_server_csr(approved_san, server_name, intermediate_ca_name, 
            validity_days=365, csr_path=csr_path, cert_path=cert_path)
            server_cert = cert_path.read_bytes().strip()
            intermediate_cert_path = (BASE_INT_DIR / intermediate_ca_name / "certs"
            / f"{intermediate_ca_name}.crt")
            intermediate_cert = intermediate_cert_path.read_bytes().strip()
            full_chain = server_cert + b"\n" + intermediate_cert + b"\n"
            return full_chain

if __name__ == "__main__":
    address = ("0.0.0.0", 8000)
    print(f"Listening on http://{address[0]}:{address[1]}")
    httpd = HTTPServer(("0.0.0.0", 8000), IssuanceHandler)
    httpd.server_name = "server6"
    httpd.intermediate_ca_name = "intermediateCA4"
    httpd.serve_forever()
   