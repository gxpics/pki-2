import hashlib
import re
import sqlite3
import time
import secrets
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from pathlib import Path
from contextlib import closing

ALLOWED_DNS_BY_SERVER = {
    "server1": ["server1.com"],
    "server2": ["server2.com"],
    "server3": ["server3.com"],
    "server4": ["server4.com"],
}

class EnrollmentError(Exception):
    """The request failed an enrollment check."""

def init_enrollment_db(db: sqlite3.Connection) -> None:
    """Create the enrollment token table if needed."""
    with db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                token_hash TEXT PRIMARY KEY,
                server_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            )
        """)

def create_enrollment_token(
    db: sqlite3.Connection,
    server_id: str,
    ttl_seconds: int = 3000,
) -> str:
    """Store the token hash and return the token for the enrolling client."""
    if not server_id.strip():
        raise ValueError("server_id must be nonempty.")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive.")

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    expires_at = int(time.time()) + ttl_seconds

    with db:
        db.execute(
            """
            INSERT INTO enrollment_tokens
                (token_hash, server_id, expires_at, used_at)
            VALUES (?, ?, ?, NULL)
            """,
            (token_hash, server_id, expires_at),
        )

    return token

def normalize_dns_name(name: str) -> str:
    """Accept ASCII DNS names, including localhost and IDNA A-labels."""
    if not name.isascii():
        raise EnrollmentError("Use ASCII DNS names.")

    name = name.lower().removesuffix(".")
    labels = name.split(".")
    label_pattern = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

    if len(name) > 253 or any(
        re.fullmatch(label_pattern, label) is None for label in labels
    ):
        raise EnrollmentError("Invalid or unsupported DNS name.")

    return name

def authorize_enrollment(
    token: str,
    csr_pem: bytes,
    db: sqlite3.Connection,
    allowed_dns_by_server: dict[str, list[str]],
) -> tuple[str, str]:
    """Approve a TLS server CSR and consume its enrollment token."""
    if not token or not token.isascii() or len(token) > 256:
        raise EnrollmentError("Invalid enrollment token.")

    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    row = db.execute(
        """
        SELECT server_id
        FROM enrollment_tokens
        WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
        """,
        (token_hash, int(time.time())),
    ).fetchone()

    if row is None:
        raise EnrollmentError("Invalid, expired, or used enrollment token.")

    server_id = row[0]
    allowed_names = {
        normalize_dns_name(name)
        for name in allowed_dns_by_server.get(server_id, [])
    }

    try:
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise EnrollmentError("Invalid CSR signature.")
        san = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (
        ValueError,
        UnsupportedAlgorithm,
        x509.ExtensionNotFound,
        x509.DuplicateExtension,
        x509.UnsupportedGeneralNameType,
    ) as error:
        raise EnrollmentError("Expected a valid PEM CSR with DNS SANs.") from error

    if not san or any(not isinstance(name, x509.DNSName) for name in san):
        raise EnrollmentError("This enrollment profile accepts only DNS SANs.")

    requested_names = list(dict.fromkeys(
        normalize_dns_name(name.value) for name in san
    ))
    if not set(requested_names).issubset(allowed_names):
        raise EnrollmentError("A requested DNS name is not authorized.")

    approved_san = ",".join(f"DNS:{name}" for name in requested_names)

    # Only one request can consume this token, even if both passed validation.
    now = int(time.time())
    with db:
        result = db.execute(
            """
            UPDATE enrollment_tokens
            SET used_at = ?
            WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
            """,
            (now, token_hash, now),
        )
        if result.rowcount != 1:
            raise EnrollmentError("Invalid, expired, or used enrollment token.")

    return server_id, approved_san

def get_token(server_id):
    with closing(sqlite3.connect("./aws_api/enrollment.db")) as db:
        token = create_enrollment_token(db, server_id)
        token = create_enrollment_token(db, server_id)
        return token
    
def main():

    with closing(sqlite3.connect("./aws_api/enrollment.db")) as db:
        init_enrollment_db(db)
    
    token = get_token("server4")
    print(token) 
    # csr_pem = Path("intermediate_ca/intermediateCA1/csr/server1.csr").read_bytes()
    
    # server_id, approved_san = authorize_enrollment(
    #     token, csr_pem, db, ALLOWED_DNS_BY_SERVER
    #     )

if __name__ == "__main__":
    main()