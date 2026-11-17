PKI-2 Certificate Issuance API
==============================

HTTP contract
-------------
POST /certificates requests certificate issuance. issue_api.py handles
this route. /echo belongs to the practice API.

Method and path: POST /certificates
Local lab URL:   http://127.0.0.1:8000/certificates
Authorization:   Bearer <enrollment-token> (required HTTP request header)
Request body:    Raw PEM-encoded certificate signing request (CSR)
Content-Length:  Required. The body must contain 1–16,384 bytes.
Success:         HTTP 201 Created with a PEM certificate in the body
Response type:   application/x-pem-file

Local example
-------------
Run this on the machine hosting the API. Use HTTPS when sending an
enrollment token over the network.

  read -rsp 'Enrollment token: ' enrollment_token
  echo
  curl --fail \
    --header "Authorization: Bearer ${enrollment_token}" \
    --data-binary @server1.csr \
    --output server1.crt \
    http://127.0.0.1:8000/certificates
  unset enrollment_token

Use server1.crt only if curl succeeds. The client keeps its private key
and sends the CSR in the body.

Enrollment and signing
----------------------
1. Initialize the SQLite enrollment database during setup. In enrollment.py,
   define each server ID and its permitted DNS names in ALLOWED_DNS_BY_SERVER.
   The administrator creates a short-lived, single-use token separately,
   using the same database as the API. The database stores the token hash,
   server ID, expiration time, and usage status. The administrator gives
   the original token to the client out of band.
2. In issue_api.py, do_POST() checks the route, extracts the Bearer token,
   validates Content-Length, and reads the CSR. It passes the token, CSR,
   database connection, and DNS policy to authorize_enrollment().
3. authorize_enrollment() hashes the submitted token, checks its database
   record, verifies the CSR signature, and checks the requested DNS SANs
   against the policy for the server ID associated with the token. On
   approval, it atomically consumes the token and returns server_id and
   approved_san.
4. do_POST() writes the same CSR bytes to a temporary file. It passes the
   returned server ID, approved SANs, and temporary input and output paths
   to sign_server_csr(). main() sets the intermediate CA name on the HTTP
   server instance, and the handler reads self.server.intermediate_ca_name.
   The signer sets the approved SANs explicitly and disables automatic
   copying of CSR extensions.
5. The API returns the signed certificate. Because the token is consumed
   before signing, a signing failure requires a fresh token for a retry.

Error responses
---------------
400  Missing, malformed, or out-of-range Content-Length or incomplete CSR
401  Missing or malformed Authorization header, with WWW-Authenticate: Bearer
403  Enrollment rejected by authorize_enrollment()
404  Unknown POST path
422  OpenSSL rejected the issuance operation
500  Database or local operation failed, or OpenSSL timed out
