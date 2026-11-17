PKI-2 Certificate Issuance API
==============================

Current HTTP contract
---------------------
The method, path, headers, and body format are the agreement between
the client and the API. This API uses POST /certificates to request
issuance. The path is an HTTP route handled by issue_api.py.
/echo belongs to the practice API.

Method and path: POST /certificates
Local lab URL:   http://127.0.0.1:8000/certificates
Request body:    Raw PEM-encoded certificate signing request (CSR)
Content-Length:  Required by this handler. Body size is 1–16,384 bytes.
Success:         HTTP 201 with a PEM certificate in the response body
Response type:   application/x-pem-file

Example (run on the machine hosting the local API):

  curl --fail-with-body --data-binary @server.csr \
    http://127.0.0.1:8000/certificates

Use the response body as the issued certificate only after a successful
response. The client retains its private key and sends only the CSR.

Errors in the original handler
------------------------------
400  Missing, malformed, or out-of-range Content-Length
404  Unknown POST path
422  OpenSSL rejected the issuance operation
500  Local operation failed or OpenSSL timed out

Planned enrollment integration
------------------------------
The local prototype uses configured issuance values such as server1 and
DNS:localhost. The proposed enrollment module replaces those fixed values
with an authorization decision for each request.

1. An administrator registers a server ID and its allowed DNS names and
   securely provisions a short-lived, single-use token for that server.
2. The client sends the same PEM CSR body over HTTPS and includes
   Authorization: Bearer <enrollment-token>.
3. api/enrollment.py validates the token, finds the registered server,
   verifies the CSR signature, and checks each requested DNS SAN against
   the server's policy. It rejects the request if any SAN is unauthorized.
4. On approval, the module consumes the token and returns the server ID
   and approved SANs. issue_api.py passes the approved SANs and the same
   validated CSR to the intermediate CA signer.

The CSR signature ties the request to its key. The token identifies the
enrollment record, and policy determines which DNS names it can receive.
The signer should set the approved SANs explicitly and disable automatic
copying of CSR extensions. The proposed module consumes the token before
signing, so a signing failure requires a new token for a retry.
