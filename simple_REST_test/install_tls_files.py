#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

CERT_DIR = Path("/etc/pki/tls/certs")
KEY_DIR = Path("/etc/pki/tls/private")


def main():
    parser = argparse.ArgumentParser(
        description="Install an NGINX TLS full-chain certificate and private key."
    )
    parser.add_argument("--cert", required=True, help="Source full-chain PEM path")
    parser.add_argument("--key", required=True, help="Source private-key path")
    parser.add_argument("--name", required=True, help="Filename label, such as server5")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace destination files if they already exist",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run this script with sudo so the installed files are root-owned.")

    if not re.fullmatch(r"[A-Za-z0-9._-]+", args.name):
        sys.exit("--name may contain only letters, numbers, dots, underscores, and hyphens.")

    cert_source = Path(args.cert)
    key_source = Path(args.key)

    for source in (cert_source, key_source):
        if not source.is_file():
            sys.exit(f"Source file not found: {source}")

    cert_destination = CERT_DIR / f"{args.name}.fullchain.pem"
    key_destination = KEY_DIR / f"{args.name}.key"

    existing = [path for path in (cert_destination, key_destination) if path.exists()]
    if existing and not args.force:
        paths = "\n".join(f"  {path}" for path in existing)
        sys.exit(
            f"Destination file(s) already exist:\n{paths}\n"
            "Review them first, or rerun with --force to replace them."
        )

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    shutil.copyfile(cert_source, cert_destination)
    os.chown(cert_destination, 0, 0)
    os.chmod(cert_destination, 0o644)

    shutil.copyfile(key_source, key_destination)
    os.chown(key_destination, 0, 0)
    os.chmod(key_destination, 0o600)

    print(f"Certificate installed at: {cert_destination}")
    print(f"Private key installed at: {key_destination}")


if __name__ == "__main__":
    main()

'''
sudo python3 install_tls_files.py \
  --cert ./server5/server5.crt \
  --key ./server5/server5.key \
  --name server5
'''