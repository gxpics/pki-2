#!/usr/bin/env python3

import os
import re
import subprocess
import sys
from pathlib import Path

NAME = "server5"
SERVER_NAME = "server5.com"  # Use a DNS name listed in the certificate's SAN.

CERT_FILE = Path(f"/etc/pki/tls/certs/{NAME}.fullchain.pem")
KEY_FILE = Path(f"/etc/pki/tls/private/{NAME}.key")
CONFIG_FILE = Path(f"/etc/nginx/conf.d/{NAME}.conf")


def run(command):
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.stdout:
        print(result.stdout, end="")
    return result.returncode


def main():
    if os.geteuid() != 0:
        sys.exit("Run this script with sudo: sudo python3 configure_nginx.py")

    if not re.fullmatch(r"[A-Za-z0-9._-]+", NAME):
        sys.exit("NAME contains characters that are not safe for a filename.")

    if not re.fullmatch(r"[A-Za-z0-9.-]+", SERVER_NAME):
        sys.exit("SERVER_NAME must be a DNS name or IPv4 address.")

    if not CERT_FILE.is_file():
        sys.exit(f"Certificate file not found: {CERT_FILE}")

    if not KEY_FILE.is_file():
        sys.exit(f"Private key file not found: {KEY_FILE}")

    certificate_text = CERT_FILE.read_text()
    certificate_count = certificate_text.count("-----BEGIN CERTIFICATE-----")

    if certificate_count < 2:
        sys.exit(
            f"{CERT_FILE} contains {certificate_count} certificate block(s). "
            "Expected the server certificate and at least one intermediate."
        )

    config_text = f"""server {{
    listen 80;
    server_name {SERVER_NAME};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {SERVER_NAME};

    ssl_certificate     {CERT_FILE};
    ssl_certificate_key {KEY_FILE};

    root /usr/share/nginx/html;
    index index.html;
}}
"""

    old_config = CONFIG_FILE.read_text() if CONFIG_FILE.exists() else None
    CONFIG_FILE.write_text(config_text)
    CONFIG_FILE.chmod(0o644)

    print("Checking the NGINX configuration...")
    if run(["nginx", "-t"]) != 0:
        if old_config is None:
            CONFIG_FILE.unlink(missing_ok=True)
        else:
            CONFIG_FILE.write_text(old_config)
        sys.exit("NGINX configuration test failed; the previous config was restored.")

    if run(["systemctl", "enable", "nginx"]) != 0:
        sys.exit("Could not enable the NGINX service.")

    active = subprocess.run(
        ["systemctl", "is-active", "--quiet", "nginx"]
    ).returncode == 0

    action = ["systemctl", "reload", "nginx"] if active else ["systemctl", "start", "nginx"]

    print(f"Applying the configuration with: {' '.join(action)}")
    if run(action) != 0:
        if old_config is None:
            CONFIG_FILE.unlink(missing_ok=True)
        else:
            CONFIG_FILE.write_text(old_config)
            if active:
                run(["systemctl", "reload", "nginx"])
        sys.exit("Could not apply the new configuration.")

    print(f"NGINX is configured for {SERVER_NAME}.")


if __name__ == "__main__":
    main()