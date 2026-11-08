from pathlib import Path
import subprocess
from common import  run_command, BASE_DIR

def install_nginx_certificate(server_name):
    """
    Copy the server chain certificate and key to nginx 
    """
    server_dir = BASE_DIR / server_name
    nginx_dir = Path("/etc/nginx/ssl")

    command = ["sudo", "mkdir", "-p", nginx_dir]

    run_command(command)

    run_command([
        "sudo", "cp",
        server_dir / "certs" / f"{server_name}-chain.crt",
        nginx_dir / f"{server_name}-chain.crt"
    ])

    run_command([
        "sudo", "cp", 
        server_dir / "private" / f"{server_name}.key",
        nginx_dir / f"{server_name}.key"
    ])


def generate_nginx_config(server_name):
    config = f"""
server {{
    listen 445 ssl;
    server_name {server_name};

    ssl_certificate /etc/nginx/ssl/{server_name}-chain.crt;
    ssl_certificate_key /etc/nginx/ssl/{server_name}.key; 

    location / {{
        return 200 "Post-Quantum PKI NGINX server\\n";
    }}
}}
"""

    # Full path to the configuration file
    config_path = BASE_DIR / server_name / f"{server_name}.conf"

    # Create the configuration file
    config_path.write_text(config)

    # Copy the configuration file to Nginx
    run_command([
        "sudo", "cp",
        str(config_path),
        f"/etc/nginx/sites-available/{server_name}.conf"
    ])

    print(f"Nginx configuration installed: {server_name}.conf")

def enable_nginx_site(server_name):
    source = Path(f"/etc/nginx/sites-available/{server_name}.conf")
    link = Path(f"/etc/nginx/sites-enabled/{server_name}.conf")

    if link.is_symlink():
        if link.resolve() == source:
            print(f"Nginx site already enabled: {server_name}")
            return

        raise RuntimeError(
            f"Symbolic link points to an unexpected location: {link}"
        )

    if link.exists():
        raise RuntimeError(
            f"Path already exists and is not a symbolic link: {link}"
        )

    run_command([
        "sudo", "ln", "-s",
        str(source),
        str(link)
    ])

    print(f"Nginx site enabled: {server_name}")


# def enable_nginx_site(server_name):
#     source = Path("/etc/nginx/sites-available") / f"{server_name}.conf"
#     link = Path("/etc/nginx/sites-enabled") / source.name

#     if link.is_symlink():
#         if link.resolve() == source.resolve():
#             print(f"Nginx site already enabled: {server_name}")
#             return

#         raise RuntimeError(
#             f"Symbolic link points to an unexpected location: "
#             f"{link} -> {link.readlink()}"
#         )

#     if link.exists():
#         raise RuntimeError(f"Expected a symbolic link at {link}, but found another entry.")

#     run_command(["sudo", "ln", "-sT", str(source), str(link)])
#     print(f"Nginx site enabled: {server_name}")

def test_nginx():
    run_command(["sudo", "nginx","-t"])

def reload_nginx():
    # Test nginx configuration first
    run_command(["sudo","nginx","-t"])

    # Reload systemd service definitions if needed
    run_command(["sudo", "systemctl", "daemon-reload"])

    # Determine whether nginx is running
    result = subprocess.run(["systemctl", "is-active", "--quiet", "nginx"])

    if result.returncode == 0:
        print("Nginx is active. Reloading nginx...")
        run_command(["sudo","systemctl","reload","nginx"])
    else:
        print("Nginx is inactive. Starting nginx...")
        run_command(["sudo", "systemctl", "start", "nginx"])

def test_nginx_tls(server_name, hostname="localhost", port=445, tls_name=None):
    """
    Test the running Nginx TLS server.

    Checks:
      - TLS handshake succeeds
      - Certificate chain validates against the Root CA
      - Certificate is valid for TLS server authentication
      - Certificate matches the expected hostname
    """
    if tls_name is None:
        tls_name = hostname

    server_dir = BASE_DIR / server_name
    root_crt = server_dir / "certs" / "rootCA.crt"

    if not root_crt.is_file():
        raise FileNotFoundError(
            f"Root CA certificate not found: {root_crt}"
        )

    command = [
        "openssl", "s_client",
        "-connect", f"{hostname}:{port}",
        "-servername", tls_name,
        "-CAfile", str(root_crt),
        "-verify_return_error",
        "-verify_hostname", tls_name,
        "-purpose", "sslserver",
        "-showcerts",
        "-brief",
        "-no_ign_eof"
    ]

    run_command(command)

    print(f"Nginx TLS verification successful: {hostname}:{port}")
    
def main():
    server_name = "server3"
    host_name = "localhost"
    # install_nginx_certificate(server_name)
    # generate_nginx_config(server_name)
    # enable_nginx_site(server_name)
    # test_nginx()

    reload_nginx()
    test_nginx_tls(server_name, hostname="localhost", port=445, tls_name=server_name)
if __name__ == "__main__":
    main()
