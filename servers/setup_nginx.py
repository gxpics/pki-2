from pathlib import Path
import subprocess
from common import  run_command, BASE_DIR
from policy import SUPPORTED_ALGORITHMS, PKI_POLICY

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
    server_name localhost;

    ssl_certificate /etc/nginx/ssl/{server_name}-chain.crt;
    ssl_certificate_key /etc/nginx/ssl/{server_name}.key;

    location / {{
        return 200 "Post-Quantum PKI NGINX server\\n";
    }}
}}
"""

    config_path = Path(f"/tmp/{server_name}")

    config_path.write_text(config)

    run_command([
        "sudo", "cp",
        config_path,
        f"/etc/nginx/sites-available/{server_name}"
    ])


def enable_nginx_site(server_name):
    run_command([
        "sudo", "ln",
        "-s",
        f"/etc/nginx/sites-available/{server_name}",
        f"/etc/nginx/sites-enabled/{server_name}"
    ])

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

def main():
    server_name = "server1"

    install_nginx_certificate(server_name)
    generate_nginx_config(server_name)
    enable_nginx_site(server_name)
    test_nginx()
    reload_nginx()


if __name__ == "__main__":
    main()
