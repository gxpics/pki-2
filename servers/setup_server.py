from pathlib import Path
import subprocess
from common import  run_command, BASE_DIR
from policy import SUPPORTED_ALGORITHMS, PKI_POLICY

def create_server_dir(server_name):
    directories = ["certs", "csr", "private"]
    server_dir = BASE_DIR / server_name
    for directory in directories:
        (server_dir / directory).mkdir(
            parents=True,
            exist_ok=True
        )

def generate_key(server_name, algorithm, key_name_extension="", options=None):

    key_path = BASE_DIR / server_name / "private" / f"{server_name}{key_name_extension}.key"
    if key_path.exists():
        print(f"Key already exists: {key_path}")
        print("Skipping key generation.")
        return

    command = ["openssl","genpkey","-algorithm", algorithm]

    if options:
        for option in options:
            command.extend(["-pkeyopt", option])

    command.extend(["-out", str(key_path)])

    run_command(command)

def generate_server_csr(server_name):
    server_dir = BASE_DIR / server_name
    command = [
        "openssl","req",
        "-new",
        "-key", server_dir / "private" / f"{server_name}.key",
        "-out", server_dir / "csr" / f"{server_name}.csr",
        "-subj", f"/C=US/ST=New York/L=Rochester/O=Hybrid PKI Lab/CN={server_name}"
    ]

    run_command(command)


def verify_server(server_name, 
                  intermediate_crt_name="intermediateCA1.crt", 
                  root_crt_name="rootCA.crt"):
    """
    Verify the complete server cert chain
    """
    server_dir = BASE_DIR / server_name
    
    root_crt = server_dir / "certs" / root_crt_name
    intermediate_crt = server_dir / "certs" / intermediate_crt_name
    server_crt = server_dir / "certs" / f"{server_name}.crt"
    command = [
        "openssl", "verify",
        "-CAfile", root_crt,
        "-untrusted", intermediate_crt, server_crt
    ]

    run_command(command)

def create_server_chain(server_name, intermediate_name):
    """
    server chain certificate = server certificate + intermediate certificate
    Python can concatenate them directly without calling cat
    """
    server_dir = BASE_DIR / server_name

    server_cert = server_dir / "certs" / f"{server_name}.crt"

    intermediate_cert = server_dir / "certs" / f"{intermediate_name}.crt"

    chain_file = server_dir / "certs" / f"{server_name}-chain.crt"
    
    chain_file.write_text(server_cert.read_text() + intermediate_cert.read_text())

    print(f"Created chain: {chain_file}")


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

def initialize_server(server_name="server1", intermediate_name="intermediateCA1", mode = "classical"):
    """
    mode = either "classical" or "post_quantum"
    """
    server_dir = BASE_DIR / "servers" / server_name
    server_key = server_dir / "private" / (server_name + ".key")
    
    create_server_dir(server_name)

    server_policy = SUPPORTED_ALGORITHMS[PKI_POLICY[mode]["server"]]
    print("server policy:", server_policy)
    generate_key(server_name, server_policy["algorithm"], key_name_extension="", options=server_policy["options"])

    generate_server_csr(server_name)


def main():

    mode_choice  = "c"# input("Choose the mode (c for classical, p for post quantum): ")
    if mode_choice == "c":
        mode = "classical" 
    else:
        mode = "post_quantum"

    server_name = "server1"
    intermediate_ca_name = "IntermediateCA1"
    # server_dir = BASE_DIR / server_name
    # server_key = server_dir / "private" / (server_name + ".key")

    initialize_server(server_name, intermediate_ca_name, mode)

    # intermedate_ca_name signs the server's csr
     
    # verify_server(server_name, intermediate_ca_name, "rootCA")
    
    # create_server_chain(server_name, intermediate_ca_name)
    # install_nginx_certificate(server_name)
    # generate_nginx_config(server_name)
    # enable_nginx_site(server_name)
    # test_nginx()
    # reload_nginx()


if __name__ == "__main__":
    main()
