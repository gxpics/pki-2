from pathlib import Path
import subprocess

#BASE_DIR = Path.home() / "pki" / "classical-pki"
BASE_DIR = Path.home() / "aws-pki-root" 

root_dir = BASE_DIR /"rootCA"

def run_command(command):
    try:
        print("\nRunning:")
        print(" ".join(str(x) for x in command))
        print()

        subprocess.run(
            [str(x) for x in command],
            check=True
        )

    except subprocess.CalledProcessError as e:
        print("Command failed.")
        print(e)
        raise