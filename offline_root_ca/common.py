from pathlib import Path
import subprocess

BASE_DIR = Path.home() / "pki-2" / "offline_root_ca"

def run_command(command, *, capture_output=False):
    try:
        command = [str(arg) for arg in command]
        print("\nRunning:")
        print(" ".join(command))
        print()

        return subprocess.run(
            command,
            check=True,
            capture_output=capture_output,
            text=True,
        )

    except subprocess.CalledProcessError as e:
        print("Command failed.")
        print(e)
        if e.stderr:
            print(e.stderr.rstrip())
        raise