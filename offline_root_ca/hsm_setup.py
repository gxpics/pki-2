"""
The HSM setup module handle the token and keys.

1. OpenSSL performs cryptographic operations and can use those keys 
through its PKCS#11 provider. 
2. SoftHSM2 stores keys and provides the PKCS#11 interface. 
3. pkcs11-tool is a utility that talks to SoftHSM through that interface. 

This project uses softhsm2-util to initialize the token, pkcs11-tool 
to generate the key pair inside it, and then OpenSSL to sign using that key.
Use softhsm2-util to initialize the token, 
then pkcs11-tool to generate the ECDSA P-384 key pair inside it.

Both the following commands display slots and tokems:
softhsm2-util --show-slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
"""
import subprocess
from common import run_command
import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters
from getpass import getpass

SOFTHSM_MODULE = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"

def initialize_hsm(token_label="RootCA"):
    """
    Initialize a SoftHSM token.
    - Skip initialization if the token already exists.
    - Prompt interactively for SO PIN and User PIN.
    - Python does not receive PINs. SoftHSM prompts for PINs directly 
    and handles them internally
    """

    # Check existing tokens
    result = subprocess.run(
        ["softhsm2-util", "--show-slots"],
        capture_output=True,
        text=True,
        check=True
    )

    # Check for an existing initialized token
    for section in result.stdout.split("Slot info:"):
        if (
            f"Label:            {token_label}" in section
            and "Initialized:      yes" in section
        ):
            print(f"Token '{token_label}' already exists.")
            return

    # Initialize a new token
    print(f"Initializing SoftHSM token: {token_label}")

    run_command([
        "softhsm2-util",
        "--init-token",
        "--free",
        "--label", token_label
    ])

    print(f"Token '{token_label}' initialized successfully.")

def generate_key(algorithm="EC", key_name="rootCA", token_label="RootCA",options=None):
    """
    Generate a key pair inside a SoftHSM token.
    Currently supports EC P-384.
    Previous implementation	    vs.     SoftHSM implementation
    openssl genpkey	                     pkcs11-tool --keypairgen
    Private key saved as rootCA.key	     Private key stored inside SoftHSM
    Check whether key file exists	     Check whether key object exists
    -pkeyopt specifies EC curve	         --key-type EC:secp384r1
    Key identified by filename	         Key identified by token label, key label, and ID
    """

    # if algorithm != "EC":
    #     raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Load the SoftHSM PKCS#11 library
    lib = pkcs11.lib(SOFTHSM_MODULE)
    token = lib.get_token(token_label=token_label)

    # Prompt for the SoftHSM User PIN
    user_pin = getpass("Enter SoftHSM User PIN: ")

    with token.open(user_pin=user_pin, rw=True) as session:

        # Check whether the private key already exists
        existing_keys = session.get_objects({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.LABEL: key_name
        })

        if next(existing_keys, None) is not None:
            print(f"Key '{key_name}' already exists.")
            print("Skipping key generation.")
            return

        # Generate EC P-384 key pair inside SoftHSM
        ec_params = encode_named_curve_parameters("secp384r1")

        public_key, private_key = session.generate_keypair(
            KeyType.EC,
            key_length=384,
            store=True,
            label=key_name,
            id=b"\x01",
            public_template={
                Attribute.EC_PARAMS: ec_params
            }
        )

        print(
            f"Generated EC P-384 key pair "
            f"inside SoftHSM token '{token_label}'."
        )

def inspect_keys(token_label="RootCA"):
    """
    Display information about keys stored in a SoftHSM token.
    Does not expose private key material.
    """

    lib = pkcs11.lib(SOFTHSM_MODULE)
    token = lib.get_token(token_label=token_label)

    user_pin = getpass("Enter SoftHSM User PIN: ")

    with token.open(user_pin=user_pin) as session:

        print(f"\nKeys in SoftHSM token '{token_label}':")
        print("-" * 50)

        count = 0

        for obj in session.get_objects():

            obj_class = obj[Attribute.CLASS]

            if obj_class not in (
                ObjectClass.PRIVATE_KEY,
                ObjectClass.PUBLIC_KEY
            ):
                continue

            count += 1

            label = obj[Attribute.LABEL]
            key_id = obj[Attribute.ID]

            print(f"Object Type : {obj_class.name}")
            print(f"Label       : {label}")
            print(f"ID          : {bytes(key_id).hex()}")
            print("-" * 50)

        if count == 0:
            print("No keys found.")

def inspect_keys(token_label="RootCA"):
    """
    Display information about keys stored in a SoftHSM token.
    Does not expose private key material.

    You can also inspect keys using pkcs11-tool command directly:
    pkcs11-tool \
  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  --token-label RootCA \
  --login \
  --list-objects
    """

    lib = pkcs11.lib(SOFTHSM_MODULE)
    token = lib.get_token(token_label=token_label)

    user_pin = getpass("Enter SoftHSM User PIN: ")

    with token.open(user_pin=user_pin) as session:

        print(f"\nKeys in SoftHSM token '{token_label}':")
        print("-" * 50)

        count = 0

        for obj in session.get_objects():

            obj_class = obj[Attribute.CLASS]

            if obj_class not in (
                ObjectClass.PRIVATE_KEY,
                ObjectClass.PUBLIC_KEY
            ):
                continue

            count += 1

            label = obj[Attribute.LABEL]
            key_id = obj[Attribute.ID]

            print(f"Object Type : {obj_class.name}")
            print(f"Label       : {label}")
            print(f"ID          : {bytes(key_id).hex()}")
            print("-" * 50)

        if count == 0:
            print("No keys found.")


if __name__ == "__main__":
    initialize_hsm()

# from getpass import getpass
# def initialize_hsm(token_label="RootCA"): # Not safe
#     """Initialize a new SoftHSM token."""

#     print(f"Initializing SoftHSM token: {token_label}")

#     so_pin = getpass("Enter new SO PIN: ")
#     user_pin = getpass("Enter new User PIN: ")

#     subprocess.run(
#         [
#             "softhsm2-util",
#             "--init-token",
#             "--free",
#             "--label", token_label,
#             "--so-pin", so_pin,
#             "--pin", user_pin
#         ],
#         check=True
#     )

#     print(f"SoftHSM token '{token_label}' initialized.")
#pin!