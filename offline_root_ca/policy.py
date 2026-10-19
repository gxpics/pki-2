SUPPORTED_ALGORITHMS = {
    "RSA-2048": {
        "algorithm": "RSA",
        "options": [
            "rsa_keygen_bits:2048"
        ],
        "digest": "sha256"
    },

    "RSA-4096": {
        "algorithm": "RSA",
        "options": [
            "rsa_keygen_bits:4096"
        ],
        "digest": "sha256"
    },

    "ECDSA-P256": {
        "algorithm": "EC",
        "options": [
            "ec_paramgen_curve:P-256"
        ],
        "digest": "sha256"
    },

    "ECDSA-P384": {
        "algorithm": "EC",
        "options": [
            "ec_paramgen_curve:P-384"
        ],
        "digest": "sha384"
    },

    "ML-DSA-44": {
        "algorithm": "ML-DSA-44",
        "options": [],
        "digest" : None
    },

    "ML-DSA-65": {
        "algorithm": "ML-DSA-65",
        "options": [],
        "digest": None
    },

    "ML-DSA-87": {
        "algorithm": "ML-DSA-87",
        "options": [],
        "digest": None
    }
}

#PKI_POLICY = {
#    "root": "RSA-4096",
#    "intermediate": "ECDSA-P384",
#    "server": "ML-DSA-65"
#}

PKI_POLICY = {
    "classical": {
        "root": "RSA-4096",
        "intermediate": "ECDSA-P384",
        "server": "ECDSA-P256"
    },

    "post_quantum": {
        "root": "ML-DSA-87",
        "intermediate": "ML-DSA-65",
        "server": "ML-DSA-65"
    }
}

import subprocess

def main():
    root_policy = SUPPORTED_ALGORITHMS[PKI_POLICY["classical"]["root"]]
    algorithm = root_policy["algorithm"]  
    option = root_policy["options"][0]

    root_key = "/home/gxpics/pki/hybrid-pki/rootCA/private/rootCA_test.key"
    subprocess.run(['openssl', 'genpkey', '-algorithm', algorithm, '-pkeyopt', str(option),'-out', root_key])

    # openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out /home/gxpics/pki/hybrid-pki/rootCA/private/rootCA_test.key



if __name__ == "__main__":
    main()
 
