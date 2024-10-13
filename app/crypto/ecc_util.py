from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.util import sigencode_string, sigdecode_string

class ECDSA_NIST256p:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """
        Generate a new ECDSA key pair using NIST256p curve.
        """
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.get_verifying_key()
        return self.private_key, self.public_key

    def load_private_key(self, key_data, password=None):
        """
        Load a private key from key data.
        """
        self.private_key = SigningKey.from_string(key_data, curve=NIST256p)
        self.public_key = self.private_key.get_verifying_key()

    def load_public_key(self, key_data):
        """
        Load a public key from key data.
        """
        self.public_key = VerifyingKey.from_string(key_data, curve=NIST256p)

    def sign(self, message):
        """
        Sign a message using the private key.
        """
        if not self.private_key:
            raise ValueError("Private key is not set.")
        return self.private_key.sign(message, sigencode=sigencode_string)

    def verify(self, signature, message):
        """
        Verify a signature using the public key.
        """
        if not self.public_key:
            raise ValueError("Public key is not set.")
        try:
            return self.public_key.verify(signature, message, sigdecode=sigdecode_string)
        except:
            return False

    def get_public_key_bytes(self):
        """
        Get the public key as bytes.
        """
        if not self.public_key:
            raise ValueError("Public key is not set.")
        return self.public_key.to_string()

    def get_private_key_bytes(self):
        """
        Get the private key as bytes.
        """
        if not self.private_key:
            raise ValueError("Private key is not set.")
        return self.private_key.to_string()

# Example usage of the Ed25519 class

# Create an instance of the Ed25519 class
#ed = Ed25519()

# Generate a new key pair
#private_key, public_key = ed.generate_keypair()

# Save keys to files
#ed.save_private_key('private_key.pem')
#ed.save_public_key('public_key.pem')

# Load keys from files
#ed.load_private_key_from_file('private_key.pem')
#ed.load_public_key_from_file('public_key.pem')

# Sign a message
#message = b'Hello, this is a test message.'
#signature = ed.sign(message)

# Verify the signature
#is_valid = ed.verify(signature, message)
#print(f"Signature valid: {is_valid}")
