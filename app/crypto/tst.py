import sys
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json
import base64
from ecdsa import SigningKey, VerifyingKey, NIST256p
import os
import sys
key = os.urandom(16).hex()

class Paillier:
    def __init__(self, bits):
        self.bits = bits
        self.pub, self.priv = self.keygen()

    def keygen(self):
        # Generate two large primes p and q
        p = getPrime(self.bits)
        q = getPrime(self.bits)
        n = p * q
        n_sq = n * n  # Calculate n squared
        Lambda = (p - 1) * (q - 1)  # Carmichael's function
        g = n + 1  # Generator g = n + 1
        mu = inverse(Lambda, n)  # Modular inverse of Lambda mod n
        return ((n, g), (Lambda, mu))

    def encrypt(self, m):
        (n, g) = self.pub
        n_sq = n * n
        # Choose random r in [1, n-1]
        r = randint(1, n - 1)
        # Compute ciphertext c = g^m * r^n mod n^2
        c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
        return c

    def decrypt(self, c):
        (Lambda, mu) = self.priv
        (n, g) = self.pub
        n_sq = n * n
        # Compute u = c^Lambda mod n^2
        u = pow(c, Lambda, n_sq)
        # Compute L(u) = (u - 1) // n
        L_u = (u - 1) // n
        # Compute plaintext m = L(u) * mu mod n
        m = (L_u * mu) % n
        return m

    def add(self, cipher_1, cipher_2):
        (n, g) = self.pub
        n_sq = n * n
        # Homomorphic addition: c = c1 * c2 * r^n mod n^2
        r = randint(1, n - 1)
        c = (cipher_1 * cipher_2 * pow(r, n, n_sq)) % n_sq
        return c

    def sub(self, cipher_1, cipher_2):
        (n, g) = self.pub
        n_sq = n * n
        # Compute inverse of cipher_2 mod n^2
        inv_cipher_2 = inverse(cipher_2, n_sq)
        # Homomorphic subtraction: c = c1 * inv(c2) * r^n mod n^2
        r = randint(1, n - 1)
        c = (cipher_1 * inv_cipher_2 * pow(r, n, n_sq)) % n_sq
        return c

    def get_keys(self):
        return self.pub, self.priv



# AES-CBC-HMAC  - Can easily be substituted for a CMAC tag.
class AES_CBC_HMAC:
    def __init__(self, key):
        # Ensure the key is bytes
        if isinstance(key, str):
            key = bytes.fromhex(key)
        # Derive a 512-bit key from the provided key
        sha_512 = hashlib.sha512(key).digest()
        # Split the derived key into HMAC key and AES key
        self.HMAC_KEY = sha_512[:32]  # 256-bit key for HMAC-SHA256
        self.AES_KEY = sha_512[32:]   # 256-bit key for AES-256
        self.block_size = AES.block_size

    def encrypt(self, raw):
        # Ensure the plaintext is bytes
        if isinstance(raw, str):
            raw = raw.encode('utf-8')
        # Pad the plaintext to be a multiple of the block size
        raw_padded = pad(raw, self.block_size)
        # Generate a random IV
        iv = get_random_bytes(self.block_size)
        # Create a new AES cipher object
        cipher = AES.new(self.AES_KEY, AES.MODE_CBC, iv)
        # Encrypt the padded plaintext
        ciphertext = cipher.encrypt(raw_padded)
        # Concatenate IV and ciphertext
        iv_ciphertext = iv + ciphertext
        # Compute HMAC over the IV and ciphertext
        hmac_tag = hmac.new(self.HMAC_KEY, iv_ciphertext, hashlib.sha256).digest()
        # Concatenate HMAC tag and encrypted data
        encrypted_data = hmac_tag + iv_ciphertext
        # Base64 encode the encrypted data to make it JSON serializable
        b64_encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
        # Return as JSON string
        return json.dumps({"ciphertext": b64_encrypted_data})

    def decrypt(self, enc_json):
        # Parse the JSON input
        enc_dict = json.loads(enc_json)
        b64_encrypted_data = enc_dict.get('ciphertext')
        if not b64_encrypted_data:
            raise ValueError("Invalid input - 'ciphertext' field not found")
        # Base64 decode the encrypted data
        enc = base64.b64decode(b64_encrypted_data)
        # Extract HMAC tag, IV, and ciphertext
        hmac_tag_received = enc[:32]  # 32 bytes for HMAC-SHA256 tag
        iv_ciphertext = enc[32:]
        iv = iv_ciphertext[:self.block_size]
        ciphertext = iv_ciphertext[self.block_size:]
        # Verify HMAC
        hmac_tag_calculated = hmac.new(self.HMAC_KEY, iv_ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_tag_received, hmac_tag_calculated):
            raise ValueError("Invalid HMAC - data may have been tampered with")
        # Decrypt the ciphertext
        cipher = AES.new(self.AES_KEY, AES.MODE_CBC, iv)
        raw_padded = cipher.decrypt(ciphertext)
        # Unpad the plaintext
        raw = unpad(raw_padded, self.block_size)
        # Return as JSON string
        return json.dumps({"plaintext": raw.decode('utf-8')})


# ECDSA Key Handling Class using NIST256p Curve
class ECDSA_NIST256p:
    def __init__(self):
        self.private_key = None # Private key (Secret multiplier)
        self.public_key = None  # Public (X, Y) ECC pointa

    def generate_keypair(self):
        """
        Generate a new ECDSA key pair using NIST256p curve.
        """
        self.private_key: SigningKey = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.verifying_key
        return self.private_key, self.public_key

    def load_private_key(self, pem_data, password=None):
        """
        Load a private key from PEM data.
        """
        self.private_key = SigningKey.from_pem(pem_data, password=password)
        self.public_key = self.private_key.verifying_key

    def load_public_key(self, pem_data):
        """
        Load a public key from PEM data.
        """
        self.public_key = VerifyingKey.from_pem(pem_data)

    def sign(self, message):
        """
        Sign a message using the private key.
        :param message: The message to sign (bytes).
        :return: The signature (bytes).
        """
        if not self.private_key:
            raise ValueError("Private key is not set.")
        signature = self.private_key.sign(message)
        return signature

    def verify(self, signature, message):
        """
        Verify a signature using the public key.
        :param signature: The signature to verify (bytes).
        :param message: The original message (bytes).
        :return: True if the signature is valid, False otherwise.
        """
        if not self.public_key:
            raise ValueError("Public key is not set.")
        return self.public_key.verify(signature, message)

    def save_private_key(self, filepath, password=None):
        """
        Save the private key to a file in PEM format.
        """
        if not self.private_key:
            raise ValueError("Private key is not set.")
        pem = self.private_key.to_pem(passphrase=password)
        with open(filepath, 'wb') as f:
            f.write(pem)

    def save_public_key(self, filepath):
        """
        Save the public key to a file in PEM format.
        """
        if not self.public_key:
            raise ValueError("Public key is not set.")
        pem = self.public_key.to_pem()
        with open(filepath, 'wb') as f:
            f.write(pem)

    def load_private_key_from_file(self, filepath, password=None):
        """
        Load a private key from a PEM file.
        """
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        self.load_private_key(pem_data, password=password)

    def load_public_key_from_file(self, filepath):
        """
        Load a public key from a PEM file.
        """
        with open(filepath, 'rb') as f:
            pem_data = f.read()
        self.load_public_key(pem_data)

# Schnorr Protocol Implementation Using NIST256p Curve
def schnorr_proof(private_key):
    """
    Generate a Schnorr proof of knowledge of the private key.

    :param private_key: SigningKey object (private key)
    :return: Tuple (R, s) where R is a point (commitment), s is an integer (response)
    """
    G = NIST256p.generator
    order = G.order()
    # Step 1: Generate random value k
    k = randint(1, order - 1)
    R_point = k * G  # R = k * G

    # Step 2: Compute challenge c = H(R || P)
    public_key = private_key.verifying_key
    R_bytes = R_point.to_bytes()
    P_bytes = public_key.to_string()
    challenge_data = R_bytes + P_bytes
    c = int.from_bytes(sha256(challenge_data).digest(), 'big') % order

    # Step 3: Compute response s = k + c * x mod n
    x = private_key.privkey.secret_multiplier
    s = (k + c * x) % order

    # Return R_point and s
    return R_point, s


def schnorr_verify(public_key, R_point, s):
    """
    Verify a Schnorr proof.

    :param public_key: VerifyingKey object (public key)
    :param R_point: Point object (commitment)
    :param s: Integer (response)
    :return: True if the proof is valid, False otherwise
    """
    G = NIST256p.generator
    order = G.order()

    # Step 1: Compute challenge c = H(R || P)
    R_bytes = R_point.to_bytes()
    P_bytes = public_key.to_string()
    challenge_data = R_bytes + P_bytes
    c = int.from_bytes(sha256(challenge_data).digest(), 'big') % order

    # Step 2: Verify that sG == R + cP
    sG = s * G
    cP = c * public_key.pubkey.point
    R_plus_cP = R_point + cP

    # Check if sG == R + cP
    return sG == R_plus_cP


def main():
    # Generate ECDSA key pair
    ecdsa = ECDSA_NIST256p()
    private_key, public_key = ecdsa.generate_keypair()

    # Generate Schnorr proof
    R_point, s = schnorr_proof(private_key)

    # Verify the proof
    is_valid = schnorr_verify(public_key, R_point, s)
    print(f"Schnorr proof verification result: {is_valid}")

    # Print keys used
    print("\nKeys Used:")
    # ECDSA Private Key
    print("ECDSA Private Key (hex):", private_key.to_string().hex())
    # ECDSA Public Key
    print("ECDSA Public Key (hex):", public_key.to_string().hex())

    # AES Key
    print("AES Key (hex):", key)

    # Paillier keys
    paillier_bits = 128  # Use at least 1024 bits in production
    paillier = Paillier(paillier_bits)
    paillier_pub, paillier_priv = paillier.get_keys()
    print("\nPaillier Keys:")
    print("Paillier Public Key (n):", paillier_pub[0])
    print("Paillier Public Key (g):", paillier_pub[1])
    print("Paillier Private Key (Lambda):", paillier_priv[0])
    print("Paillier Private Key (mu):", paillier_priv[1])


def simulate_anonymous_authentication():
    # Simulate a verifier that holds a list of registered public keys
    registered_users = {}

    # Simulate user registration
    users = ['Alice', 'Bob']
    for user in users:
        # Each user generates their own key pair
        ecdsa = ECDSA_NIST256p()
        private_key, public_key = ecdsa.generate_keypair()
        # Register both the private and public key
        registered_users[user] = {'private_key': private_key, 'public_key': public_key}
        print(f"{user} registered with public key: {public_key.to_string().hex()}")

    print("\n--- Anonymous Authentication Simulation ---\n")

    # Simulate each user attempting to authenticate anonymously
    for user in users:
        print(f"{user} is attempting to authenticate anonymously.")

        # User generates a Schnorr proof of knowledge of their private key
        private_key = registered_users[user]['private_key']
        R_point, s = schnorr_proof(private_key)

        # User sends the proof (R_point, s) to the verifier
        proof = {'R_point': R_point, 's': s}

        # Verifier tries to authenticate the user anonymously
        authenticated = False
        for keys in registered_users.values():
            pub_key = keys['public_key']
            # Verifier checks the proof against each registered public key
            if schnorr_verify(pub_key, proof['R_point'], proof['s']):
                authenticated = True
                print(f"User authenticated as a registered user (identity remains anonymous).")
                break
        if not authenticated:
            print("Authentication failed.")

        print()


if __name__ == "__main__":
    main()

    simulate_anonymous_authentication()