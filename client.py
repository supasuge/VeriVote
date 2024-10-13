import requests
import json
import hashlib
import os
from ecdsa import SigningKey, NIST256p
import logging
from Crypto.Util.number import bytes_to_long

# Configure logging
logging.basicConfig(level=logging.INFO)

# API endpoint
BASE_URL = "http://localhost:5000"

class VotingClient:
    def __init__(self):
        self.session = requests.Session()
        self.voter_fingerprint = None
        self.encrypted_private_key = None
        self.public_key = None
        self.private_key = None
        self.master_key = None  # Initialize master_key

    def register_voter(self):
        """
        Register a new voter with the e-voting system.
        
        This method sends a POST request to the /register endpoint with a master key.
        It receives a voter fingerprint and an encrypted private key in response.
        
        Returns:
            bool: True if registration was successful, False otherwise.
        """
        # Generate a master key for encryption
        self.master_key = os.urandom(32)  # 256-bit key
        
        # Prepare the registration payload
        payload = {
            'master_key': self.master_key.hex()  # Send as hex string
        }
        
        response = self.session.post(f"{BASE_URL}/register", json=payload)  # POST request with payload
        if response.status_code == 201:
            data = response.json()
            self.voter_fingerprint = data['fingerprint']  # sha256 hash of public key.
            self.encrypted_private_key = data['encrypted_private_key']  # encrypted private key
            self.public_key = data['public_key']
            print(f"Voter registered successfully. Fingerprint: {self.voter_fingerprint}")
            print(f"Encrypted Private Key: {self.encrypted_private_key}")
            print(f"Public Key: {self.public_key}")
            return True
        else:
            print(f"Registration failed. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False

    def decrypt_private_key(self):
        """
        Decrypt the private key using the master key.
        
        Args:
            None
        
        Returns:
            bool: True if decryption was successful, False otherwise.
        """
        from app.crypto.aes_util import AES_CBC_HMAC  # Ensure correct import path

        try:
            # Use the generated master_key for decryption
            cipher = AES_CBC_HMAC(self.master_key)
            decrypted_json = cipher.decrypt(self.encrypted_private_key)
            decrypted_data = json.loads(decrypted_json)
            private_key_bytes = bytes.fromhex(decrypted_data['plaintext'])
            self.private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
            self.public_key = self.private_key.get_verifying_key()
            print(f"Private key decrypted successfully.")
            return True
        except Exception as e:
            print(f"Decryption failed: {e}")
            return False

    def cast_vote(self, vote):
        """
        Cast a vote in the e-voting system.
        
        This method prepares the vote data, signs it, generates a Schnorr proof,
        and sends a POST request to the /vote endpoint.
        
        Args:
            vote (str): The vote to be cast (e.g., "candidate1").
        
        Returns:
            bool: True if the vote was cast successfully, False otherwise.
        """
        if isinstance(vote, str):
            vote = vote.encode()
        if not self.private_key or not self.public_key:
            print("Private key not decrypted. Please decrypt the private key first.")
            return False

        # Encrypt the vote (implement proper encryption as needed)
        # Placeholder: use a simple hash for demonstration (replace with actual encryption)
        encrypted_vote = hashlib.sha256(vote.encode()).hexdigest()

        # Sign the encrypted vote
        signature = self.private_key.sign(encrypted_vote.encode())

        # Generate Schnorr proof
        R_bytes, s = schnorr_proof(self.private_key)

        # Convert 's' from int to hex string without '0x' prefix
        s_hex = hex(s)[2:]

        # Prepare the vote data
        vote_data = {
            'public_key': self.public_key.to_string().hex(),
            'vote': encrypted_vote,
            'signature': signature.hex(),
            'R': R_bytes.hex(),  # Convert bytes to hex string
            's': s_hex           # Hex string without '0x'
        }
        print(f"Prepared Vote Data: {json.dumps(vote_data, indent=2)}")  # Log vote data

        # Send the vote
        response = self.session.post(f"{BASE_URL}/vote", json=vote_data)
        if response.status_code == 201:
            data = response.json()
            print(f"Vote cast successfully. Vote ID: {data['vote_id']}")
            return True
        else:
            print(f"Vote casting failed. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False

    def get_tally(self):
        """
        Retrieve the current vote tally from the e-voting system.
        
        This method sends a GET request to the /tally endpoint.
        
        Returns:
            int or None: The current vote tally if successful, None otherwise.
        """
        response = self.session.get(f"{BASE_URL}/tally")
        if response.status_code == 200:
            data = response.json()
            tally = data['tally']
            print(f"Current vote tally: {tally}")
            return tally
        else:
            print(f"Failed to retrieve tally. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None

    def validate_blockchain(self):
        """
        Validate the integrity of the blockchain used in the e-voting system.
        
        This method sends a GET request to the /blockchain/validate endpoint.
        
        Returns:
            bool or None: The validation result if successful, None otherwise.
        """
        response = self.session.get(f"{BASE_URL}/blockchain/validate")
        if response.status_code == 200:
            data = response.json()
            is_valid = data['is_valid']
            print(f"Blockchain is {'valid' if is_valid else 'invalid'}")
            return is_valid
        else:
            print(f"Failed to validate blockchain. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None


from ecdsa import SigningKey, VerifyingKey, NIST256p
from hashlib import sha256

def point_to_bytes(point):
    x_bytes = point.x().to_bytes(32, 'big')
    y_bytes = point.y().to_bytes(32, 'big')
    return x_bytes + y_bytes

def bytes_to_point(curve, data):
    x = int.from_bytes(data[:32], 'big')
    y = int.from_bytes(data[32:], 'big')
    return curve.point(x, y)  # Corrected: Removed extra '.curve'

def schnorr_proof(private_key):
    """
    Generate a Schnorr proof of knowledge of the private key.

    :param private_key: SigningKey object (private key)
    :return: Tuple (R_bytes, s) where R_bytes is bytes, s is int
    """
    G = NIST256p.generator
    order = G.order()
    k = SigningKey.generate(curve=NIST256p).privkey.secret_multiplier
    R_point = k * G
    R_bytes = point_to_bytes(R_point)
    public_key = private_key.verifying_key
    P_bytes = public_key.to_string()
    challenge_data = R_bytes + P_bytes
    c = int.from_bytes(sha256(challenge_data).digest(), 'big') % order
    x = private_key.privkey.secret_multiplier
    s = (k + c * x) % order
    return R_bytes, s

def schnorr_verify(public_key, R_bytes, s):
    """
    Verify a Schnorr proof.

    :param public_key: VerifyingKey object (public key)
    :param R_bytes: Bytes representing the commitment point
    :param s: Integer representing the response
    :return: True if the proof is valid, False otherwise
    """
    G = NIST256p.generator
    order = G.order()
    R_point = bytes_to_point(public_key.curve, R_bytes)
    P_bytes = public_key.to_string()
    challenge_data = R_bytes + P_bytes
    c = int.from_bytes(sha256(challenge_data).digest(), 'big') % order

    # Debugging: Check type of public_key.pubkey
    print(f"Type of public_key.pubkey: {type(public_key.pubkey)}")
    if not hasattr(public_key.pubkey, 'point'):
        raise AttributeError("public_key.pubkey does not have a 'point' attribute.")

    sG = s * G
    cP = c * public_key.pubkey.point
    R_plus_cP = R_point + cP
    return sG == R_plus_cP


def main():
    """
    Main function to demonstrate the e-voting process.
    
    This function creates a VotingClient instance and walks through the entire
    voting process, including registration, decrypting the private key, casting a vote,
    tallying, and blockchain validation.
    """
    client = VotingClient()

    # Step 1: Register a new voter
    if not client.register_voter():
        return

    # Step 2: Decrypt the private key
    if not client.decrypt_private_key():
        return

    # Step 3: Cast a vote
    if not client.cast_vote(int("1")):
        return

    # Step 4: Get the current tally
    tally = client.get_tally()
    if tally is None:
        return

    # Step 5: Validate the blockchain
    is_valid = client.validate_blockchain()
    if is_valid is None:
        return

    print("E-voting process completed successfully!")

if __name__ == "__main__":
    main()
