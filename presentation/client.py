import requests
import json
import hashlib
import os
from ecdsa import SigningKey, NIST256p
from app.utils.crypto.schnorr import schnorr_proof

# API endpoint
BASE_URL = "http://localhost:5000"

class VotingClient:
    def __init__(self):
        self.session = requests.Session()
        self.voter_fingerprint = None
        self.encrypted_private_key = None
        self.public_key = None
        self.private_key = None

    def register_voter(self):
        """
        Register a new voter with the e-voting system.
        
        This method sends a POST request to the /register endpoint.
        It receives a voter fingerprint and an encrypted private key in response.
        
        Returns:
            bool: True if registration was successful, False otherwise.
        """

        response = self.session.post(f"{BASE_URL}/register") # Get public key and register with registry
        if response.status_code == 200:
            data = response.json()
            self.voter_fingerprint = data['fingerprint'] # sha256 hash of public key.
            self.encrypted_private_key = data['encrypted_private_key'] # encyrpted private key
            print(f"Voter registered successfully. Fingerprint: {self.voter_fingerprint}")
            print(f"Encrypted Private Key: {self.encrypted_private_key}")
            return True
        else:
            print(f"Registration failed. Status code: {response.status_code}")
            return False

    def decrypt_private_key(self, master_key):
        """
        Decrypt the private key using the master key.
        
        In a real-world scenario, this would be done securely on the client side.
        
        Args:
            master_key (bytes): The master key used for decryption.
        
        Returns:
            bool: True if decryption was successful, False otherwise.
        """
        # This is a placeholder. In a real implementation, you would use proper decryption.
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.get_verifying_key()
        return True

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
        if not self.private_key or not self.public_key:
            print("Private key not decrypted. Please decrypt the private key first.")
            return False

        # Encrypt the vote (in a real scenario, this would use homomorphic encryption)
        #encrypted_vote = 

        # Sign the encrypted vote
        signature = self.private_key.sign(encrypted_vote.encode())

        # Generate Schnorr proof
        R, s = schnorr_proof(self.private_key.to_string())

        # Prepare the vote data
        vote_data = {
            'public_key': self.public_key.to_string().hex(),
            'vote': encrypted_vote,
            'signature': signature.hex(),
            'R': R.hex(),
            's': s.hex()
        }

        # Send the vote
        response = self.session.post(f"{BASE_URL}/vote", json=vote_data)
        if response.status_code == 200:
            data = response.json()
            print(f"Vote cast successfully. Vote ID: {data['vote_id']}")
            return True
        else:
            print(f"Vote casting failed. Status code: {response.status_code}")
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
            return None

def main():
    """
    Main function to demonstrate the e-voting process.
    
    This function creates a VotingClient instance and walks through the entire
    voting process, including registration, casting a vote, tallying, and
    blockchain validation.
    """
    client = VotingClient()

    # Step 1: Register a new voter
    if not client.register_voter():
        return

    # Step 2: Decrypt the private key (simulated)
    master_key = os.urandom(32)  # In a real scenario, this would be securely stored
    if not client.decrypt_private_key(master_key):
        return

    # Step 3: Cast a vote
    if not client.cast_vote("candidate1"):
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