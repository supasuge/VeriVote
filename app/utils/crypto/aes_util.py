import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json
import base64

class AES_CBC_HMAC:
    def __init__(self, key):
        # Ensure the key is bytes
        if isinstance(key, str):
            key = key.encode('utf-8')
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

# Example usage
#key = b'secret_master_key'
#aes_hmac = AES_CBC_HMAC(key)

#plaintext = "This is a secret message."
#print("Original plaintext:", plaintext)

# Encrypt
#ciphertext_json = aes_hmac.encrypt(plaintext)
#print("Ciphertext (JSON):", ciphertext_json)

# Decrypt
#decrypted_plaintext_json = aes_hmac.decrypt(ciphertext_json)
#print("Decrypted plaintext (JSON):", decrypted_plaintext_json)
