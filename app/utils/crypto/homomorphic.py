import sys
from random import randint
from Crypto.Util.number import getPrime, inverse, long_to_bytes
'''
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

def toStr(msg):
    return long_to_bytes(int(msg))


p = Paillier(1024)
k,y = p.get_keys()
print('pub ' + ((hex(k[0]) + ', ' + hex(k[1]))))
print('\n\n')

print('priv ', (hex(y[0]) + ', ' + hex(y[1])))

'''

# app/utils/crypto/homomorphic.py

from app.config import Config

class Paillier:
    def __init__(self):
        self.n, self.g = Config.PAILLIER_MASTER_KEY
        self.n_sq = self.n * self.n

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


