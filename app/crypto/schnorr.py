# app/crypto/schnorr.py

from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod
from ecdsa import NIST256p
from hashlib import sha256
from secrets import randbelow

def point_to_bytes(point):
    """
    Convert an elliptic curve point to bytes.
    """
    x_bytes = point.x().to_bytes(32, 'big')
    y_bytes = point.y().to_bytes(32, 'big')
    return x_bytes + y_bytes

def bytes_to_point(curve, data):
    """
    Convert bytes back to an elliptic curve point.
    """
    x = int.from_bytes(data[:32], 'big')
    y = int.from_bytes(data[32:], 'big')
    return Point(curve, x, y)  # Corrected: Use Point class directly

def schnorr_proof(private_key):
    """
    Generate a Schnorr proof of knowledge of the private key.

    :param private_key: SigningKey object (private key)
    :return: Tuple (R_bytes, s) where R_bytes is bytes, s is int
    """
    G = NIST256p.generator
    order = G.order()
    k = randbelow(order - 1) + 1  # Secure random in [1, order-1]
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
    R_point = bytes_to_point(public_key.pubkey.point.curve(), R_bytes)  # Corrected curve access
    P_bytes = public_key.to_string()
    challenge_data = R_bytes + P_bytes
    c = int.from_bytes(sha256(challenge_data).digest(), 'big') % order

    sG = s * G
    cP = c * public_key.pubkey.point
    R_plus_cP = R_point + cP
    return sG == R_plus_cP
