# app/crypto/schnorr.py

from ecdsa import SigningKey, VerifyingKey, NIST256p
from hashlib import sha256

def point_to_bytes(point):
    x_bytes = point.x().to_bytes(32, 'big')
    y_bytes = point.y().to_bytes(32, 'big')
    return x_bytes + y_bytes

def bytes_to_point(curve, data):
    x = int.from_bytes(data[:32], 'big')
    y = int.from_bytes(data[32:], 'big')
    return curve.curve.point(x, y)

def schnorr_proof(private_key):
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
    G = NIST256p.generator
    order = G.order()
    R_point = bytes_to_point(public_key.curve, R_bytes)
    P_bytes = public_key.to_string()
    challenge_data = R_bytes + P_bytes
    c = int.from_bytes(sha256(challenge_data).digest(), 'big') % order
    sG = s * G
    cP = c * public_key.pubkey.point
    R_plus_cP = R_point + cP
    return sG == R_plus_cP
