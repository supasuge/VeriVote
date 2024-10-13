
from ..crypto.ecc_util import Ed25519
import hashlib
import os

def register_voter(name, DoB, SSN):
    data = str(name) + str(DoB) + str(SSN)
    nonce = os.urandom(16)
    