import sys
import os
import unittest
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from crypto.homomorphic import Paillier
from crypto.ecc_util import ECDSA_NIST256p
from crypto.schnorr import schnorr_proof, schnorr_verify
from crypto.aes_util import AES_CBC_HMAC
from utils.blockchain import BlockchainBlock as Block