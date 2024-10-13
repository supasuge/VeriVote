from pysnark.runtime import snark
from pysnark.runtime import Secret, PubVal
import ecdsa
import hashlib
"""
Circuit requires:
- x-coordinate of public key (byte array)
- y-coordinate of public key (byte array)
- Signature (byte array)



"""




def vote_validity_circuit(vote):
    """
    Circuit to check that the vote is either 0 or 1.
    vote: Secret input representing the vote.
    """
    # Ensure vote is either 0 or 1
    is_zero = vote == 0
    is_one = vote == 1
    valid = is_zero + is_one  # valid == 1 if vote is 0 or 1
    snark.assert_eq(valid, 1)  # Assert that the vote is valid



