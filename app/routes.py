import logging
from flask import Blueprint, request, jsonify
from app import db
from app.models import Voter, Vote, Block
from app.utils.crypto.ecc_util import ECDSA_NIST256p
from app.utils.crypto.homomorphic import Paillier
from app.utils.crypto.schnorr import schnorr_proof, schnorr_verify
from app.utils.blockchain import Blockchain
import hashlib
from app.utils.crypto.aes_util import AES_CBC_HMAC
import os

main = Blueprint('main', __name__)

logger = logging.getLogger(__name__)

ecdsa = ECDSA_NIST256p()
paillier = Paillier(2048)  # Use a 2048-bit key for better security
blockchain = Blockchain()

# Use a single master key for all homomorphic operations
MASTER_KEY = os.urandom(32)

@main.route('/register', methods=['POST'])
def register():
    logger.info("Registering new voter")
    data = request.get_json()
    
    # Generate a new ECDSA key pair for the voter
    private_key, public_key = ecdsa.generate_keypair()
    voter_fingerprint = hashlib.sha256(ecdsa.get_public_key_bytes(public_key)).hexdigest()

    # Save the voter to the database
    voter = Voter(public_key=ecdsa.get_public_key_bytes(public_key).hex(), fingerprint=voter_fingerprint)
    db.session.add(voter)
    db.session.commit()

    # Encrypt the private key
    aes = AES_CBC_HMAC(MASTER_KEY)
    encrypted_private_key = aes.encrypt(ecdsa.get_private_key_bytes(private_key))

    logger.info(f"Voter registered successfully with fingerprint: {voter_fingerprint}")
    return jsonify({
        'message': 'Voter registered successfully!',
        'fingerprint': voter_fingerprint,
        'encrypted_private_key': encrypted_private_key  # In a real system, this should be securely transmitted
    })

@main.route('/vote', methods=['POST'])
def cast_vote():
    logger.info("Processing new vote")
    data = request.get_json()
    voter_public_key_hex = data['public_key']
    encrypted_vote = data['vote']
    signature_hex = data['signature']
    R_hex = data['R']
    s_hex = data['s']

    voter_public_key_bytes = bytes.fromhex(voter_public_key_hex)
    signature = bytes.fromhex(signature_hex)
    R_bytes = bytes.fromhex(R_hex)
    s = int(s_hex, 16)

    # Find the voter
    voter = Voter.query.filter_by(public_key=voter_public_key_hex).first()
    if not voter:
        logger.error("Voter not found")
        return jsonify({'error': 'Voter not found'}), 400

    # Verify the signature
    if not ecdsa.verify(signature, encrypted_vote.encode(), voter_public_key_bytes):
        logger.error("Invalid signature")
        return jsonify({'error': 'Invalid signature'}), 400

    # Verify Schnorr proof
    if not schnorr_verify(voter_public_key_bytes, R_bytes, s):
        logger.error("Invalid Schnorr proof")
        return jsonify({'error': 'Invalid Schnorr proof'}), 400

    # Link votes with hashes
    last_vote = Vote.query.order_by(Vote.id.desc()).first()
    previous_hash = last_vote.current_hash if last_vote else None

    vote_data = {
        'encrypted_vote': encrypted_vote,
        'R': R_hex,
        's': s_hex,
        'signature': signature_hex
    }
    vote_str = f"{vote_data['encrypted_vote']}{vote_data['R']}{vote_data['s']}{vote_data['signature']}"
    current_hash = hashlib.sha256(vote_str.encode()).hexdigest()

    # Save the vote
    vote = Vote(
        voter_id=voter.id,
        encrypted_vote=encrypted_vote,
        R=R_hex,
        s=s_hex,
        signature=signature_hex,
        previous_hash=previous_hash,
        current_hash=current_hash
    )
    db.session.add(vote)
    db.session.commit()

    # Add the vote to a new block in the blockchain
    new_block = blockchain.add_block({
        'vote_id': vote.id,
        'encrypted_vote': encrypted_vote,
        'voter_id': voter.id
    })

    # Save the block information to the database
    block = Block(
        block_hash=new_block.hash,
        previous_block_hash=new_block.previous_hash
    )
    db.session.add(block)
    db.session.commit()

    # Associate the vote with the block
    vote.block_id = block.id
    db.session.commit()

    logger.info(f"Vote submitted successfully. Vote ID: {vote.id}, Block hash: {new_block.hash}")
    return jsonify({
        'message': 'Vote submitted successfully!',
        'vote_id': vote.id,
        'block_hash': new_block.hash
    })

@main.route('/tally', methods=['GET'])
def tally_votes():
    logger.info("Tallying votes")
    votes = Vote.query.all()
    encrypted_sum = paillier.encrypt(0)

    for vote in votes:
        encrypted_vote_int = int(vote.encrypted_vote, 16)
        encrypted_sum = paillier.add(encrypted_sum, encrypted_vote_int)

    final_tally = paillier.decrypt(encrypted_sum)

    logger.info(f"Vote tally completed. Final tally: {final_tally}")
    return jsonify({'tally': final_tally})

@main.route('/blockchain/validate', methods=['GET'])
def validate_blockchain():
    logger.info("Validating blockchain")
    is_valid = blockchain.is_chain_valid()
    logger.info(f"Blockchain validation result: {is_valid}")
    return jsonify({'is_valid': is_valid})