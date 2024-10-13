# app/routes.py

from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models.models import Voter, Vote
from app.utils.blockchain import BlockchainBlock
from app.crypto.homomorphic import Paillier
from app.crypto.ecc_util import ECDSA_NIST256p
from app.crypto.schnorr import schnorr_verify  # Import only schnorr_verify
from app.crypto.aes_util import AES_CBC_HMAC
from app.voting.voter import submit_vote
import hashlib

main = Blueprint('main', __name__)

paillier = Paillier()
ecdsa = ECDSA_NIST256p()
blockchain = []

@main.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or 'master_key' not in data:
            return jsonify({'error': 'Master key is required for registration.'}), 400

        # Receive the master key from the client
        master_key_hex = data['master_key']
        master_key = bytes.fromhex(master_key_hex)

        # Generate a new ECDSA key pair for the voter
        private_key, public_key = ecdsa.generate_keypair()
        pub_hex = public_key.to_string().hex()
        voter_fingerprint = hashlib.sha256(public_key.to_string()).hexdigest()

        # Encrypt private key using AES-CBC-HMAC with the provided master key
        cipher = AES_CBC_HMAC(master_key)
        encrypted_private_key_json = cipher.encrypt(private_key.to_string())

        # Create a new Voter instance
        voter = Voter(
            public_key=pub_hex,
            encrypted_private_key=encrypted_private_key_json,
            fingerprint=voter_fingerprint
        )
        db.session.add(voter)
        db.session.commit()

        current_app.logger.info(f"Voter {voter.id} registered successfully.")

        return jsonify({
            'message': 'Voter registered successfully!',
            'fingerprint': voter_fingerprint,
            'public_key': '0x' + pub_hex,
            'encrypted_private_key': encrypted_private_key_json
        }), 201  # 201 Created
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Registration failed: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@main.route('/vote', methods=['POST'])
def cast_vote():
    try:
        data = request.get_json()
        voter_public_key_hex = data['public_key']
        raw_vote = data['vote']
        signature_hex = data['signature']
        R_hex = data['R']
        s_hex = data['s']
        pai = Paillier()
        v_ct = pai.encrypt(pai)
        # Convert R and s from hex to appropriate types
        R_bytes = bytes.fromhex(R_hex)
        s = int(s_hex, 16)

        # Verify the signature
        voter = Voter.query.filter_by(public_key=voter_public_key_hex).first()
        if not voter:
            return jsonify({'error': 'Voter not found'}), 400

        ecdsa.load_public_key(bytes.fromhex(voter_public_key_hex))
        if not ecdsa.verify(bytes.fromhex(signature_hex), ):
            return jsonify({'error': 'Invalid signature'}), 400

        # Verify Schnorr proof
        is_valid_proof = schnorr_verify(ecdsa.public_key, R_bytes, s)
        if not is_valid_proof:
            return jsonify({'error': 'Invalid Schnorr proof'}), 400

        # Submit the vote
        vote = submit_vote(ecdsa.private_key, ecdsa.public_key, v_ct)

        # Add the vote to a new block
        new_block = BlockchainBlock(
            index=len(blockchain),
            timestamp=vote.timestamp.timestamp(),
            data={'vote_id': vote.id, 'encrypted_vote': encrypted_vote},
            previous_hash=blockchain[-1].hash if blockchain else None
        )
        # Add block to chain
        blockchain.append(new_block)

        print(f"Vote {vote.id} cast successfully.")

        return jsonify({'message': 'Vote submitted successfully!', 'vote_id': vote.id}), 201
    except Exception as e:
        current_app.logger.error(f"Vote casting failed: {e}")
        return jsonify({'error': f'Vote casting failed, {e}'}), 500

@main.route('/tally', methods=['GET'])
def tally_votes():
    votes = Vote.query.all()
    encrypted_sum = paillier.encrypt(0)

    for vote in votes:
        encrypted_sum = paillier.add(encrypted_sum, int(vote.encrypted_vote))
    final_tally = paillier.decrypt(encrypted_sum)

    return jsonify({'tally': final_tally})

@main.route('/blockchain/validate', methods=['GET'])
def validate_blockchain():
    # Assuming BlockchainBlock has a method to validate the chain
    is_valid = BlockchainBlock.is_chain_valid(blockchain)  # Adjust based on your implementation
    return jsonify({'is_valid': is_valid})
