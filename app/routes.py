# app/routes.py

from flask import request, jsonify
from app import app, db
from app.models import Voter, Vote
from app.utils.blockchain import BlockchainBlock as Block
from app.crypto.homomorphic import Paillier
from app.crypto.ecc_util import ECDSA_NIST256p
from app.crypto.schnorr import schnorr_proof, schnorr_verify
from app.crypto.aes_util import AES_CBC_HMAC
from app.voting.voter import submit_vote
import hashlib

paillier = Paillier()
ecdsa = ECDSA_NIST256p()
blockchain = []

with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET'])
def register():
    # Generate a new ECDSA key pair for the voter
    private_key, public_key = ecdsa.generate_keypair()
    pub_hex = public_key.to_string().hex()
    voter_fingerprint = hashlib.sha256(public_key.to_string()).hexdigest()

    # Save voter in the database
    voter = Voter(public_key=pub_hex, fingerprint=voter_fingerprint)
    try:
        db.session.add(voter)
        db.session.commit()
    except Exception as e:
        app.logger.info("Exception: %s", str(e))
        db.session.rollback()

    # Encrypt private key using AES-CBC-HMAC
    key = hashlib.sha256(private_key.to_string()).digest()
    cipher = AES_CBC_HMAC(key)
    encrypted_private_key = cipher.encrypt(private_key.to_string())

    return jsonify({
        'message': 'Voter registered successfully!',
        'fingerprint': voter_fingerprint,
        'public_key': '0x' + pub_hex,
        'encrypted_private_key': encrypted_private_key
    })

@app.route('/vote', methods=['POST'])
def cast_vote():
    data = request.get_json()
    voter_public_key_hex = data['public_key']
    encrypted_vote = data['ote']  # Assuming this is the vote
    signature_hex = data['signature']

    # Verify the signature
    voter = Voter.query.filter_by(public_key=voter_public_key_hex).first()
    if not voter:
        return jsonify({'error': 'Voter not found'}), 400

    ecdsa.load_public_key(bytes.fromhex(voter_public_key_hex))
    if not ecdsa.verify(bytes.fromhex(signature_hex), encrypted_vote.encode()):
        return jsonify({'error': 'Invalid signature'}), 400

    # Generate Schnorr proof
    private_key_hex = data['private_key']  # Assuming the private key is passed
    ecdsa.load_private_key(bytes.fromhex(private_key_hex))
    R, s = schnorr_proof(ecdsa.private_key)

    # Submit the vote
    vote = submit_vote(ecdsa.private_key, ecdsa.public_key, encrypted_vote)

    # Add the vote to a new block
    new_block = Block(
        index=len(blockchain),
        timestamp=vote.timestamp.timestamp(),
        data={'vote_id': vote.id, 'encrypted_vote': encrypted_vote},
        previous_hash=blockchain[-1].hash if blockchain else None
    )
    blockchain.append(new_block)

    return jsonify({'message': 'Vote submitted successfully!', 'vote_id': vote.id})


