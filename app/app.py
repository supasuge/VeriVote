from flask import Flask, request, jsonify
from app import create_app
import hashlib
from app.blockchain import Block as BlockchainBlock
from app.voter import submit_vote
from app.homomorphic import Paillier
from app.ecc_util import Ed25519
from app.schnorr import schnorr_proof, schnorr_verify
from app.aes_util import AES_CBC_HMAC
from models import Voter, db 
app = create_app()
blockchain = []
paillier = Paillier(1024)  # Initialize with appropriate key size
ed25519 = Ed25519()  # Initialize Ed25519 handling class

@app.route('/register', methods=['GET'])
def register():
     # Import inside the function to avoid circular import

    # Generate a new Ed25519 key pair for the voter
    private_key, public_key = ed25519.generate_keypair()
    pub_hex = public_key.to_string().hex()
    voter_fingerprint = hashlib.sha256(public_key.to_string()).hexdigest()

    # Save voter in the database
    voter = Voter(public_key=public_key.public_bytes().hex(), fingerprint=voter_fingerprint)
    try:
        db.session.add(voter)
        db.session.commit()
    except Exception as e:
        logging.info("Exception ", str(e))
        db.session.rollback()
    # Encrypt private key using AES-CBC-HMAC
    key = bytes.fromhex(hashlib.sha256(private_key.private_bytes_raw()).hexdigest())
    cipher = AES_CBC_HMAC(key)
    encrypted_private_key = cipher.encrypt(cipher.pad(private_key.private_bytes_raw()))

    # TX Information for registration
    return jsonify({
        'message': 'Voter registered successfully!',
        'fingerprint': voter_fingerprint,
        'public_key': '0x' + pub_hex  # In a real system, this should be securely transmitted
    })



@app.route('/vote', methods=['POST'])
def cast_vote():
    from models import Voter, Vote, db  # Import inside the function to avoid circular import

    data = request.get_json()
    voter_public_key = data['public_key']
    encrypted_vote = data['ote']  # Assuming this is the vote
    signature = data['signature']

    # Verify the signature
    voter = Voter.query.filter_by(public_key=voter_public_key).first()
    if not voter:
        return jsonify({'error': 'Voter not found'}), 400

    if not ed25519.verify(bytes.fromhex(signature), encrypted_vote.encode()):
        return jsonify({'error': 'Invalid signature'}), 400

    # Generate Schnorr proof
    private_key = bytes.fromhex(data['private_key'])  # Assuming the private key is passed
    R, s = schnorr_proof(private_key, bytes.fromhex(voter_public_key))

    # Submit the vote
    vote = submit_vote(voter, encrypted_vote, R, s, signature)

    # Add the vote to a new block
    new_block = BlockchainBlock(
        index=len(blockchain),
        timestamp=vote.timestamp,
        data={'vote_id': vote.id, 'encrypted_vote': encrypted_vote},
        previous_hash=blockchain[-1].hash if blockchain else None
    )
    blockchain.append(new_block)

    return jsonify({'message': 'Vote submitted successfully!', 'vote_id': vote.id})

@app.route('/tally', methods=['GET'])
def tally_votes():
    from models import Vote, db  # Import inside the function to avoid circular import

    votes = Vote.query.all()
    encrypted_sum = paillier.encrypt(0)

    for vote in votes:
        encrypted_sum = paillier.add(encrypted_sum, vote.encrypted_vote)

    final_tally = paillier.decrypt(encrypted_sum)

    return jsonify({'tally': final_tally})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
