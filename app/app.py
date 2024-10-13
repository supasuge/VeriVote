from flask import Flask, request, jsonify
from app.models import Voter, Vote, Block, db
from app import create_app
import hashlib
from app.utils.blockchain import Block as BlockchainBlock
from app.voter import submit_vote
from app.homomorphic import Paillier
from app.ecc_util import Ed25519
from app.schnorr import schnorr_proof, schnorr_verify
from app.aes_util import AES_CBC_HMAC

app = create_app()
blockchain = []
paillier = Paillier(1024)  # Initialize with an appropriate key size
ed25519 = Ed25519() # Initialize Ed25519 handling class
pub, priv = paillier.get_keys()


@app.route('/register', methods=['GET'])
def register():
    # Generate a new Ed25519 key pair for the voter
    private_key, public_key = ed25519.generate_keypair()
    pub_hex = public_key.to_string().hex()
    voter_fingerprint = hashlib.sha256(public_key.encode()).hexdigest()
    priv_ct = cipher.encrypt(cipher.pad(private_key.private_bytes_raw()))
    voter = Voter(public_key=public_key.public_bytes().hex(), private_key=priv_ct, fingerprint=voter_fingerprint)
    db.session.add(voter)
    db.session.commit()
    KEY = bytes.fromhex(hashlib.sha256(private_key.private_bytes_raw()).hexdigest())
    cipher = AES_CBC_HMAC(KEY)
    plaintext
    return jsonify({
        'message': 'Voter registered successfully!',
        'fingerprint': voter_fingerprint,
        'public_key': '0x'+pub_hex  # In a real system, this should be securely transmitted
    })



@app.route('/vote', methods=['POST'])
def cast_vote():
    data = request.get_json()
    voter_public_key = data('public_key')
    vote = data('vote')
    signature = data['signature']
    
    # Verify the signature
    voter = Voter.query.filter_by(public_key=voter_public_key).first()
    if not voter:
        return jsonify({'error': 'Voter not found'}), 400
    
    if not ed25519.verify(bytes.fromhex(signature), encrypted_vote.encode()):
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Generate Schnorr proof
    R, s = schnorr_proof(bytes.fromhex(data['private_key']), bytes.fromhex(voter_public_key))
    
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


@app.route('/vote', methods=['POST'])
def cast_vote():
    data = request.get_json()
    voter_public_key_hex = data['public_key']
    vote = int(data['vote'])
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
        return jsonify({'error': 'Voter not found'}), 400

    # Encrypt the vote
    encrypted_vote = paillier.encrypt(vote)

    # Verify the signature
    if not ecdsa.verify(signature, str(encrypted_vote).encode(), voter_public_key_bytes):
        return jsonify({'error': 'Invalid signature'}), 400

    # Verify Schnorr proof
    if not schnorr_verify(voter_public_key_bytes, R_bytes, s):
        return jsonify({'error': 'Invalid Schnorr proof'}), 400

    # Save the vote
    vote = Vote(
        voter_id=voter.id,
        encrypted_vote=str(encrypted_vote),
        R=R_hex,
        s=s_hex,
        signature=signature_hex
    )
    db.session.add(vote)
    db.session.commit()

    # Add the vote to a new block in the blockchain
    new_block = blockchain.add_block({
        'vote_id': vote.id,
        'encrypted_vote': str(encrypted_vote),
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

    return jsonify({
        'message': 'Vote submitted successfully!',
        'vote_id': vote.id,
        'block_hash': new_block.hash
    })

@app.route('/tally', methods=['GET'])
def tally_votes():
    votes = Vote.query.all()
    
    # Initialize the tally
    tally = paillier.encrypt(0)
    
    # Add up all the votes
    for vote in votes:
        encrypted_vote = int(vote.encrypted_vote)
        tally = paillier.add(tally, encrypted_vote)
    
    # Decrypt the final tally
    final_tally = paillier.decrypt(tally)

    return jsonify({'tally': final_tally})

@app.route('/blockchain/validate', methods=['GET'])
def validate_blockchain():
    is_valid = blockchain.is_chain_valid()
    return jsonify({'is_valid': is_valid})



if __name__ == '__main__':
    app.run(debug=True)