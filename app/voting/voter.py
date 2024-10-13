# voting/voter.py

import hashlib
from ..crypto.schnorr import schnorr_proof  # Use relative import

def submit_vote(voter_private_key, voter_public_key, encrypted_vote):
    # Import models here to avoid circular import
    from ..models.models import Vote, db  # Adjusted import

    # Generate Schnorr proof
    R, s = schnorr_proof(voter_private_key)

    # Create vote hash chain
    last_vote = Vote.query.order_by(Vote.id.desc()).first()
    previous_hash = last_vote.current_hash if last_vote else None

    # Create vote data and link hashes
    vote_data = {
        'encrypted_vote': encrypted_vote,
        'R': R.hex(),
        's': hex(s),
        'signature': voter_private_key.sign(encrypted_vote.encode()).hex()
    }
    linked_vote_data = link_votes(previous_hash, vote_data)

    # Save the vote
    vote = Vote(
        voter_id=voter_public_key,
        encrypted_vote=encrypted_vote,
        R=linked_vote_data['R'],
        s=linked_vote_data['s'],
        signature=linked_vote_data['signature'],
        previous_hash=linked_vote_data['previous_hash'],
        current_hash=linked_vote_data['current_hash']
    )
    db.session.add(vote)
    db.session.commit()

    return vote

def generate_vote_hash(vote_data):
    vote_str = f"{vote_data['encrypted_vote']}{vote_data['R']}{vote_data['s']}{vote_data['signature']}"
    return hashlib.sha256(vote_str.encode()).hexdigest()

def link_votes(previous_vote_hash, vote_data):
    current_hash = generate_vote_hash(vote_data)
    vote_data['previous_hash'] = previous_vote_hash
    vote_data['current_hash'] = current_hash
    return vote_data
