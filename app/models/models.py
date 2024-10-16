from app import db
from sqlalchemy.sql import func

class Voter(db.Model):
    __tablename__ = 'voters'
    id = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.String, nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    fingerprint = db.Column(db.String, nullable=False)
    registration_time = db.Column(db.DateTime, default=func.now())
    is_registered = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Voter(id={self.id}, registered={self.is_registered})>"

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, nullable=False)  # Removed ForeignKey
    block_id = db.Column(db.Integer, nullable=True)
    encrypted_vote = db.Column(db.Text, nullable=False)
    R = db.Column(db.Text, nullable=False)
    s = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    previous_hash = db.Column(db.Text, nullable=True)
    current_hash = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=func.now())

    def __repr__(self):
        return f"<Vote(id={self.id}, voter_id={self.voter_id})>"

class Block(db.Model):
    __tablename__ = 'blocks'
    id = db.Column(db.Integer, primary_key=True)
    block_hash = db.Column(db.Text, nullable=False)
    previous_block_hash = db.Column(db.Text, nullable=True)
    creation_time = db.Column(db.DateTime, default=func.now())

    def __repr__(self):
        return f"<Block(id={self.id}, block_hash={self.block_hash})>"
