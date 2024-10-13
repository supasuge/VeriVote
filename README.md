# VeriVote

Note: This project is a work in progress.

Secure blockchain voting system using ZKP's for secure anonymous user registration and authentication as well as homomorphic encryption used for cast votes.


- User registers
    - Generates keys

- Cast vote
    - Voter generates ZKP that:
        - They know th plaintext of the encrypted vote, and they own the private key corresponding to their public key. 
- Signing vote
    - Voter signs encrypted vote and generates ZKP with private ECC key.

- Submitting vote
    - Encrypted vote, ZKP, and signature submitted to the blockchain.


- Vote verification
    - Verify the voter's signature using their public key
    - Valid ZKP
        - Private key belong's them, and they know the value of the encrypted vote.

- Tallying
    - Homomorphically aggregate encrypted botes usin Paillier's additive property.



`git clone https://github.com/supasuge/.....`
`cd <repo name>`
`cd app/`
`python3 -m venv env`
`source env/bin/activate`
`pip install -r requirements.txt`
`python3 app.py` - Application server
`python3 client.py` - Example of how to interact with server.
