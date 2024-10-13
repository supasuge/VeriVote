# hackdearborn-project-voting
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