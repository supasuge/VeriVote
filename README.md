# VeriVote

***

- **Submission at Hack Dearborn 2024 Rewind Reality**
- Author: [supasuge - Evan Pardon](https://github.com/supasuge)

> Note: This is an incomplete project and doesn't work properly nor does it possess "secure" functionality, although that was the end goal... Only so much you can do in 24-hours

---

Secure blockchain-like voting system concept

- User registers
    - Generates keys

- Cast vote
    - Voter generates ZKP that:
        - They know there own unique PII that would normally be submitted to a ballot plaintext of the encrypted vote, and they own the private key corresponding to their public key. 
- Signing vote
    - Voter signs encrypted vote and generates ZKP + Digital signature with private ECC key.

- Submitting vote
    - Encrypted vote, ZKP, and signature submitted to the blockchain.


- Vote verification
    - Verify the voter's signature using their public key
    - Valid ZKP
        - Private key belong's them, and they know the value of the encrypted vote.

- Tallying
    - Aggregate encrypted votes using Paillier's additive property.


```bash
git clone https://github.com/supasuge/.....
cd <repo name>`
cd app/`
python3 -m venv env`
source env/bin/activate`
pip install -r requirements.txt`
python3 app.py 
python3 client.py
```
