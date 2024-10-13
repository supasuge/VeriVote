import sys
from random import randint
from Crypto.Util.number import getPrime, inverse, long_to_bytes
import sys, os
class Paillier:
    def __init__(self):
        # Hardcoding the Paillier public key (n, g) from your config file directly
        self.n = 25240118150395567261774392658130791148967831418270115819033960234237571374867101423952269402893266241616390292033480881110345733095934589630507194435002365317853350116056441489707973484146647805560304021554839414289975796584505885160025113542233594111915394257546437439044365315212722183487334140133631952655728448107244631307054652542947160858997729020684600455321793539634471752679171007282671372852928364008581816071734343321953116966803923696385300356384261068053748199719956372320771820589462509873273367855307567070443051263734417401853034887721227222205010536474938414755448825208232003866311921889429657399553
        self.g = 25240118150395567261774392658130791148967831418270115819033960234237571374867101423952269402893266241616390292033480881110345733095934589630507194435002365317853350116056441489707973484146647805560304021554839414289975796584505885160025113542233594111915394257546437439044365315212722183487334140133631952655728448107244631307054652542947160858997729020684600455321793539634471752679171007282671372852928364008581816071734343321953116966803923696385300356384261068053748199719956372320771820589462509873273367855307567070443051263734417401853034887721227222205010536474938414755448825208232003866311921889429657399554
        self.n_sq = self.n * self.n

        self.Lambda = 25240118150395567261774392658130791148967831418270115819033960234237571374867101423952269402893266241616390292033480881110345733095934589630507194435002365317853350116056441489707973484146647805560304021554839414289975796584505885160025113542233594111915394257546437439044365315212722183487334140133631952655410321673044868775511487739142551759635374910269762567537007656892415498802012098298784176004057187407291882489354759770752799773621173178904164901000300524434303033044287754872779538299886259866144783661988831090664569444518291466715124568861879464411036268310943801346877970924138515154553786689450537940928
        # mu = inverse(self.Lambda, self.n)
        self.mu = 18775108995804501113452905772054293820284375886771523550655228367405353062834761215595224374955319657908898823587727319385762017105256916500749927682777533333231778121267656137583932586374146737803911175560909560034071375581098831070356074804536534427343440896477799402753911757328534611721419449833613640973689031201791025583827781399763395120702014549708505305593861008232973891564656315687205504106677878472253469510749195752857619531518250191120697123282667617109167129684393301371443345097964496737012820751439738693802200805134893988733113759772523992000166929772753274007216186052713092213003354831405744864352

    def encrypt(self, m):
        n_sq = self.n_sq
        # Choose random r in [1, n-1]
        r = randint(1, self.n - 1)
        # Compute ciphertext c = g^m * r^n mod n^2
        c = (pow(self.g, m, n_sq) * pow(r, self.n, n_sq)) % n_sq
        return c

    def decrypt(self, c):
        # Directly use self.Lambda and self.mu, no need for self.priv
        n_sq = self.n_sq
        # Compute u = c^Lambda mod n^2
        u = pow(c, self.Lambda, n_sq)
        # Compute L(u) = (u - 1) // n
        L_u = (u - 1) // self.n
        # Compute plaintext m = L(u) * mu mod n
        m = (L_u * self.mu) % self.n
        return m

    def add(self, cipher_1, cipher_2):
        n_sq = self.n_sq
        # Homomorphic addition: c = c1 * c2 * r^n mod n^2
        r = randint(1, self.n - 1)
        c = (cipher_1 * cipher_2 * pow(r, self.n, n_sq)) % n_sq
        return c

    @classmethod
    def toStr(cls, msg):
        return long_to_bytes(int(msg))

# Testing the Paillier class with hardcoded keys

def test():
    p = Paillier()
    e = 12345
    c = 12345
    ct1 = p.encrypt(e)
    ct2 = p.encrypt(c)

    print(f"CT1: {ct1}\nCT2: {ct2}\n")

    # Homomorphic addition and decryption
    added_cipher = p.add(ct1, ct2)
    print(f"Added Cipher: {added_cipher}\n")
    print(f"Decrypted sum: {p.decrypt(added_cipher)}")

