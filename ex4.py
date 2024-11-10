from ex1 import fermat_pr_k, fast_mod_exp
from ex2 import invmod
from Crypto.Util.number import getPrime
import random


def get_pr_strong(p_strong):
    for i in range(2, p_strong - 1):
        if (
            i**2 % p_strong != 1
            and fast_mod_exp(i, (p_strong - 1) // 2, p_strong) != 1
        ):
            return i
    else:
        raise ValueError()


class ElGamal:
    def __init__(self, p_min_len):
        self.p_min_len = p_min_len
        self.private_key = 0
        self.public_key = ()
        self.session_key = 0

    def gen_key(self):
        p = 0
        while p == 0 or fermat_pr_k(p, 15) == 0:
            q = getPrime(self.p_min_len)
            p = 2 * q + 1
        g = get_pr_strong(p)
        self.private_key = random.randint(2, p - 1)
        y = fast_mod_exp(g, self.private_key, p)
        self.public_key = (p, g, y)
        return self.public_key

    def encrypt(self, plaintext):
        self.session_key = random.randrange(3, self.public_key[0] - 1,2)
        ciphertext1 = fast_mod_exp(
            self.public_key[1], self.session_key, self.public_key[0]
        )
        ciphertext2 = (
            plaintext
            * fast_mod_exp(self.public_key[2], self.session_key, self.public_key[0])
            % self.public_key[0]
        )
        return (ciphertext1, ciphertext2)

    def decrypt(self, ciphertext):
        ciphertext1 = ciphertext[0]
        ciphertext2 = ciphertext[1]
        if ciphertext1 == None or ciphertext2 == None:
            raise ValueError()
        V = fast_mod_exp(ciphertext1, self.private_key, self.public_key[0])
        V_inv = invmod(V, self.public_key[0])
        plaintext_solved = ciphertext2 * V_inv % self.public_key[0]
        return plaintext_solved


if __name__ == "__main__":
    with open("ex4_secrets/secret0.txt") as f:
        problem = f.read()
    plaintext = int(problem)
    print("========plaintext========")
    print(plaintext)
    print("========generate private key======")
    eg = ElGamal(500)# a 150-digit decimal number would require approximately 498 bits in binary
    print("prime test to seek for a strong prime:")
    eg.gen_key()
    print("private key:", eg.private_key)
    print("========generate public key======")
    print("p:", eg.public_key[0])
    print("g:", eg.public_key[1])
    print("y=g^a: ", eg.public_key[2])
    print("========encrypt the plaintext========")
    ciphertext = eg.encrypt(plaintext)
    print("k:", eg.session_key)
    print("ciphertext:", ciphertext)
    print("========decrypt the ciphertext========")
    plaintext_solved = eg.decrypt(ciphertext)
    print(plaintext_solved)
    print("========check for the solution======")
    print(plaintext_solved == plaintext)
