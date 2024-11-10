import random
from gmssl import sm3
from abc import ABC, abstractmethod
from ex2 import invmod
from itertools import product
import math


def hex_show(i):
    hex_str = ""
    if isinstance(i, int):
        hex_str = hex(i)[2:].upper()
    if isinstance(i, bytes):
        hex_str = "".join(["{:02x}".format(byte) for byte in i]).upper()
    return hex_str


def iterate_key(keysize):
    combinations = product(range(256), repeat=keysize)
    for combo in combinations:
        yield bytes(combo)


class EllipticCurve:
    def __init__(self, q, a, b):
        self.q = q
        self.a = a
        self.b = b


class EllipticCurveP(EllipticCurve):
    def __init__(self, p, a, b):
        if (4 * a**3 + 27 * b * b) % p == 0:
            raise ValueError()
        super().__init__(p, a, b)
        self.p = p

    def take_common_point(self, x, y):
        return ECPointPCommon(x, y, self)

    def take_infinity_point(self):
        return ECPointPInfinity(self)

    def is_common_point(self, x, y):
        return (x**3 + self.a * x + self.b - y**2) % self.p == 0


class EllipticCurve2m(EllipticCurve):
    def __init__(self, m, a, b):
        super().__init__(2**m, a, b)
        self.m = m


class ECPointP(ABC):
    def __init__(self, curve):
        if not isinstance(curve, EllipticCurveP):
            raise TypeError()
        self.curve = curve

    @abstractmethod
    def __add__(self, point):
        pass


class ECPointPCommon(ECPointP):
    def __init__(self, x, y, curve):
        super().__init__(curve)
        self.x = x
        self.y = y

    def __add__(self, point):
        if isinstance(point, ECPointPInfinity):
            return self.curve.take_common_point(self.x, self.y)
        if isinstance(point, ECPointPCommon):
            if point.x == self.x and point.y == (-self.y) % self.curve.p:
                return self.curve.take_infinity_point()
            elif point.x == self.x and point.y == self.y:
                return self.double()
            else:
                lmd = ((point.y - self.y) % self.curve.p) * invmod(
                    (point.x - self.x) % self.curve.p, self.curve.p
                )
                x3 = (lmd**2 - self.x - point.x) % self.curve.p
                y3 = (lmd * (self.x - x3) - self.y) % self.curve.p
                return self.curve.take_common_point(x3, y3)
        raise TypeError()

    def __str__(self):
        return f"({hex(self.x)[2:].upper()},{hex(self.y)[2:].upper()})"

    def double(self):
        lmd = (
            (3 * self.x**2 + self.curve.a)
            * invmod(2 * self.y % self.curve.p, self.curve.p)
            % self.curve.p
        )
        x3 = (lmd**2 - 2 * self.x) % self.curve.p
        y3 = (lmd * (self.x - x3) - self.y) % self.curve.p
        return self.curve.take_common_point(x3, y3)

    def fast_mod_exp(self, exp):
        result = self.curve.take_infinity_point()
        base = self
        while exp > 0:
            if exp % 2 == 1:
                result = result + base
            base = base.double()
            exp //= 2
        return result

    def to_bytes_uncompressed(self):
        l = math.ceil(math.log2(self.curve.q) / 8)
        return (
            b"\x04"
            + self.x.to_bytes(l, byteorder="big")
            + self.y.to_bytes(l, byteorder="big")
        )


class ECPointPInfinity(ECPointP):
    def __init__(self, curve):
        super().__init__(curve)

    def __add__(self, point):
        if isinstance(point, ECPointPInfinity):
            return self.curve.take_infinity_point()
        if isinstance(point, ECPointPCommon):
            return self.curve.take_common_point(point.x, point.y)
        raise TypeError()

    def __str__(self):
        return "O(Infinity,Infinity)"

    def double(self):
        return self.curve.take_infinity_point()

    def fast_mod_exp(self):
        return self.curve.take_infinity_point()


class SM2_P:
    def __init__(self):
        p = int(
            "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3".replace(
                " ", ""
            ),
            16,
        )
        a = int(
            "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498".replace(
                " ", ""
            ),
            16,
        )
        b = int(
            "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A".replace(
                " ", ""
            ),
            16,
        )
        self.curve = EllipticCurveP(p, a, b)
        self.G = self.curve.take_common_point(
            int(
                "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D".replace(
                    " ", ""
                ),
                16,
            ),
            int(
                "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2".replace(
                    " ", ""
                ),
                16,
            ),
        )
        self.n = int(
            "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7".replace(
                " ", ""
            ),
            16,
        )
        self.d = 0
        self.P = self.curve.take_infinity_point()
        self.plaintext = ""
        self.encryption_k = 0
        self.encryption_k_len = 0
        self.encryption_point1 = self.curve.take_infinity_point()
        self.h = self.curve.p // self.n  # h must be an int
        self.encryption_C1 = b""
        self.encryption_S = self.curve.take_infinity_point()
        self.encryption_point2 = self.curve.take_infinity_point()
        self.encryption_t = ""
        self.encryption_C2 = b""
        self.encryption_C3 = b""
        self.ciphertext_bytes = b""
        self.decryption_k_len = 0
        self.decryption_C1 = b""
        self.decryption_point1 = self.curve.take_infinity_point()
        self.decryption_S = self.curve.take_infinity_point()
        self.decryption_point2 = self.curve.take_infinity_point()
        self.decryption_t = ""
        self.decryption_C2 = b""
        self.decryption_C3 = b""
        self.decryption_M = b""

    def gen_key(self):
        self.d = random.randint(1, self.n - 1)
        self.P = self.G.fast_mod_exp(self.d)

    def given_key(self, d):
        self.d = d
        self.P = self.G.fast_mod_exp(self.d)

    def get_private_key(self):
        return self.d

    def get_public_key(self):
        return self.P

    def encrypt(self, plaintext, k=None):
        legal = False
        while not legal:
            self.plaintext = plaintext
            plaintext_bytes = bytes(plaintext, "utf-8")
            self.encryption_k_len = len(plaintext_bytes) * 8
            if k == None:
                self.encryption_k = random.randint(1, self.n)
            else:
                self.encryption_k = k
            self.encryption_point1 = self.G.fast_mod_exp(self.encryption_k)
            self.encryption_C1 = self.encryption_point1.to_bytes_uncompressed()
            self.encryption_S = self.P.fast_mod_exp(self.h)
            if isinstance(self.encryption_S, ECPointPInfinity):
                raise ValueError()
            self.encryption_point2 = self.P.fast_mod_exp(self.encryption_k)
            x2 = self.encryption_point2.x.to_bytes(
                (self.encryption_point2.x.bit_length() + 7) // 8, "big"
            )
            y2 = self.encryption_point2.y.to_bytes(
                (self.encryption_point2.y.bit_length() + 7) // 8, "big"
            )
            self.encryption_t = self.KDF(
                x2 + y2,
                self.encryption_k_len,
            )
            if not all(byte == 0 for byte in self.decryption_t):
                legal = True
            self.encryption_C2 = bytes(
                x ^ y for x, y in zip(plaintext_bytes, self.encryption_t)
            )
            self.encryption_C3 = bytes.fromhex(
                sm3.sm3_hash([_ for _ in x2 + plaintext_bytes + y2])
            )
            self.ciphertext_bytes = (
                self.encryption_C1 + self.encryption_C2 + self.encryption_C3
            )
            return self.ciphertext_bytes

    def KDF(self, b, k_len):
        iter = iterate_key(4)
        next(iter)
        H = []
        for i in range(math.ceil(k_len / 256)):
            H.append(bytes.fromhex(sm3.sm3_hash([_ for _ in b + next(iter)])))
        if k_len % 256 != 0:
            H.append(H.pop()[: (k_len - (256 * (k_len // 256))) // 8])
        return b"".join(H)

    def decrypt(self, ciphertext_bytes):
        if ciphertext_bytes[0] == 4:
            l = math.ceil(math.log2(self.curve.q) / 8)
            self.decryption_C1 = ciphertext_bytes[: 2 * l + 1]
            point1_bytes = self.decryption_C1[1:]
            x1 = int.from_bytes(point1_bytes[:l], byteorder="big")
            y1 = int.from_bytes(point1_bytes[l:], byteorder="big")

            if self.curve.is_common_point(x1, y1):
                self.decryption_point1 = self.curve.take_common_point(x1, y1)
            else:
                raise ValueError()
            if isinstance(
                self.decryption_point1.fast_mod_exp(self.h), ECPointPInfinity
            ):
                raise ValueError()
            self.decryption_point2 = self.decryption_point1.fast_mod_exp(self.d)
            x2 = self.decryption_point2.x.to_bytes(
                (self.decryption_point2.x.bit_length() + 7) // 8, "big"
            )
            y2 = self.decryption_point2.y.to_bytes(
                (self.decryption_point2.y.bit_length() + 7) // 8, "big"
            )
            self.decryption_k_len = (len(ciphertext_bytes) - 2 * l - 1 - 32) * 8
            self.decryption_t = self.KDF(x2 + y2, self.decryption_k_len)
            if all(byte == 0 for byte in self.decryption_t):
                raise ValueError()
            self.decryption_C2 = ciphertext_bytes[2 * l + 1 : -(256 // 8)]
            self.decryption_M = bytes(
                x ^ y for x, y in zip(self.decryption_C2, self.decryption_t)
            )
            self.decryption_u = bytes.fromhex(
                sm3.sm3_hash([_ for _ in x2 + self.decryption_M + y2])
            )
            self.decryption_C3 = ciphertext_bytes[-(256 // 8) :]
            if self.decryption_C3 == self.decryption_u:
                return self.decryption_M
            else:
                raise ValueError()

    def document_test(self):
        print("========document case test========")
        print("========initialize the elliptic curve========")
        print("p:", hex_show(self.curve.p))
        print("a:", hex_show(self.curve.a))
        print("b:", hex_show(self.curve.b))
        print("========choose a base point G========")
        print(self.G)
        print("ord(G):", hex_show(self.n))
        d = int(
            "4C62EEFD 6ECFC2B9 5B92FD6C 3D957514 8AFA1742 5546D490 18E5388D 49DD7B4F".replace(
                " ", ""
            ),
            16,
        )
        k = int(
            "4C62EEFD 6ECFC2B9 5B92FD6C 3D957514 8AFA1742 5546D490 18E5388D 49DD7B4F".replace(
                " ", ""
            ),
            16,
        )
        print("========generate private nad public key given d that=======")
        self.gen_key()
        print("d:", hex_show(self.d))
        print("private key:", self.get_private_key())
        print("public key:", self.get_public_key())
        print("========encrypt the plaintext given k that========")
        plaintext = "encryption standard"
        ciphertext_bytes = self.encrypt(plaintext)
        print("k:", hex_show(self.encryption_k))
        print("plaintext:", plaintext)
        print(
            "plaintext in hex:",
            "".join([hex(ord(char))[2:] for char in plaintext]).upper(),
        )
        print("point C1:", self.encryption_point1)
        print("uncompressed C1:", hex_show(self.encryption_C1))
        print("[K]P(x2,y2):", self.encryption_point2)
        print("k_len:", self.encryption_k_len)
        print("t:", hex_show(self.encryption_t))
        print("C2 = M xor t:", hex_show(self.encryption_C2))
        print("C3:", hex_show(self.encryption_C3))
        print("ciphertext:")
        print(hex_show(ciphertext_bytes))
        print("========decrypt the ciphertext========")
        self.decrypt(ciphertext_bytes)
        print("k_len:", self.decryption_k_len)
        print("C1:", hex_show(self.decryption_C1))
        print("C2:", hex_show(self.decryption_C2))
        print("C3:", hex_show(self.decryption_C3))
        print("point C1:", self.decryption_point1)
        print("[d]C1=(x2,y2):", self.decryption_point2)
        print("t:", hex_show(self.decryption_t))
        print("M':", hex_show(self.decryption_M))
        print("u:", hex_show(self.decryption_u))
        print("solved plaintext:", bytes.decode(self.decryption_M, "utf-8"))
        print("========check answer========")
        print(bytes.decode(self.decryption_M, "utf-8") == plaintext)

    def display(self):
        print("========initialize the elliptic curve========")
        print("p:", hex_show(self.curve.p))
        print("a:", hex_show(self.curve.a))
        print("b:", hex_show(self.curve.b))
        print("========choose a base point G========")
        print(self.G)
        print("ord(G):", hex_show(self.n))
        print("========generate private nad public key randomly=======")
        print("private key:", self.get_private_key())
        print("public key:", self.get_public_key())
        print("========encrypt the plaintext========")
        print("k:", hex_show(self.encryption_k))
        print("plaintext:", self.plaintext)
        print(
            "plaintext in hex:",
            "".join([hex(ord(char))[2:] for char in self.plaintext]).upper(),
        )
        print("point C1:", self.encryption_point1)
        print("uncompressed C1:", hex_show(self.encryption_C1))
        print("S:", self.encryption_S)
        if not isinstance(self.encryption_S, ECPointPInfinity):
            print("S is not infinity point")
        print("[K]P(x2,y2):", self.encryption_point2)
        print("k_len:", self.encryption_k_len)
        print("t:", hex_show(self.encryption_t))
        if not all(byte == 0 for byte in self.encryption_t):
            print("t is not 0")
        print("C2 = M xor t:", hex_show(self.encryption_C2))
        print("C3:", hex_show(self.encryption_C3))
        print("ciphertext:")
        print(hex_show(self.ciphertext_bytes))
        print("========decrypt the ciphertext========")
        print("k_len:", self.decryption_k_len)
        print("C1:", hex_show(self.decryption_C1))
        print("C2:", hex_show(self.decryption_C2))
        print("C3:", hex_show(self.decryption_C3))
        print("point C1:", self.decryption_point1)
        print("[d]C1=(x2,y2):", self.decryption_point2)
        print("t:", hex_show(self.decryption_t))
        if not all(byte == 0 for byte in self.decryption_t):
            print("t is not 0")
        print("M':", hex_show(self.decryption_M))
        print("u:", hex_show(self.decryption_u))
        print("solved plaintext:", bytes.decode(self.decryption_M, "utf-8"))
        print("========check answer========")
        print(bytes.decode(self.decryption_M, "utf-8") == self.plaintext)


if __name__ == "__main__":
    sm2_p = SM2_P()
    sm2_p.document_test()
    print("========test case 6========")
    problem = ""
    with open("./ex5_secrets/6.txt") as f:
        problem = f.read()
    sm2_p.decrypt(sm2_p.encrypt(problem))
    sm2_p.display()