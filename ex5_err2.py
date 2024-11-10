import random
from gmssl import sm3
from abc import ABC, abstractmethod
from ex2 import invmod
from itertools import product
import math


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
        return (
            b"04"
            + self.x.to_bytes((self.x.bit_length() + 7) // 8, byteorder="big")
            + self.y.to_bytes((self.x.bit_length() + 7) // 8, byteorder="big")
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
        self.k = 0
        self.k_len = 0
        self._encrypt_point1 = self.curve.take_infinity_point()
        self.h = self.curve.p // self.n  # h must be an int
        self._C1 = b""
        self._S = self.curve.take_infinity_point()
        self._encrypt_point2 = self.curve.take_infinity_point()
        self._t = ""
        self._C2 = b""
        self._C3 = b""

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

    def encrypt(self, plaintext):
        bytes(plaintext, "utf-8")
        self.k = random.randint(1, self.n)

    def encrypt_given_k(self, plaintext, k):
        plaintext_bytes = bytes(plaintext, "utf-8")
        self.k_len = len(plaintext_bytes) * 8
        self.k = k
        self._encrypt_point1 = self.G.fast_mod_exp(k)
        self._C1 = self._encrypt_point1.to_bytes_uncompressed()
        self._S = self.P.fast_mod_exp(self.h)
        if isinstance(self._S, ECPointPInfinity):
            raise ValueError()
        self._encrypt_point2 = self.P.fast_mod_exp(self.k)
        self._t = self.KDF(
            self._encrypt_point2.x.to_bytes((self._encrypt_point2.x.bit_length() - 7) // 8,'big')
            + self._encrypt_point2.y.to_bytes((self._encrypt_point2.y.bit_length() - 7) // 8,'big'),
            self.k_len,
        )
        if self._t == 0:
            raise ValueError()
        print(self._t)

    def KDF(self, b, k_len):
        iter = iterate_key(4)
        next(iter)
        H = []
        for i in range(math.ceil(k_len / 512)):
            H.append(sm3.sm3_hash([_ for _ in b + next(iter)]))
        if k_len % 512 != 0:
            H.append(H.pop()[: k_len - (512 * (k_len // 512))])
        return bytes(H)

    def document_test(self):
        d = int(
            "4C62EEFD 6ECFC2B9 5B92FD6C 3D957514 8AFA1742 5546D490 18E5388D 49DD7B4F".replace(
                " ", ""
            ),
            16,
        )
        self.given_key(d)


if __name__ == "__main__":
    sm2_p = SM2_P()
    d = int(
        "1649AB77 A00637BD 5E2EFE28 3FBF3535 34AA7F7C B89463F2 08DDBC29 20BB0DA0".replace(
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
    sm2_p.given_key(d)
    print(sm2_p.get_public_key())
    print(sm2_p.G.to_bytes_uncompressed())
    sm2_p.encrypt_given_k("encryption standard",k)
