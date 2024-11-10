import random
from abc import ABC, abstractmethod
from ex2 import invmod


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
            else:
                print((point.x - self.x) % self.curve.p)
                lmd = ((point.y - self.y) % self.curve.p) * invmod(
                    (point.x - self.x) % self.curve.p, self.curve.p
                )
                x3 = (lmd**2 - self.x - point.x) % self.curve.p
                y3 = (lmd(self.x - x3) - self.y) % self.curve.p
                return self.curve.take_common_point(x3, y3)
        raise TypeError()
    
    def __str__(self):
        return f"({hex(self.x)[2:].upper},{hex(self.y)[2:].upper})"


class ECPointPInfinity(ECPointP):
    def __init__(self,curve):
        super().__init__(curve)

    def __add__(self, point):
        if isinstance(point, ECPointPInfinity):
            return self.curve.take_infinity_point()
        if isinstance(point, ECPointPCommon):
            return self.curve.take_common_point(point.x, point.y)
        raise TypeError()
    def __str__(self):
        return "O(Infinity,Infinity)"

class SM2_P:
    def __init__(self):
        p = int(
            "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3".replace(" ",''),
            16,
        )
        a = int(
            "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498".replace(" ",''),
            16,
        )
        b = int(
            "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A".replace(" ",''),
            16,
        )
        self.curve = EllipticCurveP(p, a, b)
        self.G = self.curve.take_common_point(
            int(
                "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D".replace(" ",''),
                16
            ),
            int(
                "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2".replace(" ",''),
                16
            )
        )
        self.n = int(
            "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7".replace(" ",''),16
        )
        self.d = 0
        self.P = self.curve.take_infinity_point()

    def gen_key(self):
        self.d = random.randint(1, self.n - 1)

    def get_private_key(self):
        return self.d

    def get_public_key(self):
        return self.P


if __name__ == "__main__":
    sm2_p = SM2_P()
    print(sm2_p.G+sm2_p.G)
