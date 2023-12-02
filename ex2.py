from itertools import combinations
from ex1 import gcd


def ext_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = ext_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


def invmod(e, et):
    gcd, x, y = ext_gcd(e, et)
    if gcd != 1:
        return None
    else:
        return x % et


class CongEquations:
    def __init__(self, a, m):
        if len(a) != len(m):
            raise ValueError()
        else:
            self.size = len(a)
        self.a_list = a
        self.m_list = m
        self.m = 0
        self.M_list = []
        self.M_inv_list = []
        self.xj_list = []
        self.x = []
        self.solution = ()

    def solve_CRT(self):
        # check for CRT
        for c in combinations(self.m_list, 2):
            if gcd(c[0], c[1]) != 1:
                print("not fit for CRT")
                return None
        # calculate m
        _m = 1
        for mi in self.m_list:
            _m *= mi
        self.m = _m
        # calculate Mj
        self.M_list = [
            self.m // mi for mi in self.m_list
        ]  # you are supposed to use `//` to deal with big integers
        # calculate Mj_inv
        self.M_inv_list = [invmod(Mj, mi) for Mj, mi in zip(self.M_list, self.m_list)]
        # calculate xj
        self.xj_list = [
            self.a_list[i] * self.M_list[i] * self.M_inv_list[i]
            for i in range(self.size)
        ]
        # calculate x
        self.x = sum(self.xj_list) % self.m
        self.solution = (self.x, self.m)
        return self.solution

    def display_CRT(self):
        print("m:", self.m)
        for i in range(self.size):
            print("M" + str(i) + ": " + str(self.M_list[i]))
        for i in range(self.size):
            print("M" + str(i) + "_inv: " + str(self.M_inv_list[i]))
        for i in range(self.size):
            print("x" + str(i) + ": " + str(self.xj_list[i]))
        print("x:", self.x)
        print("solution:")
        print("x = " + str(self.x) + " mod " + str(self.m))

    def test_ans(self,ans=None):
        if ans==None:
            ans=self.x
        for i in range(self.size):
            assert ans % self.m_list[i] == self.a_list[i]
        print("test passed")


if __name__ == "__main__":
    print("========problem 5========")
    with open("5.txt") as f5:
        problem5 = f5.read().split()
    a_list_5 = [int(a) for a in problem5[:3]]
    m_list_5 = [int(m) for m in problem5[3:6]]
    ce5 = CongEquations(a_list_5, m_list_5)
    if ce5.solve_CRT() != None:
        ce5.display_CRT()
        ce5.test_ans()
    print("========problem 7========")
    with open("7.txt") as f7:
        problem7 = f7.read().split()
    a_list_7 = [int(a) for a in problem7[:3]]
    m_list_7 = [int(m) for m in problem7[3:6]]
    ce7 = CongEquations(a_list_7, m_list_7)
    if ce7.solve_CRT() != None:
        ce7.display_CRT()
        ce7.test_ans()
