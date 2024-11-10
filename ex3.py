from ex2 import CongEquations
from functools import reduce
from Crypto.Util.number import getPrime
import random


class ThresholdSecretSharing:
    def __init__(self, t, n):
        self.t = t
        self.n = n
        self.ciphernum = 0
        self.d_list = []
        self.share_list = []

    def share_secret(self, ciphernum):
        self.ciphernum = ciphernum
        self.gen_primes(ciphernum)
        self.share_list = [(ciphernum % d, d) for d in self.d_list]
        return self.share_list

    def gen_primes(self, ciphernum):
        # i think the most difficult part is to satisfy k>M
        ciphernum_bit_len = ciphernum.bit_length()
        d_len = (ciphernum_bit_len + self.t - 2) // (
            self.t - 1
        )  # the best d_len i think
        M_list = [getPrime(d_len) for i in range(self.t - 1)]
        while reduce(lambda x, y: x * y, M_list) >= ciphernum:
            M_list = [getPrime(d_len) for i in range(self.t - 1)]
        d_list = [0]
        while reduce(lambda x, y: x * y, d_list[: self.t]) <= ciphernum:
            d_list = M_list.copy()
            M_min = min(M_list)
            for i in range(self.n - self.t + 1):
                p = 0
                while p > M_min or p == 0:
                    p = getPrime(d_len)
                d_list.append(p)
            d_list.sort()
        self.d_list = d_list

    def decrypt_secret(self, recover_set):
        ce = CongEquations(
            [self.share_list[i][0] for i in recover_set],
            [self.share_list[i][1] for i in recover_set],
        )
        solution = ce.solve_CRT()
        return solution

    def rand_recover_set(self, recoverd_by_num):
        if recoverd_by_num > self.n:
            raise ValueError()
        return set(random.sample(range(self.n), recoverd_by_num))


if __name__ == "__main__":
    print("(t,n) Threshold Secret Sharing Experiment")
    tss = ThresholdSecretSharing(3, 5)
    with open("ex3_secrets/secret1.txt") as f:
        problem = f.read()
    secret_num = int(problem)
    print("========secret number========")
    print(secret_num)
    print("========share secret========")
    tss.share_secret(secret_num)
    for i in range(tss.n):
        print("shared key " + str(i) + ":")
        print(tss.share_list[i])
    N = reduce(lambda x, y: x * y, tss.d_list[: tss.t])
    M = reduce(lambda x, y: x * y, tss.d_list[-tss.t+1:])
    print("N = ", N)
    print("M = ", M)
    print("N > k > M : ", N > tss.ciphernum and tss.ciphernum > M)
    print("========recover secret by 3 keys========")
    recover_set = tss.rand_recover_set(3)
    print("randomly choose indexes: ", recover_set)
    solution = tss.decrypt_secret(recover_set)
    print("recovered num: ", solution[0])
    print("check with the true secret: ", solution[0] == secret_num)
    print("========recover secret by 2 keys========")
    recover_set = tss.rand_recover_set(2)
    print("randomly choose indexes: ", recover_set)
    solution = tss.decrypt_secret(recover_set)
    print("recovered num: ", solution[0])
    print("check with the true secret: ", solution[0] == secret_num)
