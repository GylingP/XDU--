import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def fast_mod_exp(base,exp,mod):
    result=1
    bi_list=[]
    while exp>0:
        bi_list.append(exp%2)
        exp//=2    
    for i in reversed(bi_list) :
        result=result ** 2 % mod
        if i==1:
            result=result * base % mod
    return result

def get_cong_class(a,m):
    #return a**(m-1)%m
    return fast_mod_exp(a,m-1,m)

def fermat_pr_k(m,k):
    for i in range(k):
        a=random.randint(2,m-2)
        if gcd(a,m)!=1:
            return 0
        if get_cong_class(a,m)==1:
            print("Test for "+str(i+1)+" round.The probability of prime is "+str(1-1/2**(i+1)))
        else:
            return 0
    else:
        return 1-1/2**(i+1)

def fermat_test_k(m,k):
    if(fermat_pr_k(m,k))==0:
        print("composite")
    else:
        print("probably prime")


if __name__=="__main__":
    with open("1.txt") as f1:
        problem1 = f1.read()
    with open("3.txt") as f3:
        problem3 = f3.read()
    great_num1=int(problem1)
    great_num3=int(problem3)
    print("======== Fermat primality test for case 1 ======== ")
    print("case 1 : "+str(great_num1))
    fermat_test_k(great_num1,10)
    print("======== Fermat primality test for case 3 ======== ")
    print("case 3 : "+str(great_num3))
    fermat_test_k(great_num3,10)