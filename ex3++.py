from ex3 import ThresholdSecretSharing

n=5
t=3
tss = ThresholdSecretSharing(t,n)
print("n=",n)
print("t=",t)
with open("secret1.txt") as f:
    problem = f.read()
secret_num = int(problem)
tss.share_secret(secret_num)
recover_set=set(range(2))
print("recover_set",recover_set)
solution = tss.decrypt_secret(recover_set)
k_=solution[0]
M_=solution[1]
print(k_)
count=0
while k_!=secret_num:
    count+=1
    k_=k_+M_
    print("round",count)
    print(k_)