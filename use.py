from ex5 import *

sm2=SM2_P()
str1="Gyling"
str_bin = ''.join(format(ord(char), '08b') for char in str1)
int1= int(str_bin, 2)
print(hex(sm2.G.fast_mod_exp(int1).x)[2:].upper())
print(hex(sm2.G.fast_mod_exp(int1).y)[2:].upper())